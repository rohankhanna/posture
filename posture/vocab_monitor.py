"""The vocabulary monitor — the self-updating half of the map.

The glossary is the dictionary; this module is what makes it *grow on its own*
without breaking. Two paths, both AUTO (the machine notices; the human decides
to trust):

  - **emergent:** a witness emits keys of a KIND the glossary does not know
    (e.g. a brand-new advisory scheme). The engine calls `scan_emergent` after
    each witness run; an unknown kind becomes a `NewTermSignal` and is
    auto-written to the glossary as a **candidate**. The verdict for an
    unknown-kind record is tagged (never crashes, never silently trusted).

  - **structured:** a periodic sweep of the discovery aggregators (FIRST.org,
    CISA, ENISA, MITRE, OSV, CSAF, CycloneDX/SPDX, ...) for scheme/format NAMES
    not yet in the glossary. New names become candidate terms.

Candidates sit in a review queue. **Promoting** one (candidate -> known) is the
human trust gate — see `glossary.promote_term`. A security tool that auto-
promoted its own terms would be an attack surface; this is the line.

The deterministic `glossary.suggest_for_signal` gives a model-free first guess
for each signal (related by kind/role/label). The LLM classifier (off by
default) can draft a richer guess; it never judges trust.
"""

from __future__ import annotations
import datetime as _dt
import sqlite3
from dataclasses import dataclass


@dataclass
class NewTermSignal:
    kind: str          # the unknown kind (e.g. "X") or "source" for structured hits
    label: str         # a human-readable name for the candidate term
    context: str       # where/how it was seen
    citation: str      # a citable pointer (the map is cited)
    detected_at: str


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# Emergent path — unknown identifier kinds in witness output (AUTO)
# ---------------------------------------------------------------------------

def scan_emergent(conn: sqlite3.Connection, witness_id: str,
                  key_kind: str | None, keys: list[str],
                  now: str | None = None) -> list[NewTermSignal]:
    """After a witness run: if the witness declares a `key_kind` not in the
    glossary's known set, surface it as a signal and auto-write a candidate
    term. The system keeps running on the known spine; nothing breaks.

    Returns the signals raised (usually 0 or 1). A known kind raises nothing.
    """
    from . import glossary as _glossary
    from . import store as _store
    ts = now or _now()
    if not key_kind:
        return []
    # a witness's key_kind is a specific scheme id (e.g. "cve", "X"); it is
    # "known" only if a KNOWN term with that id exists. An unknown or merely-
    # candidate scheme is an emergent signal (the map grows; nothing breaks).
    existing = _glossary.get(conn, key_kind)
    if existing is not None and existing.status == "known":
        return []
    sig = NewTermSignal(
        kind=key_kind,
        label=key_kind,
        context=f"emergent: witness '{witness_id}' emitted {len(keys)} key(s) "
                f"of unknown kind (sample: {keys[0] if keys else ''})",
        citation=f"witness={witness_id}",
        detected_at=ts,
    )
    _store.add_term_signal(conn, sig.kind, sig.label, sig.context,
                            sig.citation, ts)
    if existing is None:
        _glossary.add_term(conn, _glossary.Term(
            id=key_kind, label=key_kind, kind="identifier_scheme",
            roles=[], status="candidate", citation=f"emergent via {witness_id}",
            discovered_at=ts,
        ), actor="vocab_monitor", now=ts)
    return [sig]


# ---------------------------------------------------------------------------
# Structured path — sweep aggregators for new scheme/format names (AUTO)
# ---------------------------------------------------------------------------

def scan_structured(conn: sqlite3.Connection, now: str | None = None) -> list[NewTermSignal]:
    """Sweep the discovery aggregators' known schemes/formats and surface any
    not yet in the glossary as candidate terms. Reuses `discovery.AGGREGATORS`
    + `STANDARD_FORMATS`. Offline-safe: it diffs against a static set of known
    scheme/format tokens, not a live fetch (a real impl would fetch each
    aggregator for genuinely-new feeds; the interface is what matters here)."""
    from . import discovery as _discovery
    from . import glossary as _glossary
    from . import store as _store
    ts = now or _now()
    known_ids = {t.id for t in _glossary.all(conn)}
    signals: list[NewTermSignal] = []
    # the standard formats are the bet on what new sources will speak
    for fmt, label in _discovery.STANDARD_FORMATS.items():
        if fmt in known_ids:
            continue
        sig = NewTermSignal(
            kind="advisory_format" if fmt in {"csaf", "stix", "oval"} else
                  ("inventory_format" if fmt in {"cyclonedx", "spdx"} else "other"),
            label=label,
            context=f"structured scan: standard format {fmt} not yet a known term",
            citation="discovery.STANDARD_FORMATS",
            detected_at=ts,
        )
        _store.add_term_signal(conn, sig.kind, sig.label, sig.context,
                                sig.citation, ts)
        _glossary.add_term(conn, _glossary.Term(
            id=fmt, label=label, kind=sig.kind, roles=[],
            status="candidate", citation="discovery horizon scan",
            discovered_at=ts,
        ), actor="vocab_monitor", now=ts)
        signals.append(sig)
        known_ids.add(fmt)
    return signals


# ---------------------------------------------------------------------------
# Review queue — candidates awaiting a human promote/deprecate decision
# ---------------------------------------------------------------------------

def queue(conn: sqlite3.Connection) -> list[dict]:
    """Candidate terms awaiting human review (the trust gate)."""
    from . import glossary as _glossary
    return [t.to_dict() for t in _glossary.all(conn, status="candidate")]


def open_signals(conn: sqlite3.Connection) -> list[dict]:
    from . import store as _store
    return _store.term_signals(conn, status="open")