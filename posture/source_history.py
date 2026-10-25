"""Public-infrastructure event ledger — source reliability as data.

The map is not the territory. A device's risk changes for two separable
reasons: (a) something changed on the device (a package was patched, a port
opened), and (b) something changed *upstream* in the public sources posture
depends on (NVD stopped enriching a CVE, MITRE moved to a new CVE record
format, an EPSS feed host expired, a tracker's rate limit tightened). Without
a side-by-side ledger of the second kind, a shift in the fleet view is
indistinguishable from a shift in the map — the exact conflation posture
exists to prevent.

This module is the engine-side, structured record of upstream-source events.
Each SourceEvent records *when*, *which source*, *what kind of event*,
*what changed*, *which map layer it touches*, *evidence*, *current status*,
and *how posture should interpret it*. The ledger is trust-policy adjacent:
source reliability is an engine-level concern, so the ledger lives in posture
(not in the Forebode/weatherman shell, which only surfaces a slice).

Design notes
------------
* **Open vocabulary.** event_type / map_layer / status are plain
  strings with a set of *known* constants, not closed enums. A future event
  of an unanticipated kind must record without a code change (mirrors the
  axis-set creed: the seed set is not a structural ceiling). Validation only
  rejects malformed *structure* (missing required fields, bad dates), never an
  unknown vocabulary value.
* **Data, not code, is the goal.** The seed events are bundled here so the
  first slice is self-contained and testable, but EventLedger loads/saves
  JSONL, so the canonical home can move to a versioned data file (alongside
  posture/policy/policy.yaml) without an API change.
* **Stdlib-only, offline, deterministic** — autonomy A1: no network, no
  secrets, no wall-clock dependence. Dates are stored as ISO-8601 strings.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Open vocabulary — known constants (NOT a closed set; see module docstring)
# ---------------------------------------------------------------------------

# Map layers a source event can perturb. These line up with the posture spine
# layers: who-am-I (identifier), what's known about it (enrichment), how bad
# (scoring), what fixes it (patch-state), and who we trust (trust-policy).
LAYER_IDENTIFIER = "identifier"
LAYER_ENRICHMENT = "enrichment"
LAYER_SCORING = "scoring"
LAYER_PATCH_STATE = "patch-state"
LAYER_TRUST_POLICY = "trust-policy"
KNOWN_LAYERS = frozenset({
    LAYER_IDENTIFIER, LAYER_ENRICHMENT, LAYER_SCORING,
    LAYER_PATCH_STATE, LAYER_TRUST_POLICY,
})

# Kinds of things that happen to a public source. Open set.
EVENT_DEGRADATION = "degradation"            # source lost coverage/quality
EVENT_OUTAGE = "outage"                       # source was unreachable
EVENT_FORMAT_CHANGE = "format-change"         # schema/transport changed
EVENT_DATA_CORRECTION = "data-correction"     # source fixed/retracted data
EVENT_RATE_LIMIT = "rate-limit"               # throttling policy changed
EVENT_POLICY_CHANGE = "policy-change"         # upstream governance change
EVENT_FEED_RELOCATED = "feed-relocated"       # host/URL moved
KNOWN_EVENT_TYPES = frozenset({
    EVENT_DEGRADATION, EVENT_OUTAGE, EVENT_FORMAT_CHANGE,
    EVENT_DATA_CORRECTION, EVENT_RATE_LIMIT, EVENT_POLICY_CHANGE,
    EVENT_FEED_RELOCATED,
})

# Lifecycle of a recorded event.
STATUS_ACTIVE = "active"          # still in effect / still being interpreted
STATUS_RESOLVED = "resolved"      # upstream reverted/fixed; kept for history
STATUS_SUPERSEDED = "superseded"  # replaced by a later event (see `supersedes`)
KNOWN_STATUSES = frozenset({STATUS_ACTIVE, STATUS_RESOLVED, STATUS_SUPERSEDED})

REQUIRED_FIELDS = ("id", "date", "source", "event_type", "summary",
                   "map_layer", "status")


class SourceHistoryError(ValueError):
    """Malformed event structure (missing field, bad date, bad enum shape)."""


# ---------------------------------------------------------------------------
# SourceEvent
# ---------------------------------------------------------------------------

@dataclass
class SourceEvent:
    """One dated event in a public upstream source.

    interpretation is the posture-specific read: not what happened, but
    what posture does about it (which overlay fills the gap, which gate
    prevents the failure mode, which node tracks the follow-up). This keeps
    the ledger usable as a trust-policy input, not just a diary.
    """

    id: str                       # stable slug, e.g. "nvd-2026-04-15-enrichment-gap"
    date: str                     # ISO-8601 date the event was observed/occurred
    source: str                   # source id, e.g. "nvd", "mitre", "osv", "epss"
    event_type: str               # one of KNOWN_EVENT_TYPES (open set)
    summary: str                  # what changed, one line
    map_layer: str                # which spine layer it perturbs (open set)
    status: str = STATUS_ACTIVE   # lifecycle
    evidence_url: str | None = None
    interpretation: str = ""      # how posture should read/act on it
    supersedes: str | None = None  # id of an earlier event this replaces

    def __post_init__(self) -> None:
        validate_event(asdict(self))

    def to_dict(self) -> dict:
        d = asdict(self)
        # drop None payloads to keep the JSONL tidy
        return {k: v for k, v in d.items() if v is not None}

    @classmethod
    def from_dict(cls, d: dict) -> SourceEvent:
        # Validate the raw dict first so a missing required field raises
        # SourceHistoryError (not a bare KeyError) and status does not silently
        # default when the serialized form omitted it.
        validate_event(d)
        return cls(
            id=d["id"],
            date=d["date"],
            source=d["source"],
            event_type=d["event_type"],
            summary=d["summary"],
            map_layer=d["map_layer"],
            status=d.get("status", STATUS_ACTIVE),
            evidence_url=d.get("evidence_url"),
            interpretation=d.get("interpretation", ""),
            supersedes=d.get("supersedes"),
        )


def _is_iso_date(s: str) -> bool:
    try:
        _dt.date.fromisoformat(s)
    except (ValueError, TypeError):
        return False
    return True


def validate_event(d: dict) -> None:
    """Structural validation — required fields present + well-typed + ISO date.

    Deliberately does NOT reject unknown event_type / map_layer /
    status values: the vocabulary is open (module docstring). It only
    guards against missing fields and malformed dates.
    """
    for name in REQUIRED_FIELDS:
        if not d.get(name):
            raise SourceHistoryError(f"missing required field: {name}")
    if not _is_iso_date(d["date"]):
        raise SourceHistoryError(f"date must be ISO-8601 (YYYY-MM-DD): {d['date']!r}")
    if not isinstance(d["summary"], str) or not d["summary"].strip():
        raise SourceHistoryError("summary must be a non-empty string")


# ---------------------------------------------------------------------------
# EventLedger — collection + JSONL persistence + filters
# ---------------------------------------------------------------------------

@dataclass
class EventLedger:
    events: list[SourceEvent] = field(default_factory=list)

    # -- mutation ----------------------------------------------------------
    def add(self, event: SourceEvent) -> None:
        if any(e.id == event.id for e in self.events):
            raise SourceHistoryError(f"duplicate event id: {event.id}")
        self.events.append(event)

    def extend(self, events: Iterable[SourceEvent]) -> None:
        for e in events:
            self.add(e)

    # -- query -------------------------------------------------------------
    def for_source(self, source: str) -> list[SourceEvent]:
        return [e for e in self.events if e.source == source]

    def for_layer(self, layer: str) -> list[SourceEvent]:
        return [e for e in self.events if e.map_layer == layer]

    def for_type(self, event_type: str) -> list[SourceEvent]:
        return [e for e in self.events if e.event_type == event_type]

    def active(self) -> list[SourceEvent]:
        return [e for e in self.events if e.status == STATUS_ACTIVE]

    def get(self, event_id: str) -> SourceEvent | None:
        return next((e for e in self.events if e.id == event_id), None)

    def sorted_by_date(self) -> list[SourceEvent]:
        return sorted(self.events, key=lambda e: e.date)

    # -- persistence -------------------------------------------------------
    def to_jsonl(self) -> str:
        return "".join(
            json.dumps(e.to_dict(), sort_keys=True) + "\n"
            for e in self.sorted_by_date()
        )

    def save(self, path: os.PathLike | str | Path) -> Path:  # type: ignore[name-defined]
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_jsonl(), encoding="utf-8")
        return p

    @classmethod
    def from_jsonl(cls, text: str) -> EventLedger:
        ledger = cls()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            ledger.add(SourceEvent.from_dict(json.loads(line)))
        return ledger

    @classmethod
    def load(cls, path: os.PathLike | str | Path) -> EventLedger:  # type: ignore[name-defined]
        return cls.from_jsonl(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Seed — the known public-infrastructure history posture has already lived
# through. Dates are the posture-observed/adopted dates; evidence URLs point
# at the canonical upstream. Append-only: never rewrite a past event's facts,
# only add a superseding one.
# ---------------------------------------------------------------------------

def seed_events() -> list[SourceEvent]:
    return [
        SourceEvent(
            id="nvd-2026-04-15-enrichment-gap",
            date="2026-04-15",
            source="nvd",
            event_type=EVENT_DEGRADATION,
            summary="NVD moved to risk-based enrichment; many CVEs no longer "
                    "carry CVSS vector / CPE applicability / EPSS-style data.",
            map_layer=LAYER_ENRICHMENT,
            status=STATUS_ACTIVE,
            evidence_url="https://nvd.nist.gov/general/nvd-dashboard",
            interpretation="The thin/unscored region is filled by OSV + EPSS "
                          "overlays and (operator-gated) LLM drafts labeled "
                          "source='llm:<model>'; nvd-thin rows are labeled and "
                          "barred from the assess decide path until promoted.",
        ),
        SourceEvent(
            id="nvd-2026-07-31-apikey-query-404-masquerade",
            date="2026-07-31",
            source="nvd",
            event_type=EVENT_DATA_CORRECTION,
            summary="An authenticated broad-CPE pull with the API key in the "
                    "URL query string returns 404 + empty body (the "
                    "'404-masquerade'); a DELETE+INSERT recompute then wiped "
                    "~14000 fleet rows.",
            map_layer=LAYER_IDENTIFIER,
            status=STATUS_RESOLVED,
            evidence_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            interpretation="Key is sent header-only (never in the query "
                          "string); the per-device completeness gate means an "
                          "empty/incomplete fetch preserves last-known-good "
                          "verdicts instead of wiping them (run-#10 class).",
        ),
        SourceEvent(
            id="epss-2026-09-09-feed-host-expired",
            date="2026-09-09",
            source="epss",
            event_type=EVENT_FEED_RELOCATED,
            summary="EPSS feed host epss.cyentific.com expired; feed relocated "
                    "to epss.empiricalsecurity.com.",
            map_layer=LAYER_SCORING,
            status=STATUS_RESOLVED,
            evidence_url="https://epss.empiricalsecurity.com/",
            interpretation="EPSS URL is pinned and monitored; the exploitability-"
                          "likelihood overlay (CVE-keyed, daily full refresh) "
                          "fills the NVD enrichment-degradation scoring gap.",
        ),
        SourceEvent(
            id="mitre-cvelistV5-canonical-stream",
            date="2024-02-01",
            source="mitre",
            event_type=EVENT_FORMAT_CHANGE,
            summary="CVE Program publishes cvelistV5 as the authoritative "
                    "git-published CVE record stream (CVE JSON 5.0), "
                    "superseding the legacy CVE List web downloads.",
            map_layer=LAYER_IDENTIFIER,
            status=STATUS_ACTIVE,
            evidence_url="https://github.com/CVEProject/cvelistV5",
            interpretation="The posture stream tick consumes cvelistV5 as the "
                          "publication signal (skeletons only, rate-limit-free "
                          "but git-fetch heavy); NVD enrichment runs as a "
                          "separate paced per-CVE pass, not as the publication "
                          "source.",
        ),
        SourceEvent(
            id="nvd-rate-limits",
            date="2026-04-15",
            source="nvd",
            event_type=EVENT_RATE_LIMIT,
            summary="NVD API throttles at ~5 req/30s anonymous and ~50 req/30s "
                    "with an API key.",
            map_layer=LAYER_IDENTIFIER,
            status=STATUS_ACTIVE,
            evidence_url="https://nvd.nist.gov/developers/vulnerabilities",
            interpretation="Ingestion is paced + incremental with a per-source "
                          "budget and cap-resumed backfill; rate limits become "
                          "natural throttling, not failures. The client never "
                          "holds the NVD API key in the signed-spine topology.",
        ),
        SourceEvent(
            id="osv-package-keyed-coverage",
            date="2026-08-01",
            source="osv",
            event_type=EVENT_FORMAT_CHANGE,
            summary="OSV mirrors NVD + GHSA plus many ecosystems (PyPI, npm, "
                    "Crates, etc.) keyed by package@ecosystem with affected "
                    "event-ranges, NOT by CPE.",
            map_layer=LAYER_IDENTIFIER,
            status=STATUS_ACTIVE,
            evidence_url="https://osv.dev/",
            interpretation="Consuming OSV/GHSA at assess needs a package "
                          "matcher (ecosystem+name+version) alongside nvd_cpe "
                          "and OSV-range decision logic over fixed_raw.ranges "
                          "(tracked separately; not yet wired).",
        ),
    ]


def default_ledger() -> EventLedger:
    """Ledger seeded with the known public-infrastructure history."""
    ledger = EventLedger()
    ledger.extend(seed_events())
    return ledger
