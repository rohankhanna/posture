"""Source-agnostic LLM enrichment — the LLM-as-map / human-as-trust invariant.

Where :mod:`posture.refresh` enriches MITRE skeletons from NVD (a foreign-
authored map point via curl), this module drafts catalog *map* fields for ANY
source's thin/unscored rows using an LLM — the only place an LLM touches the
catalog. It is the source-agnostic generalization of the NVD-thin enrichment
target: the same draft path covers a mitre skeleton NVD never enriched, an
unscored OSV/GHSA row, an Apple advisory, and the Ubuntu/Debian trackers, not
just NVD.

THE INVARIANT (holds for every source, enforced structurally — not by policy
an LLM could talk its way around):

  * **LLM-as-map** — the LLM drafts catalog fields only (cvss, severity,
    cvss_vector, description, fixed_raw ranges, refs, cwe, ref_tags). It NEVER
    decides trust or DEFCON. A drafted row carries ``source='llm:<model>'`` and
    ``enrich_state='llm'``.

  * **Human-as-trust** — the assess read path
    (:func:`posture.store.defects_for_cpe_head` and the territory pre-pass in
    :func:`posture.cli._inject_catalog_defects`) selects ``source='nvd'`` rows
    ONLY, so an llm-draft row is STRUCTURALLY BARRED from
    :func:`posture.sources.nvd_cve.decide_cve_for_device`. No trust or DEFCON
    verdict can ever come from an LLM draft. The bar does not depend on the LLM
    cooperating; it is a filter on the ``source`` column the LLM cannot set to
    ``'nvd'`` through this module.

  * **Real-source precedence** — a draft fills only EMPTY catalog fields; a
    later real-source enrichment (NVD/OSV/GHSA) overwrites the draft, so a
    foreign-authored map point always wins over an LLM draft. The LLM never
    clobbers a real source's value.

THE VALIDATOR (the REAL trust boundary, node_680976461c89):

  :func:`validate_draft` deterministically rejects a malformed LLM draft
  *before* it is written, so a provider's bad output cannot pollute the signed
  spine even though the ``source='nvd'`` bar already forbids it from a trust
  decision. The validator — not the prompt — is what makes providers
  interchangeable: a cheap model that hallucinates ``cvss=99.9`` or prose
  ``severity="very bad"`` is rejected by code the model cannot talk its way
  around. The checks here are the hermetic, provider-independent FORMAT gates
  (cvss range, severity vocabulary, CVSS-vector grammar, http(s) refs,
  CWE-<digits> ids, fixed_raw range shapes). The LIVE halves — url-RESOLVES
  (a HEAD check), CWE-EXISTS (against the MITRE CWE catalog), and semantic
  version-PARSE (against the package ecosystem's comparator) — are deferred
  to the provider-wiring follow-up: they need a network or a catalog the
  off-by-default seam does not ship with, and the no-local-feeding rule
  forbids network in CI tests. The format gates are the provider-independent
  trust boundary today; the live gates are additive layers on top, not
  replacements.

THE SEAM (off-by-default, operator-gated, provider-replaceable):

  The provider is NOT wired here — by design, so the trust boundary never
  depends on a specific backend. :func:`llm_enrich_tick` takes a ``draft_fn`` —
  a callable ``(defect_row) -> drafted_fields | None`` — that the operator's
  chosen provider plugs into (the node_680976461c89 gate). With ``POSTURE_LLM``
  unset the default seam (:func:`default_draft_fn`) refuses, so the LLM NEVER
  runs until the operator picks a provider. Tests inject a stub ``draft_fn``;
  no real network or provider is required for any of this code or its tests.

No-wipe: a draft failure (``draft_fn`` returns None or raises) SKIPS the row —
the tick never raises and never deletes anything. A draft is a targeted UPDATE
of catalog columns only; the trust columns (distrusted, distrust_reason) and
first-sighting (discovered_at) are never touched.

Under the operator-decided spine policy B (publish-labeled), drafted rows flow
through :func:`posture.export.export_spine` unchanged — they are defects rows
with a visible ``source='llm:<model>'`` label, retractable in signed git
history. The label is the honesty mechanism: a draft is never mistaken for a
foreign-authored map point.
"""
from __future__ import annotations

import json as _json
import os
import re as _re
from typing import Callable, Optional
from urllib.parse import urlparse as _urlparse

from . import store as _store

#: Prefix on the defects.source column that marks an LLM-drafted row.
LLM_SOURCE_PREFIX = "llm:"
#: The enrich_state value stamped on an LLM-drafted row. Sits alongside the
#: existing 'mitre' | 'nvd' | 'osv' | 'ghsa' states; the assess decide path
#: selects source='nvd' only, so this state never reaches a trust decision.
LLM_ENRICH_STATE = "llm"

# Per-tick cap on LLM drafts (the expensive part — one provider call per row).
# Safe to cap: undrafted thin rows stay thin for the next tick, no loss.
DEFAULT_CAP = 200

# Catalog MAP fields an LLM may draft. Trust/DEFCON columns (distrusted,
# distrust_reason) are deliberately ABSENT: the LLM may never set them.
_DRAFT_FIELDS = ("cvss", "severity", "cvss_vector", "description",
                 "fixed_raw", "refs", "cwe", "ref_tags")
# Defects columns stored as JSON; a drafted value must be serialized on write.
_JSON_COLS = frozenset({"fixed_raw", "refs", "cwe", "ref_tags"})

# --- the deterministic draft validator (provider-independent trust boundary) -
# CVSS vector grammar: ``CVSS:<2|3>[.x]/<METRIC>:<value>[/<METRIC>:<value>...]``.
# Keys are letters (AV, AC, PR, ...); values are any non-slash run (N, L, H,
# 'M'/'S'/'U' for Scope, etc.). One metric minimum; matches v2 and v3.x shapes.
_CVSS_VECTOR = _re.compile(r"^CVSS:[23](?:\.\d)?(?:/[A-Za-z]+:[^/\s]+)+$")
# CWE ids are ``CWE-<digits>``. CWE-EXISTS against the real MITRE catalog is the
# deferred live gate (posture ships no CWE catalog today); this format check is
# the provider-independent floor.
_CWE_ID = _re.compile(r"^CWE-\d+$")
# Severity vocabulary = NVD (CRITICAL/HIGH/MEDIUM/LOW) ∪ OSV (MODERATE/UNKNOWN).
# An LLM prose severity ("very bad", "high-risk") is rejected by code, not by a
# prompt the model could ignore. Case-insensitive.
_SEVERITIES = frozenset(s.upper() for s in
                        ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW",
                         "UNKNOWN"))
# fixed_raw range bound keys whose values (if present) must be strings (the
# structural floor of version-PARSE; semantic parsing against the package
# ecosystem's comparator is the deferred live gate — NVD CPE versions and
# dpkg versions are different schemes, so a single semantic parser would be a
# false gate today).
_RANGE_BOUND_KEYS = ("vstart_incl", "vend_excl", "vstart_excl", "vend_incl",
                     "introduced", "fixed", "last_affected")


def _valid_refs(refs: object) -> bool:
    """True if every ref is an http(s) URL with a network location — the
    provider-independent url-FORMAT gate. url-RESOLVES (a live HEAD check) is the
    deferred layer: it needs network, which the no-local-feeding rule forbids in
    CI and which the off-by-default seam ships without."""
    for r in refs:  # type: ignore[union-attr]
        if not isinstance(r, str):
            return False
        p = _urlparse(r)
        if p.scheme not in ("http", "https") or not p.netloc:
            return False
    return True


def _validate_fixed_raw(fr: object) -> tuple[bool, str]:
    """Structural check on a drafted ``fixed_raw`` dict: must be a dict; if it
    carries ``ranges``, each range is a dict whose version-bound keys (if
    present) are strings. Returns (ok, error-or-empty)."""
    if not isinstance(fr, dict):
        return False, "fixed_raw must be a dict"
    ranges = fr.get("ranges")
    if ranges is None:
        return True, ""  # cpe_heads-only / advisory-link drafts carry no ranges
    if not isinstance(ranges, list):
        return False, "fixed_raw.ranges must be a list"
    for r in ranges:
        if not isinstance(r, dict):
            return False, "fixed_raw.ranges entries must be dicts"
        for bk in _RANGE_BOUND_KEYS:
            v = r.get(bk)
            if v is not None and not isinstance(v, str):
                return False, f"fixed_raw range bound {bk} must be a string"
    return True, ""


def validate_draft(drafted: object) -> tuple[bool, list[str]]:
    """Deterministic validation of an LLM-drafted field set — the REAL trust
    boundary (node_680976461c89). A draft that fails any check is REJECTED: it
    is never written to the catalog, so malformed LLM output cannot pollute the
    signed spine even with the ``source='nvd'`` bar already barring it from a
    trust decision.

    Returns ``(ok, errors)``. Only the ``_DRAFT_FIELDS`` a draft actually
    carries are checked; absent fields are not errors (a draft may fill a
    subset). The checks are the hermetic, provider-independent FORMAT gates;
    see the module docstring for the deferred live gates (url-RESOLVES,
    CWE-EXISTS, semantic version-PARSE)."""
    errors: list[str] = []
    if not isinstance(drafted, dict):
        return False, ["draft must be a dict"]

    cvss = drafted.get("cvss")
    if cvss is not None:
        # bool is an int subclass — reject it explicitly.
        if isinstance(cvss, bool) or not isinstance(cvss, (int, float)):
            errors.append("cvss must be a number")
        elif not (0.0 <= float(cvss) <= 10.0):
            errors.append("cvss out of range [0, 10]")

    sev = drafted.get("severity")
    if sev is not None and (not isinstance(sev, str) or sev.upper() not in _SEVERITIES):
        errors.append("severity not in known vocabulary "
                      "(CRITICAL/HIGH/MEDIUM/MODERATE/LOW/UNKNOWN)")

    vec = drafted.get("cvss_vector")
    if vec is not None and (not isinstance(vec, str) or not _CVSS_VECTOR.match(vec)):
        errors.append("cvss_vector not a well-formed CVSS vector")

    desc = drafted.get("description")
    if desc is not None and (not isinstance(desc, str) or not desc.strip()):
        errors.append("description must be a non-empty string")

    refs = drafted.get("refs")
    if refs is not None and (not isinstance(refs, list) or not _valid_refs(refs)):
        errors.append("refs must be a list of http(s) URLs")

    cwe = drafted.get("cwe")
    if (cwe is not None and (not isinstance(cwe, list) or not cwe or
            not all(isinstance(c, str) and _CWE_ID.match(c) for c in cwe))):
        errors.append("cwe must be a non-empty list of CWE-<digits> ids")

    ref_tags = drafted.get("ref_tags")
    if (ref_tags is not None and (not isinstance(ref_tags, list) or
            not all(isinstance(t, str) for t in ref_tags))):
        errors.append("ref_tags must be a list of strings")

    fr = drafted.get("fixed_raw")
    if fr is not None:
        ok_fr, fr_err = _validate_fixed_raw(fr)
        if not ok_fr:
            errors.append(fr_err)

    return (not errors), errors


def _now() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def is_llm_draft(row: dict) -> bool:
    """True if this catalog row is an LLM draft (``source`` starts with
    ``llm:``). The structural bar from the assess decide path relies on
    ``source='nvd'`` selection, so an llm-draft row never reaches
    :func:`decide_cve_for_device` regardless of this helper; ``is_llm_draft``
    just makes the label explicit for callers and tests."""
    return bool((row.get("source") or "").startswith(LLM_SOURCE_PREFIX))


def _row_is_thin(row: dict) -> bool:
    """A row is 'thin/unscored' when it lacks the catalog map fields an LLM
    could draft: no CVSS score, no CVSS vector, AND no usable affected info in
    ``fixed_raw``. Source-agnostic — applies identically to a mitre skeleton,
    an unscored OSV/GHSA row, or an un-scored Apple advisory. A row that
    already carries any of these is NOT thin (a real source enriched it) and is
    left alone."""
    if row.get("cvss") is not None or row.get("cvss_vector"):
        return False
    ranges = (row.get("fixed_raw") or {}).get("ranges") or []
    # a CPE-shaped NVD range carries a criteria; an OSV/GHSA event-range carries
    # affected/events. Either is usable affected info the LLM must not re-draft.
    if any(r.get("criteria") or r.get("events") or r.get("affected")
           for r in ranges):
        return False
    return True


def thin_defect_ids(conn, source: str | None = None,
                    limit: int | None = None) -> list[str]:
    """Thin/unscored defect ids, most-recent first — the source-agnostic LLM
    draft pool. ``source`` (optional) restricts to one provenance's thin rows:
    ``source='mitre'`` is the NVD-thin case this generalizes from (skeletons
    NVD never enriched); ``source='osv'`` / ``'ghsa'`` select those peers' thin
    rows; ``None`` covers every source at once.

    Excludes rows already LLM-drafted (``source LIKE 'llm:%'``) — a draft is
    not re-drafted — and distrusted rows (a retroactively-distrusted map point
    is not re-enriched by an LLM)."""
    sql = ("SELECT id, cvss, cvss_vector, fixed_raw, source FROM defects "
           "WHERE (distrusted IS NULL OR distrusted=0) "
           "AND (source IS NULL OR source NOT LIKE ?) ")
    params: list = [LLM_SOURCE_PREFIX + "%"]
    if source is not None:
        sql += "AND source=? "
        params.append(source)
    sql += "ORDER BY published DESC"
    out: list[str] = []
    for r in conn.execute(sql, params).fetchall():
        try:
            fr = _json.loads(r["fixed_raw"]) if r["fixed_raw"] else None
        except (ValueError, TypeError):
            fr = None
        if _row_is_thin({"cvss": r["cvss"], "cvss_vector": r["cvss_vector"],
                         "fixed_raw": fr}):
            out.append(r["id"])
            if limit and len(out) >= limit:
                break
    return out


def upsert_llm_draft(conn, defect_id: str, drafted: dict, model: str,
                     policy_version: str = "",
                     fetched_at: str | None = None) -> bool:
    """Write the DRAFTED catalog map fields into one defect row, labeling it an
    LLM draft. Enforces the invariant:

      * Only EMPTY fields are filled — a field the row already carries (from a
        real source) is kept; the draft never clobbers a real value.
      * Trust columns (distrusted, distrust_reason) and discovered_at are
        NEVER touched.
      * The row must still be thin / llm-owned when the UPDATE runs: if a real
        source enriched it between selection and write (source is a non-llm
        real value AND the row is no longer thin), the draft is SKIPPED — the
        foreign-authored map point wins.
      * ``source`` becomes ``llm:<model>`` and ``enrich_state`` becomes ``llm``,
        so the assess decide path (which selects ``source='nvd'``) structurally
        bars this row from ever producing a trust/DEFCON verdict.

    Returns True if the row was drafted, False if it was skipped (real source
    won / row vanished / draft added nothing the row lacked / draft failed
    validation)."""
    # Defense in depth: the trust boundary is :func:`validate_draft`, applied in
    # the tick before this is called. Re-check here so a DIRECT caller cannot
    # bypass it and write a malformed draft to the catalog.
    ok, _errors = validate_draft(drafted)
    if not ok:
        return False
    row = _store.get_defect(conn, defect_id)
    if row is None:
        return False
    src = row.get("source") or ""
    # a real (non-llm) source that has since enriched the row wins: skip.
    if src and not src.startswith(LLM_SOURCE_PREFIX) and not _row_is_thin(row):
        return False

    # merge: keep existing real values, fill only what the draft provides AND
    # the row currently lacks.
    merged: dict = {}
    for f in _DRAFT_FIELDS:
        new = drafted.get(f)
        if new is None:
            continue
        cur = row.get(f)
        if f == "fixed_raw":
            cur_fr = cur if isinstance(cur, dict) else {}
            new_fr = new if isinstance(new, dict) else {}
            # never let an LLM draft rewrite provenance of the underlying row.
            add = {k: v for k, v in new_fr.items()
                   if k not in ("source", "provenance") and not cur_fr.get(k)}
            if add:
                merged["fixed_raw"] = {**cur_fr, **add}
            continue
        if cur in (None, "", [], {}):
            merged[f] = new

    if not merged:
        return False  # draft added nothing the row lacked

    ts = fetched_at or _now()
    set_cols = list(merged.keys()) + ["source", "enrich_state",
                                      "fetched_at", "policy_version"]
    set_sql = ", ".join(f"{c}=?" for c in set_cols)
    vals = [(_json.dumps(merged[c], default=str, sort_keys=True)
            if c in _JSON_COLS else merged[c])
           for c in merged.keys()]
    vals += [f"{LLM_SOURCE_PREFIX}{model}", LLM_ENRICH_STATE, ts, policy_version]
    conn.execute(f"UPDATE defects SET {set_sql} WHERE id=?", (*vals, defect_id))
    return True


#: A provider draft function: given a parsed defect row, return the drafted
#: catalog fields (a subset of the ``_DRAFT_FIELDS``), or None to skip.
DraftFn = Callable[[dict], Optional[dict]]


def llm_enrich_tick(conn, draft_fn: DraftFn, model: str,
                    cap: int = DEFAULT_CAP, source: str | None = None,
                    policy_version: str = "", now: str | None = None) -> dict:
    """One LLM-draft tick over the thin/unscored pool. For each thin id, call
    ``draft_fn(defect_row) -> drafted_fields | None`` and upsert the draft.

    The seam: ``draft_fn`` is the ONLY place a provider plugs in; this module
    wires no provider. With ``POSTURE_LLM`` unset, :func:`default_draft_fn`
    refuses, so the tick drafts nothing until the operator gates a provider.

    No-wipe: a ``draft_fn`` that returns None or raises is SKIPPED — the tick
    never raises and never deletes. A draft that fails :func:`validate_draft`
    is REJECTED (counted separately) and never written — the trust boundary.
    Returns a stats dict
    ``{selected, drafted, skipped, rejected, errors, provider, source}``."""
    ts = now or _now()
    stats = {"selected": 0, "drafted": 0, "skipped": 0, "rejected": 0,
             "errors": 0, "provider": model, "source": source}
    ids = thin_defect_ids(conn, source=source, limit=cap)
    stats["selected"] = len(ids)
    for cid in ids:
        row = _store.get_defect(conn, cid)
        if row is None:
            stats["skipped"] += 1
            continue
        try:
            drafted = draft_fn(row)
        except Exception:
            stats["errors"] += 1
            continue  # no-wipe: a provider error skips the row, never raises
        if not drafted:
            stats["skipped"] += 1
            continue
        ok, _errors = validate_draft(drafted)
        if not ok:
            stats["rejected"] += 1
            continue  # no-wipe: a malformed draft is rejected, never written
        if upsert_llm_draft(conn, cid, drafted, model,
                            policy_version=policy_version, fetched_at=ts):
            stats["drafted"] += 1
        else:
            stats["skipped"] += 1
    return stats


def default_draft_fn(_row: dict) -> Optional[dict]:
    """The off-by-default, provider-replaceable seam.

    * ``POSTURE_LLM`` unset -> return None (the tick drafts nothing and reports
      the selected count). The LLM cannot run unattended in CI.
    * ``POSTURE_LLM`` set but no real provider is plugged in -> raise so the
      tick records an error per row (no drafts); the operator must supply a
      real ``draft_fn`` to :func:`llm_enrich_tick` (the node_680976461c89 gate).

    This default is deliberately backend-free so the trust boundary never
    depends on a specific provider."""
    if not os.environ.get("POSTURE_LLM"):
        return None
    raise RuntimeError(
        "POSTURE_LLM is set but no provider draft_fn is wired; pass a real "
        "draft_fn to llm_enrich_tick (the operator-gated provider, "
        "node_680976461c89).")