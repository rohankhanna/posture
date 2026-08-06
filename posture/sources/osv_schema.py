"""OSV-schema normalizer — the shared record parser for OSV + GHSA peers.

OSV (https://osv.dev) defines a *one schema for all vulnerability databases*.
GitHub's Advisory Database (GHSA), RustSec, PyPA, Go, Red Hat, Debian, Ubuntu,
Alpine, … all emit records in this shape, so one normalizer + two thin peer
modules (``ghsa.py`` for the git-clone GHSA source, ``osv.py`` for the GCS OSV
hub) cover a large fraction of the aggregator peer space. This is the mirror of
:func:`posture.mitre.mitre_record` for the OSV world.

A record::

    {
      "id": "GHSA-xxxx-xxxx-xxxx",        # the flaw_id under this peer's scheme
      "aliases": ["CVE-2026-1001"],       # equivalent ids (often a CVE)
      "published": "2026-07-04T...", "modified": "2026-08-06T...",
      "summary": "...", "details": "...",
      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}],
      "affected": [{"package": {"ecosystem": "...", "name": "..."},
                    "ranges": [{"type": "GIT", "repo": "...", "events": [...]}],
                    "versions": [...]}],
      "references": [{"type": "WEB", "url": "..."}],
      "cwes": [{"cweId": "CWE-78", ...}]   # GHSA carries these at top level
    }

``osv_record`` returns the normalized fields; ``osv_skeleton`` builds the
``upsert_flaw`` row + the alias list a peer tick should register. OSV/GHSA rows
are **self-enriched on ingest** (they carry cvss + ranges), so they land with
``enrich_state = source`` (NOT ``'mitre'`` pending) and the incremental refresh
leaves them alone — only cvelistV5 skeletons stay ``'mitre'`` for NVD enrichment.

**The map is not the territory.** An OSV/GHSA row is a point on the foreign-
authored map (OSV.dev / GitHub), never a fact about a machine. Ingestion only
adds catalog rows + alias-graph edges; it writes ZERO verdicts.
"""
from __future__ import annotations

import json as _json
from typing import Any

from ..mitre import vec_fields


def _severity_label(score: float | None) -> str | None:
    """NVD-style severity bucket from a numeric CVSS score."""
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return None


def _parse_score(raw: Any) -> tuple[float | None, str | None]:
    """OSV ``severity[].score`` may be a CVSS vector STRING ('CVSS:3.1/...')
    or a bare number. Returns (numeric_score, vector_string)."""
    if raw is None:
        return None, None
    if isinstance(raw, (int, float)):
        return float(raw), None
    s = str(raw).strip()
    if s.startswith("CVSS"):
        # vector string — no numeric score embedded; derive from the vector
        # is non-trivial, so leave numeric None (the label comes from the
        # vector's qualitative parse only if a numeric is unavailable). We keep
        # the vector so a viewer can still show the class.
        return None, s
    try:
        return float(s), None
    except ValueError:
        return None, None


def osv_record(rec: dict) -> dict | None:
    """Normalize one OSV-schema record. Returns the fields a peer tick needs, or
    None if the record has no usable ``id`` (a malformed record must not sink the
    tick). Pure function — no DB, no network.

    Every ``.get`` receiver is guarded against a non-dict field (a record where
    ``severity`` holds a string, or the whole record is a JSON array) returning
    the empty default rather than raising — mirroring the hardening of
    :func:`posture.mitre.mitre_record`. A single malformed record must not sink
    the GHSA/OSV tick.
    """
    if not isinstance(rec, dict):
        return None
    rid = rec.get("id")
    if not rid:
        return None

    # severity: pick the first CVSS entry (prefer V3.1 > V3 > V4 > V2).
    sev_list = rec.get("severity") or []
    if isinstance(sev_list, dict):
        sev_list = [sev_list]
    if not isinstance(sev_list, list):
        sev_list = []
    score: float | None = None
    vector: str | None = None
    rank = {"CVSS_V3_1": 0, "CVSS_V3": 1, "CVSS_V4_0": 2, "CVSS_V2": 3}
    # sort key must not call .get on a non-dict entry (a string severity entry
    # would crash before the isinstance guard in the loop) — rank it last.
    entries = sorted(sev_list,
                     key=lambda e: rank.get(e.get("type", ""), 9)
                                   if isinstance(e, dict) else 9)
    for e in entries:
        if not isinstance(e, dict):
            continue
        s, v = _parse_score(e.get("score"))
        if v:
            vector = v
        if s is not None:
            score = s
            break
    if score is None and vector is None:
        # nothing parseable here
        pass
    severity = _severity_label(score)

    # description: prefer summary (OSV's short title), fall back to details, then
    # the first affected[].ecosystem-specific note. Empty is allowed. Both
    # fields are str-guarded (a non-str summary/details would crash .strip()).
    _sum = rec.get("summary")
    desc = (_sum.strip() if isinstance(_sum, str) else "")
    if not desc:
        _det = rec.get("details")
        desc = (_det.strip() if isinstance(_det, str) else "")
    summary = _sum.strip() if isinstance(_sum, str) else ""

    # references: list of {type, url} -> [url, ...]
    refs = [r.get("url") for r in (rec.get("references") or [])
            if isinstance(r, dict) and r.get("url")]

    # aliases: the equivalent ids (e.g. a CVE). GHSA's own id is in ``id``, not
    # aliases; OSV records sometimes list their own ecosystem id here too.
    aliases = [a for a in (rec.get("aliases") or []) if isinstance(a, str) and a]

    # affected ranges: keep the structured shape for fixed_raw (the per-source
    # extension point). Each affected entry -> {package, ranges, versions}.
    affected = []
    for a in (rec.get("affected") or []):
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        ranges = a.get("ranges") or []
        affected.append({
            "package": {"ecosystem": pkg.get("ecosystem"),
                        "name": pkg.get("name")} if isinstance(pkg, dict) else {},
            "ranges": ranges,
            "versions": a.get("versions") or [],
        })

    # cwes: GHSA carries a top-level ``cwes`` list (each {cweId, ...}); some OSV
    # records embed CWE in affected[].ecosystem_specific. Collect top-level only.
    cwes: list[str] = []
    for c in (rec.get("cwes") or []):
        if isinstance(c, dict):
            cid = c.get("cweId") or ""
        else:
            cid = str(c or "")
        if cid.startswith("CWE-") and cid not in cwes:
            cwes.append(cid)

    # published/modified: only a string carries a meaningful date prefix; a
    # non-str value yields None rather than a sliced list.
    _pub = rec.get("published")
    _mod = rec.get("modified")
    return {
        "id": rid,
        "published": (_pub[:10] if isinstance(_pub, str) else None) or None,
        "modified": (_mod[:10] if isinstance(_mod, str) else None) or None,
        "summary": summary,
        "description": desc,
        "cvss": score,
        "severity": severity,
        "cvss_vector": vector,
        "refs": refs,
        "aliases": aliases,
        "affected": affected,
        "cwes": cwes,
    }


def osv_skeleton(rec: dict, source: str, flaw_type: str,
                 policy_version: str, fetched_at: str) -> tuple[dict, list[str]] | None:
    """Build ``(upsert_flaw_row, aliases_to_register)`` from an OSV-schema record.

    The row is **self-enriched**: ``source``/``flaw_type``/``enrich_state`` all
    record the peer scheme, and ``fixed_raw`` carries the affected ranges (the
    per-source extension point). The caller sets ``enrich_state = source``
    separately (it is preserved across re-upsert) and registers each alias in
    ``aliases_to_register`` as a symmetric crosswalk edge against ``rec['id']``
    via :func:`posture.store.add_flaw_alias` (the peer's own id is NOT in the
    alias list — it is the flaw_id of the row itself).

    Returns None for a record with no id.
    """
    parsed = osv_record(rec)
    if not parsed:
        return None
    rid = parsed["id"]
    vf = vec_fields(parsed["cvss_vector"])

    row = {
        "id": rid,
        "flaw_type": flaw_type,
        "published": parsed["published"],
        "cvss": parsed["cvss"],
        "severity": parsed["severity"],
        "cvss_vector": parsed["cvss_vector"],
        "description": parsed["description"],
        "fixed_raw": {
            "source": source,
            "ranges": parsed["affected"],
            "modified": parsed["modified"],
            "av": vf["av"], "c": vf["c"], "i": vf["i"], "a": vf["a"],
        },
        "refs": parsed["refs"],
        "cwe": parsed["cwes"],
        "ref_tags": [],
        "source": source,
        "fetched_at": fetched_at,
        "policy_version": policy_version,
        "complete": True,
    }
    return row, parsed["aliases"]