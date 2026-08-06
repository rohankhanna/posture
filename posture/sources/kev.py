"""CISA KEV ingestion — the exploitability_signal overlay.

CISA's Known Exploited Vulnerabilities catalog is a static JSON file
(``cisa.gov/.../known_exploited_vulnerabilities.json``) of ~1,660 entries, no
rate limit, business-day updates. Each entry carries only a ``cveID``, so KEV is
a CVE-keyed **overlay** — the ``exploitability_signal`` role — NOT a new
flaw_type. It annotates an existing cve catalog row ("this CVE is
known-exploited; required action X; due date Y; ransomware-linked Z") without
owning the flaw_id.

``kev_ingest_tick`` is an idempotent full refresh: fetch the static JSON via
:func:`posture.sources._net.curl_get`, upsert one ``kev`` row per
``vulnerabilities[]`` entry. The file is tiny, so re-pulling it whole each tick
is cheaper + simpler than diffing. Only-adds overlay rows; never touches
``verdicts`` / territory (the map, not the territory).

Real ingestion runs ONLY in CI — never from a local machine (the no-local-
feeding rule). Tests monkeypatch ``curl_get`` against a local fixture JSON.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import _net

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def kev_ingest_tick(conn, url: str | None = None, now: str | None = None) -> dict:
    """One KEV ingestion tick: fetch the static catalog JSON and upsert one
    ``kev`` overlay row per ``vulnerabilities[]`` entry. Returns a stats dict.

    Idempotent full refresh (INSERT OR REPLACE on cve_id PK). No-wipe: writes
    only the ``kev`` overlay table — never ``cves`` verdicts, never ``verdicts``.
    On fetch failure returns ``error`` and touches nothing.
    """
    fetched_at = now or _now()
    stats = {"upserted": 0, "skipped": 0, "catalog_version": None,
             "date_released": None, "error": None}

    data, code, _ = _net.curl_get(url or KEV_URL, max_time=120)
    if data is None or not isinstance(data, dict):
        stats["error"] = f"fetch failed (http {code})"
        return stats

    vulns = data.get("vulnerabilities") or []
    catalog_version = data.get("catalogVersion")
    date_released = data.get("dateReleased")
    stats["catalog_version"] = catalog_version
    stats["date_released"] = date_released

    for v in vulns:
        cve_id = v.get("cveID")
        if not cve_id:
            stats["skipped"] += 1
            continue
        from .. import store as _store
        _store.upsert_kev(conn, {
            "cve_id": cve_id,
            "date_added": v.get("dateAdded"),
            "vendor_project": v.get("vendorProject"),
            "product": v.get("product"),
            "name": v.get("vulnerabilityName"),
            "short_description": v.get("shortDescription"),
            "required_action": v.get("requiredAction"),
            "due_date": v.get("dueDate"),
            "ransomware_use": v.get("knownRansomwareCampaignUse"),
            "cwes": v.get("cwes") or [],
            "catalog_version": catalog_version,
            "date_released": date_released,
            "fetched_at": fetched_at,
        })
        stats["upserted"] += 1
    return stats