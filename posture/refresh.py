"""Wipe-proof incremental refresh (Phase 2) — NVD per-CVE enrichment + per-CVE
re-decide, upserted through the no-wipe gate.

Where :func:`posture.engine.assess` is the FULL re-pull (per-device, per-CPE,
bulk DELETE-then-INSERT through ``commit_device_verdicts`` — the rare
reconciliation), the incremental refresh is the cheap, frequent path that turns
the stream's MITRE skeletons into enriched, decided verdicts WITHOUT ever
bulk-deleting:

  1. **Enrich** — take the pending MITRE skeletons (``enrich_state='mitre'``)
     and fetch each from NVD per-CVE via :func:`posture.sources.nvd_cve.nvd_query_cve`
     (curl, **header-only** apiKey). On success: upsert the full catalog row
     (cvss/severity/vector/ranges) + promote ``enrich_state`` to 'nvd'. On a
     provable-absent (404 twice): leave pending. On an incomplete fetch: leave
     pending (no-wipe — a failed pull never deletes anything).
  2. **Re-decide** — for each newly-enriched CVE, for each fleet device whose
     CPE head the CVE touches, re-decide via
     :func:`posture.sources.nvd_cve.decide_cve_for_device` and upsert ONE
     verdict row through :func:`posture.store.upsert_verdict` (per-key
     ON CONFLICT DO UPDATE — only the touched CVE's row changes; every other
     verdict for the device/axis is left byte-identical).

It never calls ``commit_device_verdicts`` (the bulk swap). An incomplete NVD
fetch simply upserts fewer rows — it cannot wipe last-known-good verdicts the
way the run-#10 empty broad-CPE pull did. Full re-pull is demoted to the rare
``posture assess`` reconciliation.

**The map is not the territory.** A NVD-enriched row is still a point on the
foreign-authored NVD map (a US NIST coordinate system), not a fact about a
machine. An "unpatched" verdict means "NVD places this CVE on this device's
CPE," never "this device is exploitable." The NVD attribution line is emitted
wherever NVD data surfaces (the CLI output; see ``attribution.NVD_ATTRIBUTION``).
"""

from __future__ import annotations

import datetime as _dt

from . import store as _store
from .axis import Axis
from . import provenance as _prov
from .witness import Provenance
from .sources.nvd_cve import (
    nvd_query_cve, decide_cve_for_device, _metrics, _desc, _refs, _cwes,
    _ref_tags, _cpe_head,
    NVD_URL,
)

# Per-tick cap on NVD enrichments (the expensive part — one curl per CVE). Safe
# to cap: un-enriched ids stay pending for the next tick, no loss. Full re-pull
# is the rare reconciliation (assess), not this loop.
DEFAULT_CAP = 200
# Skeletons NVD hasn't enriched after this many days stop retrying (NVD lag is
# real but not infinite). They stay in the catalog as mitre skeletons; the TTL
# only retires the *retry*, never deletes the row.
PENDING_TTL_DAYS = 30


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _all_ranges(cve: dict) -> list[dict]:
    """Every vulnerable cpeMatch across the CVE's configurations (device-
    agnostic), each stamped with its criteria head — the catalog record of what
    NVD says this CVE affects. Stored in ``fixed_raw`` for traceability + later
    re-decide without a re-fetch."""
    out: list[dict] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                if not cm.get("vulnerable"):
                    continue
                crit = cm.get("criteria", "")
                out.append({
                    "criteria": crit,
                    "head": _cpe_head(crit),
                    "vstart_incl": cm.get("versionStartIncluding"),
                    "vstart_excl": cm.get("versionStartExcluding"),
                    "vend_incl": cm.get("versionEndIncluding"),
                    "vend_excl": cm.get("versionEndExcluding"),
                })
    return out


def _enriched_record(cve: dict, policy_version: str, fetched_at: str) -> dict:
    """Build the full NVD-enriched ``upsert_cve`` row from one NVD cve object."""
    score, sev, vec = _metrics(cve)
    ranges = _all_ranges(cve)
    return {
        "id": cve.get("id"),
        "published": (cve.get("published") or "")[:10] or None,
        "cvss": score,
        "severity": sev,
        "cvss_vector": vec,
        "description": _desc(cve),
        "fixed_raw": {"source": "nvd", "ranges": ranges,
                      "cpe_heads": sorted({r["head"] for r in ranges})},
        "refs": _refs(cve),
        "cwe": _cwes(cve),
        "ref_tags": _ref_tags(cve),
        "source": "nvd",
        "fetched_at": fetched_at,
        "policy_version": policy_version,
        "complete": True,
    }


def _device_cpe_matchers(device: dict) -> list[dict]:
    return [m for m in device.get("matchers", [])
            if m.get("type") == "nvd_cpe" and m.get("cpe")]


def _pending_within_ttl(conn, cve_ids: list[str], now: str) -> list[str]:
    """Filter out skeletons older than PENDING_TTL_DAYS (retire the retry, not
    the row). A cheap in-Python filter over the small per-tick cap."""
    if not cve_ids:
        return []
    cutoff = (_dt.datetime.fromisoformat(now)
              - _dt.timedelta(days=PENDING_TTL_DAYS)).isoformat()
    out: list[str] = []
    for cid in cve_ids:
        row = _store.get_cve(conn, cid)
        if not row:
            continue
        disc = row.get("discovered_at") or row.get("fetched_at") or ""
        if disc and disc < cutoff:
            continue  # past TTL — stop retrying; row stays as a mitre skeleton
        out.append(cid)
    return out


def refresh_tick(
    conn,
    devices: list[dict],
    policy_version: str = "",
    cap: int = DEFAULT_CAP,
    live: bool = True,
    now: str | None = None,
    registry=None,
) -> dict:
    """One incremental refresh tick. Enriches pending MITRE skeletons from NVD
    and per-CVE re-decides device verdicts through the no-wipe upsert gate.

    ``devices`` is the fleet (each a dict with ``id`` + ``matchers``). ``live``
    selects real NVD per-CVE curl vs no enrichment (tests monkeypatch
    :func:`nvd_query_cve`). Returns a stats dict.

    ``registry`` (optional): if supplied, after the NVD re-decide the vendor
    witnesses on the vulnerability axis (ubuntu/debian/apple — any non-nvd
    witness with ``key_kind='cve'``) are run per enriched CVE per device with
    ``cve_candidates`` set to the enriched ids, so a freshly-enriched CVE a
    vendor tracker would clear is corrected in THIS tick instead of being left
    as a false NVD 'unpatched' until the next full assess. The vendor verdict
    co-exists with NVD's (separate witness row); override is by policy order at
    rollup, never a row overwrite. ``None`` skips the pass (backward compatible).

    No-wipe guarantees:
      * An incomplete NVD fetch (``complete=False``) enriches nothing and upserts
        nothing — pending skeletons stay pending, stored verdicts untouched.
      * Verdict writes go through :func:`store.upsert_verdict` (per-key ON
        CONFLICT DO UPDATE), never :func:`store.commit_device_verdicts` (bulk
        DELETE-then-INSERT). Only the touched CVE's row changes.
    """
    fetched_at = now or _now()
    stats = {"enriched": 0, "absent": 0, "incomplete": 0, "ttl_retired": 0,
             "verdicts_upserted": 0, "vendor_overrides": 0,
             "devices": len(devices),
             "pending_before": 0, "pending_after": 0, "errors": []}

    pending = _store.pending_mitre_ids(conn, limit=cap)
    stats["pending_before"] = len(pending)
    pending = _pending_within_ttl(conn, pending, fetched_at)
    stats["ttl_retired"] = stats["pending_before"] - len(pending)

    enriched: list[tuple[str, dict]] = []  # (cve_id, nvd_cve_obj) for re-decide
    for cid in pending:
        try:
            cve, complete, reason = nvd_query_cve(cid) if live else (None, True, "offline")
        except Exception as exc:  # a single CVE's fetch error must not sink the tick
            stats["errors"].append(f"{cid}: {exc}")
            continue
        if not complete:
            stats["incomplete"] += 1
            continue  # no-wipe: leave pending, retry next tick
        if cve is None:
            stats["absent"] += 1
            continue  # NVD proved absent (404 twice / zero) — leave skeleton pending
        rec = _enriched_record(cve, policy_version, fetched_at)
        if not rec["id"]:
            stats["errors"].append(f"{cid}: enriched record has no id")
            continue
        _store.upsert_cve(conn, rec)
        _store.set_enrich_state(conn, rec["id"], "nvd")
        enriched.append((rec["id"], cve))
        stats["enriched"] += 1
        conn.commit()

    # Per-CVE re-decide against the fleet, upserted one row at a time (no-wipe).
    for cid, cve in enriched:
        for device in devices:
            dev_id = device.get("id")
            if not dev_id:
                continue
            for m in _device_cpe_matchers(device):
                cpe = m["cpe"]
                device_ver = (m.get("version") or device.get("os_version")
                              or device.get("patch_level") or "*")
                status, fixed_in, severity, detail, _ranges = \
                    decide_cve_for_device(cve, device_ver, cpe)
                if status is None:
                    continue  # CVE doesn't touch this device's CPE -> no verdict
                ref = next((u for u in _refs(cve)
                            if "nvd.nist.gov/vuln/detail" in u), None) \
                    or f"{NVD_URL}?cveId={cid}"
                _store.upsert_verdict(conn, {
                    "device_id": dev_id,
                    "axis": Axis.VULNERABILITY.value,
                    "key": cid,
                    "status": status,
                    "severity": severity,
                    "fixed_in": fixed_in,
                    "detail": detail or "",
                    "provenance": Provenance(
                        witness="nvd", policy_version=policy_version,
                        fetched_at=fetched_at, complete=True, raw_ref=ref,
                    ),
                }, fetched_at)
                stats["verdicts_upserted"] += 1
    conn.commit()

    # Per-CVE vendor-witness overrides (ubuntu/debian/apple): a CVE just
    # NVD-enriched that a vendor tracker would clear is corrected NOW, not left
    # as a false NVD 'unpatched' until the next full assess. Reuses the fan-out
    # contract: each vendor witness self-filters devices lacking its inputs
    # (returns no verdicts). The vendor verdict co-exists with NVD's (a
    # separate witness row); override is by policy order at rollup, never a row
    # overwrite. Vendor witnesses ignore `policy` (their decision comes from the
    # tracker, not the trust policy), so None is passed.
    if registry is not None and enriched:
        enriched_cids = [cid for cid, _ in enriched]
        vendor_ws = [w for w in registry.all()
                     if Axis.VULNERABILITY in w.axes and w.id != "nvd"
                     and getattr(w, "key_kind", None) == "cve"]
        for w in vendor_ws:
            for device in devices:
                dev_id = device.get("id")
                if not dev_id:
                    continue
                dev = dict(device)
                dev["cve_candidates"] = enriched_cids
                try:
                    result = w.assess(dev, None)
                except Exception as exc:  # one vendor/device error must not sink the tick
                    stats["errors"].append(f"{w.id}/{dev_id}: {exc}")
                    continue
                if not result.verdicts:
                    continue
                stamped = _prov.stamp(result.verdicts, policy_version=policy_version,
                                      fetched_at=fetched_at, complete=result.complete)
                for v in stamped:
                    d = v.to_dict()
                    d["device_id"] = dev_id
                    _store.upsert_verdict(conn, d, fetched_at)
                    stats["vendor_overrides"] += 1
        conn.commit()

    stats["pending_after"] = len(_store.pending_mitre_ids(conn))
    return stats