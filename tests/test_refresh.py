"""Incremental refresh tests (Phase 2) — NVD per-CVE enrichment + per-CVE
re-decide through the no-wipe upsert gate. The header-only apiKey assertion is
the run-#10 fleet-wipe root-cause guard: the NVD key MUST travel in the apiKey
HEADER, never the query string.
"""
from __future__ import annotations

import pytest

from posture import store, refresh
from posture.axis import Axis
from posture.sources import nvd_cve
from posture.witness import Witness, WitnessResult, Verdict, Provenance, WitnessRegistry
import posture.refresh as _refresh


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _skeleton(conn, cve_id="CVE-2026-1", published="2026-08-01"):
    store.upsert_cve(conn, {
        "id": cve_id, "published": published, "description": "skeleton",
        "fixed_raw": {"source": "mitre", "pending_nvd": True}, "refs": [],
        "source": "mitre", "fetched_at": "t", "policy_version": "v", "complete": 1,
    })
    store.set_enrich_state(conn, cve_id, "mitre")


def _nvd_cve(cve_id="CVE-2026-1", criteria="cpe:2.3:o:vendor:product",
             vstart="6.0", vend_excl="6.5", score=9.9, sev="CRITICAL"):
    return {
        "id": cve_id,
        "published": "2026-08-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "a test vuln"}],
        "metrics": {"cvssMetricV31": [{"baseSeverity": sev,
            "cvssData": {"baseScore": score,
                         "vectorString": "CVSS:3.1/AV:N/AC:L/C:H/I:H/A:H"}}]},
        "references": [{"url": "https://example/x", "tags": ["Vendor Advisory"]},
                        {"url": "https://example/p", "tags": ["Patch"]}],
        "weaknesses": [{"description": [{"value": "CWE-89"},
                                        {"value": "CWE-79"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": criteria,
             "versionStartIncluding": vstart,
             "versionEndExcluding": vend_excl}]}]}],
    }


def _device(cpe="cpe:2.3:o:vendor:product", version="6.2", dev_id="host"):
    return {"id": dev_id,
            "matchers": [{"type": "nvd_cpe", "cpe": cpe, "version": version}]}


# --- THE root-cause guard: header-only apiKey, never the query string -------

def test_nvd_query_cve_uses_curl_header_only_apikey(monkeypatch):
    """Putting the NVD key in the query string triggers NVD's 404-masquerade —
    the actual root cause of Forebode's run-#10 fleet wipe. Assert the key
    travels in the apiKey HEADER only, and that nvd_cve does not import
    `requests` (curl is the fetcher)."""
    assert not hasattr(nvd_cve, "requests"), \
        "nvd_cve must not import requests (use curl)"
    captured = {}

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        captured["url"] = url
        captured["headers"] = headers or []
        return ({"vulnerabilities": [{"cve": _nvd_cve()}]}, 200, "{}")

    monkeypatch.setattr(nvd_cve, "curl_get", fake_curl_get)
    monkeypatch.setenv("NVD_API_KEY", "SECRET-KEY-123")

    cve, complete, reason = nvd_cve.nvd_query_cve("CVE-2026-1", throttle=False)
    assert complete is True and cve["id"] == "CVE-2026-1"
    # The key is in a HEADER ...
    assert any("apiKey: SECRET-KEY-123" in h for h in captured["headers"])
    # ... and NOWHERE in the URL / query string.
    assert "apiKey" not in captured["url"]
    assert "SECRET-KEY-123" not in captured["url"]
    assert "cveId=CVE-2026-1" in captured["url"]  # the real query param


def test_nvd_query_cve_absent_returns_complete_none(monkeypatch):
    monkeypatch.setattr(nvd_cve, "curl_get",
                        lambda url, headers=None, max_time=60, extra=None:
                        ({"vulnerabilities": []}, 200, "{}"))
    cve, complete, reason = nvd_cve.nvd_query_cve("CVE-NOTHERE", throttle=False)
    assert cve is None and complete is True  # genuine absent (not a wipe trigger)


def test_nvd_query_cve_incomplete_returns_not_complete(monkeypatch):
    monkeypatch.setattr(nvd_cve, "curl_get",
                        lambda url, headers=None, max_time=60, extra=None:
                        (None, 0, ""))  # timeout / network failure
    cve, complete, reason = nvd_cve.nvd_query_cve("CVE-NETFAIL", throttle=False)
    assert cve is None and complete is False  # no-wipe: leave pending


# --- enrich promotes a skeleton mitre -> nvd --------------------------------

def test_refresh_enrich_promotes_skeleton_and_upserts_verdict(conn, monkeypatch):
    _skeleton(conn)
    monkeypatch.setattr(_refresh, "nvd_query_cve",
                        lambda cid, throttle=True: (_nvd_cve(cid), True, "enriched"))
    devs = [_device()]
    stats = refresh.refresh_tick(conn, devs, policy_version="v", live=True)
    assert stats["enriched"] == 1
    assert stats["verdicts_upserted"] == 1
    row = store.get_cve(conn, "CVE-2026-1")
    assert row["enrich_state"] == "nvd"
    assert row["cvss"] == 9.9 and row["severity"] == "CRITICAL"
    assert row["fixed_raw"]["source"] == "nvd"
    assert row["source"] == "nvd"
    # CWE + reference tags captured into the catalog row (foothold/arming signal)
    assert row["cwe"] == ["CWE-79", "CWE-89"]
    assert row["ref_tags"] == ["Patch", "Vendor Advisory"]
    assert row["refs"] == ["https://example/x", "https://example/p"]
    # device 6.2 is in [6.0, 6.5) -> unpatched, fixed_in 6.5
    v = store.verdicts_for_device_axis(conn, "host", "vulnerability")[0]
    assert v["status"] == "unpatched" and v["fixed_in"] == "6.5"
    assert v["witness"] == "nvd" and v["severity"] == "CRITICAL"
    # pending pool drained
    assert stats["pending_after"] == 0


# --- no-wipe: an incomplete fetch preserves everything ----------------------

def test_refresh_incomplete_fetch_no_wipe(conn, monkeypatch):
    _skeleton(conn)
    # pre-seed an unrelated device verdict
    store.upsert_verdict(conn, {
        "device_id": "host", "axis": "vulnerability", "key": "CVE-OLD",
        "status": "unpatched", "severity": "HIGH", "fixed_in": None, "detail": "prior",
        "provenance": {"witness": "nvd", "policy_version": "v",
                       "fetched_at": "t", "complete": 1},
    }, "t")
    monkeypatch.setattr(_refresh, "nvd_query_cve",
                        lambda cid, throttle=True: (None, False, "incomplete"))
    stats = refresh.refresh_tick(conn, [_device()], policy_version="v", live=True)
    assert stats["enriched"] == 0 and stats["incomplete"] == 1
    assert stats["verdicts_upserted"] == 0
    # skeleton stays pending; old verdict untouched
    assert store.get_cve(conn, "CVE-2026-1")["enrich_state"] == "mitre"
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1 and rows[0]["key"] == "CVE-OLD"


def test_refresh_incremental_preserves_unrelated_verdicts(conn, monkeypatch):
    # 5 unrelated verdicts; refresh one new CVE; the 5 must be byte-identical.
    for i in range(5):
        store.upsert_verdict(conn, {
            "device_id": "host", "axis": "vulnerability", "key": f"CVE-old-{i}",
            "status": "unpatched", "severity": "HIGH", "fixed_in": None, "detail": "d",
            "provenance": {"witness": "nvd", "policy_version": "v",
                           "fetched_at": "t", "complete": 1},
        }, "t")
    _skeleton(conn)
    before = {r["key"]: dict(r) for r in
              store.verdicts_for_device_axis(conn, "host", "vulnerability")}
    monkeypatch.setattr(_refresh, "nvd_query_cve",
                        lambda cid, throttle=True: (_nvd_cve(cid), True, "ok"))
    refresh.refresh_tick(conn, [_device()], policy_version="v", live=True)
    after = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(after) == 6  # 5 old + 1 new
    for r in after:
        if r["key"].startswith("CVE-old-"):
            assert dict(r) == before[r["key"]]  # byte-identical, no wipe


# --- NVD 404 / absent leaves the skeleton pending ---------------------------

def test_refresh_absent_leaves_pending(conn, monkeypatch):
    _skeleton(conn)
    monkeypatch.setattr(_refresh, "nvd_query_cve",
                        lambda cid, throttle=True: (None, True, "absent"))
    stats = refresh.refresh_tick(conn, [_device()], policy_version="v", live=True)
    assert stats["absent"] == 1 and stats["enriched"] == 0
    assert store.get_cve(conn, "CVE-2026-1")["enrich_state"] == "mitre"
    assert "CVE-2026-1" in store.pending_mitre_ids(conn)


# --- CPE gate: a CVE that doesn't touch the device's CPE -> no verdict ------

def test_refresh_cpe_gate_skips_non_matching_device(conn, monkeypatch):
    _skeleton(conn)
    monkeypatch.setattr(_refresh, "nvd_query_cve",
                        lambda cid, throttle=True: (_nvd_cve(cid), True, "ok"))
    # device on a totally different product -> no verdict upserted
    devs = [_device(cpe="cpe:2.3:o:other:thing", version="1.0")]
    stats = refresh.refresh_tick(conn, devs, policy_version="v", live=True)
    assert stats["enriched"] == 1  # catalog still enriched
    assert stats["verdicts_upserted"] == 0  # but no device verdict (CPE gate)
    assert store.verdicts_for_device_axis(conn, "host", "vulnerability") == []


# --- TTL: skeletons older than PENDING_TTL_DAYS stop retrying (row stays) ----

def test_refresh_ttl_retires_retry_without_deleting(conn, monkeypatch):
    _skeleton(conn)
    # age the skeleton past the TTL
    old = "2020-01-01T00:00:00+00:00"
    conn.execute("UPDATE cves SET discovered_at=? WHERE id='CVE-2026-1'", (old,))
    conn.commit()
    called = {"n": 0}

    def fake(cid, throttle=True):
        called["n"] += 1
        return (_nvd_cve(cid), True, "ok")

    monkeypatch.setattr(_refresh, "nvd_query_cve", fake)
    stats = refresh.refresh_tick(conn, [_device()], policy_version="v", live=True)
    assert called["n"] == 0  # not retried
    assert stats["ttl_retired"] == 1
    # the row is retained as a mitre skeleton (retire the retry, not the row)
    assert store.get_cve(conn, "CVE-2026-1") is not None
    assert store.get_cve(conn, "CVE-2026-1")["enrich_state"] == "mitre"


# --- offline (no live fetch) is a safe no-op --------------------------------

def test_refresh_offline_no_enrichment_no_wipe(conn):
    _skeleton(conn)
    stats = refresh.refresh_tick(conn, [_device()], policy_version="v", live=False)
    assert stats["enriched"] == 0 and stats["verdicts_upserted"] == 0
    assert store.get_cve(conn, "CVE-2026-1")["enrich_state"] == "mitre"


# --- CWE + reference-tag capture (foothold/arming signal) -------------------

def test_cwe_and_ref_tag_helpers_filter_dedup_and_sort():
    """`_cwes` keeps only id-shaped values (drops prose), de-dups, sorts;
    `_ref_tags` unions + de-dups + sorts across references."""
    cve = {
        "weaknesses": [
            {"description": [{"value": "CWE-89"},
                             {"value": "Improper Neutralization of SQL"},  # prose
                             {"value": "CWE-89"}]},  # dup
        ],
        "references": [
            {"url": "https://a", "tags": ["Patch", "Vendor Advisory"]},
            {"url": "https://b", "tags": ["Patch"]},  # dup tag
            {"url": "https://c"},  # no tags
        ],
    }
    assert nvd_cve._cwes(cve) == ["CWE-89"]
    assert nvd_cve._ref_tags(cve) == ["Patch", "Vendor Advisory"]


def test_cwe_and_ref_tag_helpers_empty_when_absent():
    assert nvd_cve._cwes({}) == []
    assert nvd_cve._ref_tags({}) == []


# --- per-CVE vendor-witness overrides during refresh -----------------------

def test_refresh_vendor_override_clears_nvd_false_alarm_same_tick(conn, monkeypatch):
    """A freshly NVD-enriched CVE that a vendor tracker would clear is corrected
    in THIS tick (not left as a false NVD 'unpatched' until the next full
    assess). The vendor verdict co-exists with NVD's (separate witness row);
    override is by policy order at rollup, never a row overwrite."""
    _skeleton(conn)
    monkeypatch.setattr(_refresh, "nvd_query_cve",
                        lambda cid, throttle=True: (_nvd_cve(cid), True, "enriched"))

    class FakeVendor(Witness):
        """Stands in for ubuntu_tracker: clears any candidate CVE to 'patched'.
        The real ubuntu_tracker is unit-tested in test_ubuntu_tracker; this
        isolates the refresh override MECHANISM (registry -> assess -> upsert)."""
        id = "ubuntu_tracker"
        axes = (Axis.VULNERABILITY,)
        key_kind = "cve"
        bias = "false-safe"

        def __init__(self):
            super().__init__(id=self.id, axes=self.axes, bias=self.bias,
                             key_kind=self.key_kind)

        def assess(self, device, policy):
            cids = [c for c in (device.get("cve_candidates") or [])]
            verdicts = [Verdict(
                axis="vulnerability", key=c, status="patched", fixed_in="6.17.9",
                provenance=Provenance(witness="ubuntu_tracker", policy_version="",
                                      fetched_at="", complete=True,
                                      raw_ref=f"https://ubuntu.com/security/{c}"),
            ) for c in cids]
            return WitnessResult(verdicts=verdicts, complete=True, reason="fake")

    reg = WitnessRegistry()
    reg.register(FakeVendor())
    stats = refresh.refresh_tick(conn, [_device()], policy_version="v",
                                 live=True, registry=reg)

    assert stats["enriched"] == 1
    assert stats["vendor_overrides"] == 1
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    by_w = {r["witness"]: r for r in rows}
    # NVD's false alarm is still present (no-wipe: the row is never overwritten)
    assert by_w["nvd"]["status"] == "unpatched"
    # ...and the vendor cleared it in the same tick, as a separate row
    assert by_w["ubuntu_tracker"]["status"] == "patched"
    assert by_w["ubuntu_tracker"]["fixed_in"] == "6.17.9"


def test_refresh_without_registry_skips_vendor_override(conn, monkeypatch):
    """Backward compat: registry=None (the default) skips the vendor pass —
    existing callers see only NVD re-decide, no new behavior or stats noise."""
    _skeleton(conn)
    monkeypatch.setattr(_refresh, "nvd_query_cve",
                        lambda cid, throttle=True: (_nvd_cve(cid), True, "enriched"))
    stats = refresh.refresh_tick(conn, [_device()], policy_version="v", live=True)
    assert stats["enriched"] == 1
    assert stats["vendor_overrides"] == 0
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1 and rows[0]["witness"] == "nvd"


# --- CI catalog-only mode: --no-devices enriches the MAP, writes 0 verdicts --

def test_refresh_no_devices_enriches_catalog_zero_verdicts(conn, monkeypatch):
    """The CI contract: refresh_tick(conn, devices=[], live=True, registry=None)
    enriches the catalog (the MAP) and writes ZERO verdict rows — no device
    data, no territory. The re-decide loop (refresh.py:200 `for device in devices`)
    and the vendor-override loop (refresh.py:240, guarded by
    `if registry is not None`) are both inert. This is what `posture refresh
    --no-devices` runs in CI so no feeding/enrichment needs a local machine."""
    _skeleton(conn)
    monkeypatch.setattr(_refresh, "nvd_query_cve",
                        lambda cid, throttle=True: (_nvd_cve(cid), True, "enriched"))
    stats = refresh.refresh_tick(conn, devices=[], policy_version="v",
                                 live=True, registry=None)
    # the MAP was enriched ...
    assert stats["enriched"] == 1
    row = store.get_cve(conn, "CVE-2026-1")
    assert row["enrich_state"] == "nvd" and row["severity"] == "CRITICAL"
    # ... and NO territory was written (zero verdicts, zero device rows)
    assert stats["verdicts_upserted"] == 0
    assert stats["vendor_overrides"] == 0
    assert conn.execute("SELECT count(*) FROM verdicts").fetchone()[0] == 0