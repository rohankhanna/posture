"""CISA KEV overlay tests — the exploitability_signal.

KEV is a CVE-keyed **overlay** (not a new defect_type): the static CISA catalog
JSON maps a cveID to known-exploited metadata (required action, due date,
ransomware use). ``kev_ingest_tick`` does an idempotent full refresh; the spine
export serializes ``kev`` as a flat table. All local fixtures — no network:
``curl_get`` is monkeypatched to return a hand-built KEV JSON.
"""
from __future__ import annotations

import json

import pytest

from posture import store, export, spine as _spine
from posture.sources import kev as _kev
from posture.sources import _net


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _kev_json(catalog_version="2026.08.06", date_released="2026-08-06T00:00:00Z"):
    """A minimal KEV-shaped catalog: two entries, one with cwes, one without."""
    return {
        "catalogVersion": catalog_version,
        "dateReleased": date_released,
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1001",
                "vendorProject": "Acme", "product": "Widget",
                "vulnerabilityName": "Acme Widget RCE",
                "shortDescription": "remote code execution",
                "requiredAction": "Apply patch.", "dueDate": "2026-09-01",
                "knownRansomwareCampaignUse": "Known",
                "cwes": ["CWE-78"], "dateAdded": "2026-08-01",
            },
            {
                "cveID": "CVE-2026-1002",
                "vendorProject": "Globex", "product": "Sprocket",
                "vulnerabilityName": "Globex Sprocket XSS",
                "shortDescription": "stored xss",
                "requiredAction": "Mitigate via WAF.", "dueDate": "2026-10-01",
                "knownRansomwareCampaignUse": "Unknown",
                "cwes": "", "dateAdded": "2026-08-02",
            },
        ],
    }


def _patch_curl(monkeypatch, payload: dict, code: int = 200):
    """Monkeypatch ``curl_get`` to return (parsed_json, code, body)."""
    body = json.dumps(payload)
    monkeypatch.setattr(_net, "curl_get",
                       lambda url, headers=None, max_time=60, extra=None:
                       (payload, code, body))


# --- populates the overlay (idempotent full refresh) -------------------------

def test_kev_ingest_populates_overlay(conn, monkeypatch):
    _patch_curl(monkeypatch, _kev_json())
    stats = _kev.kev_ingest_tick(conn, now="2026-08-06T12:00:00Z")
    assert stats["upserted"] == 2
    assert stats["error"] is None
    assert stats["catalog_version"] == "2026.08.06"
    assert stats["date_released"] == "2026-08-06T00:00:00Z"
    rows = store.kev_all(conn)
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1001", "CVE-2026-1002"]
    r1 = store.kev_for_cve(conn, "CVE-2026-1001")
    assert r1["vendor_project"] == "Acme"
    assert r1["ransomware_use"] == "Known"
    assert r1["cwes"] == ["CWE-78"]               # parsed JSON array
    assert r1["required_action"] == "Apply patch."
    # the entry with an empty cwes string -> []
    r2 = store.kev_for_cve(conn, "CVE-2026-1002")
    assert r2["cwes"] == []


# --- idempotent: re-ingest replaces, never duplicates ------------------------

def test_kev_ingest_idempotent_full_refresh(conn, monkeypatch):
    _patch_curl(monkeypatch, _kev_json())
    _kev.kev_ingest_tick(conn, now="t1")
    # a refreshed catalog (same CVE, new required action + new version)
    payload = _kev_json(catalog_version="2026.08.07")
    payload["vulnerabilities"][0]["requiredAction"] = "Apply patch v2."
    _patch_curl(monkeypatch, payload)
    stats = _kev.kev_ingest_tick(conn, now="t2")
    assert stats["upserted"] == 2                 # full refresh, not append
    assert conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0] == 2
    r1 = store.kev_for_cve(conn, "CVE-2026-1001")
    assert r1["required_action"] == "Apply patch v2."
    assert r1["catalog_version"] == "2026.08.07"  # overlay updated in place


# --- no-wipe: the overlay never touches verdicts -----------------------------

def test_kev_ingest_does_not_touch_verdicts(conn, monkeypatch):
    store.upsert_verdict(conn, {
        "device_id": "host", "axis": "vulnerability", "key": "CVE-2026-1001",
        "status": "unpatched", "severity": "HIGH", "fixed_in": None,
        "detail": "prior", "provenance": {"observer": "nvd",
                                          "policy_version": "v",
                                          "fetched_at": "t", "complete": 1},
    }, "t")
    conn.commit()
    _patch_curl(monkeypatch, _kev_json())
    _kev.kev_ingest_tick(conn, now="t")
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1 and rows[0]["key"] == "CVE-2026-1001"
    assert rows[0]["status"] == "unpatched"       # verdict untouched


# --- fetch failure is a no-op (touches nothing) ------------------------------

def test_kev_ingest_fetch_failure_is_noop(conn, monkeypatch):
    monkeypatch.setattr(_net, "curl_get",
                       lambda url, headers=None, max_time=60, extra=None:
                       (None, 503, ""))
    stats = _kev.kev_ingest_tick(conn, now="t")
    assert stats["error"] is not None
    assert stats["upserted"] == 0
    assert conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0] == 0


# --- export/import round-trip (kev is a flat table) --------------------------

def test_kev_export_import_round_trip(conn, monkeypatch, tmp_path):
    _patch_curl(monkeypatch, _kev_json())
    _kev.kev_ingest_tick(conn, now="t")
    conn.commit()

    out = tmp_path / "out"
    manifest = export.export_spine(conn, out_dir=out, policy_version="v")
    assert manifest["counts"]["kev"] == 2
    assert (out / "spine" / "kev.jsonl").exists()

    other = store.connect(":memory:")
    stats = export.import_spine(other, from_dir=out)
    assert stats["kev"] == 2
    # the overlay rows survive the round trip identical
    assert store.kev_all(conn) == store.kev_all(other)


# --- zero device data in the spine snapshot ----------------------------------

def test_kev_export_has_no_device_data(conn, monkeypatch, tmp_path):
    _patch_curl(monkeypatch, _kev_json())
    _kev.kev_ingest_tick(conn, now="t")
    conn.commit()
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    # the spine/ dir must not contain a verdicts file at all
    assert not (out / "spine" / "verdicts.jsonl").exists()
    # and the kev shard carries only KEV metadata, never device state
    text = (out / "spine" / "kev.jsonl").read_text()
    assert "device_id" not in text and "verdict" not in text.lower()