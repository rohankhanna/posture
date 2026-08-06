"""CVE catalog store tests — cves/seen_cves/state + the no-wipe per-key
upsert_verdict path. In-memory sqlite via store.connect (runs the full SCHEMA).
"""
from __future__ import annotations

import json

import pytest

from posture import store


@pytest.fixture
def conn():
    return store.connect(":memory:")


# --- cves catalog + provenance ----------------------------------------------

def test_upsert_cve_inserts_with_provenance_and_discovered_at(conn):
    store.upsert_cve(conn, {
        "id": "CVE-2026-1", "published": "2026-08-01", "description": "t",
        "fixed_raw": {"source": "mitre", "pending_nvd": True, "reason": "r"},
        "refs": ["https://e/1"], "source": "mitre", "fetched_at": "now",
        "policy_version": "v", "complete": 1,
    })
    row = store.get_cve(conn, "CVE-2026-1")
    assert row["enrich_state"] is None  # upsert_cve does NOT set enrich_state
    assert row["source"] == "mitre"
    assert row["discovered_at"] == "now" or row["discovered_at"]  # first sighting stamped
    assert row["fixed_raw"]["source"] == "mitre"
    assert row["refs"] == ["https://e/1"]


def test_upsert_cve_preserves_enrich_state_and_discovered_at_on_re_upsert(conn):
    store.upsert_cve(conn, {"id": "CVE-2026-1", "published": "2026-08-01",
                            "description": "skeleton", "fixed_raw": {"source": "mitre"},
                            "refs": [], "source": "mitre", "fetched_at": "t1",
                            "policy_version": "v", "complete": 1})
    store.set_enrich_state(conn, "CVE-2026-1", "mitre")
    first_seen = store.get_cve(conn, "CVE-2026-1")["discovered_at"]
    # NVD enrichment re-upserts the same id with full data.
    store.upsert_cve(conn, {"id": "CVE-2026-1", "published": "2026-08-01",
                            "cvss": 9.8, "severity": "CRITICAL", "description": "enriched",
                            "fixed_raw": {"source": "nvd"}, "refs": [],
                            "source": "nvd", "fetched_at": "t2",
                            "policy_version": "v", "complete": 1})
    row = store.get_cve(conn, "CVE-2026-1")
    # enrich_state preserved (upsert_cve does NOT touch it) — set_enrich_state must.
    assert row["enrich_state"] == "mitre"
    assert row["cvss"] == 9.8 and row["source"] == "nvd"  # data updated
    assert row["discovered_at"] == first_seen  # first sighting never clobbered


def test_set_enrich_state_and_pending_mitre_ids(conn):
    for i in range(3):
        store.upsert_cve(conn, {"id": f"CVE-2026-{i}", "published": f"2026-08-0{i}",
                                "description": "", "fixed_raw": {"source": "mitre"},
                                "refs": [], "source": "mitre", "fetched_at": "t",
                                "policy_version": "v", "complete": 1})
        store.set_enrich_state(conn, f"CVE-2026-{i}", "mitre")
    assert store.pending_mitre_ids(conn) == ["CVE-2026-2", "CVE-2026-1", "CVE-2026-0"]
    assert store.pending_mitre_ids(conn, limit=2) == ["CVE-2026-2", "CVE-2026-1"]
    # Promote one to nvd -> it leaves the pending pool.
    store.set_enrich_state(conn, "CVE-2026-1", "nvd")
    assert "CVE-2026-1" not in store.pending_mitre_ids(conn)


def test_catalog_list_filters_by_enrich_state(conn):
    store.upsert_cve(conn, {"id": "CVE-A", "published": "2026-08-01", "description": "",
                            "fixed_raw": {}, "refs": [], "source": "mitre",
                            "fetched_at": "t", "policy_version": "v", "complete": 1})
    store.set_enrich_state(conn, "CVE-A", "mitre")
    store.upsert_cve(conn, {"id": "CVE-B", "published": "2026-08-02", "description": "",
                            "fixed_raw": {}, "refs": [], "source": "nvd",
                            "fetched_at": "t", "policy_version": "v", "complete": 1})
    store.set_enrich_state(conn, "CVE-B", "nvd")
    mitre = [r["id"] for r in store.catalog_list(conn, enrich_state="mitre")]
    nvd = [r["id"] for r in store.catalog_list(conn, enrich_state="nvd")]
    assert mitre == ["CVE-A"]
    assert nvd == ["CVE-B"]
    # unfiltered -> most-recent first
    assert [r["id"] for r in store.catalog_list(conn)] == ["CVE-B", "CVE-A"]


def test_mark_cve_distrust_marks_not_deletes(conn):
    store.upsert_cve(conn, {"id": "CVE-X", "published": "2026-08-01", "description": "",
                            "fixed_raw": {}, "refs": [], "source": "nvd",
                            "fetched_at": "t", "policy_version": "v", "complete": 1})
    assert store.mark_cve_distrust(conn, "CVE-X", "audit") is True
    row = store.get_cve(conn, "CVE-X")
    assert row["distrusted"] == 1 and row["distrust_reason"] == "audit"
    # row retained (not deleted), re-mark is a no-op
    assert store.mark_cve_distrust(conn, "CVE-X", "again") is False
    assert store.get_cve(conn, "CVE-X") is not None


# --- seen_cves --------------------------------------------------------------

def test_mark_seen_returns_only_newly_seen(conn):
    store.upsert_cve(conn, {"id": "CVE-1", "published": "2026-08-01", "description": "",
                            "fixed_raw": {}, "refs": [], "source": "mitre",
                            "fetched_at": "t", "policy_version": "v", "complete": 1})
    store.mark_seen(conn, ["CVE-1"])
    newly = store.mark_seen(conn, ["CVE-1", "CVE-2", "CVE-3"])
    assert newly == {"CVE-2", "CVE-3"}
    assert store.seen_first_seen(conn, "CVE-1") is not None
    assert store.seen_first_seen(conn, "CVE-missing") is None


# --- state (cursor) ---------------------------------------------------------

def test_state_round_trip(conn):
    assert store.get_state(conn, "stream:mitre_cursor") is None
    store.set_state(conn, "stream:mitre_cursor", "abc123")
    assert store.get_state(conn, "stream:mitre_cursor") == "abc123"
    store.set_state(conn, "stream:mitre_cursor", "def456")  # overwrite
    assert store.get_state(conn, "stream:mitre_cursor") == "def456"


# --- upsert_verdict: the no-wipe per-key path -------------------------------

def _v(cve_id, status="unpatched", witness="nvd", fixed_in=None):
    return {
        "device_id": "host", "axis": "vulnerability", "key": cve_id,
        "status": status, "severity": "HIGH", "fixed_in": fixed_in,
        "detail": "d", "provenance": {"witness": witness, "policy_version": "v",
                                       "fetched_at": "t", "complete": 1},
    }


def test_upsert_verdict_inserts_then_updates_no_wipe(conn):
    store.upsert_verdict(conn, _v("CVE-1", "unpatched"), "t1")
    store.upsert_verdict(conn, _v("CVE-2", "unpatched"), "t1")
    # an unrelated device's verdict must be untouched
    store.upsert_verdict(conn, {**_v("CVE-9", "patched", fixed_in="2.0"),
                                "device_id": "phone"}, "t1")
    # update CVE-1 in place (now patched)
    store.upsert_verdict(conn, _v("CVE-1", "patched", fixed_in="1.5"), "t2")
    rows = {r["key"]: (r["status"], r["fixed_in"], r["computed_at"])
            for r in store.verdicts_for_device_axis(conn, "host", "vulnerability")}
    assert rows["CVE-1"] == ("patched", "1.5", "t2")
    assert rows["CVE-2"] == ("unpatched", None, "t1")
    assert len(rows) == 2  # no duplicate CVE-1
    phone = store.verdicts_for_device_axis(conn, "phone", "vulnerability")
    assert phone[0]["status"] == "patched"  # other device untouched


def test_upsert_verdict_never_deletes_other_keys(conn):
    # Pre-seed 5 unrelated verdicts.
    for i in range(5):
        store.upsert_verdict(conn, _v(f"CVE-old-{i}", "unpatched"), "t1")
    before = {r["key"]: dict(r) for r in
              store.verdicts_for_device_axis(conn, "host", "vulnerability")}
    # An incremental refresh upserts one new CVE.
    store.upsert_verdict(conn, _v("CVE-new", "unpatched"), "t2")
    after = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(after) == 6
    # the 5 pre-existing rows are byte-identical
    for r in after:
        if r["key"].startswith("CVE-old-"):
            assert dict(r) == before[r["key"]]