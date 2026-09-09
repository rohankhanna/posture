"""Bounded-growth purge tests — ancient defects removed, active defects kept.

Covers the six purge conditions and orphaned-overlay cleanup.
"""
from __future__ import annotations

from posture import store
import pytest


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _add_defect(conn, cid, published, enrich_state="mitre"):
    store.upsert_defect(conn, {
        "id": cid, "published": published, "description": "",
        "fixed_raw": {}, "refs": [], "source": "mitre",
        "fetched_at": "2026-09-09T00:00:00+00:00",
        "policy_version": "v", "complete": 1,
    })
    store.set_enrich_state(conn, cid, enrich_state)
    store.mark_seen(conn, [cid])


def test_purge_removes_ancient_defect(conn):
    _add_defect(conn, "CVE-2000-1", "2000-01-01")
    _add_defect(conn, "CVE-2026-1", "2026-08-01")
    stats = store.purge_defects(conn, max_age_days=3650,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["defects_purged"] == 1
    assert store.get_defect(conn, "CVE-2000-1") is None
    assert store.get_defect(conn, "CVE-2026-1") is not None


def test_purge_keeps_defect_in_kev(conn):
    _add_defect(conn, "CVE-2000-1", "2000-01-01")
    conn.execute(
        "INSERT INTO kev (cve_id, date_added, fetched_at) VALUES (?,?,?)",
        ("CVE-2000-1", "2020-01-01", "2026-09-09"))
    conn.commit()
    stats = store.purge_defects(conn, max_age_days=3650,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["defects_purged"] == 0
    assert store.get_defect(conn, "CVE-2000-1") is not None


def test_purge_keeps_high_epss_defect(conn):
    _add_defect(conn, "CVE-2000-1", "2000-01-01")
    conn.execute(
        "INSERT INTO epss (cve_id, epss, percentile, fetched_at) VALUES (?,?,?,?)",
        ("CVE-2000-1", 0.95, 0.99, "2026-09-09"))
    conn.commit()
    stats = store.purge_defects(conn, max_age_days=3650,
                                keep_epss_percentile=0.70,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["defects_purged"] == 0


def test_purge_keeps_open_debian_fix(conn):
    _add_defect(conn, "CVE-2000-1", "2000-01-01")
    conn.execute(
        "INSERT INTO debian_fixes (cve_id, release, package, status, fetched_at) "
        "VALUES (?,?,?,?,?)",
        ("CVE-2000-1", "trixie", "linux", "open", "2026-09-09"))
    conn.commit()
    stats = store.purge_defects(conn, max_age_days=3650,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["defects_purged"] == 0


def test_purge_keeps_needs_triage_ubuntu_fix(conn):
    _add_defect(conn, "CVE-2000-1", "2000-01-01")
    conn.execute(
        "INSERT INTO ubuntu_fixes (cve_id, release, package, status, fetched_at) "
        "VALUES (?,?,?,?,?)",
        ("CVE-2000-1", "noble", "linux", "needs-triage", "2026-09-09"))
    conn.commit()
    stats = store.purge_defects(conn, max_age_days=3650,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["defects_purged"] == 0


def test_purge_keeps_apple_fix(conn):
    _add_defect(conn, "CVE-2000-1", "2000-01-01")
    conn.execute(
        "INSERT INTO apple_fixes (cve_id, product, fixed_in, fetched_at) "
        "VALUES (?,?,?,?)",
        ("CVE-2000-1", "iphone_os", "17.5", "2026-09-09"))
    conn.commit()
    stats = store.purge_defects(conn, max_age_days=3650,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["defects_purged"] == 0


def test_purge_keeps_no_date_defect(conn):
    _add_defect(conn, "CVE-2000-1", None)
    stats = store.purge_defects(conn, max_age_days=3650,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["defects_purged"] == 0
    assert store.get_defect(conn, "CVE-2000-1") is not None


def test_purge_removes_resolved_debian_fix_defect(conn):
    _add_defect(conn, "CVE-2000-1", "2000-01-01")
    conn.execute(
        "INSERT INTO debian_fixes (cve_id, release, package, status, fetched_at) "
        "VALUES (?,?,?,?,?)",
        ("CVE-2000-1", "trixie", "linux", "resolved", "2026-09-09"))
    conn.commit()
    stats = store.purge_defects(conn, max_age_days=3650,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["defects_purged"] == 1
    assert stats["orphan_overlays_purged"]["debian_fixes"] == 1


def test_purge_cleans_crosswalk_and_seen(conn):
    _add_defect(conn, "CVE-2000-1", "2000-01-01")
    _add_defect(conn, "CVE-2026-1", "2026-08-01")
    store.add_defect_alias(conn, "CVE-2000-1", "cve", "GHSA-0001", "ghsa")
    stats = store.purge_defects(conn, max_age_days=3650,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["defects_purged"] == 1
    assert stats["crosswalk_purged"] >= 2
    assert stats["seen_defects_purged"] == 1
    aliases = store.resolve_crosswalk(conn, "CVE-2000-1")
    assert aliases == []


def test_purge_dry_run_does_not_delete(conn):
    _add_defect(conn, "CVE-2000-1", "2000-01-01")
    stats = store.purge_defects(conn, max_age_days=3650, dry_run=True,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["dry_run"] is True
    assert stats["candidate_count"] == 1
    assert stats["defects_purged"] == 0
    assert store.get_defect(conn, "CVE-2000-1") is not None


def test_purge_low_epss_defect_removed(conn):
    _add_defect(conn, "CVE-2000-1", "2000-01-01")
    conn.execute(
        "INSERT INTO epss (cve_id, epss, percentile, fetched_at) VALUES (?,?,?,?)",
        ("CVE-2000-1", 0.001, 0.05, "2026-09-09"))
    conn.commit()
    stats = store.purge_defects(conn, max_age_days=3650,
                                keep_epss_percentile=0.70,
                                now="2026-09-09T00:00:00+00:00")
    assert stats["defects_purged"] == 1
    assert stats["orphan_overlays_purged"]["epss"] == 1
