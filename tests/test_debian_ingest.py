"""Debian fix-status ingestion tests — the ``debian_fixes`` spine overlay.

Mirrors the ``apple_fixes`` overlay test archetypes, adapted to the
(cve_id, release, package) key + the authoritative-status-words signal that
distinguishes this overlay from the OSV Debian catalog rows:

  1. the ingest tick populates the overlay from the bulk tracker, per
     (release, package) sheet;
  2. status words are preserved verbatim (resolved/open/undetermined, "0" =
     not affected) — the NEW signal the OSV mirror lacks;
  3. sheets are isolated per (release, package);
  4. re-ingest is an idempotent full refresh (replace, never append);
  5. a CVE aged off a release sheet is dropped (full refresh, no stale rows);
  6. a failed bulk fetch is a no-op (no-wipe: preserve last-known-good);
  7. no scope (--release/--package) errors and touches nothing;
  8. the overlay never touches verdicts (no-wipe / map-not-territory);
  9. the spine export/import round-trips the overlay identical; no device data.

All offline: ``debian_tracker.curl_get`` (the binding the ingest tick routes
every read through) is monkeypatched to serve the bundled JSON fixture.
NVD_API_KEY never touched.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from posture import store, export
from posture.sources import debian_ingest as _di
import posture.sources.debian_tracker as _dt

FIXTURE = Path(__file__).resolve().parent.parent / "posture" / "fixtures" / "debian_tracker" / "data.json"


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _bulk(data=None, code=200):
    """Monkeypatch the debian_tracker curl binding the ingest tick routes
    through. Serves the bundled fixture by default; ``data=None`` simulates an
    outage (non-200)."""
    if data is None and code == 200:
        data = json.loads(FIXTURE.read_text())

    def fake_curl_get(url, headers=None, max_time=120, extra=None):
        return data, code, ""
    return fake_curl_get


def test_debian_ingest_populates_overlay_per_sheet(conn, monkeypatch):
    monkeypatch.setattr(_dt, "curl_get", _bulk())
    stats = _di.debian_ingest_tick(
        conn, releases=["trixie", "bookworm"], packages=["linux"], now="t1")
    assert stats["error"] is None
    assert stats["fetched"] is True
    assert stats["sheets"] == 2          # 2 releases x 1 package
    # trixie/linux sheet: 99901(resolved,6.18.5-1), 99903(resolved,0),
    # 99902(open), 99907(undetermined) -> 4 rows
    trixie = store.debian_fixes_for_release_package(conn, "trixie", "linux")
    assert len(trixie) == 4
    # bookworm/linux sheet: only 99901(open) is tracked for bookworm -> 1 row
    bookworm = store.debian_fixes_for_release_package(conn, "bookworm", "linux")
    assert len(bookworm) == 1
    assert bookworm[0]["cve_id"] == "CVE-2026-99901"
    assert bookworm[0]["status"] == "open"


def test_debian_ingest_preserves_status_words(conn, monkeypatch):
    # The NEW signal this overlay brings over the OSV catalog: the raw tracker
    # status words + the "0" = not-affected sentinel, verbatim.
    monkeypatch.setattr(_dt, "curl_get", _bulk())
    _di.debian_ingest_tick(conn, releases=["trixie"], packages=["linux"], now="t1")
    by_cve = {r["cve_id"]: r for r in
              store.debian_fixes_for_release_package(conn, "trixie", "linux")}
    assert by_cve["CVE-2026-99901"]["status"] == "resolved"
    assert by_cve["CVE-2026-99901"]["fixed_in"] == "6.18.5-1"
    assert by_cve["CVE-2026-99903"]["status"] == "resolved"
    assert by_cve["CVE-2026-99903"]["fixed_in"] == "0"   # not affected
    assert by_cve["CVE-2026-99902"]["status"] == "open"
    assert by_cve["CVE-2026-99902"]["fixed_in"] in (None, "")  # no fix recorded
    assert by_cve["CVE-2026-99907"]["status"] == "undetermined"


def test_debian_ingest_sheets_are_isolated(conn, monkeypatch):
    monkeypatch.setattr(_dt, "curl_get", _bulk())
    _di.debian_ingest_tick(
        conn, releases=["trixie", "bookworm"], packages=["linux"], now="t1")
    # 99903 is trixie-only (resolved, "0"); bookworm must NOT have it.
    assert store.debian_fixes_for(conn, "CVE-2026-99903", "trixie", "linux") is not None
    assert store.debian_fixes_for(conn, "CVE-2026-99903", "bookworm", "linux") is None
    all_rows = store.debian_fixes_all(conn)
    # ordered by (release, package, cve_id): bookworm first, then trixie
    assert [r["release"] for r in all_rows] == sorted(r["release"] for r in all_rows)


def test_debian_ingest_idempotent_re_ingest_replaces(conn, monkeypatch):
    monkeypatch.setattr(_dt, "curl_get", _bulk())
    _di.debian_ingest_tick(conn, releases=["trixie"], packages=["linux"], now="t1")
    n1 = conn.execute(
        "SELECT COUNT(*) FROM debian_fixes WHERE release='trixie' AND package='linux'"
    ).fetchone()[0]
    _di.debian_ingest_tick(conn, releases=["trixie"], packages=["linux"], now="t2")
    n2 = conn.execute(
        "SELECT COUNT(*) FROM debian_fixes WHERE release='trixie' AND package='linux'"
    ).fetchone()[0]
    assert n1 == n2                      # replace, never append
    # fetched_at advanced to the second tick
    rows = store.debian_fixes_for_release_package(conn, "trixie", "linux")
    assert all(r["fetched_at"] == "t2" for r in rows)


def test_debian_ingest_full_refresh_drops_aged_off_cve(conn, monkeypatch):
    # First ingest: 99901 is open in bookworm.
    monkeypatch.setattr(_dt, "curl_get", _bulk())
    _di.debian_ingest_tick(conn, releases=["bookworm"], packages=["linux"], now="t1")
    assert store.debian_fixes_for(conn, "CVE-2026-99901", "bookworm", "linux") is not None
    # Second ingest: the tracker dropped 99901 from bookworm (aged off). The
    # full refresh (DELETE WHERE release+package + INSERT) must NOT leave a
    # stale row.
    aged_off = {"linux": {"CVE-2026-99902": {"releases": {
        "bookworm": {"status": "open", "fixed_version": ""}}}}}
    monkeypatch.setattr(_dt, "curl_get", _bulk(data=aged_off))
    _di.debian_ingest_tick(conn, releases=["bookworm"], packages=["linux"], now="t2")
    assert store.debian_fixes_for(conn, "CVE-2026-99901", "bookworm", "linux") is None
    assert store.debian_fixes_for(conn, "CVE-2026-99902", "bookworm", "linux") is not None


def test_debian_ingest_fetch_failure_is_noop(conn, monkeypatch):
    # Pre-seed last-known-good, then fail the fetch: the overlay is untouched.
    monkeypatch.setattr(_dt, "curl_get", _bulk())
    _di.debian_ingest_tick(conn, releases=["trixie"], packages=["linux"], now="t1")
    before = store.debian_fixes_all(conn)
    assert before
    monkeypatch.setattr(_dt, "curl_get", _bulk(data=None, code=503))
    stats = _di.debian_ingest_tick(conn, releases=["trixie"], packages=["linux"], now="t2")
    assert stats["error"] is not None
    assert stats["fetched"] is False
    assert stats["rows"] == 0
    assert store.debian_fixes_all(conn) == before      # no-wipe: last-known-good kept


def test_debian_ingest_no_scope_errors(conn, monkeypatch):
    monkeypatch.setattr(_dt, "curl_get", _bulk())
    # missing releases
    s = _di.debian_ingest_tick(conn, releases=[], packages=["linux"], now="t1")
    assert s["error"] is not None and "scope" in s["error"]
    # missing packages
    s = _di.debian_ingest_tick(conn, releases=["trixie"], packages=[], now="t1")
    assert s["error"] is not None and "scope" in s["error"]
    # nothing written + no fetch attempted
    assert conn.execute("SELECT COUNT(*) FROM debian_fixes").fetchone()[0] == 0
    assert s["fetched"] is False


def test_debian_ingest_does_not_touch_verdicts(conn, monkeypatch):
    store.upsert_verdict(conn, {
        "device_id": "host", "axis": "vulnerability", "key": "CVE-2026-99901",
        "status": "unpatched", "severity": "HIGH", "fixed_in": None,
        "detail": "prior", "provenance": {"observer": "nvd",
                                          "policy_version": "v",
                                          "fetched_at": "t", "complete": 1},
    }, "t")
    conn.commit()
    monkeypatch.setattr(_dt, "curl_get", _bulk())
    _di.debian_ingest_tick(conn, releases=["trixie"], packages=["linux"], now="t1")
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1 and rows[0]["key"] == "CVE-2026-99901"
    assert rows[0]["status"] == "unpatched"      # verdict untouched


def test_debian_ingest_export_import_round_trip(conn, monkeypatch, tmp_path):
    monkeypatch.setattr(_dt, "curl_get", _bulk())
    _di.debian_ingest_tick(
        conn, releases=["trixie", "bookworm"], packages=["linux"], now="t1")
    conn.commit()

    out = tmp_path / "out"
    manifest = export.export_spine(conn, out_dir=out, policy_version="v")
    assert manifest["counts"]["debian_fixes"] >= 5
    assert (out / "spine" / "debian_fixes.jsonl").exists()

    other = store.connect(":memory:")
    stats = export.import_spine(other, from_dir=out)
    assert stats["debian_fixes"] == manifest["counts"]["debian_fixes"]
    # the overlay rows survive the round trip identical (same ordered shape)
    assert store.debian_fixes_all(conn) == store.debian_fixes_all(other)
    # no device data on the wire: the spine shards are defects + flat tables only
    shard_names = {p.relative_to(out / "spine").as_posix()
                   for p in (out / "spine").rglob("*.jsonl")}
    assert not any("verdict" in n or "device" in n for n in shard_names)