"""Ubuntu fix-status ingestion tests — the ``ubuntu_fixes`` spine overlay.

Mirrors the ``debian_fixes`` overlay test archetypes, adapted to the paginated
bulk-CVE-JSON feed + the (cve_id, release, package) key + the authoritative-
status-words signal that distinguishes this overlay from the OSV Ubuntu
catalog rows:

  1. the ingest tick populates the overlay from the bulk feed, per
     (release, package) sheet;
  2. status words are preserved verbatim (released/needed/needs-triage/
     not-affected/DNE) — the NEW signal the OSV mirror lacks;
  3. the per-release ``description`` note is preserved verbatim as ``fixed_in``
     (the fixed version when released; None when empty);
  4. package selection is correct — a CVE page listing multiple source
     packages ingests ONLY the requested package's status;
  5. sheets are isolated per (release, package);
  6. re-ingest is an idempotent full refresh (replace, never append);
  7. a CVE aged off a release sheet is dropped (full refresh, no stale rows);
  8. pagination across pages accumulates the full per-package CVE set;
  9. a failed fetch is a no-op (no-wipe: preserve last-known-good);
  10. no scope (--release/--package) errors and touches nothing;
  11. the overlay never touches verdicts (no-wipe / map-not-territory);
  12. the spine export/import round-trips the overlay identical; no device data.

All offline: ``ubuntu_tracker.curl_get`` (the binding the ingest tick routes
every read through) is monkeypatched to serve the bundled JSON fixture.
NVD_API_KEY never touched.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from posture import store, export
from posture.sources import ubuntu_ingest as _ui
import posture.sources.ubuntu_tracker as _ut

FIXTURE = Path(__file__).resolve().parent.parent / "posture" / "fixtures" / "ubuntu_tracker" / "cves.json"


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _feed(data=None, code=200, paginate=False):
    """Monkeypatch the ubuntu_tracker curl binding the ingest tick routes
    through. Serves the bundled fixture by default; ``data=None`` simulates an
    outage (non-200). ``paginate`` slices the fixture's cves by the requested
    offset/limit so the pager accumulates across pages."""
    if data is None and code == 200:
        data = json.loads(FIXTURE.read_text())

    def fake_curl_get(url, headers=None, max_time=300, extra=None):
        if not paginate:
            return data, code, ""
        # paginated serve: slice the cves by the requested offset/limit
        qs = parse_qs(urlparse(url).query)
        offset = int(qs.get("offset", ["0"])[0])
        limit = int(qs.get("limit", ["500"])[0])
        page = dict(data)
        page["cves"] = data["cves"][offset:offset + limit]
        page["offset"] = offset
        page["limit"] = limit
        return page, code, ""
    return fake_curl_get


def test_ubuntu_ingest_populates_overlay_per_sheet(conn, monkeypatch):
    monkeypatch.setattr(_ut, "curl_get", _feed())
    stats = _ui.ubuntu_ingest_tick(
        conn, releases=["noble", "jammy"], packages=["linux"], now="t1")
    assert stats["error"] is None
    assert stats["fetched"] is True
    assert stats["sheets"] == 2          # 2 releases x 1 package
    # noble/linux sheet: 99901(released), 99902(needs-triage), 99903(not-affected)
    noble = store.ubuntu_fixes_for_release_package(conn, "noble", "linux")
    assert len(noble) == 3
    # jammy/linux sheet: 99901(needed), 99902(released) -> 2 rows
    jammy = store.ubuntu_fixes_for_release_package(conn, "jammy", "linux")
    assert len(jammy) == 2


def test_ubuntu_ingest_preserves_status_words_and_notes(conn, monkeypatch):
    # The NEW signal this overlay brings over the OSV catalog: the raw tracker
    # status words + the per-release description note, verbatim.
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["noble", "jammy", "focal"],
                          packages=["linux"], now="t1")
    noble = {r["cve_id"]: r for r in
             store.ubuntu_fixes_for_release_package(conn, "noble", "linux")}
    assert noble["CVE-2026-99901"]["status"] == "released"
    assert noble["CVE-2026-99901"]["fixed_in"] == "5.15.0-25.25"
    assert noble["CVE-2026-99902"]["status"] == "needs-triage"
    assert noble["CVE-2026-99902"]["fixed_in"] in (None, "")  # empty note -> None
    assert noble["CVE-2026-99903"]["status"] == "not-affected"
    assert noble["CVE-2026-99903"]["fixed_in"] == "5.15.0-9.12"
    jammy = {r["cve_id"]: r for r in
             store.ubuntu_fixes_for_release_package(conn, "jammy", "linux")}
    assert jammy["CVE-2026-99901"]["status"] == "needed"
    assert jammy["CVE-2026-99902"]["status"] == "released"
    assert jammy["CVE-2026-99902"]["fixed_in"] == "5.15.0-1011"
    focal = {r["cve_id"]: r for r in
             store.ubuntu_fixes_for_release_package(conn, "focal", "linux")}
    assert focal["CVE-2026-99901"]["status"] == "DNE"


def test_ubuntu_ingest_selects_only_requested_package(conn, monkeypatch):
    # 99901's page lists TWO source packages for noble: linux(released) and
    # linux-nvidia-6.17(needs-triage). Ingesting `linux` must take linux's
    # status, NOT the nvidia sibling's.
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t1")
    row = store.ubuntu_fixes_for(conn, "CVE-2026-99901", "noble", "linux")
    assert row is not None
    assert row["status"] == "released"        # linux, not needs-triage
    assert row["fixed_in"] == "5.15.0-25.25"


def test_ubuntu_ingest_sheets_are_isolated(conn, monkeypatch):
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(
        conn, releases=["noble", "jammy"], packages=["linux"], now="t1")
    # 99903 is noble-only (not-affected); jammy must NOT have it.
    assert store.ubuntu_fixes_for(conn, "CVE-2026-99903", "noble", "linux") is not None
    assert store.ubuntu_fixes_for(conn, "CVE-2026-99903", "jammy", "linux") is None
    all_rows = store.ubuntu_fixes_all(conn)
    # ordered by (release, package, cve_id): jammy first, then noble
    assert [r["release"] for r in all_rows] == sorted(r["release"] for r in all_rows)


def test_ubuntu_ingest_idempotent_re_ingest_replaces(conn, monkeypatch):
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t1")
    n1 = conn.execute(
        "SELECT COUNT(*) FROM ubuntu_fixes WHERE release='noble' AND package='linux'"
    ).fetchone()[0]
    _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t2")
    n2 = conn.execute(
        "SELECT COUNT(*) FROM ubuntu_fixes WHERE release='noble' AND package='linux'"
    ).fetchone()[0]
    assert n1 == n2                      # replace, never append
    # fetched_at advanced to the second tick
    rows = store.ubuntu_fixes_for_release_package(conn, "noble", "linux")
    assert all(r["fetched_at"] == "t2" for r in rows)


def test_ubuntu_ingest_full_refresh_drops_aged_off_cve(conn, monkeypatch):
    # First ingest: 99901 is needed in jammy.
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["jammy"], packages=["linux"], now="t1")
    assert store.ubuntu_fixes_for(conn, "CVE-2026-99901", "jammy", "linux") is not None
    # Second ingest: the tracker dropped 99901 from jammy (aged off). The
    # full refresh (DELETE WHERE release+package + INSERT) must NOT leave a
    # stale row.
    aged_off = {"cves": [
        {"id": "CVE-2026-99902", "packages": [{"name": "linux", "statuses": [
            {"release_codename": "jammy", "status": "released",
             "description": "5.15.0-1011"}]}]}],
        "offset": 0, "limit": 500, "total_results": 1}
    monkeypatch.setattr(_ut, "curl_get", _feed(data=aged_off))
    _ui.ubuntu_ingest_tick(conn, releases=["jammy"], packages=["linux"], now="t2")
    assert store.ubuntu_fixes_for(conn, "CVE-2026-99901", "jammy", "linux") is None
    assert store.ubuntu_fixes_for(conn, "CVE-2026-99902", "jammy", "linux") is not None


def test_ubuntu_ingest_paginates_full_package_set(conn, monkeypatch):
    # page_size=2 over a 3-CVE fixture -> 2 pages (offset 0: 2 cves, offset 2:
    # 1 cve). The pager must accumulate the full set, not just the first page.
    monkeypatch.setattr(_ut, "curl_get", _feed(paginate=True))
    stats = _ui.ubuntu_ingest_tick(
        conn, releases=["noble"], packages=["linux"], page_size=2, now="t1")
    assert stats["error"] is None
    noble = {r["cve_id"]: r for r in
             store.ubuntu_fixes_for_release_package(conn, "noble", "linux")}
    # all three CVEs reached the overlay across the two pages
    assert set(noble) == {"CVE-2026-99901", "CVE-2026-99902", "CVE-2026-99903"}


def test_ubuntu_ingest_fetch_failure_is_noop(conn, monkeypatch):
    # Pre-seed last-known-good, then fail the fetch: the overlay is untouched.
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t1")
    before = store.ubuntu_fixes_all(conn)
    assert before
    monkeypatch.setattr(_ut, "curl_get", _feed(data=None, code=503))
    stats = _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t2")
    assert stats["error"] is not None
    assert stats["fetched"] is False
    assert stats["rows"] == 0
    assert store.ubuntu_fixes_all(conn) == before      # no-wipe: last-known-good kept


def test_ubuntu_ingest_no_scope_errors(conn, monkeypatch):
    monkeypatch.setattr(_ut, "curl_get", _feed())
    # missing releases
    s = _ui.ubuntu_ingest_tick(conn, releases=[], packages=["linux"], now="t1")
    assert s["error"] is not None and "scope" in s["error"]
    # missing packages
    s = _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=[], now="t1")
    assert s["error"] is not None and "scope" in s["error"]
    # nothing written + no fetch attempted
    assert conn.execute("SELECT COUNT(*) FROM ubuntu_fixes").fetchone()[0] == 0
    assert s["fetched"] is False


def test_ubuntu_ingest_does_not_touch_verdicts(conn, monkeypatch):
    store.upsert_verdict(conn, {
        "device_id": "host", "axis": "vulnerability", "key": "CVE-2026-99901",
        "status": "unpatched", "severity": "HIGH", "fixed_in": None,
        "detail": "prior", "provenance": {"observer": "nvd",
                                          "policy_version": "v",
                                          "fetched_at": "t", "complete": 1},
    }, "t")
    conn.commit()
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t1")
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1 and rows[0]["key"] == "CVE-2026-99901"
    assert rows[0]["status"] == "unpatched"      # verdict untouched


def test_ubuntu_ingest_export_import_round_trip(conn, monkeypatch, tmp_path):
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(
        conn, releases=["noble", "jammy"], packages=["linux"], now="t1")
    conn.commit()

    out = tmp_path / "out"
    manifest = export.export_spine(conn, out_dir=out, policy_version="v")
    assert manifest["counts"]["ubuntu_fixes"] >= 5
    assert (out / "spine" / "ubuntu_fixes.jsonl").exists()

    other = store.connect(":memory:")
    stats = export.import_spine(other, from_dir=out)
    assert stats["ubuntu_fixes"] == manifest["counts"]["ubuntu_fixes"]
    # the overlay rows survive the round trip identical (same ordered shape)
    assert store.ubuntu_fixes_all(conn) == store.ubuntu_fixes_all(other)
    # no device data on the wire: the spine shards are defects + flat tables only
    shard_names = {p.relative_to(out / "spine").as_posix()
                   for p in (out / "spine").rglob("*.jsonl")}
    assert not any("verdict" in n or "device" in n for n in shard_names)