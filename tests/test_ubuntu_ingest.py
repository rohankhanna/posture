"""Ubuntu fix-status ingestion tests — the ubuntu_fixes spine overlay.

Mirrors the debian_fixes overlay test archetypes, adapted to the paginated
bulk-CVE-JSON feed + the (cve_id, release, package) key + the authoritative-
status-words signal that distinguishes this overlay from the OSV Ubuntu
catalog rows:

  1. the ingest tick populates the overlay from the bulk feed, per
     (release, package) sheet;
  2. status words are preserved verbatim (released/needed/needs-triage/
     not-affected/DNE) — the NEW signal the OSV mirror lacks;
  3. the per-release description note is preserved verbatim as fixed_in
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

All offline: ubuntu_tracker.curl_get (the binding the ingest tick routes
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
    through. Serves the bundled fixture by default; data=None simulates an
    outage (non-200). paginate slices the fixture's cves by the requested
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

# ---------------------------------------------------------------------------
# Circuit breaker tests — restored from 9942d90 + new intermittent-degradation
# tests for the defect where bursts of 503s under MAX_CONSECUTIVE_FAIL are
# separated by slow 200s that reset consecutive_fail while failures reset
# consecutive_slow, leaving every counter below threshold while the tick
# grinds for hours until systemd kills it.
# ---------------------------------------------------------------------------

def _degrading_feed():
    """First page (offset 0) succeeds with a large total_results so the pager
    does not break early; every later page fails (503). Models a sustained
    upstream outage that begins mid-pagination."""
    fixture = json.loads(FIXTURE.read_text())

    def fake_curl_get(url, headers=None, max_time=300, extra=None):
        qs = parse_qs(urlparse(url).query)
        offset = int(qs.get("offset", ["0"])[0])
        if offset == 0:
            page = dict(fixture)
            page["cves"] = fixture["cves"][:1]
            page["total_results"] = 10000
            return page, 200, ""
        return None, 503, ""
    return fake_curl_get


def _slow_clock(step=6.0):
    """Fake time.monotonic stepping by step seconds per call so each
    page appears to take step seconds (above the slow-page watermark)."""
    state = {"t": 0.0}

    def fake_monotonic():
        v = state["t"]
        state["t"] += step
        return v
    return fake_monotonic


def _intermittent_degrading_feed(burst_fail=7, fail_code=503):
    """Simulate the real VPS degradation pattern: the first page succeeds,
    then bursts of burst_fail consecutive 503/504 pages separated by a
    single successful (but slow) 200 page. This is the pattern that evaded
    the original breaker: consecutive_fail resets at each success (every
    burst_fail+1 pages), and consecutive_slow was reset on every failure
    (every burst_fail pages), so neither counter ever reached its threshold.

    With the fix (consecutive_slow incremented on failure too, reset only by
    a fast success), the slow+failed counter accumulates across both failures
    and slow successes, hitting MAX_CONSECUTIVE_SLOW or MAX_TOTAL_SLOW.

    Uses the request offset (not a call counter) to determine success/failure,
    so _fetch_page's 3x retry on each failure does not desync the pattern.
    """
    fixture = json.loads(FIXTURE.read_text())

    def fake_curl_get(url, headers=None, max_time=300, extra=None):
        qs = parse_qs(urlparse(url).query)
        offset = int(qs.get("offset", ["0"])[0])
        # First page (offset 0) succeeds (passes the total-outage guard).
        if offset == 0:
            page = dict(fixture)
            page["cves"] = fixture["cves"][:1]
            page["total_results"] = 100000
            return page, 200, ""
        # After the first page: bursts of burst_fail failures then one success.
        # With page_size=1, offset == page_index.
        pos = (offset - 1) % (burst_fail + 1)
        if pos < burst_fail:
            return None, fail_code, ""
        # The single "successful" page in each cycle (slow 200).
        page = dict(fixture)
        page["cves"] = fixture["cves"][:1]
        page["total_results"] = 100000
        return page, 200, ""
    return fake_curl_get


def _intermittent_clock(fail_step=0.1, slow_step=10.0, burst_fail=7):
    """Fake time.monotonic that makes failure pages appear fast (the 503
    comes back in ~0.1s) and successful pages appear slow (10s, above the 5s
    watermark). This models the real VPS timing: 503s are quick, 200s are
    throttled to multi-second.

    The clock is called in this sequence in ubuntu_ingest_tick:
      call 1 = tick_start (before the loop)
      call 2 = t0 for page 0
      call 3 = elapsed for page 0
      call 4 = t0 for page 1
      call 5 = elapsed for page 1
      ...
    Time advances only on elapsed calls (odd calls >= 3)."""
    state = {"t": 0.0, "call": 0}

    def fake_monotonic():
        state["call"] += 1
        is_elapsed = (state["call"] >= 3) and (state["call"] % 2 == 1)
        if is_elapsed:
            page_index = (state["call"] - 3) // 2
            if page_index == 0:
                step = slow_step  # first page is a slow success
            else:
                pos = (page_index - 1) % (burst_fail + 1)
                if pos < burst_fail:
                    step = fail_step  # failure page
                else:
                    step = slow_step  # slow success page
            state["t"] += step
        return state["t"]
    return fake_monotonic


def test_ubuntu_ingest_consecutive_fail_breaker_no_wipe(conn, monkeypatch):
    # Pre-seed last-known-good, then degrade: first page OK (passes the
    # total-outage guard), then sustained 503s. The consecutive-failure
    # circuit breaker aborts the tick fast (retry sleeps are no-ops so the
    # test stays fast). vps_spine.sh's `|| ... spine continues` then fires
    # because posture ingest ubuntu exits non-zero on stats["error"].
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t1")
    before = store.ubuntu_fixes_all(conn)
    assert before
    monkeypatch.setattr(_ui.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(_ut, "curl_get", _degrading_feed())
    stats = _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t2")
    assert stats["error"] is not None
    assert "consecutive" in stats["error"]
    assert stats["fetched"] is False
    assert stats["rows"] == 0
    assert store.ubuntu_fixes_all(conn) == before      # no-wipe


def test_ubuntu_ingest_slow_page_breaker_no_wipe(conn, monkeypatch):
    # Pre-seed last-known-good, then a degraded upstream that answers 200 but
    # slowly (6s/page > the 5s watermark). The slow-page breaker aborts after
    # MAX_CONSECUTIVE_SLOW sustained slow pages; the abort writes nothing.
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t1")
    before = store.ubuntu_fixes_all(conn)
    assert before
    monkeypatch.setattr(_ui, "MAX_CONSECUTIVE_SLOW", 3)
    monkeypatch.setattr(_ui.time, "monotonic", _slow_clock(6.0))
    monkeypatch.setattr(_ut, "curl_get", _feed(paginate=True))
    stats = _ui.ubuntu_ingest_tick(
        conn, releases=["noble"], packages=["linux"], page_size=1, now="t2")
    assert stats["error"] is not None
    assert "slow" in stats["error"]
    assert stats["fetched"] is False
    assert stats["rows"] == 0
    assert store.ubuntu_fixes_all(conn) == before      # no-wipe


def test_ubuntu_ingest_intermittent_degradation_breaker_no_wipe(conn, monkeypatch):
    # THE KEY REGRESSION TEST: bursts of 7 consecutive 503s (just under
    # MAX_CONSECUTIVE_FAIL=8) separated by single slow 200s. The original
    # breaker did NOT fire on this pattern because:
    #   - consecutive_fail reset at each slow 200 (every 8 pages)
    #   - consecutive_slow was reset on every 503 (every 7 pages)
    # The fix: consecutive_slow is NOT reset on failure, so the slow+failed
    # counter accumulates across bursts and hits MAX_CONSECUTIVE_SLOW.
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t1")
    before = store.ubuntu_fixes_all(conn)
    assert before
    monkeypatch.setattr(_ui.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(_ui, "MAX_CONSECUTIVE_SLOW", 10)
    monkeypatch.setattr(_ui.time, "monotonic",
                        _intermittent_clock(fail_step=0.1, slow_step=10.0, burst_fail=7))
    monkeypatch.setattr(_ut, "curl_get", _intermittent_degrading_feed(burst_fail=7))
    stats = _ui.ubuntu_ingest_tick(
        conn, releases=["noble"], packages=["linux"], page_size=1, now="t2")
    assert stats["error"] is not None
    assert "degraded" in stats["error"]
    assert stats["fetched"] is False
    assert stats["rows"] == 0
    assert store.ubuntu_fixes_all(conn) == before      # no-wipe


def test_ubuntu_ingest_total_slow_breaker_no_wipe(conn, monkeypatch):
    # Cumulative slow-page threshold: even if fast successes reset
    # consecutive_slow occasionally, the total_slow counter accumulates
    # across the whole tick and aborts when it reaches MAX_TOTAL_SLOW.
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t1")
    before = store.ubuntu_fixes_all(conn)
    assert before
    # Alternate slow success (10s) and fast success (0.1s) so consecutive_slow
    # keeps resetting but total_slow accumulates.
    call_state = {"t": 0.0, "call": 0}

    def alt_clock():
        call_state["call"] += 1
        is_elapsed = (call_state["call"] >= 3) and (call_state["call"] % 2 == 1)
        if is_elapsed:
            page_index = (call_state["call"] - 3) // 2
            # Even pages are slow (10s), odd pages are fast (0.1s).
            step = 10.0 if page_index % 2 == 0 else 0.1
            call_state["t"] += step
        return call_state["t"]
    monkeypatch.setattr(_ui, "MAX_TOTAL_SLOW", 5)
    monkeypatch.setattr(_ui, "MAX_CONSECUTIVE_SLOW", 999)  # disable consecutive
    monkeypatch.setattr(_ui.time, "monotonic", alt_clock)

    # Feed that always succeeds (paginated) with a large total_results so the
    # pager does not break early. Cycles through the fixture's CVEs so the
    # feed never runs out.
    fixture = json.loads(FIXTURE.read_text())

    def always_success(url, headers=None, max_time=300, extra=None):
        qs = parse_qs(urlparse(url).query)
        offset = int(qs.get("offset", ["0"])[0])
        limit = int(qs.get("limit", ["500"])[0])
        cves = fixture["cves"]
        page_cves = [cves[offset % len(cves)]]  # cycle through fixture CVEs
        page = dict(fixture)
        page["cves"] = page_cves
        page["total_results"] = 100000
        return page, 200, "" 
    monkeypatch.setattr(_ut, "curl_get", always_success)
    stats = _ui.ubuntu_ingest_tick(
        conn, releases=["noble"], packages=["linux"], page_size=1, now="t2")
    assert stats["error"] is not None
    assert "total slow" in stats["error"]
    assert stats["fetched"] is False
    assert store.ubuntu_fixes_all(conn) == before      # no-wipe


def test_ubuntu_ingest_wall_clock_budget_no_wipe(conn, monkeypatch):
    # Wall-clock budget backstop: even if the specific failure pattern evades
    # the consecutive and total counters, the tick aborts when it exceeds
    # TICK_MAX_SECONDS. This is the safety net for any unanticipated
    # degradation pattern.
    monkeypatch.setattr(_ut, "curl_get", _feed())
    _ui.ubuntu_ingest_tick(conn, releases=["noble"], packages=["linux"], now="t1")
    before = store.ubuntu_fixes_all(conn)
    assert before
    monkeypatch.setattr(_ui, "TICK_MAX_SECONDS", 5)  # 5-second budget
    monkeypatch.setattr(_ui, "MAX_CONSECUTIVE_FAIL", 999)  # disable
    monkeypatch.setattr(_ui, "MAX_TOTAL_FAIL", 999)  # disable
    monkeypatch.setattr(_ui, "MAX_CONSECUTIVE_SLOW", 999)  # disable
    monkeypatch.setattr(_ui, "MAX_TOTAL_SLOW", 999)  # disable

    # Clock where each page takes 3 seconds (under SLOW_PAGE_SECONDS so the slow
    # breaker doesn't fire), but the budget is only 5 seconds.
    budget_state = {"t": 0.0, "call": 0}

    def budget_clock():
        budget_state["call"] += 1
        is_elapsed = (budget_state["call"] >= 3) and (budget_state["call"] % 2 == 1)
        if is_elapsed:
            budget_state["t"] += 3.0
        return budget_state["t"]
    monkeypatch.setattr(_ui.time, "monotonic", budget_clock)

    # Feed that always succeeds with a large total_results so the pager
    # does not break early before the budget is exceeded.
    fixture = json.loads(FIXTURE.read_text())

    def budget_feed(url, headers=None, max_time=300, extra=None):
        qs = parse_qs(urlparse(url).query)
        offset = int(qs.get("offset", ["0"])[0])
        limit = int(qs.get("limit", ["500"])[0])
        page = dict(fixture)
        page["cves"] = fixture["cves"][offset:offset + limit]
        page["total_results"] = 100000
        return page, 200, ""
    monkeypatch.setattr(_ut, "curl_get", budget_feed)
    stats = _ui.ubuntu_ingest_tick(
        conn, releases=["noble"], packages=["linux"], page_size=1, now="t2")
    assert stats["error"] is not None
    assert "wall-clock" in stats["error"]
    assert stats["fetched"] is False
    assert store.ubuntu_fixes_all(conn) == before      # no-wipe
