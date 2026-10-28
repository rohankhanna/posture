"""Ubuntu CVE-tracker git-source ingestion tests — the ubuntu_fixes spine
overlay from the plain-text git repo.

These tests verify that the git-source path
(:mod:`posture.sources.ubuntu_git_ingest`) produces the same ubuntu_fixes
overlay rows as the JSON-API path (:mod:`posture.sources.ubuntu_ingest`), so
the two sources are interchangeable and the spine manifest stays byte-compatible.

The bundled fixture under posture/fixtures/ubuntu_cve_tracker/active/
carries the same three CVEs (CVE-2026-99901, -99902, -99903) with the same
package (linux) + release (noble, jammy, focal) statuses as the JSON fixture
under posture/fixtures/ubuntu_tracker/cves.json, so the overlay rows match
exactly.

Test archetypes (mirror the JSON-API test suite):
  1. the git ingest tick populates the overlay from the plain-text files, per
     (release, package) sheet;
  2. status words are preserved verbatim (released/needed/needs-triage/
     not-affected/DNE) — the NEW signal the OSV mirror lacks;
  3. the per-release parenthetical note is preserved verbatim as fixed_in
     (the fixed version when released; None when absent);
  4. package selection is correct — a CVE file listing multiple source packages
     ingests ONLY the requested package's status;
  5. sheets are isolated per (release, package);
  6. re-ingest is an idempotent full refresh (replace, never append);
  7. a CVE aged off a release sheet is dropped (full refresh, no stale rows);
  8. a failed fetch with no prior checkout is a no-op (no-wipe);
  9. a failed fetch with a prior checkout proceeds (graceful degradation);
  10. no scope (--release/--package) errors and touches nothing;
  11. the overlay never touches verdicts (no-wipe / map-not-territory);
  12. non-CVE files in the tracker directory are skipped;
  13. byte-compatibility with the JSON-API path on the same CVE set.

All offline: :func:`clone_or_pull_tracker` is monkeypatched to point at the
bundled fixture directory; no network, no NVD_API_KEY.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from posture import store, export
from posture.sources import ubuntu_git_ingest as _ugi
from posture.sources import ubuntu_ingest as _ui
import posture.sources.ubuntu_tracker as _ut

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures" / "ubuntu_cve_tracker"
STATES_FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures" / "ubuntu_cve_tracker_states"
JSON_FIXTURE = Path(__file__).resolve().parent.parent / "posture" / "fixtures" / "ubuntu_tracker" / "cves.json"


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _fake_clone_success(dest_dir=None, repo_url=None, timeout=600):
    """Monkeypatch clone_or_pull_tracker to 'succeed' by pointing at the fixture."""
    return str(FIXTURE_DIR), "fixture"


def _fake_clone_failure(dest_dir=None, repo_url=None, timeout=600):
    """Monkeypatch clone_or_pull_tracker to simulate a network failure."""
    return None, "git clone failed (simulated)"


# ---------------------------------------------------------------------------
# 1. Populates the overlay per sheet
# ---------------------------------------------------------------------------

def test_git_ingest_populates_overlay_per_sheet(conn, monkeypatch):
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    stats = _ugi.ubuntu_git_ingest_tick(
        conn, releases=["noble", "jammy"], packages=["linux"], now="t1")
    assert stats["error"] is None
    assert stats["fetched"] is True
    assert stats["source"] == "git"
    assert stats["sheets"] == 2          # 2 releases x 1 package
    # noble/linux sheet: 99901(released), 99902(needs-triage), 99903(not-affected)
    noble = store.ubuntu_fixes_for_release_package(conn, "noble", "linux")
    assert len(noble) == 3
    # jammy/linux sheet: 99901(needed), 99902(released) -> 2 rows
    jammy = store.ubuntu_fixes_for_release_package(conn, "jammy", "linux")
    assert len(jammy) == 2


# ---------------------------------------------------------------------------
# 2. Status words preserved verbatim
# 3. Parenthetical note preserved as fixed_in
# ---------------------------------------------------------------------------

def test_git_ingest_preserves_status_words_and_notes(conn, monkeypatch):
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    _ugi.ubuntu_git_ingest_tick(conn, releases=["noble", "jammy", "focal"],
                                packages=["linux"], now="t1")
    noble = {r["cve_id"]: r for r in
             store.ubuntu_fixes_for_release_package(conn, "noble", "linux")}
    assert noble["CVE-2026-99901"]["status"] == "released"
    assert noble["CVE-2026-99901"]["fixed_in"] == "5.15.0-25.25"
    assert noble["CVE-2026-99902"]["status"] == "needs-triage"
    assert noble["CVE-2026-99902"]["fixed_in"] in (None, "")
    assert noble["CVE-2026-99903"]["status"] == "not-affected"
    assert noble["CVE-2026-99903"]["fixed_in"] == "5.15.0-9.12"
    jammy = {r["cve_id"]: r for r in
             store.ubuntu_fixes_for_release_package(conn, "jammy", "linux")}
    assert jammy["CVE-2026-99901"]["status"] == "needed"
    assert jammy["CVE-2026-99901"]["fixed_in"] in (None, "")
    assert jammy["CVE-2026-99902"]["status"] == "released"
    assert jammy["CVE-2026-99902"]["fixed_in"] == "5.15.0-1011"
    focal = {r["cve_id"]: r for r in
             store.ubuntu_fixes_for_release_package(conn, "focal", "linux")}
    assert focal["CVE-2026-99901"]["status"] == "DNE"
    assert focal["CVE-2026-99901"]["fixed_in"] in (None, "")


# ---------------------------------------------------------------------------
# 4. Package selection — only the requested package, not siblings
# ---------------------------------------------------------------------------

def test_git_ingest_selects_only_requested_package(conn, monkeypatch):
    # 99901's file lists TWO source packages for noble: linux(released) and
    # linux-nvidia-6.17(needs-triage). Ingesting `linux` must take linux's
    # status, NOT the nvidia sibling's.
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    _ugi.ubuntu_git_ingest_tick(conn, releases=["noble"], packages=["linux"],
                                now="t1")
    row = store.ubuntu_fixes_for(conn, "CVE-2026-99901", "noble", "linux")
    assert row is not None
    assert row["status"] == "released"
    assert row["fixed_in"] == "5.15.0-25.25"
    # The nvidia sibling must NOT appear in the linux sheet.
    nvidia = store.ubuntu_fixes_for_release_package(conn, "noble",
                                                     "linux-nvidia-6.17")
    assert len(nvidia) == 0


# ---------------------------------------------------------------------------
# 5. Sheets isolated per (release, package)
# ---------------------------------------------------------------------------

def test_git_ingest_sheets_isolated(conn, monkeypatch):
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    _ugi.ubuntu_git_ingest_tick(conn, releases=["noble", "jammy"],
                                packages=["linux"], now="t1")
    noble = store.ubuntu_fixes_for_release_package(conn, "noble", "linux")
    jammy = store.ubuntu_fixes_for_release_package(conn, "jammy", "linux")
    noble_ids = {r["cve_id"] for r in noble}
    jammy_ids = {r["cve_id"] for r in jammy}
    # noble has 3 CVEs; jammy has 2 (no 99903 row for jammy)
    assert noble_ids == {"CVE-2026-99901", "CVE-2026-99902",
                         "CVE-2026-99903"}
    assert jammy_ids == {"CVE-2026-99901", "CVE-2026-99902"}


# ---------------------------------------------------------------------------
# 6. Re-ingest is an idempotent full refresh
# ---------------------------------------------------------------------------

def test_git_ingest_idempotent_refresh(conn, monkeypatch):
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    s1 = _ugi.ubuntu_git_ingest_tick(conn, releases=["noble"],
                                     packages=["linux"], now="t1")
    assert s1["rows"] == 3
    s2 = _ugi.ubuntu_git_ingest_tick(conn, releases=["noble"],
                                     packages=["linux"], now="t2")
    assert s2["rows"] == 3           # same count, not doubled
    noble = store.ubuntu_fixes_for_release_package(conn, "noble", "linux")
    assert len(noble) == 3           # no duplicates


# ---------------------------------------------------------------------------
# 7. CVE aged off a release sheet is dropped (full refresh)
# ---------------------------------------------------------------------------

def test_git_ingest_aged_off_cve_dropped(conn, monkeypatch, tmp_path):
    # First ingest with the full fixture.
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    _ugi.ubuntu_git_ingest_tick(conn, releases=["noble"],
                                packages=["linux"], now="t1")
    assert len(store.ubuntu_fixes_for_release_package(conn, "noble", "linux")) == 3

    # Build a reduced fixture with one CVE file removed.
    reduced = tmp_path / "active"
    reduced.mkdir(parents=True)
    for f in (FIXTURE_DIR / "active").iterdir():
        if f.name == "CVE-2026-99903":
            continue  # aged off
        reduced.joinpath(f.name).write_text(f.read_text())

    def fake_reduced(dest_dir=None, repo_url=None, timeout=600):
        return str(tmp_path), "fixture-reduced"

    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", fake_reduced)
    _ugi.ubuntu_git_ingest_tick(conn, releases=["noble"],
                                packages=["linux"], now="t2")
    noble = {r["cve_id"] for r in
             store.ubuntu_fixes_for_release_package(conn, "noble", "linux")}
    assert "CVE-2026-99903" not in noble   # aged off, no stale row
    assert len(noble) == 2


# ---------------------------------------------------------------------------
# 8. Failed fetch with no prior checkout is a no-op (no-wipe)
# ---------------------------------------------------------------------------

def test_git_ingest_failed_fetch_no_checkout_noop(conn, monkeypatch):
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_failure)
    stats = _ugi.ubuntu_git_ingest_tick(
        conn, releases=["noble"], packages=["linux"], now="t1",
        tracker_dir="/nonexistent/path/that/does/not/exist")
    assert stats["error"] is not None
    assert stats["fetched"] is False
    assert stats["rows"] == 0
    assert stats["sheets"] == 0
    # Overlay must be empty (nothing was written).
    assert len(store.ubuntu_fixes_for_release_package(conn, "noble", "linux")) == 0


# ---------------------------------------------------------------------------
# 9. Failed fetch with a prior checkout proceeds (graceful degradation)
# ---------------------------------------------------------------------------

def test_git_ingest_failed_fetch_prior_checkout_proceeds(conn, monkeypatch):
    # First, a successful ingest to populate the overlay.
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    _ugi.ubuntu_git_ingest_tick(conn, releases=["noble"],
                                packages=["linux"], now="t1")
    assert len(store.ubuntu_fixes_for_release_package(conn, "noble", "linux")) == 3

    # Now simulate a failed fetch, but point at the existing fixture directory.
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_failure)
    stats = _ugi.ubuntu_git_ingest_tick(
        conn, releases=["noble"], packages=["linux"], now="t2",
        tracker_dir=str(FIXTURE_DIR))
    # fetch failed but the directory exists, so the tick proceeds.
    assert stats["fetched"] is False
    assert stats["error"] is None
    assert stats["rows"] == 3           # parsed from the stale checkout


# ---------------------------------------------------------------------------
# 10. No scope errors and touches nothing
# ---------------------------------------------------------------------------

def test_git_ingest_no_scope_errors(conn, monkeypatch):
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    stats = _ugi.ubuntu_git_ingest_tick(conn, releases=[], packages=["linux"],
                                        now="t1")
    assert stats["error"] is not None
    assert stats["rows"] == 0
    stats = _ugi.ubuntu_git_ingest_tick(conn, releases=["noble"], packages=[],
                                        now="t1")
    assert stats["error"] is not None
    assert stats["rows"] == 0


# ---------------------------------------------------------------------------
# 11. The overlay never touches verdicts (map-not-territory)
# ---------------------------------------------------------------------------

def test_git_ingest_never_touches_verdicts(conn, monkeypatch):
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    _ugi.ubuntu_git_ingest_tick(conn, releases=["noble"],
                                packages=["linux"], now="t1")
    cur = conn.execute("SELECT count(*) FROM verdicts")
    assert cur.fetchone()[0] == 0


# ---------------------------------------------------------------------------
# 12. Non-CVE files in the tracker directory are skipped
# ---------------------------------------------------------------------------

def test_git_ingest_skips_non_cve_files(conn, monkeypatch):
    # The fixture directory contains 10autotriage.linux which is not a CVE.
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    _ugi.ubuntu_git_ingest_tick(conn, releases=["noble"],
                                packages=["linux"], now="t1")
    noble = {r["cve_id"] for r in
             store.ubuntu_fixes_for_release_package(conn, "noble", "linux")}
    # Only real CVE ids, no spurious entries from the non-CVE file.
    assert noble == {"CVE-2026-99901", "CVE-2026-99902",
                     "CVE-2026-99903"}


# ---------------------------------------------------------------------------
# 13. Byte-compatibility with the JSON-API path on the same CVE set
# ---------------------------------------------------------------------------

def test_git_ingest_byte_compatible_with_json_api(conn, monkeypatch):
    """The git-source path and the JSON-API path must produce identical overlay
    rows for the same CVE set, so the spine manifest stays byte-compatible."""
    # JSON-API path
    def fake_curl_get(url, headers=None, max_time=300, extra=None):
        data = json.loads(JSON_FIXTURE.read_text())
        return data, 200, ""

    monkeypatch.setattr(_ut, "curl_get", fake_curl_get)
    json_stats = _ui.ubuntu_ingest_tick(
        conn, releases=["noble", "jammy", "focal"], packages=["linux"],
        now="t1")
    assert json_stats["error"] is None

    # Snapshot the JSON-API overlay.
    json_rows = {}
    for rel in ("noble", "jammy", "focal"):
        rows = store.ubuntu_fixes_for_release_package(conn, rel, "linux")
        json_rows[rel] = {r["cve_id"]: (r["status"], r["fixed_in"]) for r in rows}

    # Wipe the overlay and re-ingest from the git source.
    for rel in ("noble", "jammy", "focal"):
        conn.execute(
            "DELETE FROM ubuntu_fixes WHERE release=? AND package=?",
            (rel, "linux"))

    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    git_stats = _ugi.ubuntu_git_ingest_tick(
        conn, releases=["noble", "jammy", "focal"], packages=["linux"],
        now="t1")
    assert git_stats["error"] is None

    # Compare: every (release, cve_id) must have the same (status, fixed_in).
    for rel in ("noble", "jammy", "focal"):
        rows = store.ubuntu_fixes_for_release_package(conn, rel, "linux")
        git_rows = {r["cve_id"]: (r["status"], r["fixed_in"]) for r in rows}
        assert git_rows == json_rows[rel], (
            f"byte-compat mismatch for {rel}: "
            f"git={git_rows} vs json={json_rows[rel]}")


# ---------------------------------------------------------------------------
# 14. Spine export/import round-trips the overlay (no device data)
# ---------------------------------------------------------------------------

def test_git_ingest_spine_export_import_roundtrip(conn, monkeypatch, tmp_path):
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_success)
    _ugi.ubuntu_git_ingest_tick(
        conn, releases=["noble", "jammy"], packages=["linux"], now="t1")
    conn.commit()

    out = tmp_path / "out"
    manifest = export.export_spine(conn, out_dir=out, policy_version="v")
    assert manifest["counts"]["ubuntu_fixes"] >= 5
    assert (out / "spine" / "ubuntu_fixes.jsonl").exists()

    other = store.connect(":memory:")
    stats = export.import_spine(other, from_dir=out)
    assert stats["ubuntu_fixes"] == manifest["counts"]["ubuntu_fixes"]
    assert store.ubuntu_fixes_all(conn) == store.ubuntu_fixes_all(other)
    shard_names = {p.relative_to(out / "spine").as_posix()
                   for p in (out / "spine").rglob("*.jsonl")}
    assert not any("verdict" in n or "device" in n for n in shard_names)


# ---------------------------------------------------------------------------
# 15. Every tracker state directory is read, not just `active`
# ---------------------------------------------------------------------------

def _fake_clone_states(dest_dir=None, repo_url=None, timeout=600):
    """Point the clone seam at the fixture that carries all three state dirs."""
    return str(STATES_FIXTURE_DIR), "fixture"


def test_git_ingest_reads_every_tracker_state_directory(conn, monkeypatch):
    # The tracker keeps a CVE file in `active` (open), `retired` (resolved) or
    # `ignored` (explicitly ignored). The published bulk-CVE JSON feed spans
    # all three, and the resolved CVEs are the bulk of the rows, so a scan that
    # read only `active` would publish a far smaller overlay than the HTTP
    # feed and silently drop the fix-status row of every resolved CVE.
    monkeypatch.setattr(_ugi, "clone_or_pull_tracker", _fake_clone_states)
    stats = _ugi.ubuntu_git_ingest_tick(
        conn, releases=["noble", "jammy", "focal"], packages=["linux"], now="t1")
    assert stats["error"] is None
    assert stats["fetched"] is True
    # active/ -> noble, retired/ -> jammy, ignored/ -> focal: one sheet each.
    assert stats["sheets"] == 3
    noble = store.ubuntu_fixes_for_release_package(conn, "noble", "linux")
    jammy = store.ubuntu_fixes_for_release_package(conn, "jammy", "linux")
    focal = store.ubuntu_fixes_for_release_package(conn, "focal", "linux")
    assert [r["cve_id"] for r in noble] == ["CVE-2026-99911"]
    assert [r["cve_id"] for r in jammy] == ["CVE-2024-99912"]
    assert [r["cve_id"] for r in focal] == ["CVE-2023-99913"]
    # The status word and the note survive verbatim from each state dir.
    assert noble[0]["status"] == "released"
    assert noble[0]["fixed_in"] == "5.15.0-25.25"
    assert jammy[0]["status"] == "released"
    assert jammy[0]["fixed_in"] == "5.15.0-1011.109"
    assert focal[0]["status"] == "ignored"
    assert focal[0]["fixed_in"] == "end of standard support"
