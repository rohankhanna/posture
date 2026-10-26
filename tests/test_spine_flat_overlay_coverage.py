"""The flat overlay coverage of a published map (Apple fix and EPSS).

The overlay coverage checks (items 16-19) bind the distro-tracker overlays
at every granularity. The known-exploited coverage check (item 20) binds the
confirmed-exploited set. None of them binds the Apple fix overlay
(apple_fixes) or the EPSS exploitability-probability overlay (epss), which
are flat tables the export writes with no per-release or per-package
structure. Both ingests are no-wipe on the caller side, so a failed fetch
leaves the last-known-good rows in place: the served map stays intact,
consistent with its own manifest, signed and fresh, every other check on it
still passes, and only the age of those rows shows the overlay stopped
being refreshed.

These tests pin the flat overlay coverage the published manifest states and
the checks that read it, on the operator's own verify command.

Offline and hermetic: no network, no fixtures on disk.
"""
from __future__ import annotations

import pytest

from posture import export, store
from posture.cli import main


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _seed_apple(conn, rows: int = 1,
                fetched_at: str = "2026-10-26T00:00:00+00:00",
                product: str = "iphone_os",
                start: int = 0) -> None:
    store.replace_apple_fixes(conn, product, [
        {"cve_id": f"CVE-2026-9{n:04d}", "fixed_in": f"18.{n}",
         "advisory_id": f"HT{n:06d}"}
        for n in range(start, start + rows)
    ], fetched_at=fetched_at)


def _seed_epss(conn, rows: int = 1,
               fetched_at: str = "2026-10-26T00:00:00+00:00",
               start: int = 0) -> None:
    store.replace_epss(conn, [
        {"cve_id": f"CVE-2026-9{n:04d}", "epss": 0.01 * (n + 1),
         "percentile": 0.5}
        for n in range(start, start + rows)
    ], fetched_at=fetched_at)


def _publish(conn, tmp_path) -> None:
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")


# ---------------------------------------------------------------------------
# What the published manifest states (Apple fix)
# ---------------------------------------------------------------------------

def test_the_manifest_states_the_apple_fix_coverage(conn, tmp_path):
    _seed_apple(conn, rows=3)
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["apple_fixes_coverage"]
    assert coverage["rows"] == 3
    assert coverage["newest_fetched_at"] == "2026-10-26T00:00:00+00:00"


def test_the_manifest_states_an_empty_apple_fix_set_as_empty(conn, tmp_path):
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["apple_fixes_coverage"]
    assert coverage["rows"] == 0
    assert coverage["newest_fetched_at"] is None


def test_the_manifest_records_the_newest_apple_fix_fetch_time(conn, tmp_path):
    # The apple_fixes ingest is per-product full refresh, so the two
    # batches must be different products to coexist.
    _seed_apple(conn, rows=1, fetched_at="2026-10-20T00:00:00+00:00",
                product="iphone_os")
    _seed_apple(conn, rows=1, fetched_at="2026-10-26T00:00:00+00:00",
                product="macos", start=1)
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["apple_fixes_coverage"]
    assert coverage["rows"] == 2
    assert coverage["newest_fetched_at"] == "2026-10-26T00:00:00+00:00"


# ---------------------------------------------------------------------------
# What the published manifest states (EPSS)
# ---------------------------------------------------------------------------

def test_the_manifest_states_the_epss_coverage(conn, tmp_path):
    _seed_epss(conn, rows=5)
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["epss_coverage"]
    assert coverage["rows"] == 5
    assert coverage["newest_fetched_at"] == "2026-10-26T00:00:00+00:00"


def test_the_manifest_states_an_empty_epss_set_as_empty(conn, tmp_path):
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["epss_coverage"]
    assert coverage["rows"] == 0
    assert coverage["newest_fetched_at"] is None


def test_the_manifest_records_the_newest_epss_fetch_time(conn, tmp_path):
    # The epss ingest is a full refresh (DELETE all + INSERT) with one
    # fetched_at per batch, so insert two rows with different fetch times
    # directly to test that the manifest records the newest.
    conn.execute(
        "INSERT OR REPLACE INTO epss (cve_id, epss, percentile, fetched_at) "
        "VALUES (?,?,?,?)",
        ("CVE-2026-90000", 0.01, 0.5, "2026-10-20T00:00:00+00:00"))
    conn.execute(
        "INSERT OR REPLACE INTO epss (cve_id, epss, percentile, fetched_at) "
        "VALUES (?,?,?,?)",
        ("CVE-2026-90001", 0.02, 0.6, "2026-10-26T00:00:00+00:00"))
    conn.commit()
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["epss_coverage"]
    assert coverage["rows"] == 2
    assert coverage["newest_fetched_at"] == "2026-10-26T00:00:00+00:00"


# ---------------------------------------------------------------------------
# The Apple fix coverage check
# ---------------------------------------------------------------------------

def test_apple_check_accepts_a_map_that_carries_the_required_rows(conn,
                                                                  tmp_path):
    _seed_apple(conn, rows=5)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_apple_fixes_coverage(manifest, min_rows=5)
    assert checked["rows"] == 5


def test_apple_check_rejects_a_map_below_the_row_floor(conn, tmp_path):
    _seed_apple(conn, rows=2)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="fewer than the 10"):
        export.verify_apple_fixes_coverage(manifest, min_rows=10)


def test_apple_check_rejects_a_map_with_no_apple_fix_rows(conn, tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="0"):
        export.verify_apple_fixes_coverage(manifest, min_rows=1)


def test_apple_check_rejects_a_set_that_stopped_being_refreshed(conn,
                                                                tmp_path):
    _seed_apple(conn, rows=5, fetched_at="2020-01-01T00:00:00+00:00")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="stopped being refreshed"):
        export.verify_apple_fixes_coverage(manifest, min_rows=5,
                                           max_age_days=3)


def test_apple_check_accepts_a_fresh_set_within_the_allowance(conn, tmp_path):
    _seed_apple(conn, rows=5, fetched_at="2026-10-25T00:00:00+00:00")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_apple_fixes_coverage(
        manifest, min_rows=5, max_age_days=3,
        now="2026-10-26T00:00:00+00:00")
    assert checked["rows"] == 5


def test_apple_check_rejects_a_set_with_no_recorded_fetch_time(conn,
                                                                tmp_path):
    _seed_apple(conn, rows=5)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    manifest["apple_fixes_coverage"]["newest_fetched_at"] = None
    with pytest.raises(ValueError, match="no fetch time"):
        export.verify_apple_fixes_coverage(manifest, min_rows=5,
                                           max_age_days=3)


def test_apple_check_rejects_a_manifest_without_apple_fix_coverage():
    manifest = {"counts": {}, "files": [], "release_coverage": {},
                "kev_coverage": {"rows": 0, "newest_fetched_at": None,
                                 "catalog_version": None,
                                 "date_released": None}}
    with pytest.raises(ValueError, match="no apple-fixes coverage"):
        export.verify_apple_fixes_coverage(manifest, min_rows=1)


def test_apple_check_rejects_a_floor_below_one_row(conn, tmp_path):
    _seed_apple(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="minimum is one"):
        export.verify_apple_fixes_coverage(manifest, min_rows=0)


def test_apple_check_rejects_a_non_positive_freshness_allowance(conn,
                                                                 tmp_path):
    _seed_apple(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="positive"):
        export.verify_apple_fixes_coverage(manifest, min_rows=1,
                                           max_age_days=0)


def test_apple_check_defaults_to_at_least_one_row(conn, tmp_path):
    _seed_apple(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_apple_fixes_coverage(manifest)
    assert checked["rows"] == 1


# ---------------------------------------------------------------------------
# The EPSS coverage check
# ---------------------------------------------------------------------------

def test_epss_check_accepts_a_map_that_carries_the_required_rows(conn,
                                                                 tmp_path):
    _seed_epss(conn, rows=5)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_epss_coverage(manifest, min_rows=5)
    assert checked["rows"] == 5


def test_epss_check_rejects_a_map_below_the_row_floor(conn, tmp_path):
    _seed_epss(conn, rows=2)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="fewer than the 10"):
        export.verify_epss_coverage(manifest, min_rows=10)


def test_epss_check_rejects_a_map_with_no_epss_rows(conn, tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="0"):
        export.verify_epss_coverage(manifest, min_rows=1)


def test_epss_check_rejects_a_set_that_stopped_being_refreshed(conn,
                                                               tmp_path):
    _seed_epss(conn, rows=5, fetched_at="2020-01-01T00:00:00+00:00")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="stopped being refreshed"):
        export.verify_epss_coverage(manifest, min_rows=5, max_age_days=3)


def test_epss_check_accepts_a_fresh_set_within_the_allowance(conn, tmp_path):
    _seed_epss(conn, rows=5, fetched_at="2026-10-25T00:00:00+00:00")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_epss_coverage(
        manifest, min_rows=5, max_age_days=3,
        now="2026-10-26T00:00:00+00:00")
    assert checked["rows"] == 5


def test_epss_check_rejects_a_set_with_no_recorded_fetch_time(conn,
                                                               tmp_path):
    _seed_epss(conn, rows=5)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    manifest["epss_coverage"]["newest_fetched_at"] = None
    with pytest.raises(ValueError, match="no fetch time"):
        export.verify_epss_coverage(manifest, min_rows=5, max_age_days=3)


def test_epss_check_rejects_a_manifest_without_epss_coverage():
    manifest = {"counts": {}, "files": [], "release_coverage": {},
                "kev_coverage": {"rows": 0, "newest_fetched_at": None,
                                 "catalog_version": None,
                                 "date_released": None}}
    with pytest.raises(ValueError, match="no epss coverage"):
        export.verify_epss_coverage(manifest, min_rows=1)


def test_epss_check_rejects_a_floor_below_one_row(conn, tmp_path):
    _seed_epss(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="minimum is one"):
        export.verify_epss_coverage(manifest, min_rows=0)


def test_epss_check_rejects_a_non_positive_freshness_allowance(conn,
                                                                tmp_path):
    _seed_epss(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="positive"):
        export.verify_epss_coverage(manifest, min_rows=1, max_age_days=0)


def test_epss_check_defaults_to_at_least_one_row(conn, tmp_path):
    _seed_epss(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_epss_coverage(manifest)
    assert checked["rows"] == 1


# ---------------------------------------------------------------------------
# CLI: the operator's verification of the served map
# ---------------------------------------------------------------------------

def test_cli_verify_accepts_a_map_that_carries_the_apple_fix_rows(conn,
                                                                  tmp_path,
                                                                  capsys):
    _seed_apple(conn, rows=5)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-apple-fixes", "5"]) == 0
    out = capsys.readouterr().out
    assert "Apple fix coverage OK" in out, out
    assert "5 row(s)" in out, out


def test_cli_verify_rejects_a_map_below_the_apple_fix_floor(conn, tmp_path,
                                                            capsys):
    _seed_apple(conn, rows=2)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-apple-fixes", "10"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "fewer than the 10" in out, out


def test_cli_verify_rejects_a_stale_apple_fix_overlay(conn, tmp_path,
                                                      capsys):
    _seed_apple(conn, rows=5, fetched_at="2020-01-01T00:00:00+00:00")
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-apple-fixes", "5",
                 "--require-apple-fixes-max-age-days", "3"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "stopped being refreshed" in out, out


def test_cli_verify_accepts_a_map_that_carries_the_epss_rows(conn, tmp_path,
                                                             capsys):
    _seed_epss(conn, rows=5)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-epss", "5"]) == 0
    out = capsys.readouterr().out
    assert "EPSS coverage OK" in out, out
    assert "5 row(s)" in out, out


def test_cli_verify_rejects_a_map_below_the_epss_floor(conn, tmp_path,
                                                       capsys):
    _seed_epss(conn, rows=2)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-epss", "10"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "fewer than the 10" in out, out


def test_cli_verify_rejects_a_stale_epss_overlay(conn, tmp_path, capsys):
    _seed_epss(conn, rows=5, fetched_at="2020-01-01T00:00:00+00:00")
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-epss", "5",
                 "--require-epss-max-age-days", "3"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "stopped being refreshed" in out, out


def test_cli_verify_without_the_flat_overlay_requirements_checks_nothing(
        conn, tmp_path, capsys):
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Apple fix" not in out, out
    assert "EPSS" not in out, out
