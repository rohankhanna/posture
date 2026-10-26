"""The per-release overlay coverage of a published map.

The overlay coverage check is a per-table question: does the `ubuntu_fixes`
table hold rows? That answer hides a per-release failure. The nightly job's
per-(release, package) refresh deletes the rows it is about to replace, so
a release whose tracker feed returned nothing ends up with no rows at all
while the table as a whole still holds the other releases' rows. The
presence check still passes, the map is still intact, consistent with its
own manifest, signed and fresh, and the only thing that is gone is the
fix-status rows of the release that would have cleared NVD's unknown-fix
false positives on that release.

The other silent direction is the mirror image: a release the nightly job
stops ingesting keeps its last-known-good rows, so only the age of those
rows shows that they stopped being refreshed.

These tests pin the per-release coverage the published manifest now states
and the check that reads it, on the operator's own verify command.

Offline and hermetic: no network, no fixtures on disk.
"""
from __future__ import annotations

import pytest

from posture import export, store
from posture.cli import main


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _seed_ubuntu(conn, release: str, rows: int = 1,
                 fetched_at: str = "2026-10-26T00:00:00+00:00") -> None:
    store.replace_ubuntu_fixes(
        conn, release, "linux",
        [{"cve_id": f"CVE-2026-7{release[:2]}{n:02d}", "status": "released",
          "fixed_in": "1.2.3"} for n in range(rows)],
        fetched_at=fetched_at)


def _seed_debian(conn, release: str, rows: int = 1,
                 fetched_at: str = "2026-10-26T00:00:00+00:00") -> None:
    store.replace_debian_fixes(
        conn, release, "linux",
        [{"cve_id": f"CVE-2026-8{release[:2]}{n:02d}", "status": "resolved",
          "fixed_in": "1.2.3"} for n in range(rows)],
        fetched_at=fetched_at)


def _publish(conn, tmp_path) -> None:
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")


# ---------------------------------------------------------------------------
# What the published manifest states
# ---------------------------------------------------------------------------

def test_the_release_keyed_overlay_tables_are_the_distro_tracker_ones():
    assert export.RELEASE_KEYED_OVERLAY_TABLES == ("ubuntu_fixes",
                                                    "debian_fixes")


def test_the_manifest_states_the_coverage_of_every_release(conn, tmp_path):
    _seed_ubuntu(conn, "noble", 3)
    _seed_ubuntu(conn, "jammy", 2)
    _seed_debian(conn, "trixie", 1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    coverage = manifest["release_coverage"]
    assert set(coverage["ubuntu_fixes"]) == {"noble", "jammy"}
    assert coverage["ubuntu_fixes"]["noble"]["rows"] == 3
    assert coverage["ubuntu_fixes"]["jammy"]["rows"] == 2
    assert coverage["debian_fixes"]["trixie"]["rows"] == 1
    assert coverage["ubuntu_fixes"]["noble"]["packages"]["linux"] == 3
    assert coverage["ubuntu_fixes"]["noble"]["newest_fetched_at"] == (
        "2026-10-26T00:00:00+00:00")


def test_the_manifest_states_an_empty_coverage_for_a_table_with_no_rows(
        conn, tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    assert manifest["release_coverage"]["ubuntu_fixes"] == {}
    assert manifest["release_coverage"]["debian_fixes"] == {}


# ---------------------------------------------------------------------------
# The per-release coverage check
# ---------------------------------------------------------------------------

def test_the_check_accepts_a_map_that_carries_every_required_release(conn,
                                                                       tmp_path):
    _seed_ubuntu(conn, "noble", 3)
    _seed_debian(conn, "trixie", 1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_overlay_release_coverage(
        manifest, [("ubuntu_fixes", "noble", 3), ("debian_fixes", "trixie", 1)])
    assert checked["ubuntu_fixes"]["noble"]["rows"] == 3
    assert checked["debian_fixes"]["trixie"]["rows"] == 1


def test_the_check_rejects_a_release_the_map_does_not_carry_at_all(conn,
                                                                   tmp_path):
    # The table as a whole is populated; the release is missing.
    _seed_ubuntu(conn, "noble", 3)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="jammy"):
        export.verify_overlay_release_coverage(
            manifest, [("ubuntu_fixes", "jammy", 1)])
    with pytest.raises(ValueError, match="no rows for that release"):
        export.verify_overlay_release_coverage(
            manifest, [("ubuntu_fixes", "jammy", 1)])


def test_the_check_rejects_a_release_below_its_row_floor(conn, tmp_path):
    _seed_ubuntu(conn, "noble", 2)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="fewer than the 10"):
        export.verify_overlay_release_coverage(
            manifest, [("ubuntu_fixes", "noble", 10)])


def test_the_check_rejects_rows_that_are_older_than_the_allowance(conn,
                                                                   tmp_path):
    # A release the nightly job stopped ingesting keeps its last-known-good
    # rows: the rows are there, and they are stale.
    _seed_ubuntu(conn, "noble", 3,
                 fetched_at="2026-10-01T00:00:00+00:00")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="stopped being refreshed"):
        export.verify_overlay_release_coverage(
            manifest, [("ubuntu_fixes", "noble", 1)], max_age_days=2,
            now="2026-10-26T00:00:00+00:00")
    # Within the allowance the same map passes.
    assert export.verify_overlay_release_coverage(
        manifest, [("ubuntu_fixes", "noble", 1)], max_age_days=30,
        now="2026-10-26T00:00:00+00:00")


def test_the_check_rejects_a_release_with_no_recorded_fetch_time(conn,
                                                                  tmp_path):
    _seed_ubuntu(conn, "noble", 1, fetched_at="")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="no fetch time"):
        export.verify_overlay_release_coverage(
            manifest, [("ubuntu_fixes", "noble", 1)], max_age_days=2,
            now="2026-10-26T00:00:00+00:00")


def test_the_check_rejects_a_table_that_is_not_release_keyed():
    with pytest.raises(ValueError, match="not a release-keyed overlay table"):
        export.verify_overlay_release_coverage(
            {"release_coverage": {}}, [("kev", "noble", 1)])


def test_the_check_rejects_a_manifest_without_per_release_coverage():
    with pytest.raises(ValueError, match="no per-release overlay coverage"):
        export.verify_overlay_release_coverage(
            {"counts": {}}, [("ubuntu_fixes", "noble", 1)])


def test_the_check_rejects_a_floor_below_one_row():
    with pytest.raises(ValueError, match="the minimum is one"):
        export.verify_overlay_release_coverage(
            {"release_coverage": {}}, [("ubuntu_fixes", "noble", 0)])


def test_the_check_without_a_requirement_checks_nothing(conn, tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    assert export.verify_overlay_release_coverage(manifest, None) == {}
    assert export.verify_overlay_release_coverage(manifest, []) == {}


# ---------------------------------------------------------------------------
# CLI: the operator's verification of the served map
# ---------------------------------------------------------------------------

def test_cli_verify_accepts_a_map_that_carries_every_required_release(conn,
                                                                       tmp_path,
                                                                       capsys):
    _seed_ubuntu(conn, "noble", 3)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay", "ubuntu_fixes",
                 "--require-overlay-release", "ubuntu_fixes:noble:3"]) == 0
    out = capsys.readouterr().out
    assert "per-release overlay coverage OK" in out, out
    assert "ubuntu_fixes noble 3 row(s)" in out, out


def test_cli_verify_rejects_a_map_that_is_quietly_narrow(conn, tmp_path,
                                                          capsys):
    # The table holds rows; the release the host requires does not.
    _seed_ubuntu(conn, "noble", 3)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay", "ubuntu_fixes"]) == 0
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay", "ubuntu_fixes",
                 "--require-overlay-release", "ubuntu_fixes:jammy:1"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "jammy" in out, out


def test_cli_verify_rejects_stale_overlay_rows(conn, tmp_path, capsys):
    _seed_ubuntu(conn, "noble", 3, fetched_at="2026-10-01T00:00:00+00:00")
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay-release", "ubuntu_fixes:noble:1",
                 "--require-overlay-max-age-days", "2"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "stopped being refreshed" in out, out


def test_cli_verify_rejects_a_malformed_release_requirement(conn, tmp_path,
                                                            capsys):
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay-release", "ubuntu_fixes:noble"]) == 1
    out = capsys.readouterr().out
    assert "TABLE:RELEASE:MIN_ROWS" in out, out
