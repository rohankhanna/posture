"""The per-package overlay coverage of a published map.

The per-release coverage check is a per-release question: does the
`ubuntu_fixes` table hold rows for release `noble`? That answer hides a
per-package failure. The nightly job ingests each distro-tracker overlay
per release and per source package (`posture ingest ubuntu --release noble
--package linux`), and the per-(release, package) refresh deletes the rows
it is about to replace, so a source package whose tracker feed returned
nothing ends up with no rows at all while the release as a whole still
holds the other packages' rows. The per-release floor still passes, the
map is still intact, consistent with its own manifest, signed and fresh,
and the only thing that is gone is the fix-status rows of the package that
would have cleared NVD's unknown-fix false positives for that source on
that release.

These tests pin the per-package coverage the published manifest already
states (it records, per release, which source packages contributed rows
and how many) and the check that reads it, on the operator's own verify
command.

Offline and hermetic: no network, no fixtures on disk.
"""
from __future__ import annotations

import pytest

from posture import export, store
from posture.cli import main


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _seed_ubuntu(conn, release: str, package: str, rows: int = 1,
                 fetched_at: str = "2026-10-26T00:00:00+00:00") -> None:
    store.replace_ubuntu_fixes(
        conn, release, package,
        [{"cve_id": f"CVE-2026-7{release[:2]}{package[:2]}{n:02d}",
          "status": "released", "fixed_in": "1.2.3"} for n in range(rows)],
        fetched_at=fetched_at)


def _seed_debian(conn, release: str, package: str, rows: int = 1,
                 fetched_at: str = "2026-10-26T00:00:00+00:00") -> None:
    store.replace_debian_fixes(
        conn, release, package,
        [{"cve_id": f"CVE-2026-8{release[:2]}{package[:2]}{n:02d}",
          "status": "resolved", "fixed_in": "1.2.3"} for n in range(rows)],
        fetched_at=fetched_at)


def _publish(conn, tmp_path) -> None:
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")


# ---------------------------------------------------------------------------
# What the published manifest states
# ---------------------------------------------------------------------------

def test_the_manifest_states_the_per_package_counts(conn, tmp_path):
    _seed_ubuntu(conn, "noble", "linux", 3)
    _seed_ubuntu(conn, "noble", "linux-nvidia", 2)
    _seed_debian(conn, "trixie", "linux", 1)
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["release_coverage"]
    noble = coverage["ubuntu_fixes"]["noble"]
    assert noble["packages"]["linux"] == 3
    assert noble["packages"]["linux-nvidia"] == 2
    assert coverage["debian_fixes"]["trixie"]["packages"]["linux"] == 1


def test_the_manifest_omits_a_package_that_carried_no_rows(conn, tmp_path):
    # A package the ingest scope declares but whose tracker feed returned
    # nothing is absent from the per-package map, not zero — the refresh
    # deletes the rows it is about to replace, so an empty feed leaves no
    # entry at all.
    _seed_ubuntu(conn, "noble", "linux", 3)
    _publish(conn, tmp_path)
    packages = (export.read_manifest(tmp_path)["release_coverage"]
                ["ubuntu_fixes"]["noble"]["packages"])
    assert "linux" in packages
    assert "linux-nvidia" not in packages


# ---------------------------------------------------------------------------
# The per-package coverage check
# ---------------------------------------------------------------------------

def test_the_check_accepts_a_map_that_carries_every_required_package(conn,
                                                                       tmp_path):
    _seed_ubuntu(conn, "noble", "linux", 3)
    _seed_ubuntu(conn, "noble", "linux-nvidia", 2)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_overlay_package_coverage(
        manifest,
        [("ubuntu_fixes", "noble", "linux", 3),
         ("ubuntu_fixes", "noble", "linux-nvidia", 2)])
    assert checked["ubuntu_fixes"]["noble"]["linux"] == 3
    assert checked["ubuntu_fixes"]["noble"]["linux-nvidia"] == 2


def test_the_check_rejects_a_package_the_map_does_not_carry(conn, tmp_path):
    # The release as a whole is populated; the package is missing.
    _seed_ubuntu(conn, "noble", "linux", 3)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="linux-nvidia"):
        export.verify_overlay_package_coverage(
            manifest, [("ubuntu_fixes", "noble", "linux-nvidia", 1)])
    with pytest.raises(ValueError, match="fewer than the 1"):
        export.verify_overlay_package_coverage(
            manifest, [("ubuntu_fixes", "noble", "linux-nvidia", 1)])


def test_the_check_rejects_a_package_below_its_row_floor(conn, tmp_path):
    _seed_ubuntu(conn, "noble", "linux", 2)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="fewer than the 10"):
        export.verify_overlay_package_coverage(
            manifest, [("ubuntu_fixes", "noble", "linux", 10)])


def test_the_check_rejects_a_release_the_map_does_not_carry_at_all(conn,
                                                                   tmp_path):
    _seed_ubuntu(conn, "noble", "linux", 3)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="jammy"):
        export.verify_overlay_package_coverage(
            manifest, [("ubuntu_fixes", "jammy", "linux", 1)])
    with pytest.raises(ValueError, match="no rows for that release"):
        export.verify_overlay_package_coverage(
            manifest, [("ubuntu_fixes", "jammy", "linux", 1)])


def test_the_check_rejects_a_table_that_is_not_release_keyed():
    with pytest.raises(ValueError, match="not a release-keyed overlay table"):
        export.verify_overlay_package_coverage(
            {"release_coverage": {}}, [("kev", "noble", "linux", 1)])


def test_the_check_rejects_a_manifest_without_per_release_coverage():
    with pytest.raises(ValueError, match="no per-release overlay coverage"):
        export.verify_overlay_package_coverage(
            {"counts": {}}, [("ubuntu_fixes", "noble", "linux", 1)])


def test_the_check_rejects_a_floor_below_one_row():
    with pytest.raises(ValueError, match="the minimum is one"):
        export.verify_overlay_package_coverage(
            {"release_coverage": {}}, [("ubuntu_fixes", "noble", "linux", 0)])


def test_the_check_rejects_a_requirement_that_names_no_package():
    with pytest.raises(ValueError, match="names no package"):
        export.verify_overlay_package_coverage(
            {"release_coverage": {}}, [("ubuntu_fixes", "noble", "", 1)])


def test_the_check_without_a_requirement_checks_nothing(conn, tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    assert export.verify_overlay_package_coverage(manifest, None) == {}
    assert export.verify_overlay_package_coverage(manifest, []) == {}


# ---------------------------------------------------------------------------
# CLI: the operator's verification of the served map
# ---------------------------------------------------------------------------

def test_cli_verify_accepts_a_map_that_carries_every_required_package(conn,
                                                                       tmp_path,
                                                                       capsys):
    _seed_ubuntu(conn, "noble", "linux", 3)
    _seed_ubuntu(conn, "noble", "linux-nvidia", 2)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay", "ubuntu_fixes",
                 "--require-overlay-release", "ubuntu_fixes:noble:5",
                 "--require-overlay-package", "ubuntu_fixes:noble:linux:3",
                 "--require-overlay-package",
                 "ubuntu_fixes:noble:linux-nvidia:2"]) == 0
    out = capsys.readouterr().out
    assert "per-package overlay coverage OK" in out, out
    assert "ubuntu_fixes noble linux 3 row(s)" in out, out
    assert "ubuntu_fixes noble linux-nvidia 2 row(s)" in out, out


def test_cli_verify_rejects_a_map_that_is_quietly_narrow(conn, tmp_path,
                                                          capsys):
    # The release holds rows; the package the host requires does not.
    _seed_ubuntu(conn, "noble", "linux", 3)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay", "ubuntu_fixes",
                 "--require-overlay-release", "ubuntu_fixes:noble:1"]) == 0
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay", "ubuntu_fixes",
                 "--require-overlay-release", "ubuntu_fixes:noble:1",
                 "--require-overlay-package",
                 "ubuntu_fixes:noble:linux-nvidia:1"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "linux-nvidia" in out, out


def test_cli_verify_rejects_a_malformed_package_requirement(conn, tmp_path,
                                                            capsys):
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay-package",
                 "ubuntu_fixes:noble:linux"]) == 1
    out = capsys.readouterr().out
    assert "TABLE:RELEASE:PACKAGE:MIN_ROWS" in out, out
