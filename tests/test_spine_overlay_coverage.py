"""The overlay coverage of a published map.

The publish path is atomic: a build that fails leaves the previously
published map serving, intact and internally consistent. A build that
SUCCEEDS while the vendor fix-status overlays are missing has the same
shape: the map keeps serving, every digest, row-count, signature and
freshness check on it still passes, and the only thing that shows the
overlay rows are gone is the map's own row counts. Those rows are what
clear NVD's unknown-fix false positives on a fully-updated host, so their
absence is a map that reports patched packages as unpatched.

These tests pin the check that reads those counts, on the operator's own
verify command.

Offline and hermetic: no network, no fixtures on disk.
"""
from __future__ import annotations

import pytest

from posture import export, store
from posture.cli import main


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _seed_overlay(conn, table: str, rows: int = 1) -> None:
    """Write `rows` fix-status overlay rows into the named table."""
    if table == "ubuntu_fixes":
        writer = store.replace_ubuntu_fixes
    elif table == "debian_fixes":
        writer = store.replace_debian_fixes
    else:
        raise AssertionError(f"not an overlay table this test seeds: {table}")
    writer(conn, "noble" if table == "ubuntu_fixes" else "trixie", "linux",
           [{"cve_id": f"CVE-2026-70{n:02d}", "status": "released",
             "fixed_in": "1.2.3"} for n in range(rows)],
           fetched_at="t1")


def _publish(conn, tmp_path) -> None:
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")


# ---------------------------------------------------------------------------
# The overlay tables the map can carry
# ---------------------------------------------------------------------------

def test_the_overlay_tables_include_the_vendor_fix_status_overlays():
    assert "ubuntu_fixes" in export.OVERLAY_TABLES
    assert "debian_fixes" in export.OVERLAY_TABLES
    assert "apple_fixes" in export.OVERLAY_TABLES
    assert "kev" in export.OVERLAY_TABLES


def test_every_overlay_table_is_a_table_the_export_writes():
    for table in export.OVERLAY_TABLES:
        assert table in export.FLAT_TABLES


# ---------------------------------------------------------------------------
# The coverage check
# ---------------------------------------------------------------------------

def test_verify_overlay_coverage_accepts_a_map_that_carries_the_rows(conn,
                                                                     tmp_path):
    _seed_overlay(conn, "ubuntu_fixes", 3)
    _seed_overlay(conn, "debian_fixes", 2)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    coverage = export.verify_overlay_coverage(
        manifest, ["ubuntu_fixes", "debian_fixes"])
    assert coverage == {"ubuntu_fixes": 3, "debian_fixes": 2}


def test_verify_overlay_coverage_rejects_a_map_with_an_empty_overlay(conn,
                                                                     tmp_path):
    # The map is intact and carries no Ubuntu overlay rows at all.
    _seed_overlay(conn, "debian_fixes", 1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="ubuntu_fixes"):
        export.verify_overlay_coverage(manifest, ["ubuntu_fixes"])
    with pytest.raises(ValueError, match="empty"):
        export.verify_overlay_coverage(manifest, ["ubuntu_fixes"])


def test_verify_overlay_coverage_rejects_an_overlay_the_map_does_not_carry(
        conn, tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="does not carry the overlay rows"):
        export.verify_overlay_coverage(manifest, ["ubuntu_fixes"])


def test_verify_overlay_coverage_rejects_a_table_the_map_cannot_carry(conn,
                                                                      tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="not an overlay table"):
        export.verify_overlay_coverage(manifest, ["defects"])


def test_verify_overlay_coverage_rejects_a_manifest_without_row_counts():
    with pytest.raises(ValueError, match="no row counts"):
        export.verify_overlay_coverage({"generated_at": "t"}, ["ubuntu_fixes"])


def test_verify_overlay_coverage_without_a_requirement_checks_nothing(conn,
                                                                      tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    assert export.verify_overlay_coverage(manifest, None) == {}
    assert export.verify_overlay_coverage(manifest, []) == {}


# ---------------------------------------------------------------------------
# CLI: the operator's verification of the served map
# ---------------------------------------------------------------------------

def test_cli_verify_accepts_a_map_that_carries_the_required_overlays(conn,
                                                                    tmp_path,
                                                                    capsys):
    _seed_overlay(conn, "ubuntu_fixes", 2)
    _seed_overlay(conn, "debian_fixes", 1)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay", "ubuntu_fixes",
                 "--require-overlay", "debian_fixes"]) == 0
    out = capsys.readouterr().out
    assert "OK" in out, out
    assert "overlay coverage OK" in out, out
    assert "ubuntu_fixes 2 row(s)" in out, out


def test_cli_verify_rejects_a_map_without_the_required_overlay_rows(conn,
                                                                    tmp_path,
                                                                    capsys):
    # The map is intact, consistent with its own manifest and fresh; the
    # Ubuntu overlay rows are simply not in it.
    _seed_overlay(conn, "debian_fixes", 1)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path)]) == 0
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay", "ubuntu_fixes"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "ubuntu_fixes" in out, out


def test_cli_verify_rejects_an_unknown_overlay_table(conn, tmp_path, capsys):
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-overlay", "defects"]) == 1
    out = capsys.readouterr().out
    assert "not an overlay table" in out, out
