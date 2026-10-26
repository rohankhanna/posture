"""The per-product Apple fix coverage of a published map.

The flat overlay coverage check (item 21) binds the Apple fix overlay at
the table level only. That is a per-table question, and a per-table answer
hides a per-product failure: the apple_fixes ingest is a per-product full
refresh (DELETE WHERE product + INSERT), so a product whose Apple advisory
feed returned nothing loses its rows entirely while the other products keep
theirs, the table still holds rows, and the table-level row floor and
freshness allowance both still pass. The map is then quietly narrow in a
direction that matters: the missing product's fix versions are gone, so a
patched device of that product is reported as unpatched.

These tests pin the per-product coverage the published manifest states and
the check that reads it, on the operator's own verify command.

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


def _publish(conn, tmp_path) -> None:
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")


# ---------------------------------------------------------------------------
# What the published manifest states
# ---------------------------------------------------------------------------

def test_the_manifest_states_the_per_product_apple_fix_coverage(conn,
                                                                 tmp_path):
    _seed_apple(conn, rows=3, product="iphone_os")
    _seed_apple(conn, rows=2, product="macos", start=3)
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["apple_fixes_coverage"]
    assert coverage["rows"] == 5
    assert coverage["products"]["iphone_os"]["rows"] == 3
    assert coverage["products"]["macos"]["rows"] == 2
    assert (coverage["products"]["iphone_os"]["newest_fetched_at"]
            == "2026-10-26T00:00:00+00:00")


def test_the_manifest_records_each_products_own_fetch_time(conn, tmp_path):
    # Each product is refreshed on its own, so the per-product fetch time
    # is that product's own fetch and not a sibling's timestamp.
    _seed_apple(conn, rows=1, fetched_at="2026-10-20T00:00:00+00:00",
                product="iphone_os")
    _seed_apple(conn, rows=1, fetched_at="2026-10-26T00:00:00+00:00",
                product="macos", start=1)
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["apple_fixes_coverage"]
    assert (coverage["products"]["iphone_os"]["newest_fetched_at"]
            == "2026-10-20T00:00:00+00:00")
    assert (coverage["products"]["macos"]["newest_fetched_at"]
            == "2026-10-26T00:00:00+00:00")


def test_the_manifest_states_an_empty_product_set_as_absent(conn, tmp_path):
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["apple_fixes_coverage"]
    assert coverage["rows"] == 0
    assert coverage["products"] == {}


# ---------------------------------------------------------------------------
# The per-product coverage check
# ---------------------------------------------------------------------------

def test_check_accepts_a_map_that_carries_every_required_product(conn,
                                                                 tmp_path):
    _seed_apple(conn, rows=2, product="iphone_os")
    _seed_apple(conn, rows=2, product="macos", start=2)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_apple_fixes_product_coverage(
        manifest, [("iphone_os", 1), ("macos", 2)])
    assert checked["iphone_os"]["rows"] == 2
    assert checked["macos"]["rows"] == 2


def test_check_rejects_a_product_the_map_carries_no_rows_for(conn, tmp_path):
    # The table-level floor still passes here: the map holds the other
    # product's rows, so only a per-product requirement can see the loss.
    _seed_apple(conn, rows=5, product="iphone_os")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    export.verify_apple_fixes_coverage(manifest, min_rows=1)
    with pytest.raises(ValueError, match="no Apple fix rows for that "
                                         "product"):
        export.verify_apple_fixes_product_coverage(
            manifest, [("iphone_os", 1), ("macos", 1)])


def test_check_rejects_a_product_below_its_floor(conn, tmp_path):
    _seed_apple(conn, rows=2, product="iphone_os")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="fewer than the 10"):
        export.verify_apple_fixes_product_coverage(
            manifest, [("iphone_os", 10)])


def test_check_rejects_a_product_that_stopped_being_refreshed(conn,
                                                                tmp_path):
    _seed_apple(conn, rows=5, product="iphone_os",
                fetched_at="2020-01-01T00:00:00+00:00")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="stopped being refreshed"):
        export.verify_apple_fixes_product_coverage(
            manifest, [("iphone_os", 5)], max_age_days=3,
            now="2026-10-26T00:00:00+00:00")


def test_check_accepts_a_fresh_product_within_the_allowance(conn, tmp_path):
    _seed_apple(conn, rows=5, product="iphone_os",
                fetched_at="2026-10-25T00:00:00+00:00")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_apple_fixes_product_coverage(
        manifest, [("iphone_os", 5)], max_age_days=3,
        now="2026-10-26T00:00:00+00:00")
    assert checked["iphone_os"]["rows"] == 5


def test_check_rejects_a_product_with_no_recorded_fetch_time(conn, tmp_path):
    _seed_apple(conn, rows=5, product="iphone_os")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    manifest["apple_fixes_coverage"]["products"]["iphone_os"][
        "newest_fetched_at"] = None
    with pytest.raises(ValueError, match="no fetch time"):
        export.verify_apple_fixes_product_coverage(
            manifest, [("iphone_os", 5)], max_age_days=3)


def test_check_rejects_a_manifest_without_apple_fix_coverage():
    manifest = {"counts": {}, "files": [], "release_coverage": {},
                "kev_coverage": {"rows": 0, "newest_fetched_at": None,
                                 "catalog_version": None,
                                 "date_released": None}}
    with pytest.raises(ValueError, match="no Apple fix coverage"):
        export.verify_apple_fixes_product_coverage(
            manifest, [("iphone_os", 1)])


def test_check_rejects_a_manifest_without_per_product_coverage(conn,
                                                               tmp_path):
    _seed_apple(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    del manifest["apple_fixes_coverage"]["products"]
    with pytest.raises(ValueError, match="no per-product Apple fix coverage"):
        export.verify_apple_fixes_product_coverage(
            manifest, [("iphone_os", 1)])


def test_check_rejects_a_requirement_that_names_no_product(conn, tmp_path):
    _seed_apple(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="names no product"):
        export.verify_apple_fixes_product_coverage(manifest, [(" ", 1)])


def test_check_rejects_a_floor_below_one_row(conn, tmp_path):
    _seed_apple(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="minimum is one"):
        export.verify_apple_fixes_product_coverage(
            manifest, [("iphone_os", 0)])


def test_check_rejects_a_non_positive_freshness_allowance(conn, tmp_path):
    _seed_apple(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="positive"):
        export.verify_apple_fixes_product_coverage(
            manifest, [("iphone_os", 1)], max_age_days=0)


def test_check_without_requirements_checks_nothing(conn, tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    assert export.verify_apple_fixes_product_coverage(manifest) == {}


# ---------------------------------------------------------------------------
# CLI: the operator's verification of the served map
# ---------------------------------------------------------------------------

def test_cli_verify_accepts_a_map_that_carries_every_required_product(conn,
                                                                      tmp_path,
                                                                      capsys):
    _seed_apple(conn, rows=2, product="iphone_os")
    _seed_apple(conn, rows=2, product="macos", start=2)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-apple-fixes-product", "iphone_os:1",
                 "--require-apple-fixes-product", "macos:2"]) == 0
    out = capsys.readouterr().out
    assert "per-product Apple fix coverage OK" in out, out
    assert "macos 2 row(s)" in out, out


def test_cli_verify_rejects_a_map_missing_a_required_product(conn, tmp_path,
                                                             capsys):
    _seed_apple(conn, rows=5, product="iphone_os")
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-apple-fixes-product", "iphone_os:1",
                 "--require-apple-fixes-product", "macos:1"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "macos" in out, out


def test_cli_verify_rejects_a_stale_product(conn, tmp_path, capsys):
    _seed_apple(conn, rows=5, product="iphone_os",
                fetched_at="2020-01-01T00:00:00+00:00")
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-apple-fixes-product", "iphone_os:5",
                 "--require-apple-fixes-product-max-age-days", "3"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "stopped being refreshed" in out, out


def test_cli_verify_rejects_a_malformed_product_requirement(conn, tmp_path,
                                                            capsys):
    _seed_apple(conn, rows=1)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-apple-fixes-product", "iphone_os"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "PRODUCT:MIN_ROWS" in out, out


def test_cli_verify_without_the_product_requirements_checks_nothing(conn,
                                                                     tmp_path,
                                                                     capsys):
    _seed_apple(conn, rows=1)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "per-product" not in out, out
