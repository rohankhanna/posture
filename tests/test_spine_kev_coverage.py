"""The known-exploited coverage of a published map.

The overlay coverage checks bind the vendor fix-status overlays: the
Ubuntu and Debian tracker rows that clear NVD's unknown-fix false
positives. None of them binds the known-exploited set, and that set is
what the map says about what is being exploited in the wild — it is what
the threat axis reads. The CISA KEV ingest is a no-wipe full refresh of a
static file, so a fetch that fails leaves the last-known-good rows in
place: the served map stays intact, consistent with its own manifest,
signed and fresh, every other check on it still passes, and the only
thing that shows the known-exploited set stopped being refreshed is the
age of its rows.

These tests pin the known-exploited coverage the published manifest
states and the check that reads it, on the operator's own verify command.

Offline and hermetic: no network, no fixtures on disk.
"""
from __future__ import annotations

import pytest

from posture import export, store
from posture.cli import main


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _seed_kev(conn, rows: int = 1,
              fetched_at: str = "2026-10-26T00:00:00+00:00",
              catalog_version: str = "2026.10.26",
              date_released: str = "2026-10-26",
              start: int = 0) -> None:
    for n in range(start, start + rows):
        store.upsert_kev(conn, {
            "cve_id": f"CVE-2026-9{n:04d}",
            "date_added": "2026-10-01",
            "vendor_project": "Example",
            "product": "Example",
            "name": f"Example defect {n}",
            "short_description": "Example",
            "required_action": "Apply updates",
            "due_date": "2026-11-01",
            "ransomware_use": "Unknown",
            "cwes": [],
            "catalog_version": catalog_version,
            "date_released": date_released,
            "fetched_at": fetched_at,
        })


def _publish(conn, tmp_path) -> None:
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")


# ---------------------------------------------------------------------------
# What the published manifest states
# ---------------------------------------------------------------------------

def test_the_manifest_states_the_known_exploited_coverage(conn, tmp_path):
    _seed_kev(conn, rows=3)
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["kev_coverage"]
    assert coverage["rows"] == 3
    assert coverage["newest_fetched_at"] == "2026-10-26T00:00:00+00:00"
    assert coverage["catalog_version"] == "2026.10.26"
    assert coverage["date_released"] == "2026-10-26"


def test_the_manifest_states_an_empty_known_exploited_set_as_empty(conn,
                                                                   tmp_path):
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["kev_coverage"]
    assert coverage["rows"] == 0
    assert coverage["newest_fetched_at"] is None


def test_the_manifest_records_the_newest_fetch_time(conn, tmp_path):
    _seed_kev(conn, rows=1, fetched_at="2026-10-20T00:00:00+00:00")
    _seed_kev(conn, rows=1, fetched_at="2026-10-26T00:00:00+00:00",
              start=1)
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["kev_coverage"]
    assert coverage["rows"] == 2
    assert coverage["newest_fetched_at"] == "2026-10-26T00:00:00+00:00"


# ---------------------------------------------------------------------------
# The known-exploited coverage check
# ---------------------------------------------------------------------------

def test_the_check_accepts_a_map_that_carries_the_required_rows(conn,
                                                                tmp_path):
    _seed_kev(conn, rows=5)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_kev_coverage(manifest, min_rows=5)
    assert checked["rows"] == 5


def test_the_check_rejects_a_map_below_the_row_floor(conn, tmp_path):
    _seed_kev(conn, rows=2)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="fewer than the 10"):
        export.verify_kev_coverage(manifest, min_rows=10)


def test_the_check_rejects_a_map_with_no_known_exploited_rows(conn, tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="fewer than the 1"):
        export.verify_kev_coverage(manifest, min_rows=1)


def test_the_check_rejects_a_set_that_stopped_being_refreshed(conn, tmp_path):
    # The rows are all there, and they are all from an older catalog: the
    # row floor passes and only the age of the rows shows the truth.
    _seed_kev(conn, rows=5, fetched_at="2026-10-01T00:00:00+00:00")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    assert export.verify_kev_coverage(manifest, min_rows=5)["rows"] == 5
    with pytest.raises(ValueError, match="stopped being refreshed"):
        export.verify_kev_coverage(manifest, min_rows=5, max_age_days=3,
                                   now="2026-10-26T00:00:00+00:00")


def test_the_check_accepts_a_fresh_set_within_the_allowance(conn, tmp_path):
    _seed_kev(conn, rows=5, fetched_at="2026-10-25T00:00:00+00:00")
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_kev_coverage(manifest, min_rows=5, max_age_days=3,
                                         now="2026-10-26T00:00:00+00:00")
    assert checked["rows"] == 5


def test_the_check_rejects_a_set_with_no_recorded_fetch_time(conn, tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    manifest["kev_coverage"] = {"rows": 5, "newest_fetched_at": None}
    with pytest.raises(ValueError, match="no fetch time"):
        export.verify_kev_coverage(manifest, min_rows=1, max_age_days=3)


def test_the_check_rejects_a_manifest_without_known_exploited_coverage():
    with pytest.raises(ValueError, match="no known-exploited coverage"):
        export.verify_kev_coverage({"counts": {}}, min_rows=1)


def test_the_check_rejects_a_floor_below_one_row():
    with pytest.raises(ValueError, match="the minimum is one"):
        export.verify_kev_coverage({"kev_coverage": {"rows": 0}}, min_rows=0)


def test_the_check_rejects_a_non_positive_freshness_allowance():
    with pytest.raises(ValueError, match="positive number of days"):
        export.verify_kev_coverage({"kev_coverage": {"rows": 5}},
                                   min_rows=1, max_age_days=0)


def test_the_check_defaults_to_at_least_one_row(conn, tmp_path):
    _seed_kev(conn, rows=1)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    assert export.verify_kev_coverage(manifest)["rows"] == 1


# ---------------------------------------------------------------------------
# CLI: the operator's verification of the served map
# ---------------------------------------------------------------------------

def test_cli_verify_accepts_a_map_that_carries_the_required_rows(conn,
                                                                 tmp_path,
                                                                 capsys):
    _seed_kev(conn, rows=5)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-kev", "5"]) == 0
    out = capsys.readouterr().out
    assert "known-exploited coverage OK" in out, out
    assert "5 row(s)" in out, out


def test_cli_verify_rejects_a_map_below_the_row_floor(conn, tmp_path,
                                                       capsys):
    _seed_kev(conn, rows=2)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-kev", "10"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "fewer than the 10" in out, out


def test_cli_verify_rejects_a_set_that_stopped_being_refreshed(conn,
                                                               tmp_path,
                                                               capsys):
    _seed_kev(conn, rows=5, fetched_at="2020-01-01T00:00:00+00:00")
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--require-kev", "5",
                 "--require-kev-max-age-days", "3"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "stopped being refreshed" in out, out


def test_cli_verify_without_the_requirement_checks_nothing(conn, tmp_path,
                                                           capsys):
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "known-exploited" not in out, out
