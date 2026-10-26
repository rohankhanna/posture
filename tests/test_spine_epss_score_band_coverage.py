"""The per-EPSS-score-band coverage of a published map.

The flat overlay coverage check (item 21) binds the EPSS overlay at the
table level only. That is a per-table question, and a per-table answer
hides a distribution failure: the EPSS ingest scores every published CVE
with a probability of exploitation and a percentile, so a map that holds
270 thousand rows passes the table-level floor while quietly losing every
CVE in the top percentile bands if the model distribution shifted or a
partial fetch narrowed the set. The map is then quietly blind in the
direction that matters most: the high-severity CVEs, the ones an operator
triages first, are gone, so the prioritization surface the EPSS overlay
exists to provide is silently narrowed.

These tests pin the per-band coverage the published manifest states and
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


def _seed_epss(conn, rows: list[dict],
               fetched_at: str = "2026-10-26T00:00:00+00:00") -> None:
    store.replace_epss(conn, rows, fetched_at=fetched_at)


def _publish(conn, tmp_path) -> None:
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")


def _band_rows(count: int, percentile: float,
               start: int = 0) -> list[dict]:
    """Build count EPSS rows whose percentile is exactly percentile."""
    return [
        {"cve_id": f"CVE-2026-{n + start:05d}",
         "epss": percentile * 0.5, "percentile": percentile}
        for n in range(count)
    ]


# ---------------------------------------------------------------------------
# What the published manifest states
# ---------------------------------------------------------------------------

def test_the_manifest_states_the_per_band_epss_coverage(conn, tmp_path):
    rows = _band_rows(5, 0.95) + _band_rows(10, 0.5, start=5)
    _seed_epss(conn, rows)
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["epss_coverage"]
    assert coverage["rows"] == 15
    bands = coverage["score_bands"]
    # 0.9 threshold: the 5 CVEs at 0.95 are >= 0.9, the 10 at 0.5 are not
    assert bands["0.9"] == 5
    # 0.95 threshold: only the 5 at 0.95
    assert bands["0.95"] == 5
    # 0.99 threshold: none
    assert bands["0.99"] == 0


def test_the_manifest_states_an_empty_epss_set_as_zero_bands(conn, tmp_path):
    _publish(conn, tmp_path)
    coverage = export.read_manifest(tmp_path)["epss_coverage"]
    assert coverage["rows"] == 0
    bands = coverage["score_bands"]
    assert bands["0.9"] == 0
    assert bands["0.95"] == 0
    assert bands["0.99"] == 0


def test_the_manifest_records_all_standard_thresholds(conn, tmp_path):
    _seed_epss(conn, _band_rows(1, 0.999))
    _publish(conn, tmp_path)
    bands = export.read_manifest(tmp_path)["epss_coverage"]["score_bands"]
    assert set(bands.keys()) == {"0.9", "0.95", "0.99"}


# ---------------------------------------------------------------------------
# The verify function
# ---------------------------------------------------------------------------

def test_the_check_passes_when_every_band_meets_its_floor(conn, tmp_path):
    _seed_epss(conn, _band_rows(5, 0.95))
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_epss_score_band_coverage(
        manifest,
        requirements=[(0.9, 1), (0.95, 1)])
    assert checked["0.9"]["rows"] == 5
    assert checked["0.95"]["rows"] == 5


def test_the_check_fails_when_a_band_is_below_its_floor(conn, tmp_path):
    _seed_epss(conn, _band_rows(3, 0.95))
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="fewer than the 10"):
        export.verify_epss_score_band_coverage(
            manifest, requirements=[(0.9, 10)])


def test_the_check_fails_when_a_band_is_absent_from_the_manifest(conn,
                                                                  tmp_path):
    _seed_epss(conn, _band_rows(1, 0.95))
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    # A threshold the manifest does not record (e.g. 0.75) is a mismatch.
    with pytest.raises(ValueError, match="records no count for that band"):
        export.verify_epss_score_band_coverage(
            manifest, requirements=[(0.75, 1)])


def test_the_check_fails_when_the_manifest_carries_no_epss_coverage(conn,
                                                                     tmp_path):
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    # Remove epss_coverage to simulate a pre-recording map.
    manifest.pop("epss_coverage")
    with pytest.raises(ValueError, match="carries no EPSS coverage"):
        export.verify_epss_score_band_coverage(
            manifest, requirements=[(0.9, 1)])


def test_the_check_fails_when_the_manifest_carries_no_score_bands(conn,
                                                                   tmp_path):
    _seed_epss(conn, _band_rows(1, 0.95))
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    manifest["epss_coverage"].pop("score_bands")
    with pytest.raises(ValueError, match="records no per-band EPSS"):
        export.verify_epss_score_band_coverage(
            manifest, requirements=[(0.9, 1)])


def test_the_check_rejects_an_out_of_range_percentile(conn, tmp_path):
    _seed_epss(conn, _band_rows(1, 0.95))
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="outside the 0..1 range"):
        export.verify_epss_score_band_coverage(
            manifest, requirements=[(1.5, 1)])


def test_the_check_rejects_a_zero_floor(conn, tmp_path):
    _seed_epss(conn, _band_rows(1, 0.95))
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="minimum is one"):
        export.verify_epss_score_band_coverage(
            manifest, requirements=[(0.9, 0)])


def test_the_check_returns_empty_when_no_requirements(conn, tmp_path):
    _seed_epss(conn, _band_rows(1, 0.95))
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    checked = export.verify_epss_score_band_coverage(manifest)
    assert checked == {}


# ---------------------------------------------------------------------------
# The CLI surface
# ---------------------------------------------------------------------------

def test_the_cli_verify_reports_per_band_coverage(conn, tmp_path, capsys):
    _seed_epss(conn, _band_rows(5, 0.95))
    _publish(conn, tmp_path)
    rc = main([
        "spine", "verify", "--from", str(tmp_path),
        "--require-epss-score-band", "0.9:1",
        "--require-epss-score-band", "0.95:1",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "per-band EPSS coverage OK" in out
    assert "p>=0.9" in out
    assert "p>=0.95" in out


def test_the_cli_verify_fails_when_a_band_is_below_its_floor(conn, tmp_path,
                                                              capsys):
    _seed_epss(conn, _band_rows(3, 0.95))
    _publish(conn, tmp_path)
    rc = main([
        "spine", "verify", "--from", str(tmp_path),
        "--require-epss-score-band", "0.9:10",
    ])
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAILED" in out
    assert "fewer than the 10" in out


def test_the_cli_verify_rejects_a_malformed_band_argument(conn, tmp_path,
                                                           capsys):
    _seed_epss(conn, _band_rows(1, 0.95))
    _publish(conn, tmp_path)
    rc = main([
        "spine", "verify", "--from", str(tmp_path),
        "--require-epss-score-band", "not-a-band",
    ])
    assert rc == 1
    out = capsys.readouterr().out
    assert "does not name a percentile and a row count" in out
