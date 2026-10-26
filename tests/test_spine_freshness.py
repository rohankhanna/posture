"""The freshness of a published map.

The publish path is atomic: a daily build that fails leaves the previously
published map serving, intact and internally consistent. Every digest check
on that map still passes, so the only thing that shows the build has stopped
is the map's own build timestamp (generated_at). These tests pin the
check that reads that timestamp, on the operator's verify command and on the
client's import path.

Offline and hermetic: no network, no fixtures on disk.
"""
from __future__ import annotations

import datetime as dt
import json

import pytest

from posture import export, store
from posture.cli import main


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _seed(conn) -> None:
    store.upsert_defect(conn, {
        "id": "CVE-2026-7001", "published": "2026-07-04", "cvss": 9.9,
        "severity": "CRITICAL", "description": "published defect",
        "fixed_raw": {"source": "nvd", "ranges": []}, "refs": [],
        "source": "nvd", "fetched_at": "t1", "policy_version": "v",
        "complete": 1,
    })
    store.set_enrich_state(conn, "CVE-2026-7001", "nvd")


def _publish(conn, tmp_path) -> None:
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")


def _restamp(tmp_path, generated_at: str | None) -> None:
    """Rewrite the served map's build timestamp (or drop it entirely)."""
    manifest_path = tmp_path / export.SPINE_DIR / export.MANIFEST_NAME
    data = json.loads(manifest_path.read_text())
    if generated_at is None:
        data.pop("generated_at", None)
    else:
        data["generated_at"] = generated_at
    manifest_path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")


def _days_ago(days: float) -> str:
    moment = dt.datetime.now(dt.UTC) - dt.timedelta(days=days)
    return moment.replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# The age of a manifest
# ---------------------------------------------------------------------------

def test_read_manifest_returns_the_served_manifest(conn, tmp_path):
    _seed(conn)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    assert manifest["manifest_version"] == export.MANIFEST_VERSION
    assert "generated_at" in manifest


def test_manifest_age_days_measures_the_age_from_generated_at(conn, tmp_path):
    _seed(conn)
    _publish(conn, tmp_path)
    _restamp(tmp_path, "2026-10-20T03:07:00+00:00")
    manifest = export.read_manifest(tmp_path)
    reference = dt.datetime(2026, 10, 26, 3, 7, tzinfo=dt.UTC)
    assert export.manifest_age_days(manifest, now=reference) == pytest.approx(
        6.0, abs=0.01)


def test_manifest_age_days_reads_a_utc_suffix_timestamp(conn, tmp_path):
    _seed(conn)
    _publish(conn, tmp_path)
    _restamp(tmp_path, "2026-10-26T03:07:00Z")
    manifest = export.read_manifest(tmp_path)
    reference = dt.datetime(2026, 10, 26, 3, 7, tzinfo=dt.UTC)
    assert export.manifest_age_days(manifest, now=reference) == pytest.approx(
        0.0, abs=0.01)


def test_manifest_age_days_refuses_a_manifest_without_a_timestamp(conn,
                                                                   tmp_path):
    _seed(conn)
    _publish(conn, tmp_path)
    _restamp(tmp_path, None)
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="generated_at"):
        export.manifest_age_days(manifest)


def test_manifest_age_days_refuses_an_unreadable_timestamp(conn, tmp_path):
    _seed(conn)
    _publish(conn, tmp_path)
    _restamp(tmp_path, "not a timestamp")
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="not a readable"):
        export.manifest_age_days(manifest)


# ---------------------------------------------------------------------------
# The freshness check
# ---------------------------------------------------------------------------

def test_verify_manifest_freshness_accepts_a_fresh_map(conn, tmp_path):
    _seed(conn)
    _publish(conn, tmp_path)
    manifest = export.read_manifest(tmp_path)
    age = export.verify_manifest_freshness(manifest, 2)
    assert age < 1.0


def test_verify_manifest_freshness_rejects_a_stale_map(conn, tmp_path):
    _seed(conn)
    _publish(conn, tmp_path)
    _restamp(tmp_path, _days_ago(6))
    manifest = export.read_manifest(tmp_path)
    with pytest.raises(ValueError, match="older than the 2 day"):
        export.verify_manifest_freshness(manifest, 2)


def test_verify_manifest_freshness_rejects_a_non_positive_age():
    with pytest.raises(ValueError, match="positive number of days"):
        export.verify_manifest_freshness({"generated_at": _days_ago(0)}, 0)


# ---------------------------------------------------------------------------
# CLI: the operator's verification of the served map
# ---------------------------------------------------------------------------

def test_cli_verify_accepts_a_fresh_map_with_a_max_age(conn, tmp_path, capsys):
    _seed(conn)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--max-age-days", "2"]) == 0
    out = capsys.readouterr().out
    assert "OK" in out, out
    assert "day(s) old" in out, out


def test_cli_verify_rejects_a_stale_map_with_a_max_age(conn, tmp_path, capsys):
    # The map is intact and internally consistent; only its build timestamp
    # shows that the daily build has stopped.
    _seed(conn)
    _publish(conn, tmp_path)
    assert main(["spine", "verify", "--from", str(tmp_path)]) == 0
    _restamp(tmp_path, _days_ago(6))
    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--max-age-days", "2"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out
    assert "older than the 2 day" in out, out


def test_cli_verify_without_a_max_age_does_not_check_freshness(conn, tmp_path):
    _seed(conn)
    _publish(conn, tmp_path)
    _restamp(tmp_path, _days_ago(400))
    assert main(["spine", "verify", "--from", str(tmp_path)]) == 0


def test_cli_verify_rejects_a_non_positive_max_age(conn, tmp_path):
    _seed(conn)
    _publish(conn, tmp_path)
    with pytest.raises(SystemExit):
        main(["spine", "verify", "--from", str(tmp_path),
              "--max-age-days", "0"])


# ---------------------------------------------------------------------------
# CLI: the client's import path
# ---------------------------------------------------------------------------

def test_cli_import_rejects_a_stale_map_with_a_max_age(conn, tmp_path, capsys):
    _seed(conn)
    _publish(conn, tmp_path)
    _restamp(tmp_path, _days_ago(6))
    db = tmp_path / "client.db"
    assert main(["spine", "import", "--db", str(db), "--from", str(tmp_path),
                 "--max-age-days", "2"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out, out


def test_cli_import_accepts_a_fresh_map_with_a_max_age(conn, tmp_path, capsys):
    _seed(conn)
    _publish(conn, tmp_path)
    db = tmp_path / "client.db"
    assert main(["spine", "import", "--db", str(db), "--from", str(tmp_path),
                 "--max-age-days", "2"]) == 0
    out = capsys.readouterr().out
    assert "day(s) old" in out, out
