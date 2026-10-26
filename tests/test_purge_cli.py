"""The `posture purge` command surface.

The bounded-growth purge is what keeps the catalog on a small host bounded, so
the command that runs it must be reachable, honest about what it would do
(dry run), and loud when it fails. These tests pin the command surface end to
end: parser routing, a real run against a real database file, and the exit
code of a failed run.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from posture import store
from posture.cli import build_parser, _cmd_purge

REPO_ROOT = Path(__file__).resolve().parents[1]


def _seed_defect(db_path: Path, defect_id: str, published: str) -> None:
    conn = store.connect(str(db_path))
    store.upsert_defect(conn, {
        "id": defect_id, "published": published, "description": "",
        "fixed_raw": {}, "refs": [], "source": "mitre",
        "fetched_at": "2026-10-25T00:00:00+00:00",
        "policy_version": "v", "complete": 1,
    })
    conn.commit()
    conn.close()


def test_purge_routes():
    args = build_parser().parse_args(
        ["purge", "--max-age-days", "365", "--keep-epss-percentile", "0.8",
         "--dry-run", "--db", "/tmp/p.db"])
    assert args.func is _cmd_purge
    assert args.max_age_days == 365
    assert args.keep_epss_percentile == 0.8
    assert args.dry_run is True
    assert args.db == "/tmp/p.db"


def test_purge_defaults_are_the_bounded_growth_defaults():
    args = build_parser().parse_args(["purge"])
    assert args.max_age_days == store.DEFAULT_PURGE_AGE_DAYS
    assert args.keep_epss_percentile == store.DEFAULT_KEEP_EPSS_PERCENTILE
    assert args.dry_run is False


def test_purge_command_runs_against_a_real_database(tmp_path, capsys):
    db_path = tmp_path / "posture.db"
    _seed_defect(db_path, "CVE-2000-1", "2000-01-01")
    _seed_defect(db_path, "CVE-2026-1", "2026-08-01")

    rc = _cmd_purge(build_parser().parse_args(
        ["purge", "--max-age-days", "3650", "--db", str(db_path)]))
    out = capsys.readouterr().out
    assert rc == 0
    assert "defects purged:       1" in out

    conn = store.connect(str(db_path))
    assert store.get_defect(conn, "CVE-2000-1") is None
    assert store.get_defect(conn, "CVE-2026-1") is not None
    conn.close()


def test_purge_command_dry_run_changes_nothing(tmp_path, capsys):
    db_path = tmp_path / "posture.db"
    _seed_defect(db_path, "CVE-2000-1", "2000-01-01")

    rc = _cmd_purge(build_parser().parse_args(
        ["purge", "--max-age-days", "3650", "--dry-run", "--db", str(db_path)]))
    out = capsys.readouterr().out
    assert rc == 0
    assert "DRY RUN" in out

    conn = store.connect(str(db_path))
    assert store.get_defect(conn, "CVE-2000-1") is not None
    conn.close()


def test_purge_command_exits_non_zero_when_the_database_is_unusable(tmp_path):
    # A growth guard that cannot run must be loud, not silent. A directory
    # where the database file should be is such a failure.
    unusable = tmp_path / "not-a-database"
    unusable.mkdir()
    result = subprocess.run(
        [sys.executable, "-m", "posture", "purge", "--db", str(unusable)],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    assert result.returncode != 0
    assert "error" in (result.stderr + result.stdout).lower()
