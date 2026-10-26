"""Spine shard size caps — no published file may cross the host's hard limit.

The repository host refuses a push that contains a file above its hard
per-file limit, so every shard the export writes is capped well below it: a
defect month that outgrows the cap becomes numbered parts, and the flat
overlay tables are capped the same way. These tests pin that behaviour and
the fail-closed guard that keeps an oversize shard from being published.
"""
from __future__ import annotations

import json

import pytest

from posture import export, store


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _seed_flat_rows(conn, count: int = 12) -> None:
    """A flat overlay table with more rows than the (patched) cap allows."""
    for i in range(count):
        store.mark_seen(conn, [f"CVE-2026-{i:04d}"])
    for i in range(count):
        store.add_crosswalk(conn, f"CVE-2026-{i:04d}", f"GHSA-{i:04d}", "ghsa")


def test_flat_table_that_outgrows_the_cap_becomes_numbered_parts(conn, tmp_path,
                                                                monkeypatch):
    monkeypatch.setattr(export, "MAX_FLAT_SHARD_BYTES", 1)
    _seed_flat_rows(conn)
    out = tmp_path / "out"
    manifest = export.export_spine(conn, out_dir=out, policy_version="v")

    root = out / "spine"
    # the unsplit shape is gone; the table is now numbered parts
    assert not (root / "seen_defects.jsonl").exists()
    assert not (root / "crosswalk.jsonl").exists()
    parts = sorted(root.glob("seen_defects-*.jsonl"))
    assert len(parts) == 12
    assert all(p.stat().st_size < 200 for p in parts)

    # the manifest pins every part, and the per-table count is the total
    listed = [e["path"] for e in manifest["files"]
              if e["path"].startswith("seen_defects")]
    assert listed == [f"seen_defects-{i:06d}.jsonl" for i in range(1, 13)]
    assert manifest["counts"]["seen_defects"] == 12
    assert manifest["counts"]["crosswalk"] == 12

    # the importer reads every part back
    other = store.connect(":memory:")
    stats = export.import_spine(other, from_dir=out)
    assert stats["seen_defects"] == 12
    assert stats["crosswalk"] == 12
    assert next(store.seen_defects_iter(other)) is not None


def test_no_written_shard_exceeds_the_cap(conn, tmp_path, monkeypatch):
    monkeypatch.setattr(export, "MAX_FLAT_SHARD_BYTES", 400)
    _seed_flat_rows(conn, count=40)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")

    for path in (out / "spine").rglob("*.jsonl"):
        assert path.stat().st_size <= 400, path


def test_export_fails_closed_when_a_shard_reaches_the_hard_limit(conn, tmp_path,
                                                                  monkeypatch):
    """An oversize shard is a map the host refuses to publish, so the export
    refuses to publish it too — and it writes no manifest claiming it."""
    _seed_flat_rows(conn, count=3)
    out = tmp_path / "out"
    monkeypatch.setattr(export, "HARD_FILE_SIZE_LIMIT_BYTES", 10)
    with pytest.raises(ValueError, match="hard file limit"):
        export.export_spine(conn, out_dir=out, policy_version="v")
    assert not (out / "spine" / "manifest.json").exists()


def test_stale_unsplit_flat_file_is_cleaned_when_a_table_splits(conn, tmp_path,
                                                                monkeypatch):
    """A table that used to fit in one file and now needs parts must not leave
    the old single file beside the new parts (the export self-cleans shards it
    did not write)."""
    _seed_flat_rows(conn, count=4)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    assert (out / "spine" / "seen_defects.jsonl").exists()

    monkeypatch.setattr(export, "MAX_FLAT_SHARD_BYTES", 1)
    manifest = export.export_spine(conn, out_dir=out, policy_version="v")
    assert not (out / "spine" / "seen_defects.jsonl").exists()
    assert manifest["counts"]["seen_defects"] == 4


def test_stale_part_files_from_a_crashed_run_are_removed(conn, tmp_path):
    """The hidden .<name>.jsonl.part-NNNNNN staging files a crashed run
    left behind are garbage: the export removes them instead of publishing
    them beside the finished shards."""
    _seed_flat_rows(conn, count=2)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    stale = out / "spine" / ".seen_defects.jsonl.part-000009"
    stale.write_text('{"defect_id":"STALE"}\n')

    export.export_spine(conn, out_dir=out, policy_version="v")
    assert not stale.exists()
    assert not list((out / "spine").glob(".*.part-*"))


def test_a_single_row_is_never_split_across_parts(conn, tmp_path, monkeypatch):
    """A row larger than the cap stays intact in its own part — the cap splits
    between rows, never inside one."""
    monkeypatch.setattr(export, "MAX_FLAT_SHARD_BYTES", 1)
    store.mark_seen(conn, ["CVE-2026-0001"])
    store.mark_seen(conn, ["CVE-2026-0002"])
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    parts = sorted((out / "spine").glob("seen_defects-*.jsonl"))
    assert len(parts) == 2
    for part in parts:
        lines = [l for l in part.read_text().splitlines() if l.strip()]
        assert len(lines) == 1          # one whole row per part
        row = json.loads(lines[0])      # and the row is intact JSON
        assert row["defect_id"].startswith("CVE-2026-")
