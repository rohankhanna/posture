"""Back-fill tests — the one-shot cvelistV5 back-catalog enumeration.

Reuses the test_stream git fixture (bare upstream + blobless work clone). The
back-fill is the SEPARATE history path the forward-only stream can't take: it
enumerates ``cves/`` past a path cursor, cap-resumed across ticks, only-adds
skeletons, and self-disables when exhausted. All local fixtures — no network.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from posture import store, stream

# reuse the git fixture helpers from the stream tests (same shape, no network)
from tests.test_stream import _make_repos, _commit, _mitre_json


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _backfill(conn, work, cap=1000, policy_version="v"):
    return stream.backfill_tick(conn, repo_path=work, cap=cap,
                                 policy_version=policy_version)


def _seed_catalog(tmp_path: Path, n: int) -> Path:
    """One upstream commit with n CVE files under cves/ (the back-catalog)."""
    _, seed, work = _make_repos(tmp_path)
    files = {f"cves/2026/{10 + i:05d}xxx/CVE-2026-{10000 + i}.json":
             _mitre_json(f"CVE-2026-{10000 + i}", f"desc {i}") for i in range(n)}
    _commit(seed, files, "catalog")
    return work


# --- populates skeletons from the back-catalog ------------------------------

def test_backfill_populates_skeletons(conn, tmp_path):
    work = _seed_catalog(tmp_path, 3)
    stats = _backfill(conn, work, cap=1000)
    assert stats["upserted"] == 3
    assert stats["done"] is True
    ids = {r[0] for r in conn.execute("SELECT id FROM cves")}
    assert ids == {f"CVE-2026-{10000 + i}" for i in range(3)}
    row = store.get_cve(conn, "CVE-2026-10000")
    assert row["enrich_state"] == "mitre"
    assert row["flaw_type"] == "cve"          # backfill skeletons are cve peers
    assert row["fixed_raw"]["source"] == "mitre"
    assert row["fixed_raw"]["pending_nvd"] is True
    for i in range(3):
        assert store.seen_first_seen(conn, f"CVE-2026-{10000 + i}") is not None


# --- cap-resumed across ticks ------------------------------------------------

def test_backfill_resumes_across_ticks_via_cursor(conn, tmp_path):
    work = _seed_catalog(tmp_path, 5)
    s1 = _backfill(conn, work, cap=2)
    assert s1["upserted"] == 2 and s1["done"] is False
    assert store.get_state(conn, stream.BACKFILL_CURSOR_KEY) is not None
    s2 = _backfill(conn, work, cap=2)
    assert s2["upserted"] == 2 and s2["done"] is False
    s3 = _backfill(conn, work, cap=2)
    assert s3["upserted"] == 1 and s3["done"] is True  # only 1 left
    assert conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 5


# --- self-disables once exhausted --------------------------------------------

def test_backfill_self_disables_when_done(conn, tmp_path):
    work = _seed_catalog(tmp_path, 2)
    assert _backfill(conn, work, cap=1000)["done"] is True
    assert store.get_state(conn, stream.BACKFILL_DONE_KEY) == "1"
    # a second call short-circuits without touching git (no fetched_tip)
    stats = _backfill(conn, work, cap=1000)
    assert stats["done"] is True
    assert stats["upserted"] == 0
    assert stats["fetched_tip"] is None  # never fetched


# --- idempotent on re-run of the same slice ----------------------------------

def test_backfill_idempotent_on_re_diff(conn, tmp_path):
    work = _seed_catalog(tmp_path, 3)
    _backfill(conn, work, cap=1000)
    # rewind the cursor (simulate a tick killed mid-sweep retrying the range)
    store.set_state(conn, stream.BACKFILL_DONE_KEY, None)
    store.set_state(conn, stream.BACKFILL_CURSOR_KEY, None)
    _backfill(conn, work, cap=1000)
    # no double-count: upsert is keyed on id; mark_seen is idempotent
    assert conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 3
    assert _backfill(conn, work, cap=1000)["upserted"] == 0  # now done again


# --- no-wipe: the back-fill never touches verdicts ----------------------------

def test_backfill_does_not_touch_verdicts(conn, tmp_path):
    store.upsert_verdict(conn, {
        "device_id": "host", "axis": "vulnerability", "key": "CVE-OLD",
        "status": "unpatched", "severity": "HIGH", "fixed_in": None, "detail": "prior",
        "provenance": {"witness": "nvd", "policy_version": "v",
                       "fetched_at": "t", "complete": 1},
    }, "t")
    conn.commit()
    work = _seed_catalog(tmp_path, 2)
    _backfill(conn, work, cap=1000)
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1 and rows[0]["key"] == "CVE-OLD" and rows[0]["status"] == "unpatched"


# --- empty back-catalog ------------------------------------------------------

def test_backfill_empty_catalog_is_done(conn, tmp_path):
    _, seed, work = _make_repos(tmp_path)
    _commit(seed, {"README.md": "no cves here"}, "empty")  # nothing under cves/
    stats = _backfill(conn, work, cap=1000)
    assert stats["upserted"] == 0 and stats["done"] is True