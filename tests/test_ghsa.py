"""GHSA ingestion tests — the GitHub Advisory Database git-clone tick (Phase 4).

Reuses the test_stream git fixture (bare upstream + blobless work clone). The
GHSA peer is a self-enriched OSV peer (``flaw_type='ghsa'``,
``enrich_state='ghsa'``): it only-adds catalog rows + symmetric alias edges,
never touches verdicts. The backfill is cap-resumed across ticks and self-
disables once exhausted; subsequent ticks take the incremental diff path. All
local fixtures — no network.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from posture import store
from posture.sources import ghsa

# reuse the git fixture helpers from the stream tests (same shape, no network)
from tests.test_stream import _make_repos, _commit


@pytest.fixture
def conn():
    return store.connect(":memory:")


# --- fixture helpers --------------------------------------------------------

def _ghsa_json(ghsa_id: str, cve_alias: str | None = None,
               summary: str = "x", score: str = "CVSS:3.1/AV:N/AC:L",
               pkg: str = "foo", ecosystem: str = "npm") -> dict:
    """Build one OSV-schema advisory dict with id/aliases/published/summary/
    severity/affected/references/cwes — the shape found at
    ``advisories/github-reviewed/<YYYY>/<MM>/<id>/<id>.json``."""
    rec: dict = {
        "id": ghsa_id,
        "published": "2026-07-31T10:00:00.000Z",
        "modified": "2026-08-01T10:00:00.000Z",
        "summary": summary,
        "details": f"advisory body for {ghsa_id}",
        "severity": [{"type": "CVSS_V3", "score": score}],
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": pkg},
            "ranges": [{"type": "GIT", "repo": "https://github.com/x/foo",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
            "versions": ["1.0.0"],
        }],
        "references": [{"type": "WEB", "url": f"https://example/{ghsa_id}"},
                       {"type": "PACKAGE", "url": f"https://npmjs.com/pkg/{pkg}"}],
        "cwes": [{"cweId": "CWE-787", "name": "Out-of-bounds Write"}],
    }
    aliases = []
    if cve_alias:
        aliases.append(cve_alias)
    rec["aliases"] = aliases
    return rec


def _ghsa_path(ghsa_id: str) -> str:
    """The repo-relative path of one advisory JSON in the github-reviewed tree."""
    return f"advisories/github-reviewed/2026/07/{ghsa_id}/{ghsa_id}.json"


def _seed_advisories(tmp_path: Path, n: int,
                     cve_aliases: list[str | None] | None = None) -> tuple:
    """One upstream commit with n GHSA advisory files under
    ``advisories/github-reviewed/``. Returns (seed, work)."""
    _, seed, work = _make_repos(tmp_path)
    if cve_aliases is None:
        cve_aliases = [f"CVE-2026-{10000 + i}" for i in range(n)]
    files = {}
    for i in range(n):
        gid = f"GHSA-{i:04d}-{i:04d}-{i:04d}"
        files[_ghsa_path(gid)] = _ghsa_json(gid, cve_aliases[i])
    _commit(seed, files, "catalog")
    return seed, work


def _tick(conn, work, cap=1000, policy_version="v"):
    return ghsa.ghsa_ingest_tick(conn, repo_path=work, cap=cap,
                                 policy_version=policy_version)


# --- backfill populates ghsa rows + crosswalk -------------------------------

def test_ghsa_backfill_populates_rows_and_crosswalk(conn, tmp_path):
    _, work = _seed_advisories(tmp_path, 3)
    stats = _tick(conn, work, cap=1000)
    assert stats["upserted"] == 3
    assert stats["done"] is True
    assert stats["incremental"] is False

    ids = {r[0] for r in conn.execute("SELECT id FROM cves")}
    ghsa_ids = {f"GHSA-{i:04d}-{i:04d}-{i:04d}" for i in range(3)}
    assert ids == ghsa_ids

    gid = "GHSA-0000-0000-0000"
    row = store.get_cve(conn, gid)
    assert row["flaw_type"] == "ghsa"
    assert row["enrich_state"] == "ghsa"          # self-enriched, NOT pending mitre
    assert row["source"] == "ghsa"
    assert row["cvss_vector"].startswith("CVSS:3.1")
    # score was a vector STRING (no numeric embedded), so cvss/severity stay
    # None — the vector is kept so a viewer can still show the class.
    assert row["cvss"] is None
    assert row["severity"] is None
    assert row["fixed_raw"]["source"] == "ghsa"
    assert "ranges" in row["fixed_raw"]
    assert row["cwe"] == ["CWE-787"]
    assert store.seen_first_seen(conn, gid) is not None

    # crosswalk symmetric: resolve(ghsa) -> cve, reverse(cve) -> ghsa
    assert store.resolve_crosswalk(conn, gid) == [
        {"alias": "CVE-2026-10000", "kind": "cve"}]
    assert store.reverse_crosswalk(conn, "CVE-2026-10000") == [
        {"flaw_id": gid, "kind": "cve"}]


# --- cap-resumed across ticks ------------------------------------------------

def test_ghsa_backfill_cap_resumed_across_ticks(conn, tmp_path):
    _, work = _seed_advisories(tmp_path, 5)
    s1 = _tick(conn, work, cap=2)
    assert s1["upserted"] == 2 and s1["done"] is False
    assert store.get_state(conn, ghsa.GHSA_CURSOR_KEY) is not None
    s2 = _tick(conn, work, cap=2)
    assert s2["upserted"] == 2 and s2["done"] is False
    s3 = _tick(conn, work, cap=2)
    assert s3["upserted"] == 1 and s3["done"] is True  # only 1 left
    assert conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 5
    assert store.get_state(conn, ghsa.GHSA_DONE_KEY) == "1"
    assert store.get_state(conn, ghsa.GHSA_TIP_KEY) is not None


# --- self-disables / switches to incremental ----------------------------------

def test_ghsa_incremental_after_backfill(conn, tmp_path):
    seed, work = _seed_advisories(tmp_path, 2)
    s1 = _tick(conn, work, cap=1000)
    assert s1["upserted"] == 2 and s1["done"] is True and s1["incremental"] is False
    tip_after_backfill = store.get_state(conn, ghsa.GHSA_TIP_KEY)

    # commit a NEW advisory + modify an existing one
    new_id = "GHSA-9999-9999-9999"
    first_id = "GHSA-0000-0000-0000"
    _commit(seed, {
        _ghsa_path(new_id): _ghsa_json(new_id, "CVE-2026-99999", "new vuln"),
        _ghsa_path(first_id): _ghsa_json(first_id, "CVE-2026-10000", "updated body"),
    }, "c2")

    s2 = _tick(conn, work, cap=1000)
    # incremental path taken, no re-backfill
    assert s2["incremental"] is True
    assert s2["done"] is True
    assert s2["upserted"] == 2  # one new + one modified
    # the tip advanced past the backfill tip
    assert store.get_state(conn, ghsa.GHSA_TIP_KEY) != tip_after_backfill

    # both advisories present, the new one too
    row = store.get_cve(conn, new_id)
    assert row is not None and row["flaw_type"] == "ghsa"
    assert store.resolve_crosswalk(conn, new_id) == [
        {"alias": "CVE-2026-99999", "kind": "cve"}]
    # 3 total catalog rows (2 backfill + 1 new)
    assert conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 3


# --- idempotent on re-diff ---------------------------------------------------

def test_ghsa_incremental_idempotent_on_re_diff(conn, tmp_path):
    seed, work = _seed_advisories(tmp_path, 2)
    _tick(conn, work, cap=1000)  # backfill done

    new_id = "GHSA-9999-9999-9999"
    _commit(seed, {
        _ghsa_path(new_id): _ghsa_json(new_id, "CVE-2026-99999", "new"),
    }, "c2")
    s1 = _tick(conn, work, cap=1000)  # incremental: 1 change
    assert s1["upserted"] == 1
    count_after = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]

    # rewind the tip cursor (simulate a tick killed mid-sweep retrying the range)
    old_tip = subprocess.run(["git", "-C", str(seed), "rev-parse", "HEAD~1"],
                             capture_output=True, text=True).stdout.strip()
    store.set_state(conn, ghsa.GHSA_TIP_KEY, old_tip)
    s2 = _tick(conn, work, cap=1000)
    # re-diffed the same range — upsert is keyed on id, mark_seen idempotent
    assert s2["incremental"] is True
    assert count_after == conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    assert store.seen_first_seen(conn, new_id) is not None  # still seen, not re-counted


# --- no-wipe: the tick never touches verdicts --------------------------------

def test_ghsa_does_not_touch_verdicts(conn, tmp_path):
    store.upsert_verdict(conn, {
        "device_id": "host", "axis": "vulnerability", "key": "CVE-OLD",
        "status": "unpatched", "severity": "HIGH", "fixed_in": None, "detail": "prior",
        "provenance": {"witness": "nvd", "policy_version": "v",
                       "fetched_at": "t", "complete": 1},
    }, "t")
    conn.commit()
    _, work = _seed_advisories(tmp_path, 2)
    _tick(conn, work, cap=1000)
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1
    assert rows[0]["key"] == "CVE-OLD"
    assert rows[0]["status"] == "unpatched"


# --- cve-less GHSA advisory still anchors as a first-class peer --------------

def test_ghsa_cve_less_advisory_anchors(conn, tmp_path):
    # an advisory with NO cve alias — aliases=[]
    _, work = _seed_advisories(tmp_path, 1, cve_aliases=[None])
    stats = _tick(conn, work, cap=1000)
    assert stats["upserted"] == 1

    gid = "GHSA-0000-0000-0000"
    row = store.get_cve(conn, gid)
    assert row is not None
    assert row["flaw_type"] == "ghsa"
    assert row["enrich_state"] == "ghsa"
    # no crosswalk edge for a cve-less advisory
    assert store.resolve_crosswalk(conn, gid) == []
    # but it still counts as a ghsa peer in the catalog
    counts = {c["flaw_type"]: c["n"] for c in store.flaw_type_counts(conn)}
    assert counts.get("ghsa") == 1