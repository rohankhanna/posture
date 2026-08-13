"""CVE stream tests — the MITRE cvelistV5 git-diff tick (Phase 1, detection
only). In-memory sqlite via store.connect; network is a temp git repo (a bare
'upstream' + a blobless no-checkout 'work' clone), mirroring Forebode's
test_stream.py fixture.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from posture import store, stream


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _mitre_json(cve_id: str, desc: str = "x") -> dict:
    return {
        "cveMetadata": {"cveId": cve_id,
                        "datePublished": "2026-07-31T10:00:00.000Z"},
        "containers": {"cna": {
            "descriptions": [{"lang": "en", "value": desc}],
            "references": [{"url": f"https://support.example/{cve_id}", "tags": []}],
            "metrics": [{"cvssV3_1": {"vectorString": "CVSS:3.1/AV:N/AC:L"}}],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-787"}]}],
        }},
    }


def _make_repos(tmp_path: Path):
    """A bare 'upstream' repo + a blobless no-checkout 'work' clone of it.
    Commits are made in a seed dir pushed to upstream; the work clone fetches
    them — mirroring the real cvelistV5 setup without touching the network."""
    upstream = tmp_path / "upstream"
    subprocess.run(["git", "init", "--bare", str(upstream)], check=True, capture_output=True)
    seed = tmp_path / "seed"
    subprocess.run(["git", "init", str(seed)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.email", "t@t"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.name", "t"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "remote", "add", "origin", str(upstream)],
                   check=True, capture_output=True)
    work = tmp_path / "work"
    subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout",
                    str(upstream), str(work)], check=True, capture_output=True)
    return upstream, seed, work


def _commit(seed: Path, files: dict[str, dict], msg: str) -> str:
    for rel, obj in files.items():
        p = seed / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj))
    subprocess.run(["git", "-C", str(seed), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "commit", "-m", msg], check=True, capture_output=True)
    sha = subprocess.run(["git", "-C", str(seed), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    subprocess.run(["git", "-C", str(seed), "push", "origin", "HEAD:main"],
                   check=True, capture_output=True)
    return sha


def _tick(conn, work, policy_version="v"):
    return stream.stream_tick(conn, repo_path=work, policy_version=policy_version)


# --- bootstrap --------------------------------------------------------------

def test_stream_first_run_bootstraps_cursor(conn, tmp_path):
    _, seed, work = _make_repos(tmp_path)
    _commit(seed, {"cves/2026/11xxx/CVE-2026-11111.json": _mitre_json("CVE-2026-11111")}, "c1")
    stats = _tick(conn, work)
    assert stats["bootstrapped"] is True
    assert stats["new"] == 0
    assert store.get_state(conn, stream.CURSOR_KEY) is not None  # cursor set
    # No CVE rows inserted on the bootstrap tick (O(1), no back-fill).
    assert conn.execute("SELECT COUNT(*) FROM flaws").fetchone()[0] == 0


# --- diff + skeleton upsert -------------------------------------------------

def test_stream_diff_upserts_skeletons(conn, tmp_path):
    _, seed, work = _make_repos(tmp_path)
    _commit(seed, {"cves/2026/11xxx/CVE-2026-11111.json":
                   _mitre_json("CVE-2026-11111", "first")}, "c1")
    _tick(conn, work)  # bootstrap

    _commit(seed, {
        "cves/2026/22xxx/CVE-2026-22222.json": _mitre_json("CVE-2026-22222", "new vuln"),
        "cves/2026/11xxx/CVE-2026-11111.json": _mitre_json("CVE-2026-11111", "updated"),
    }, "c2")
    stats = _tick(conn, work)

    assert stats["changed_files"] == 2
    # Bootstrap inserted nothing, so both changed files are newly seen now.
    assert stats["new"] == 2
    ids = {r[0] for r in conn.execute("SELECT id FROM flaws")}
    assert ids == {"CVE-2026-11111", "CVE-2026-22222"}
    # Skeleton provenance + shape (the map, not the territory).
    row = store.get_flaw(conn, "CVE-2026-22222")
    assert row["enrich_state"] == "mitre"
    assert row["cvss"] is None and row["severity"] is None  # skeleton, NVD not yet
    assert row["cvss_vector"].startswith("CVSS:3.1")
    assert row["fixed_raw"]["source"] == "mitre"
    assert row["fixed_raw"]["pending_nvd"] is True
    # the honest stratum reason — NEVER "you are vulnerable"
    assert row["fixed_raw"]["reason"] == stream.SKELETON_REASON
    assert "CVE-2026-22222" in row["refs"][0]
    assert row["source"] == "mitre" and row["policy_version"] == "v"
    # Both marked seen (drive "new since last tick").
    for cid in ("CVE-2026-11111", "CVE-2026-22222"):
        assert store.seen_first_seen(conn, cid) is not None


def test_stream_skeleton_idempotent_on_re_diff(conn, tmp_path):
    # A tick killed mid-sweep retries the same range next time; re-upserting
    # skeletons is harmless (no double-count: mark_seen is idempotent).
    _, seed, work = _make_repos(tmp_path)
    _commit(seed, {"cves/2026/11xxx/CVE-2026-11111.json":
                   _mitre_json("CVE-2026-11111")}, "c1")
    _tick(conn, work)  # bootstrap
    _commit(seed, {"cves/2026/22xxx/CVE-2026-22222.json":
                   _mitre_json("CVE-2026-22222")}, "c2")
    _tick(conn, work)
    # Manually rewind the cursor so the next tick re-diffs the same range.
    c1 = subprocess.run(["git", "-C", str(seed), "rev-parse", "HEAD~1"],
                        capture_output=True, text=True).stdout.strip()
    store.set_state(conn, stream.CURSOR_KEY, c1)
    stats = _tick(conn, work)
    assert stats["changed_files"] == 1  # CVE-2026-22222 again
    assert stats["new"] == 0  # already seen -> not newly counted
    assert conn.execute("SELECT COUNT(*) FROM flaws WHERE id='CVE-2026-22222'").fetchone()[0] == 1


# --- no-wipe: the stream never touches verdicts -----------------------------

def test_stream_does_not_touch_verdicts(conn, tmp_path):
    # Pre-seed a device verdict; stream ticks must leave it byte-identical.
    store.upsert_verdict(conn, {
        "device_id": "host", "axis": "vulnerability", "key": "CVE-OLD",
        "status": "unpatched", "severity": "HIGH", "fixed_in": None, "detail": "prior",
        "provenance": {"observer": "nvd", "policy_version": "v",
                       "fetched_at": "t", "complete": 1},
    }, "t")
    conn.commit()
    _, seed, work = _make_repos(tmp_path)
    _commit(seed, {"cves/2026/11xxx/CVE-2026-11111.json": _mitre_json("CVE-2026-11111")}, "c1")
    _tick(conn, work)
    _commit(seed, {"cves/2026/22xxx/CVE-2026-22222.json": _mitre_json("CVE-2026-22222")}, "c2")
    _tick(conn, work)
    # No verdict rows added/changed by the stream (Phase 1: detection only).
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1
    assert rows[0]["key"] == "CVE-OLD"
    assert rows[0]["status"] == "unpatched"


# --- history rewrite / GC: never fail into a wipe path ----------------------

def test_stream_history_rewrite_resets_cursor(conn, tmp_path):
    _, seed, work = _make_repos(tmp_path)
    _commit(seed, {"cves/2026/11xxx/CVE-2026-11111.json": _mitre_json("CVE-2026-11111")}, "c1")
    _tick(conn, work)  # cursor = c1 sha
    # Corrupt the cursor so `git diff old..new` fails (simulates force-push/GC).
    store.set_state(conn, stream.CURSOR_KEY, "0" * 40)
    _commit(seed, {"cves/2026/22xxx/CVE-2026-22222.json": _mitre_json("CVE-2026-22222")}, "c2")
    stats = _tick(conn, work)
    assert stats["error"] is not None and "diff failed" in stats["error"]
    # Cursor reset to the current tip; nothing wiped.
    assert store.get_state(conn, stream.CURSOR_KEY) != "0" * 40
    assert conn.execute("SELECT COUNT(*) FROM flaws").fetchone()[0] == 0


def test_stream_fetch_failure_does_not_touch_cursor(conn, tmp_path, monkeypatch):
    _, seed, work = _make_repos(tmp_path)
    _commit(seed, {"cves/2026/11xxx/CVE-2026-11111.json": _mitre_json("CVE-2026-11111")}, "c1")
    _tick(conn, work)
    cursor_before = store.get_state(conn, stream.CURSOR_KEY)
    # Make the next fetch fail (network down).
    monkeypatch.setattr(stream, "_git", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("fetch failed: network")))
    stats = _tick(conn, work)
    assert stats["error"] is not None and "fetch failed" in stats["error"]
    # cursor unchanged — the tick retries the same range next time.
    assert store.get_state(conn, stream.CURSOR_KEY) == cursor_before


# --- malformed records: a single bad record must not sink the tick -----------
# Regression for the first real CI run: the stream parsed real MITRE records for
# the first time and one record where a normally-dict field was a list raised
# ``'list' object has no attribute 'get'`` and sank the whole tick. The parser
# guards every ``.get`` receiver (mitre_record/mitre_refs) AND stream_tick wraps
# ``_skeleton`` in try/except — both layers must hold.

from posture import mitre as _mitre_mod


@pytest.mark.parametrize("bad", [
    # containers as a list (the original CI crash shape: a truthy list keeps the
    # `or {}` short-circuit, then `.get("cna")` raised AttributeError).
    {"cveMetadata": {"cveId": "CVE-2026-1", "datePublished": "2026-01-01T00:00:00Z"},
     "containers": [{"cna": {"descriptions": [{"lang": "en", "value": "x"}]}}]},
    # cveMetadata as a list (meta.get(...) would raise).
    {"cveMetadata": [{"cveId": "CVE-2026-2"}],
     "containers": {"cna": {"descriptions": [{"lang": "en", "value": "y"}]}}},
    # cna itself as a list.
    {"cveMetadata": {"cveId": "CVE-2026-3"},
     "containers": {"cna": [{"descriptions": [{"lang": "en", "value": "z"}]}]}},
    # a descriptions element that is a list, not a dict.
    {"cveMetadata": {"cveId": "CVE-2026-4"},
     "containers": {"cna": {"descriptions": [["en", "v"]]}}},
    # a problemTypes element that is a list.
    {"cveMetadata": {"cveId": "CVE-2026-5"},
     "containers": {"cna": {"problemTypes": [["x"]]}}},
    # a references element that is a list (mitre_refs must not crash).
    {"cveMetadata": {"cveId": "CVE-2026-6"},
     "containers": {"cna": {"references": [["https://x"]]}}},
    # rec itself is a list, not a dict.
    [{"cveMetadata": {"cveId": "CVE-2026-7"}}],
    # metrics as a list of non-dict entries.
    {"cveMetadata": {"cveId": "CVE-2026-8"},
     "containers": {"cna": {"metrics": ["not-a-dict", {"cvssV3_1": "also-not"}]}}},
])
def test_mitre_record_tolerates_non_dict_fields(bad):
    # must not raise; returns a dict (id empty when unparseable).
    rec = _mitre_mod.mitre_record(bad)
    assert isinstance(rec, dict)
    refs = _mitre_mod.mitre_refs(bad)
    assert isinstance(refs, list)


def test_stream_skips_malformed_record_does_not_sink_tick(conn, tmp_path):
    # A well-formed record plus two malformed ones (one with a valid id but
    # ``containers`` as a list — the original CI crash shape; one with NO
    # extractable id) in the SAME diff. The good one upserts fully; the valid-id
    # malformed one degrades gracefully to a minimal skeleton (no crash); the
    # id-less one is skipped. The tick completes (no error, cursor advances) —
    # the single-bad-record invariant the first CI run violated.
    _, seed, work = _make_repos(tmp_path)
    _commit(seed, {"cves/2026/11xxx/CVE-2026-11111.json":
                   _mitre_json("CVE-2026-11111")}, "c1")
    _tick(conn, work)  # bootstrap

    bad_valid_id = {"cveMetadata": {"cveId": "CVE-2026-BAD1",
                                    "datePublished": "2026-02-02T00:00:00Z"},
                    "containers": [{"cna": {"descriptions": [{"lang": "en",
                                                               "value": "bad"}]}}]}
    # no cveMetadata + containers a list -> no extractable id -> skipped.
    bad_no_id = {"containers": [{"cna": {"descriptions": [{"lang": "en",
                                                            "value": "noid"}]}}]}
    _commit(seed, {
        "cves/2026/22xxx/CVE-2026-22222.json": _mitre_json("CVE-2026-22222", "good"),
        "cves/2026/22xxx/CVE-2026-BAD1.json": bad_valid_id,
        "cves/2026/22xxx/CVE-2026-NOID.json": bad_no_id,
    }, "c2")
    stats = _tick(conn, work)
    assert stats["error"] is None  # the tick did NOT crash
    assert stats["changed_files"] == 3
    # the good record landed with full content.
    good = store.get_flaw(conn, "CVE-2026-22222")
    assert good is not None and good["description"] == "good"
    # the valid-id malformed record degraded to a minimal skeleton (graceful, not
    # a crash): empty description, no refs, no vector — but it IS anchored.
    bad1 = store.get_flaw(conn, "CVE-2026-BAD1")
    assert bad1 is not None
    assert bad1["description"] == "" and bad1["cvss_vector"] is None
    # the id-less record was skipped (nothing to anchor on).
    assert store.get_flaw(conn, "CVE-2026-NOID") is None
    # cursor still advanced (the tick completed cleanly past the bad records).
    assert store.get_state(conn, stream.CURSOR_KEY) is not None