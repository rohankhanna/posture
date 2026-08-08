"""Spine export/import tests — the signed-directory interface between CI and
clients.

The load-bearing test is the **round trip**: DB A -> export -> import into
DB B -> assert the five MAP tables (flaws, crosswalk, candidates, distrust_marks,
seen_flaws) are identical. The spine is the MAP; territory (verdicts) must never
leak into it, and the manifest's per-file sha256 must be tamper-evident.
"""
from __future__ import annotations

import json

import pytest

from posture import store, export


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _seed(conn) -> None:
    """A mix of mitre skeletons + nvd-enriched rows + crosswalk + candidates +
    distrust_marks + seen_flaws, across two published months + an unknown."""
    store.upsert_flaw(conn, {
        "id": "CVE-2026-1001", "published": "2026-07-04", "cvss": 9.9,
        "severity": "CRITICAL", "cvss_vector": "CVSS:3.1/AV:N",
        "description": "enriched one", "fixed_raw": {"source": "nvd", "ranges": []},
        "refs": ["https://x", "https://p"], "cwe": ["CWE-89"], "ref_tags": ["Patch"],
        "source": "nvd", "fetched_at": "t1", "policy_version": "v", "complete": 1,
    })
    store.set_enrich_state(conn, "CVE-2026-1001", "nvd")

    store.upsert_flaw(conn, {
        "id": "CVE-2026-1002", "published": "2026-06-15",
        "description": "skeleton", "fixed_raw": {"source": "mitre"},
        "refs": [], "cwe": [], "ref_tags": [], "source": "mitre",
        "fetched_at": "t2", "policy_version": "v", "complete": 1,
    })
    store.set_enrich_state(conn, "CVE-2026-1002", "mitre")

    store.upsert_flaw(conn, {
        "id": "CVE-2026-1003", "published": None,
        "description": "no published date", "fixed_raw": None,
        "refs": [], "cwe": [], "ref_tags": [], "source": "mitre",
        "fetched_at": "t3", "policy_version": "v", "complete": 1,
    })
    store.set_enrich_state(conn, "CVE-2026-1003", "mitre")

    # a self-enriched non-cve PEER row (GHSA) — flaw_type survives the round trip
    store.upsert_flaw(conn, {
        "id": "GHSA-aaaa-bbbb-cccc", "flaw_type": "ghsa",
        "published": "2026-07-20", "cvss": 7.5, "severity": "HIGH",
        "cvss_vector": "CVSS:3.1/AV:N",
        "description": "ghsa peer row", "fixed_raw": {"source": "ghsa"},
        "refs": [], "cwe": ["CWE-78"], "ref_tags": [], "source": "ghsa",
        "fetched_at": "t4", "policy_version": "v", "complete": 1,
    })
    store.set_enrich_state(conn, "GHSA-aaaa-bbbb-cccc", "ghsa")

    store.add_crosswalk(conn, "CVE-2026-1001", "GHSA-aaaa-bbbb-cccc", "ghsa")
    store.add_crosswalk(conn, "CVE-2026-1001", "UBUNTU-CVE-2026-1001", "usn")
    store.add_crosswalk(conn, "CVE-2026-1002", "OSV-2026-6", "osv_id")

    store.add_candidate(conn, "https://example/new", "csaf", "vulnerability",
                        "surfaced by horizon scan")
    store.set_candidate_status(conn, "https://example/new", "review")

    store.mark_distrust(conn, "shodan", "stub never wired")
    store.mark_flaw_distrust(conn, "CVE-2026-1002", "withdrew from NVD")

    store.mark_seen(conn, ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003",
                            "GHSA-aaaa-bbbb-cccc"])

    # one KEV overlay row keyed on CVE-2026-1001 (exploitability_signal overlay)
    store.upsert_kev(conn, {
        "cve_id": "CVE-2026-1001", "date_added": "2026-08-01",
        "vendor_project": "Acme", "product": "Widget", "name": "Acme Widget RCE",
        "short_description": "remote code execution",
        "required_action": "Apply patch.", "due_date": "2026-09-01",
        "ransomware_use": "Known", "cwes": ["CWE-78"],
        "catalog_version": "2026.08.06", "date_released": "2026-08-06",
        "fetched_at": "t1",
    })

    conn.commit()


def _all_tables(conn) -> dict:
    """The six MAP tables (flaws, crosswalk, candidates, distrust_marks,
    seen_flaws, kev) as comparable structures (sets/lists of dicts)."""
    return {
        "flaws": store.catalog_all(conn),
        "crosswalk": store.crosswalk_all(conn),
        "candidates": store.candidates(conn),
        "distrust_marks": store.distrust_marks(conn),
        "seen_flaws": store.seen_flaws(conn),
        "kev": store.kev_all(conn),
    }


# --- the load-bearing correctness test ---------------------------------------

def test_export_round_trip_identical(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    manifest = export.export_spine(conn, out_dir=out, policy_version="v")
    assert manifest["counts"] == {"flaws": 4, "crosswalk": 3, "candidates": 1,
                                   "distrust_marks": 1, "seen_flaws": 4, "kev": 1,
                                   "apple_fixes": 0}

    other = store.connect(":memory:")
    stats = export.import_spine(other, from_dir=out)
    assert stats == manifest["counts"]

    a, b = _all_tables(conn), _all_tables(other)
    # order-stable on both sides (export orders by id; import preserves), so
    # direct equality is meaningful.
    for table in a:
        assert a[table] == b[table], f"round-trip drift in {table}"
    # specifically: enrich_state + distrusted + discovered_at survive the round
    # trip (import uses a full INSERT OR REPLACE, not upsert_flaw which drops them)
    cve = store.get_flaw(other, "CVE-2026-1001")
    assert cve["enrich_state"] == "nvd"
    assert cve["cwe"] == ["CWE-89"] and cve["ref_tags"] == ["Patch"]
    assert store.get_flaw(other, "CVE-2026-1002")["distrusted"] == 1
    # the non-cve PEER row (GHSA) survives the round trip with its flaw_type +
    # enrich_state intact — the multi-peer spine shape, not just cve rows.
    ghsa = store.get_flaw(other, "GHSA-aaaa-bbbb-cccc")
    assert ghsa is not None
    assert ghsa["flaw_type"] == "ghsa"
    assert ghsa["enrich_state"] == "ghsa"
    assert ghsa["source"] == "ghsa"


# --- territory never leaks into the spine ------------------------------------

def test_export_excludes_verdicts(conn, tmp_path):
    _seed(conn)
    # a verdict is TERRITORY (device-specific) — it must never appear in the spine
    store.upsert_verdict(conn, {
        "device_id": "host-PRIVATE", "axis": "vulnerability", "key": "CVE-2026-1001",
        "status": "unpatched", "severity": "CRITICAL", "fixed_in": None, "detail": "private",
        "provenance": {"witness": "nvd", "policy_version": "v",
                       "fetched_at": "t", "complete": 1},
    }, "t")
    conn.commit()
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    blob = "".join(p.read_text() for p in (out / "spine").rglob("*.jsonl"))
    assert "host-PRIVATE" not in blob
    assert "verdict" not in json.loads((out / "spine" / "manifest.json").read_text())["counts"]


# --- sharding by published month (100MB-file limit design) ------------------

def test_export_shards_by_published_month(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    cves_dir = out / "spine" / "flaws"
    shards = {p.name: [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
              for p in cves_dir.glob("*.jsonl")}
    assert set(shards) == {"2026-06.jsonl", "2026-07.jsonl", "unknown.jsonl"}
    assert shards["2026-07.jsonl"][0]["id"] == "CVE-2026-1001"
    assert shards["2026-06.jsonl"][0]["id"] == "CVE-2026-1002"
    assert shards["unknown.jsonl"][0]["id"] == "CVE-2026-1003"


def test_export_self_cleans_stale_shards(conn, tmp_path):
    """Re-running export after a format rename drops stale shards it no longer
    writes (e.g. a prior run's spine/cves/*.jsonl + seen_cves.jsonl) instead of
    leaving them beside the new spine/flaws/*.jsonl + seen_flaws.jsonl. Export
    is the producer side; this keeps the signed directory tidy across renames."""
    _seed(conn)
    out = tmp_path / "out"
    # seed the out dir with stale shards from a hypothetical prior (cves-named) run.
    # Several stale cves/ shards — the self-clean must unlink each AND rmtree the
    # now-empty cves/ dir; materializing the rglob list first is what makes that
    # safe (mutating the tree mid-rglob raises FileNotFoundError on the dir rglob
    # still intends to descend into).
    (out / "spine" / "cves").mkdir(parents=True)
    for shard in ("2005-01", "2005-02", "2026-07", "unknown"):
        (out / "spine" / "cves" / f"{shard}.jsonl").write_text('{"id":"STALE"}\n')
    (out / "spine" / "seen_cves.jsonl").write_text('{"cve_id":"STALE"}\n')
    # a crosswalk shard IS still produced — it must survive the self-clean
    (out / "spine" / "crosswalk.jsonl").write_text('{"flaw_id":"KEEP","alias":"x","kind":"x"}\n')

    export.export_spine(conn, out_dir=out, policy_version="v")

    assert not (out / "spine" / "cves").exists()              # stale shard dir gone
    assert not (out / "spine" / "seen_cves.jsonl").exists()   # stale flat file gone
    assert (out / "spine" / "flaws").exists()                 # new shard dir present
    assert (out / "spine" / "seen_flaws.jsonl").exists()      # new flat file present
    assert (out / "spine" / "crosswalk.jsonl").exists()       # still-produced shard kept


# --- the manifest is self-auditing (tamper-evident without git history) ------

def test_manifest_sha256_is_tamper_evident(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    shard = out / "spine" / "flaws" / "2026-07.jsonl"
    shard.write_text(shard.read_text() + '{"id":"EVIL"}\n')  # tamper
    with pytest.raises(ValueError, match="sha256 mismatch"):
        export.verify_spine(out)


def test_verify_spine_clean_on_untampered(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    manifest = export.verify_spine(out)  # no raise
    assert manifest["counts"]["flaws"] == 4


# --- import options ----------------------------------------------------------

def test_import_no_verify_skips_check(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    # tamper a shard IN PLACE (same line count, so counts match; sha256 won't)
    shard = out / "spine" / "flaws" / "2026-07.jsonl"
    rows = [json.loads(l) for l in shard.read_text().splitlines() if l.strip()]
    rows[0]["description"] = "TAMPERED"
    shard.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
    other = store.connect(":memory:")
    # default (verify) must raise on the sha256 mismatch ...
    with pytest.raises(ValueError, match="sha256 mismatch"):
        export.import_spine(other, from_dir=out)
    # ... --no-verify loads anyway (the manifest check is skipped entirely)
    stats = export.import_spine(other, from_dir=out, verify_manifest=False)
    assert stats["flaws"] == 4


def test_import_is_idempotent(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    other = store.connect(":memory:")
    first = export.import_spine(other, from_dir=out)
    second = export.import_spine(other, from_dir=out)
    assert first == second  # counts unchanged; INSERT OR REPLACE is idempotent
    assert store.catalog_all(other) == store.catalog_all(conn)


def test_export_readonly_db(conn, tmp_path):
    """export must work against a read-only connection and never write to the DB."""
    _seed(conn)
    # snapshot into a file DB, reopen read-only-style (connect never writes on read)
    out = tmp_path / "out"
    manifest = export.export_spine(conn, out_dir=out, policy_version="v")
    assert manifest["counts"]["flaws"] == 4
    # the source DB's row count is unchanged (export wrote nothing to it)
    assert len(store.catalog_all(conn)) == 4