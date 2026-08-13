"""OSV ingestion tests — the practical hub peer.

OSV.dev's GCS export is the practical hub: many peers (RustSec, PyPA, Go, Red
Hat, Debian, Ubuntu, Alpine, ...) emit OSV-schema records, so one ingest path
covers a large fraction of the aggregator peer space. ``osv_ingest_tick`` is a
two-phase cap-resumed ingestion (backfill per-ecosystem, then incremental). All
local fixtures — no network: ``curl_get`` is monkeypatched to serve files from a
temp dir that mirrors the GCS layout (``ecosystems.txt``, ``<ECO>/all.zip``,
``<ECO>/modified_id.csv``, ``<ECO>/<ID>.json``).
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from posture import store
from posture.sources import osv as _osv
from posture.sources import _net
from posture.sources import osv_schema as _osv_schema


# --- fixtures + helpers -----------------------------------------------------

@pytest.fixture
def conn():
    return store.connect(":memory:")


def _osv_json(osv_id, cve_alias=None, summary="test vuln",
              modified="2026-08-06T00:00:00Z", published="2026-01-01T00:00:00Z"):
    """Build a minimal OSV-schema record. ``cve_alias`` adds one alias (a CVE,
    GHSA, or ecosystem id) to ``aliases``; pass None for a cve-less record."""
    rec = {
        "id": osv_id,
        "published": published,
        "modified": modified,
        "summary": summary,
        "severity": [{"type": "CVSS_V3_1",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "affected": [{"package": {"ecosystem": "PySEC", "name": "pkg"},
                      "ranges": [], "versions": ["1.0.0"]}],
        "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
    }
    aliases = []
    if cve_alias:
        aliases.append(cve_alias)
    rec["aliases"] = aliases
    return rec


def _build_zip(base_dir: Path, eco: str, records: list[dict]) -> Path:
    """Write ``<base_dir>/<eco>/all.zip`` containing one JSON file per record.
    Returns the zip path."""
    eco_dir = base_dir / eco
    eco_dir.mkdir(parents=True, exist_ok=True)
    zip_path = eco_dir / "all.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for rec in records:
            zf.writestr(f"{rec['id']}.json", json.dumps(rec))
    return zip_path


def _write_ecosystems(base_dir: Path, ecosystems: list[str]) -> Path:
    """Write ``<base_dir>/ecosystems.txt`` (newline-separated ecosystem list)."""
    path = base_dir / "ecosystems.txt"
    path.write_text("\n".join(ecosystems) + "\n")
    return path


def _write_modified_csv(base_dir: Path, eco: str,
                        rows: list[dict]) -> Path:
    """Write ``<base_dir>/<eco>/modified_id.csv`` with header ``id,modified``."""
    eco_dir = base_dir / eco
    eco_dir.mkdir(parents=True, exist_ok=True)
    path = eco_dir / "modified_id.csv"
    lines = ["id,modified"]
    for r in rows:
        lines.append(f"{r['id']},{r['modified']}")
    path.write_text("\n".join(lines) + "\n")
    return path


def _write_record_json(base_dir: Path, eco: str, rec: dict) -> Path:
    """Write ``<base_dir>/<eco>/<ID>.json`` for an individual incremental record."""
    eco_dir = base_dir / eco
    eco_dir.mkdir(parents=True, exist_ok=True)
    path = eco_dir / f"{rec['id']}.json"
    path.write_text(json.dumps(rec))
    return path


def _make_fake_fetch(base_dir: Path):
    """Build a fake ``curl_get`` (text) that maps a URL (a local path under
    base_dir) to the file's contents. Returns ``(parsed_json, 200, body)`` for
    .json and ``(None, 200, body_text)`` for .txt/.csv. ``(None, 404, "")`` when
    the file is missing. Binary ``.zip`` payloads are served by the separate
    binary-safe fake (``curl_get_bytes``) — see :func:`_patch_fetch`."""
    def _fetch(url, headers=None, max_time=60, extra=None):
        path = Path(url)
        if not path.exists():
            return (None, 404, "")
        if url.endswith(".json"):
            body = path.read_text()
            return (json.loads(body), 200, body)
        body = path.read_text()
        return (None, 200, body)
    return _fetch


def _make_fake_fetch_bytes(base_dir: Path):
    """Build a fake ``curl_get_bytes`` (binary-safe) that serves ``.zip`` files
    as raw bytes: ``(bytes, 200)``. ``(None, 404)`` when the file is missing."""
    def _fetch(url, headers=None, max_time=60, extra=None):
        path = Path(url)
        if not path.exists():
            return (None, 404)
        return (path.read_bytes(), 200)
    return _fetch


def _patch_fetch(monkeypatch, base_dir: Path):
    """Monkeypatch ``curl_get`` (text) + ``curl_get_bytes`` (binary) to serve
    from ``base_dir`` — the same split real CI uses (json/txt/csv via the text
    fetch, the all.zip via the binary-safe fetch)."""
    monkeypatch.setattr(_net, "curl_get", _make_fake_fetch(base_dir))
    monkeypatch.setattr(_net, "curl_get_bytes", _make_fake_fetch_bytes(base_dir))


# --- 1. backfill populates osv rows + registers the CVE alias ----------------

def test_backfill_populates_osv_rows_and_alias(conn, tmp_path, monkeypatch):
    eco = "PySEC"
    _write_ecosystems(tmp_path, [eco])
    _build_zip(tmp_path, eco, [
        _osv_json("OSV-2026-1", cve_alias="CVE-2026-1001"),
        _osv_json("OSV-2026-2", cve_alias="CVE-2026-1002"),
    ])
    _patch_fetch(monkeypatch, tmp_path)

    stats = _osv.osv_ingest_tick(conn, cap=100, now="2026-08-06T12:00:00Z",
                                base_url=str(tmp_path))
    assert stats["upserted"] == 2
    assert stats["error"] is None
    assert stats["ecosystems_done"] is True

    # the osv catalog rows: flaw_type='osv', enrich_state='osv', source='osv'
    row1 = store.get_flaw(conn, "OSV-2026-1")
    assert row1 is not None
    assert row1["flaw_type"] == "osv"
    assert row1["enrich_state"] == "osv"
    assert row1["source"] == "osv"
    assert row1["description"] == "test vuln"

    # the CVE alias is registered as a symmetric crosswalk edge.
    # resolve(OSV-2026-1) -> CVE-2026-1001 typed 'cve'
    fwd = store.resolve_crosswalk(conn, "OSV-2026-1")
    assert any(a["alias"] == "CVE-2026-1001" and a["kind"] == "cve" for a in fwd)
    # reverse_resolve(CVE-2026-1001) -> OSV-2026-1 typed 'osv' (the symmetric edge)
    back = store.reverse_crosswalk(conn, "CVE-2026-1001")
    assert any(r["flaw_id"] == "OSV-2026-1" and r["kind"] == "cve" for r in back)


# --- 2. cap-resumed across ticks (cap=2 over 5 records: 2+2+1) ---------------

def test_backfill_cap_resumed_across_ticks(conn, tmp_path, monkeypatch):
    eco = "PySEC"
    _write_ecosystems(tmp_path, [eco])
    _build_zip(tmp_path, eco, [_osv_json(f"OSV-2026-{i}",
                                         cve_alias=f"CVE-2026-{i}")
                               for i in range(1, 6)])
    _patch_fetch(monkeypatch, tmp_path)

    # tick 1: cap=2 -> 2 records, ecosystem not done
    s1 = _osv.osv_ingest_tick(conn, cap=2, now="t1", base_url=str(tmp_path))
    assert s1["upserted"] == 2
    assert s1["ecosystems_done"] is False
    assert s1["done"] is False

    # tick 2: cap=2 -> 2 more records, ecosystem not done
    s2 = _osv.osv_ingest_tick(conn, cap=2, now="t2", base_url=str(tmp_path))
    assert s2["upserted"] == 2
    assert s2["ecosystems_done"] is False

    # tick 3: cap=2 -> 1 remaining record, zip exhausted, ecosystem marked done
    s3 = _osv.osv_ingest_tick(conn, cap=2, now="t3", base_url=str(tmp_path))
    assert s3["upserted"] == 1
    assert s3["ecosystems_done"] is True
    # done=False: backfill just finished, incremental hasn't run yet
    assert s3["done"] is False

    # all 5 records are in the catalog
    all_ids = {r["id"] for r in store.catalog_all(conn)}
    assert all_ids == {f"OSV-2026-{i}" for i in range(1, 6)}

    # a 4th tick runs incremental with no changes -> done=True
    s4 = _osv.osv_ingest_tick(conn, cap=2, now="t4", base_url=str(tmp_path))
    assert s4["incremental"] is True
    assert s4["upserted"] == 0
    assert s4["done"] is True


# --- 3. multi-ecosystem: first tick capped, next tick continues --------------

def test_multi_ecosystem_capped_then_continues(conn, tmp_path, monkeypatch):
    eco1, eco2 = "PySEC", "Go"
    _write_ecosystems(tmp_path, [eco1, eco2])
    _build_zip(tmp_path, eco1, [_osv_json(f"OSV-PY-{i}",
                                          cve_alias=f"CVE-2026-{i}")
                                for i in range(1, 4)])  # 3 records
    _build_zip(tmp_path, eco2, [_osv_json(f"OSV-GO-1",
                                           cve_alias="CVE-2026-99")])  # 1 record
    _patch_fetch(monkeypatch, tmp_path)

    # tick 1: cap=2 -> 2 records from eco1, cap hit, eco1 not done
    s1 = _osv.osv_ingest_tick(conn, cap=2, now="t1", base_url=str(tmp_path))
    assert s1["upserted"] == 2
    assert s1["fetched_ecosystem"] == "PySEC"
    assert s1["ecosystems_done"] is False

    # tick 2: cap=2 -> 1 remaining from eco1 (exhausted, done) + 1 from eco2
    # (exhausted, done). Both ecosystems done.
    s2 = _osv.osv_ingest_tick(conn, cap=2, now="t2", base_url=str(tmp_path))
    assert s2["upserted"] == 2
    assert s2["ecosystems_done"] is True

    # all 4 records across both ecosystems are in the catalog
    all_ids = {r["id"] for r in store.catalog_all(conn)}
    assert all_ids == {"OSV-PY-1", "OSV-PY-2", "OSV-PY-3", "OSV-GO-1"}


# --- 4. switches to incremental after all ecosystems done ---------------------

def test_incremental_after_backfill_done(conn, tmp_path, monkeypatch):
    eco = "PySEC"
    _write_ecosystems(tmp_path, [eco])
    _build_zip(tmp_path, eco, [_osv_json("OSV-2026-1", cve_alias="CVE-2026-1")])
    _patch_fetch(monkeypatch, tmp_path)

    # tick 1: backfill the one record, ecosystem done
    s1 = _osv.osv_ingest_tick(conn, cap=100, now="t1", base_url=str(tmp_path))
    assert s1["ecosystems_done"] is True
    assert s1["incremental"] is False

    # set up an incremental change: a new record in modified_id.csv past the
    # (empty) cursor, with its individual JSON file available.
    _write_modified_csv(tmp_path, eco, [
        {"id": "OSV-2026-99", "modified": "2026-09-01T00:00:00Z"},
    ])
    _write_record_json(tmp_path, eco,
                       _osv_json("OSV-2026-99", cve_alias="CVE-2026-99",
                                 summary="incremental change"))

    # tick 2: incremental mode, upserts the changed record
    s2 = _osv.osv_ingest_tick(conn, cap=100, now="t2", base_url=str(tmp_path))
    assert s2["incremental"] is True
    assert s2["upserted"] == 1
    assert s2["done"] is False  # a change was made

    row = store.get_flaw(conn, "OSV-2026-99")
    assert row is not None
    assert row["flaw_type"] == "osv"
    assert row["description"] == "incremental change"

    # the cursor advanced; a 3rd tick finds no changes -> done=True
    s3 = _osv.osv_ingest_tick(conn, cap=100, now="t3", base_url=str(tmp_path))
    assert s3["incremental"] is True
    assert s3["upserted"] == 0
    assert s3["done"] is True


# --- 5. no-wipe: the tick never touches verdicts -----------------------------

def test_osv_ingest_does_not_touch_verdicts(conn, tmp_path, monkeypatch):
    eco = "PySEC"
    _write_ecosystems(tmp_path, [eco])
    _build_zip(tmp_path, eco, [_osv_json("OSV-2026-1", cve_alias="CVE-2026-1")])
    _patch_fetch(monkeypatch, tmp_path)

    # pre-seed a verdict for the aliased CVE
    store.upsert_verdict(conn, {
        "device_id": "host", "axis": "vulnerability", "key": "CVE-2026-1",
        "status": "unpatched", "severity": "HIGH", "fixed_in": None,
        "detail": "prior", "provenance": {"observer": "nvd",
                                          "policy_version": "v",
                                          "fetched_at": "t", "complete": 1},
    }, "t")
    conn.commit()

    _osv.osv_ingest_tick(conn, cap=100, now="t", base_url=str(tmp_path))
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1 and rows[0]["key"] == "CVE-2026-1"
    assert rows[0]["status"] == "unpatched"  # verdict untouched


# --- 6. cve-less OSV record still anchors as an osv row ----------------------

def test_cveless_osv_record_anchors(conn, tmp_path, monkeypatch):
    eco = "PySEC"
    _write_ecosystems(tmp_path, [eco])
    _build_zip(tmp_path, eco, [
        _osv_json("OSV-2026-1", cve_alias=None),  # no cve alias
    ])
    _patch_fetch(monkeypatch, tmp_path)

    stats = _osv.osv_ingest_tick(conn, cap=100, now="t", base_url=str(tmp_path))
    assert stats["upserted"] == 1

    # the osv row exists, keyed by its own id
    row = store.get_flaw(conn, "OSV-2026-1")
    assert row is not None
    assert row["flaw_type"] == "osv"

    # flaw_type_counts includes osv
    counts = {r["flaw_type"]: r["n"] for r in store.flaw_type_counts(conn)}
    assert counts.get("osv") == 1


# --- 7. fetch failure is a no-op (touches nothing) ---------------------------

def test_fetch_failure_is_noop(conn, monkeypatch):
    monkeypatch.setattr(_net, "curl_get",
                       lambda url, headers=None, max_time=60, extra=None:
                       (None, 503, ""))
    stats = _osv.osv_ingest_tick(conn, cap=100, now="t")
    assert stats["error"] is not None
    assert stats["upserted"] == 0
    assert conn.execute("SELECT COUNT(*) FROM flaws").fetchone()[0] == 0


# --- 8. malformed records never crash the parser (mirror of mitre hardening) -
# A single record where a normally-dict/list field is the wrong type must not
# raise — osv_record returns None (no id) or a minimal dict, and the ingest
# loop skips it. The 'list' object has no attribute 'get' class of bug.

@pytest.mark.parametrize("bad", [
    # rec itself is a list, not a dict.
    [{"id": "OSV-1"}],
    # severity holds a non-dict entry (a string) — the sort key must not crash.
    {"id": "OSV-2", "severity": ["CVSS:3.1/AV:N"]},
    # severity is a dict (not a list).
    {"id": "OSV-3", "severity": {"type": "CVSS_V3_1", "score": 7.0}},
    # severity is a string.
    {"id": "OSV-4", "severity": "high"},
    # summary is a list (must not crash .strip()).
    {"id": "OSV-5", "summary": ["a", "b"]},
    # published is a list (must yield None, not a sliced list).
    {"id": "OSV-6", "published": ["2026-01-01"]},
    # references element is a string.
    {"id": "OSV-7", "references": ["https://x"]},
    # affected element is a list.
    {"id": "OSV-8", "affected": [["pkg"]]},
])
def test_osv_record_tolerates_non_dict_fields(bad):
    rec = _osv_schema.osv_record(bad)
    # must not raise; either None (no id) or a dict.
    assert rec is None or isinstance(rec, dict)


def test_osv_backfill_skips_malformed_record(conn, tmp_path, monkeypatch):
    # A zip with three records: one good, one malformed-but-valid-id (severity is
    # a string — would have crashed the old sort key), and one with NO id (a dict
    # with no ``id`` field). The good + malformed-valid-id land (the latter as a
    # minimal row — graceful degrade, not a crash); the id-less one is skipped
    # (osv_record returns None). The tick completes with no error. The zip is
    # built manually (not via _build_zip, which assumes every record has an id
    # for its filename) so the no-id record can carry an arbitrary filename.
    eco = "PySEC"
    _write_ecosystems(tmp_path, [eco])
    good = _osv_json("OSV-GOOD", cve_alias="CVE-2026-1")
    malformed_valid = {"id": "OSV-BAD", "severity": "high",
                       "affected": [{"package": {"ecosystem": "PySEC", "name": "p"}}]}
    no_id = {"summary": "no id here"}  # dict with no id -> osv_record returns None
    eco_dir = tmp_path / eco
    eco_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(eco_dir / "all.zip", "w") as zf:
        zf.writestr("OSV-GOOD.json", json.dumps(good))
        zf.writestr("OSV-BAD.json", json.dumps(malformed_valid))
        zf.writestr("NOID.json", json.dumps(no_id))
    _patch_fetch(monkeypatch, tmp_path)

    stats = _osv.osv_ingest_tick(conn, cap=100, now="t", base_url=str(tmp_path))
    assert stats["error"] is None
    assert stats["upserted"] == 2  # good + malformed-valid-id (id-less skipped)
    assert stats["skipped"] == 1
    good_row = store.get_flaw(conn, "OSV-GOOD")
    assert good_row is not None and good_row["flaw_type"] == "osv"
    # the malformed-valid-id record degraded to a minimal row (no crash): no
    # vector, no cvss — but it IS anchored. The invariant is "no crash", not
    # "skip records with a valid id".
    bad = store.get_flaw(conn, "OSV-BAD")
    assert bad is not None and bad["cvss_vector"] is None


# --- 9. best-effort per-ecosystem (one ecosystem's all.zip failure must not
# sink the ingest tick / the daily spine commit) -----------------------------

def test_backfill_skips_failing_ecosystem_continues_to_next(conn, tmp_path,
                                                             monkeypatch):
    """One ecosystem's all.zip fetch failure (404 / http 0 / timeout) is
    BEST-EFFORT: the tick skips it (retried next tick, stays NOT done) and
    continues to the next ecosystem. The good ecosystem is upserted; the bad
    one is recorded in failed_ecosystems; no error (exit 0). This is the fix
    for the CI failure where a single ecosystem outage sank the whole ingest
    job + the daily spine commit."""
    _write_ecosystems(tmp_path, ["Good", "Bad"])
    _build_zip(tmp_path, "Good", [_osv_json("OSV-GOOD-1", cve_alias="CVE-2026-1")])
    # 'Bad' has NO all.zip -> curl_get_bytes returns (None, 404) -> skip.
    _patch_fetch(monkeypatch, tmp_path)
    stats = _osv.osv_ingest_tick(conn, cap=100, now="t", base_url=str(tmp_path))
    assert stats["error"] is None                 # partial failure -> exit 0
    assert stats["upserted"] == 1                 # the Good ecosystem landed
    assert stats["failed_ecosystems"] == ["Bad"]  # the bad one recorded
    assert store.get_flaw(conn, "OSV-GOOD-1") is not None
    # Bad stays NOT done (retried next tick).
    done = json.loads(store.get_state(conn, _osv.OSV_DONE_ECOSYSTEMS_KEY) or "[]")
    assert "Bad" not in done
    assert "Good" in done


def test_backfill_total_outage_surfaces_error(conn, tmp_path, monkeypatch):
    """If EVERY attempted ecosystem's all.zip fails (total OSV outage), the tick
    surfaces ``error`` (exit 1) — a genuine total failure must not silently pass.
    Distinguished from a partial failure (some ecosystems succeeded = exit 0)."""
    _write_ecosystems(tmp_path, ["Down1", "Down2"])
    # neither ecosystem has an all.zip -> both fetches fail.
    _patch_fetch(monkeypatch, tmp_path)
    stats = _osv.osv_ingest_tick(conn, cap=100, now="t", base_url=str(tmp_path))
    assert stats["error"] is not None             # total outage -> exit 1
    assert stats["upserted"] == 0
    assert sorted(stats["failed_ecosystems"]) == ["Down1", "Down2"]
    assert conn.execute("SELECT COUNT(*) FROM flaws").fetchone()[0] == 0


def test_backfill_cursor_ecosystem_failure_clears_cursor_unblocks_next(conn,
        tmp_path, monkeypatch):
    """A mid-zip cursor pointing at an ecosystem whose all.zip then fails must
    be CLEARED (not stuck): the failed fetch has no mid-zip progress to preserve,
    and without clearing, the cursor_eco != eco skip-ahead would block every
    later ecosystem too. After clearing, the next ecosystem proceeds."""
    _write_ecosystems(tmp_path, ["Bad", "Good"])
    _build_zip(tmp_path, "Good", [_osv_json("OSV-GOOD-1", cve_alias="CVE-2026-1")])
    # 'Bad' has NO all.zip. Seed a mid-zip cursor at Bad so the tick resumes there.
    store.set_state(conn, _osv.OSV_BACKFILL_CURSOR_KEY,
                    json.dumps({"ecosystem": "Bad", "index": 5}))
    conn.commit()
    _patch_fetch(monkeypatch, tmp_path)
    stats = _osv.osv_ingest_tick(conn, cap=100, now="t", base_url=str(tmp_path))
    assert stats["error"] is None                 # Good succeeded -> partial, exit 0
    assert stats["upserted"] == 1
    assert stats["failed_ecosystems"] == ["Bad"]
    # cursor was cleared (not left pointing at the failing Bad).
    assert store.get_state(conn, _osv.OSV_BACKFILL_CURSOR_KEY) == ""
    assert store.get_flaw(conn, "OSV-GOOD-1") is not None


def test_incremental_records_failing_ecosystem_skips(conn, tmp_path,
                                                     monkeypatch):
    """The incremental sweep already skipped a failed modified_id.csv; it now
    ALSO records the ecosystem in failed_ecosystems (best-effort + visible).
    One ecosystem's csv missing -> skipped + recorded, others proceed, exit 0."""
    # Both ecosystems already done -> the tick takes the incremental path.
    _write_ecosystems(tmp_path, ["Good", "Bad"])
    store.set_state(conn, _osv.OSV_DONE_ECOSYSTEMS_KEY,
                    json.dumps(["Good", "Bad"]))
    conn.commit()
    # Good has a modified_id.csv with one new record past the cursor; Bad has none.
    _write_modified_csv(tmp_path, "Good",
                       [{"id": "OSV-GOOD-1", "modified": "2026-08-06T00:00:00Z"}])
    _write_record_json(tmp_path, "Good", _osv_json("OSV-GOOD-1", cve_alias="CVE-2026-1"))
    _patch_fetch(monkeypatch, tmp_path)
    stats = _osv.osv_ingest_tick(conn, cap=100, now="t", base_url=str(tmp_path))
    assert stats["error"] is None
    assert stats["incremental"] is True
    assert stats["upserted"] == 1                 # Good's new record landed
    assert stats["failed_ecosystems"] == ["Bad"]  # Bad's csv missing -> recorded
    assert store.get_flaw(conn, "OSV-GOOD-1") is not None