"""EPSS ingestion tests — the ``epss`` spine overlay.

Mirrors the ``kev`` overlay test archetypes, adapted to the gzipped-CSV bulk
snapshot + the full-refresh (DELETE all + INSERT) shape:

  1. the ingest tick populates the overlay from the daily CSV snapshot;
  2. numeric scores + percentiles survive verbatim (the new exploitability
     signal, complementary to kev);
  3. re-ingest is an idempotent full refresh (replace, never append);
  4. a CVE dropped from the snapshot is removed (full refresh, no stale rows);
  5. a failed fetch is a no-op (no-wipe: preserve last-known-good);
  6. a gzip-decode failure is a no-op (no-wipe);
  7. a 200-but-empty/zero-row body is a soft no-op (no-wipe);
  8. the overlay never touches verdicts (no-wipe / map-not-territory);
  9. the spine export/import round-trips the overlay identical; no device data.

All offline: ``epss.curl_get_bytes`` (the binding the ingest tick routes
through) is monkeypatched to serve a gzipped-CSV built in-process. NVD_API_KEY
never touched.
"""
from __future__ import annotations

import gzip

import pytest

from posture import store, export
from posture.sources import epss as _ep
from posture.sources import epss as _epss_mod

# A realistic EPSS CSV: a leading '#cve,epss,percentile' comment header (the
# real file carries a model-version comment), then data rows, incl. a malformed
# row (non-numeric) that must be skipped, not crash the parse.
SAMPLE_CSV = (
    "#cve,epss,percentile,model=v2026-08-20\n"
    "CVE-2024-1086,0.94321,0.99812\n"
    "CVE-2024-3094,0.87650,0.98401\n"
    "CVE-2023-0001,0.00120,0.04500\n"
    "CVE-2023-0002,notanumber,0.5\n"     # malformed -> skipped
    "CVE-2023-0003,0.5,\n"               # missing percentile -> skipped
    "CVE-2023-0004,0.25,0.70\n"
)


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _gz(data: bytes):
    return gzip.compress(data)


def _curl_ok(csv_text=SAMPLE_CSV, code=200):
    """Monkeypatch the epss curl binding to serve a gzipped CSV (200)."""
    def fake(url, headers=None, max_time=300, extra=None):
        return _gz(csv_text.encode("utf-8")), code
    return fake


def test_epss_ingest_populates_overlay(conn, monkeypatch):
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", _curl_ok())
    stats = _ep.epss_ingest_tick(conn, now="t1")
    assert stats["error"] is None
    assert stats["fetched"] is True
    # 4 valid rows (the 2 malformed/missing skipped)
    assert stats["rows"] == 4
    row = store.epss_for_cve(conn, "CVE-2024-1086")
    assert row is not None
    assert row["epss"] == pytest.approx(0.94321)
    assert row["percentile"] == pytest.approx(0.99812)
    assert row["fetched_at"] == "t1"


def test_epss_ingest_skips_malformed_rows(conn, monkeypatch):
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", _curl_ok())
    _ep.epss_ingest_tick(conn, now="t1")
    assert store.epss_for_cve(conn, "CVE-2023-0002") is None   # non-numeric
    assert store.epss_for_cve(conn, "CVE-2023-0003") is None   # missing pct
    assert store.epss_for_cve(conn, "CVE-2023-0004") is not None


def test_epss_ingest_idempotent_re_ingest_replaces(conn, monkeypatch):
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", _curl_ok())
    _ep.epss_ingest_tick(conn, now="t1")
    n1 = conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0]
    _ep.epss_ingest_tick(conn, now="t2")
    n2 = conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0]
    assert n1 == n2                                # replace, never append
    # fetched_at advanced to the second tick
    assert store.epss_for_cve(conn, "CVE-2024-1086")["fetched_at"] == "t2"


def test_epss_ingest_full_refresh_drops_dropped_cve(conn, monkeypatch):
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", _curl_ok())
    _ep.epss_ingest_tick(conn, now="t1")
    assert store.epss_for_cve(conn, "CVE-2023-0004") is not None
    # next day's snapshot dropped CVE-2023-0004 from the model
    smaller = (
        "#cve,epss,percentile\n"
        "CVE-2024-1086,0.95,0.999\n"
        "CVE-2024-3094,0.88,0.98\n"
    )
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", _curl_ok(csv_text=smaller))
    _ep.epss_ingest_tick(conn, now="t2")
    assert store.epss_for_cve(conn, "CVE-2023-0004") is None   # no stale row
    assert conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0] == 2


def test_epss_ingest_fetch_failure_is_noop(conn, monkeypatch):
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", _curl_ok())
    _ep.epss_ingest_tick(conn, now="t1")
    before = store.epss_all(conn)
    assert before
    # outage: non-200
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", _curl_ok(code=503))
    stats = _ep.epss_ingest_tick(conn, now="t2")
    assert stats["error"] is not None
    assert stats["fetched"] is False
    assert stats["rows"] == 0
    assert store.epss_all(conn) == before          # no-wipe: last-known-good kept


def test_epss_ingest_gzip_decode_failure_is_noop(conn, monkeypatch):
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", _curl_ok())
    _ep.epss_ingest_tick(conn, now="t1")
    before = store.epss_all(conn)
    # serve a 200 with NON-gzip body -> gzip.decompress raises -> no-op
    def fake(url, headers=None, max_time=300, extra=None):
        return b"not actually gzipped", 200
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", fake)
    stats = _ep.epss_ingest_tick(conn, now="t2")
    assert stats["error"] is not None and "gzip" in stats["error"]
    assert store.epss_all(conn) == before


def test_epss_ingest_empty_body_is_soft_noop(conn, monkeypatch):
    # 200 but a snapshot that parses to zero rows (header only, no data)
    monkeypatch.setattr(_epss_mod, "curl_get_bytes",
                        _curl_ok(csv_text="#cve,epss,percentile\n"))
    stats = _ep.epss_ingest_tick(conn, now="t1")
    assert stats["error"] is not None and "zero rows" in stats["error"]
    assert conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0] == 0


def test_epss_ingest_does_not_touch_verdicts(conn, monkeypatch):
    store.upsert_verdict(conn, {
        "device_id": "host", "axis": "vulnerability", "key": "CVE-2024-1086",
        "status": "unpatched", "severity": "HIGH", "fixed_in": None,
        "detail": "prior", "provenance": {"observer": "nvd",
                                          "policy_version": "v",
                                          "fetched_at": "t", "complete": 1},
    }, "t")
    conn.commit()
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", _curl_ok())
    _ep.epss_ingest_tick(conn, now="t1")
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1 and rows[0]["key"] == "CVE-2024-1086"
    assert rows[0]["status"] == "unpatched"      # verdict untouched


def test_epss_ingest_export_import_round_trip(conn, monkeypatch, tmp_path):
    monkeypatch.setattr(_epss_mod, "curl_get_bytes", _curl_ok())
    _ep.epss_ingest_tick(conn, now="t1")
    conn.commit()

    out = tmp_path / "out"
    manifest = export.export_spine(conn, out_dir=out, policy_version="v")
    assert manifest["counts"]["epss"] == 4
    assert (out / "spine" / "epss.jsonl").exists()

    other = store.connect(":memory:")
    stats = export.import_spine(other, from_dir=out)
    assert stats["epss"] == manifest["counts"]["epss"]
    # the overlay rows survive the round trip identical (ordered by cve_id)
    assert store.epss_all(conn) == store.epss_all(other)
    # no device data on the wire: spine shards are defects + flat tables only
    shard_names = {p.relative_to(out / "spine").as_posix()
                   for p in (out / "spine").rglob("*.jsonl")}
    assert not any("verdict" in n or "device" in n for n in shard_names)