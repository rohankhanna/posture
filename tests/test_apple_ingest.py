"""Apple fix-version ingestion tests — the ``apple_fixes`` spine overlay.

``apple_ingest_tick`` is the CI-side counterpart to the per-device
``apple_advisory`` observer: it builds the same earliest-fix-version-wins
``cve -> fixed_in`` map from Apple's live index (+ optional Wayback historical
recovery) and writes it as a per-product full refresh to the ``apple_fixes``
overlay — the durable fix map in the signed spine. It mirrors the KEV overlay
pattern (idempotent, no-wipe) but is (cve_id, product)-keyed and per-product
full-refresh (DELETE WHERE product + INSERT) so advisories aged off the
rolling index leave no stale rows.

These pin:
  1. the index pass populates the overlay with earliest-fix-version-wins +
     faithful per-CVE advisory_id provenance;
  2. per-product full refresh is idempotent AND removes rows for advisories
     aged off the index (the DELETE-then-INSERT difference vs INSERT OR REPLACE);
  3. ``history=True`` recovers the pre-index CVE the live index misses and
     replaces an index sighting with an earlier historical one, while
     ``history=False`` does not (the index-only map stands);
  4. cross-product advisories (Safari for iOS) never contaminate the overlay;
  5. a failed index fetch is a no-op (touches nothing); unknown product errors;
  6. no-wipe: the overlay never touches verdicts;
  7. the spine export/import round-trips the overlay identical; no device data.

All offline: ``curl_get`` (the apple_advisory binding the ingest tick routes
through) is monkeypatched to serve the bundled HTML fixtures + a fake Wayback
CDX/snapshot. NVD_API_KEY never touched. Fixtures under posture/fixtures/apple_advisory/
(shared with tests/test_apple_backfill.py).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from posture import store, export
from posture.sources import apple_ingest as _ai
from posture.sources.apple_advisory import advisory_id_of
import posture.sources.apple_advisory as _aa

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
APPLE = FIXTURE_DIR / "apple_advisory"
INDEX_HTML = (APPLE / "index.html").read_text()
SNAPSHOT_HTML = (APPLE / "ht1222_snapshot.html").read_text()
ADV = {a: (APPLE / f"{a}.html").read_text()
       for a in ("HT111111", "HT222222", "HT333333", "HT444444", "HT555555")}


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _ingest_curl(monkeypatch, index_html=INDEX_HTML, snapshot=SNAPSHOT_HTML,
                 advisories=ADV, cdx_rows=None, index_ok=True):
    """Monkeypatch the apple_advisory curl binding the ingest tick routes every
    network read through. Serves the index, the Wayback CDX JSON, Wayback
    snapshot pages, and per-advisory pages from fixtures. ``index_ok=False``
    simulates an index outage (non-200)."""
    if cdx_rows is None:
        # row[0] is the CDX header (skipped), row[1] carries the timestamp.
        cdx_rows = [["hdr"], ["support.apple.com/en-us/HT1222", "20210601000000"]]

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        if "web.archive.org/cdx" in url:
            return cdx_rows, 200, "[]"
        if "web.archive.org/web/" in url:
            return None, 200, snapshot
        if "100100" in url:
            if not index_ok:
                return None, 503, ""
            return None, 200, index_html
        return None, 200, advisories.get(advisory_id_of(url), "")
    monkeypatch.setattr(_aa, "curl_get", fake_curl_get)


# --- populates the overlay (earliest-wins + advisory provenance) --------------

def test_apple_ingest_populates_overlay_iphone_os(conn, monkeypatch):
    _ingest_curl(monkeypatch)
    stats = _ai.apple_ingest_tick(conn, product="iphone_os", now="t1")
    assert stats["error"] is None
    assert stats["rows"] == 3                       # 99910, 99911, 99912
    assert stats["index_cves"] == 3
    rows = store.apple_fixes_for_product(conn, "iphone_os")
    by_cve = {r["cve_id"]: r for r in rows}
    assert by_cve["CVE-2026-99910"]["fixed_in"] == "16.7.15"   # earliest, not 17.1
    assert by_cve["CVE-2026-99911"]["fixed_in"] == "16.7.15"
    assert by_cve["CVE-2026-99912"]["fixed_in"] == "17.1"
    # advisory_id provenance names the advisory that states each earliest fix
    assert by_cve["CVE-2026-99910"]["advisory_id"] == "HT111111"
    assert by_cve["CVE-2026-99912"]["advisory_id"] == "HT222222"
    assert by_cve["CVE-2026-99910"]["fetched_at"] == "t1"


def test_apple_ingest_macos_product(conn, monkeypatch):
    _ingest_curl(monkeypatch)
    stats = _ai.apple_ingest_tick(conn, product="macos", now="t1")
    assert stats["rows"] == 1
    rows = store.apple_fixes_for_product(conn, "macos")
    assert rows[0]["cve_id"] == "CVE-2026-99920"
    assert rows[0]["fixed_in"] == "26.5"
    assert rows[0]["advisory_id"] == "HT333333"


def test_apple_ingest_products_are_isolated(conn, monkeypatch):
    # iphone_os rows do not leak into macos and vice versa (composite PK).
    _ingest_curl(monkeypatch)
    _ai.apple_ingest_tick(conn, product="iphone_os", now="t1")
    _ai.apple_ingest_tick(conn, product="macos", now="t1")
    assert store.apple_fixes_for(conn, "CVE-2026-99920", "iphone_os") is None
    assert store.apple_fixes_for(conn, "CVE-2026-99920", "macos") is not None
    assert store.apple_fixes_for(conn, "CVE-2026-99910", "macos") is None
    all_rows = store.apple_fixes_all(conn)
    assert {r["product"] for r in all_rows} == {"iphone_os", "macos"}


# --- per-product full refresh: idempotent + drops aged-off advisories ----------

def test_apple_ingest_idempotent_re_ingest_replaces(conn, monkeypatch):
    _ingest_curl(monkeypatch)
    _ai.apple_ingest_tick(conn, product="iphone_os", now="t1")
    n1 = conn.execute("SELECT COUNT(*) FROM apple_fixes WHERE product='iphone_os'").fetchone()[0]
    _ai.apple_ingest_tick(conn, product="iphone_os", now="t2")
    n2 = conn.execute("SELECT COUNT(*) FROM apple_fixes WHERE product='iphone_os'").fetchone()[0]
    assert n1 == n2 == 3                       # full refresh, not append
    # the refreshed fetched_at propagated
    rows = store.apple_fixes_for_product(conn, "iphone_os")
    assert all(r["fetched_at"] == "t2" for r in rows)


def test_apple_ingest_full_refresh_drops_aged_off_advisory(conn, monkeypatch):
    # The key DELETE-then-INSERT difference vs INSERT OR REPLACE: when an
    # advisory ages off the rolling index, its CVE must NOT linger as a stale
    # row. Simulate the index losing the HT222222 (17.1) row on a re-ingest.
    _ingest_curl(monkeypatch)
    _ai.apple_ingest_tick(conn, product="iphone_os", now="t1")
    assert store.apple_fixes_for(conn, "CVE-2026-99912", "iphone_os") is not None
    # rebuild the index WITHOUT the 17.1 row (HT222222 aged off)
    aged_off = INDEX_HTML.replace(
        '      <a href="https://support.apple.com/en-us/HT222222">iOS 17.1 and '
        'iPadOS 17.1</a>\n      &mdash; released 2025\n    </li>\n', "")
    assert "HT222222" not in aged_off
    _ingest_curl(monkeypatch, index_html=aged_off)
    _ai.apple_ingest_tick(conn, product="iphone_os", now="t2")
    assert store.apple_fixes_for(conn, "CVE-2026-99912", "iphone_os") is None
    # 99910 + 99911 (from HT111111, still on the index) remain
    assert store.apple_fixes_for(conn, "CVE-2026-99910", "iphone_os") is not None
    assert conn.execute("SELECT COUNT(*) FROM apple_fixes WHERE product='iphone_os'").fetchone()[0] == 2


# --- history=True recovers pre-index CVEs; history=False does not --------------

def test_apple_ingest_history_recovers_pre_index_cve(conn, monkeypatch):
    # CVE-2026-99920 is fixed only in the pre-index HT444444 (iOS 15.7.1); the
    # live index does not cover it for iphone_os. history=True recovers it.
    _ingest_curl(monkeypatch)
    stats = _ai.apple_ingest_tick(conn, product="iphone_os", history=True, now="t1")
    assert stats["error"] is None
    assert stats["history_cves_added"] >= 1
    row = store.apple_fixes_for(conn, "CVE-2026-99920", "iphone_os")
    assert row is not None
    assert row["fixed_in"] == "15.7.1"
    assert row["advisory_id"] == "HT444444"


def test_apple_ingest_history_earliest_wins_replaces_index_sighting(conn, monkeypatch):
    # CVE-2026-99910 is on the index at 16.7.15 but re-mentioned in the
    # pre-index HT444444 at 15.7.1 (strictly earlier) -> the overlay must keep
    # 15.7.1 with advisory_id HT444444.
    _ingest_curl(monkeypatch)
    _ai.apple_ingest_tick(conn, product="iphone_os", history=True, now="t1")
    row = store.apple_fixes_for(conn, "CVE-2026-99910", "iphone_os")
    assert row["fixed_in"] == "15.7.1"
    assert row["advisory_id"] == "HT444444"


def test_apple_ingest_history_false_does_not_recover_pre_index(conn, monkeypatch):
    # history=False (default): 99920 is absent (the index does not cover it for
    # iphone_os); 99910 keeps the index's 16.7.15.
    _ingest_curl(monkeypatch)
    _ai.apple_ingest_tick(conn, product="iphone_os", now="t1")
    assert store.apple_fixes_for(conn, "CVE-2026-99920", "iphone_os") is None
    assert store.apple_fixes_for(conn, "CVE-2026-99910", "iphone_os")["fixed_in"] == "16.7.15"


def test_apple_ingest_history_skips_cross_product_advisory(conn, monkeypatch):
    # HT555555 is a Safari advisory; its CVE-2026-99930 must never enter the
    # iphone_os overlay, even with history on.
    _ingest_curl(monkeypatch)
    _ai.apple_ingest_tick(conn, product="iphone_os", history=True, now="t1")
    assert store.apple_fixes_for(conn, "CVE-2026-99930", "iphone_os") is None


def test_apple_ingest_history_best_effort_when_wayback_down(conn, monkeypatch):
    # Wayback CDX returns no snapshots (header only) -> no historical URLs ->
    # the index map stands; the run is a success, not an error.
    _ingest_curl(monkeypatch, cdx_rows=[["hdr"]])
    stats = _ai.apple_ingest_tick(conn, product="iphone_os", history=True, now="t1")
    assert stats["error"] is None
    assert stats["rows"] == 3                      # index-only map
    assert store.apple_fixes_for(conn, "CVE-2026-99920", "iphone_os") is None


# --- fetch failure is a no-op; unknown product errors -------------------------

def test_apple_ingest_index_fetch_failure_is_noop(conn, monkeypatch):
    _ingest_curl(monkeypatch, index_ok=False)
    stats = _ai.apple_ingest_tick(conn, product="iphone_os", now="t1")
    assert stats["error"] is not None
    assert stats["rows"] == 0
    assert conn.execute("SELECT COUNT(*) FROM apple_fixes").fetchone()[0] == 0


def test_apple_ingest_unknown_product_errors(conn, monkeypatch):
    _ingest_curl(monkeypatch)
    stats = _ai.apple_ingest_tick(conn, product="watchos", now="t1")
    assert stats["error"] is not None
    assert "watchos" in stats["error"]
    # no fetch attempted for an unknown product (no curl into apple's index)
    assert conn.execute("SELECT COUNT(*) FROM apple_fixes").fetchone()[0] == 0


# --- no-wipe: the overlay never touches verdicts -----------------------------

def test_apple_ingest_does_not_touch_verdicts(conn, monkeypatch):
    store.upsert_verdict(conn, {
        "device_id": "host", "axis": "vulnerability", "key": "CVE-2026-99910",
        "status": "unpatched", "severity": "HIGH", "fixed_in": None,
        "detail": "prior", "provenance": {"observer": "nvd",
                                          "policy_version": "v",
                                          "fetched_at": "t", "complete": 1},
    }, "t")
    conn.commit()
    _ingest_curl(monkeypatch)
    _ai.apple_ingest_tick(conn, product="iphone_os", now="t")
    rows = store.verdicts_for_device_axis(conn, "host", "vulnerability")
    assert len(rows) == 1 and rows[0]["key"] == "CVE-2026-99910"
    assert rows[0]["status"] == "unpatched"      # verdict untouched


# --- export/import round-trip (apple_fixes is a flat table) -------------------

def test_apple_ingest_export_import_round_trip(conn, monkeypatch, tmp_path):
    _ingest_curl(monkeypatch)
    _ai.apple_ingest_tick(conn, product="iphone_os", history=True, now="t1")
    _ai.apple_ingest_tick(conn, product="macos", now="t1")
    conn.commit()

    out = tmp_path / "out"
    manifest = export.export_spine(conn, out_dir=out, policy_version="v")
    assert manifest["counts"]["apple_fixes"] >= 4
    assert (out / "spine" / "apple_fixes.jsonl").exists()

    other = store.connect(":memory:")
    stats = export.import_spine(other, from_dir=out)
    assert stats["apple_fixes"] == manifest["counts"]["apple_fixes"]
    # the overlay rows survive the round trip identical (ordered by product,cve)
    assert store.apple_fixes_all(conn) == store.apple_fixes_all(other)


def test_apple_ingest_export_has_no_device_data(conn, monkeypatch, tmp_path):
    _ingest_curl(monkeypatch)
    _ai.apple_ingest_tick(conn, product="iphone_os", now="t1")
    conn.commit()
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    assert not (out / "spine" / "verdicts.jsonl").exists()
    text = (out / "spine" / "apple_fixes.jsonl").read_text()
    assert "device_id" not in text and "verdict" not in text.lower()