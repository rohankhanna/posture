"""Catalog-backed assess tests — the release condition that retires the
live-curl NVD path at assess time. ``NvdCveObserver`` reads the imported
spine defects table (injected by the territory pre-pass as
``device["catalog_defects"]``) and decides verdicts with NO network and NO
fixture file, reusing the SAME ``decide_cve_for_device`` logic as a live pull.

The load-bearing test is the PARITY property: for an identical CVE, the
catalog path and the fixture path emit byte-identical verdicts. The catalog
row is built by ``refresh._enriched_record`` — the exact function CI ingestion
uses — so this pins the real round-trip, not a hand-rolled shape.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from posture import store, engine
from posture.axis import Axis
from posture.policy import Policy, default_policy_path
from posture.sources import build_default_registry
from posture.sources.nvd_cve import NvdCveObserver, _cpe_head
from posture.refresh import _enriched_record

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
SAMPLE_DEVICE = FIXTURE_DIR / "sample_device.yaml"
NVD_SAMPLE = FIXTURE_DIR / "nvd_sample.json"


def _sample_device():
    return yaml.safe_load(SAMPLE_DEVICE.read_text())


def _nvd_page():
    return json.loads(NVD_SAMPLE.read_text())


def _seed_catalog_from_fixture(conn) -> None:
    """Build the catalog the way CI does: turn each fixture NVD cve into an
    enriched defect row via ``_enriched_record`` + ``upsert_defect``."""
    for v in _nvd_page()["vulnerabilities"]:
        row = _enriched_record(v["cve"], policy_version="v", fetched_at="2026-08-22")
        store.upsert_defect(conn, row)
        store.set_enrich_state(conn, row["id"], "nvd")
    conn.commit()


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


# --- store read path ---------------------------------------------------------

def test_defects_for_cpe_head_returns_only_matching_nvd_rows(conn):
    _seed_catalog_from_fixture(conn)
    head = _cpe_head("cpe:2.3:o:linux:linux_kernel")
    rows = store.defects_for_cpe_head(conn, head)
    ids = sorted(r["id"] for r in rows)
    # the 4 linux_kernel CVEs; the iphone_os-only 99905 is excluded
    assert ids == ["CVE-2026-99901", "CVE-2026-99902",
                   "CVE-2026-99903", "CVE-2026-99904"]
    # parsed shape: fixed_raw is a dict carrying the cpe heads + ranges
    r0 = rows[0]
    assert isinstance(r0["fixed_raw"], dict)
    assert head in r0["fixed_raw"]["cpe_heads"]
    assert r0["fixed_raw"]["ranges"]


def test_defects_for_cpe_head_excludes_osv_rows_without_cpe_heads(conn):
    """OSV/GHSA rows are ecosystem-shaped (no cpe_heads) -> never match a CPE
    head, even when they sit beside NVD rows in the same catalog."""
    _seed_catalog_from_fixture(conn)
    # an OSV-style self-enriched row (no cpe_heads, source='osv')
    store.upsert_defect(conn, {
        "id": "PYSEC-2026-1", "published": "2026-08-01", "description": "p",
        "fixed_raw": {"source": "osv", "ranges": []}, "refs": [],
        "source": "osv", "fetched_at": "now", "policy_version": "v",
        "complete": 1,
    })
    conn.commit()
    head = _cpe_head("cpe:2.3:o:linux:linux_kernel")
    ids = {r["id"] for r in store.defects_for_cpe_head(conn, head)}
    assert "PYSEC-2026-1" not in ids
    assert "CVE-2026-99901" in ids


def test_defects_for_cpe_head_skips_distrusted_rows(conn):
    """A retroactively-distrusted coordinate is not re-emitted as a verdict."""
    _seed_catalog_from_fixture(conn)
    store.mark_defect_distrust(conn, "CVE-2026-99901", "captured source")
    conn.commit()
    head = _cpe_head("cpe:2.3:o:linux:linux_kernel")
    ids = {r["id"] for r in store.defects_for_cpe_head(conn, head)}
    assert "CVE-2026-99901" not in ids
    assert "CVE-2026-99902" in ids  # the rest still returned


def test_defects_for_cpe_head_empty_when_no_match(conn):
    _seed_catalog_from_fixture(conn)
    head = _cpe_head("cpe:2.3:o:vendor:nonexistent")
    assert store.defects_for_cpe_head(conn, head) == []


# --- observer catalog path: the parity property -----------------------------

def test_catalog_assess_matches_fixture_assess_verdict_for_verdict(conn):
    """THE parity test: the catalog path and the fixture path emit identical
    verdicts for the same CVEs. Builds the catalog the way CI does
    (``_enriched_record`` -> ``upsert_defect``), injects ``catalog_defects``,
    and compares against the offline-fixture observer run."""
    _seed_catalog_from_fixture(conn)
    head = _cpe_head("cpe:2.3:o:linux:linux_kernel")
    device = _sample_device()
    device["catalog_defects"] = {head: store.defects_for_cpe_head(conn, head)}

    pol = Policy.from_file(default_policy_path())
    cat = NvdCveObserver(live=False).assess(device, pol)
    fix = NvdCveObserver(live=False).assess(_sample_device(), pol)

    assert cat.complete is True
    assert fix.complete is True
    assert len(cat.verdicts) == len(fix.verdicts) == 4
    by_cat = {v.key: v for v in cat.verdicts}
    by_fix = {v.key: v for v in fix.verdicts}
    assert set(by_cat) == set(by_fix)
    for key in by_fix:
        cv, fv = by_cat[key], by_fix[key]
        assert cv.status == fv.status, key
        assert cv.fixed_in == fv.fixed_in, key
        assert cv.severity == fv.severity, key
        assert cv.detail == fv.detail, key
        assert cv.cvss == fv.cvss, key
        assert cv.cvss_vector == fv.cvss_vector, key
        # published: the catalog path truncates to the date part (YYYY-MM-DD)
        # via _enriched_record; the fixture path carries the full NVD timestamp.
        # Both must be non-None and agree on the date prefix.
        assert cv.published is not None and fv.published is not None, key
        assert fv.published.startswith(cv.published), key
        assert cv.provenance.observer == "nvd"
    # spot-check the four known verdicts (pinned by the fixture test too)
    assert by_cat["CVE-2026-99901"].status == "unpatched"
    assert by_cat["CVE-2026-99901"].fixed_in == "6.18.5"
    assert by_cat["CVE-2026-99901"].severity == "CRITICAL"
    assert by_cat["CVE-2026-99902"].status == "patched"
    assert by_cat["CVE-2026-99903"].status == "unpatched"
    assert by_cat["CVE-2026-99904"].status == "not_affected"
    assert cat.reason == "catalog"


def test_catalog_assess_empty_head_is_complete_absent_not_fixture_leak(conn):
    """A head the spine covers with ZERO rows is a COMPLETE-absent answer —
    the catalog path returns no verdicts, NOT the bundled fixture's sample
    CVEs. (A real client must never inherit the demo fixture's linux verdicts
    for a CPE the spine simply doesn't list.)"""
    _seed_catalog_from_fixture(conn)
    device = _sample_device()
    # ask for a head the spine has no rows for, but DO inject (catalog present)
    head = _cpe_head("cpe:2.3:o:vendor:nonexistent")
    device["matchers"] = [{"type": "nvd_cpe", "cpe": "cpe:2.3:o:vendor:nonexistent",
                          "version": "1.0"}]
    device["catalog_defects"] = {head: store.defects_for_cpe_head(conn, head)}
    pol = Policy.from_file(default_policy_path())
    result = NvdCveObserver(live=False).assess(device, pol)
    assert result.complete is True
    assert result.verdicts == []  # absent, NOT the 4 fixture linux verdicts


def test_catalog_assess_takes_precedence_over_fixture_when_present(conn):
    """When the territory injects ``catalog_defects``, the offline observer
    uses the catalog (no fixture), even for the demo device whose matcher head
    the fixture would otherwise serve. Confirms the precedence order on the
    non-live branch: catalog > fixture."""
    _seed_catalog_from_fixture(conn)
    head = _cpe_head("cpe:2.3:o:linux:linux_kernel")
    device = _sample_device()
    # inject ONLY 99901 -> the catalog path must see just that one, not the
    # fixture's 4
    rows = [r for r in store.defects_for_cpe_head(conn, head)
            if r["id"] == "CVE-2026-99901"]
    device["catalog_defects"] = {head: rows}
    pol = Policy.from_file(default_policy_path())
    result = NvdCveObserver(live=False).assess(device, pol)
    assert result.reason == "catalog"
    assert [v.key for v in result.verdicts] == ["CVE-2026-99901"]


def test_live_still_wins_over_catalog(conn, monkeypatch):
    """An explicit ``--live`` operator pull wins even when a catalog is
    injected — the operator asked for the network. (Mocked curl so no real
    network; asserts the catalog is NOT consulted.)"""
    page = _nvd_page()
    calls = []

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        calls.append(url)
        return page, 200, json.dumps(page)

    monkeypatch.setattr("posture.sources.nvd_cve.curl_get", fake_curl_get)
    _seed_catalog_from_fixture(conn)
    head = _cpe_head("cpe:2.3:o:linux:linux_kernel")
    device = _sample_device()
    device["catalog_defects"] = {head: store.defects_for_cpe_head(conn, head)}
    pol = Policy.from_file(default_policy_path())
    result = NvdCveObserver(live=True).assess(device, pol)
    assert result.complete is True
    assert len(result.verdicts) == 4  # the live page, not the catalog
    assert calls, "live curl_get was called (catalog was NOT used)"


# --- the territory pre-pass wiring ------------------------------------------

def test_inject_catalog_defects_only_when_db_has_nvd_rows(conn):
    """A fresh/demo DB (no NVD rows) -> ``catalog_defects`` is left ABSENT so
    the observer falls back to its fixture (preserves ``posture demo``). A DB
    that mirrors a real spine -> every nvd_cpe head is injected, empty heads
    included (complete-absent, not a fixture leak)."""
    from posture.cli import _inject_catalog_defects

    device = _sample_device()
    # fresh DB: no injection
    _inject_catalog_defects(device, conn)
    assert "catalog_defects" not in device

    # now seed a real spine
    _seed_catalog_from_fixture(conn)
    _inject_catalog_defects(device, conn)
    assert "catalog_defects" in device
    head = _cpe_head("cpe:2.3:o:linux:linux_kernel")
    assert head in device["catalog_defects"]
    assert len(device["catalog_defects"][head]) == 4


def test_inject_catalog_defects_never_clobbers_operator_input(conn):
    from posture.cli import _inject_catalog_defects
    _seed_catalog_from_fixture(conn)
    device = _sample_device()
    device["catalog_defects"] = {"preset": []}  # operator/hermetic override
    _inject_catalog_defects(device, conn)
    assert device["catalog_defects"] == {"preset": []}


def test_full_engine_assess_is_network_free_offline_with_spine(conn):
    """End-to-end: with a real spine in the DB, ``engine.assess`` (conn, no
    --live) produces the vulnerability axis from the catalog — the path the
    weatherman client takes, with zero network. The verdicts match the fixture
    run, and the axis is decided by the nvd observer reading the spine."""
    _seed_catalog_from_fixture(conn)
    reg = build_default_registry()
    pol = Policy.from_file(default_policy_path())
    device = _sample_device()
    from posture.cli import _inject_catalog_overlays
    _inject_catalog_overlays(device, conn)
    dp = engine.assess(device, reg, pol, conn=conn, now="2026-08-22T00:00:00+00:00")
    by_axis = {a.axis: a for a in dp.axes}
    assert by_axis["vulnerability"].status == "unpatched"
    assert by_axis["vulnerability"].deciding_observer == "nvd"
    assert by_axis["vulnerability"].commit_state == "swapped"
    assert "nvd" in dp.used_observers


def test_full_engine_assess_falls_back_to_fixture_on_fresh_db():
    """The other half of the wiring contract: a fresh DB (demo / first run,
    no spine imported yet) leaves ``catalog_defects`` absent, so the engine
    run against a fresh memory DB still serves the demo fixture's 4 linux
    verdicts — ``posture demo`` is unchanged."""
    conn = store.connect(":memory:")
    reg = build_default_registry()
    pol = Policy.from_file(default_policy_path())
    device = _sample_device()
    from posture.cli import _inject_catalog_overlays
    _inject_catalog_overlays(device, conn)
    assert "catalog_defects" not in device  # fresh DB -> fixture fallback
    dp = engine.assess(device, reg, pol, conn=conn, now="2026-08-22T00:00:00+00:00")
    by_axis = {a.axis: a for a in dp.axes}
    assert by_axis["vulnerability"].status == "unpatched"  # 4 fixture verdicts
    assert "nvd" in dp.used_observers

# --- verdict fidelity: cvss, cvss_vector, published --------------------------

def test_fixture_verdicts_carry_real_cvss_vector_and_published():
    """The NvdCveObserver populates the real numeric CVSS score, CVSS vector
    string, and publish date on each Verdict — not just the severity string.
    This is the fidelity gap that the posture adapter previously worked around
    with threshold-mapped severity→cvss; now the real values flow through."""
    device = _sample_device()
    pol = Policy.from_file(default_policy_path())
    result = NvdCveObserver(live=False).assess(device, pol)
    assert result.complete is True
    assert len(result.verdicts) == 4
    for v in result.verdicts:
        assert v.cvss is not None, f"{v.key}: cvss should be populated"
        assert v.cvss_vector is not None, f"{v.key}: cvss_vector should be populated"
        assert v.published is not None, f"{v.key}: published should be populated"
    # spot-check known fixture values
    by_key = {v.key: v for v in result.verdicts}
    crit = by_key["CVE-2026-99901"]
    assert crit.severity == "CRITICAL"
    assert crit.cvss >= 9.0  # CRITICAL threshold
    assert crit.cvss_vector.startswith("CVSS:")
    assert len(crit.published) >= 10  # ISO date


def test_catalog_verdicts_carry_real_cvss_vector_and_published(conn):
    """The catalog-backed assess path also populates cvss, cvss_vector, and
    published — the _defect_row_to_vuln reconstruction includes them so
    the catalog path matches the fixture path on the new fields too."""
    _seed_catalog_from_fixture(conn)
    head = _cpe_head("cpe:2.3:o:linux:linux_kernel")
    device = _sample_device()
    device["catalog_defects"] = {head: store.defects_for_cpe_head(conn, head)}
    pol = Policy.from_file(default_policy_path())
    result = NvdCveObserver(live=False).assess(device, pol)
    assert result.complete is True
    assert len(result.verdicts) == 4
    for v in result.verdicts:
        assert v.cvss is not None, f"{v.key}: cvss should be populated from catalog"
        assert v.cvss_vector is not None, f"{v.key}: cvss_vector should be populated from catalog"
        assert v.published is not None, f"{v.key}: published should be populated from catalog"
