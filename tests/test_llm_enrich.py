"""Source-agnostic LLM enrichment tests — the LLM-as-map / human-as-trust
invariant. The LLM drafts catalog MAP fields only; drafted rows carry
source='llm:<model>' and are STRUCTURALLY BARRED from the assess trust-decide
path (which selects source='nvd' only). No real provider is wired — a stub
draft_fn is injected; POSTURE_LLM is kept unset so the off-by-default seam is
exercised as it ships.
"""
from __future__ import annotations

import os

import pytest

from posture import store, llm_enrich, export
from posture.sources.nvd_cve import _cpe_head


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _skeleton(conn, cid, published="2026-08-01", source="mitre",
              fixed_raw=None, cvss=None, cvss_vector=None):
    """Insert a defect row of a given provenance. Defaults to a thin/unscored
    skeleton (no cvss, no vector, no usable ranges) — the LLM draft target."""
    store.upsert_defect(conn, {
        "id": cid, "published": published, "description": "skeleton",
        "cvss": cvss, "cvss_vector": cvss_vector,
        "fixed_raw": fixed_raw or {"source": source, "pending_nvd": True},
        "refs": [], "source": source, "fetched_at": "t", "policy_version": "v",
        "complete": 1,
    })
    store.set_enrich_state(conn, cid, "mitre" if source == "mitre" else source)


def _enriched_nvd(conn, cid="CVE-NVD-1", head="cpe:2.3:o:vendor:product",
                  vstart="6.0", vend_excl="6.5"):
    """A real NVD-enriched row (source='nvd', has cvss + a CPE range) — NOT thin,
    and the only kind the assess decide path is allowed to read."""
    rng = {"criteria": f"{head}:*:*:*:*:*:*", "head": head,
           "vstart_incl": vstart, "vend_excl": vend_excl}
    store.upsert_defect(conn, {
        "id": cid, "published": "2026-08-02", "cvss": 9.9,
        "severity": "CRITICAL", "cvss_vector": "CVSS:3.1/AV:N/AC:L/C:H/I:H/A:H",
        "description": "real nvd vuln",
        "fixed_raw": {"source": "nvd", "ranges": [rng], "cpe_heads": [head]},
        "refs": ["https://example/x"], "cwe": ["CWE-89"],
        "ref_tags": ["Vendor Advisory"], "source": "nvd", "fetched_at": "t2",
        "policy_version": "v", "complete": 1,
    })
    store.set_enrich_state(conn, cid, "nvd")
    return cid


# --- thin selector: source-agnostic ----------------------------------------

def test_thin_selector_picks_unscored_across_sources(conn):
    """The selector is source-agnostic: a thin mitre skeleton, a thin osv row,
    and a thin ghsa row are all eligible; an NVD-enriched row (has cvss+ranges)
    and an existing llm-draft row are excluded."""
    _skeleton(conn, "CVE-M", source="mitre")
    _skeleton(conn, "GHSA-1", source="ghsa", fixed_raw={"source": "ghsa"})
    _skeleton(conn, "OSV-1", source="osv", fixed_raw={"source": "osv"})
    _enriched_nvd(conn)  # not thin
    _skeleton(conn, "CVE-LLM", source="llm:stub")  # already drafted -> excluded
    store.set_enrich_state(conn, "CVE-LLM", "llm")
    ids = llm_enrich.thin_defect_ids(conn)
    assert set(ids) == {"CVE-M", "GHSA-1", "OSV-1"}
    assert "CVE-NVD-1" not in ids and "CVE-LLM" not in ids


def test_thin_selector_source_filter_mitre_is_nvd_thin(conn):
    """source='mitre' is the NVD-thin case this generalizes from: skeletons NVD
    never enriched. The filter restricts to one provenance's thin rows."""
    _skeleton(conn, "CVE-M", source="mitre")
    _skeleton(conn, "OSV-1", source="osv", fixed_raw={"source": "osv"})
    ids = llm_enrich.thin_defect_ids(conn, source="mitre")
    assert ids == ["CVE-M"]
    assert "OSV-1" not in ids


def test_thin_selector_excludes_rows_with_ranges_or_score(conn):
    """A row is thin only when it lacks cvss, vector, AND usable ranges."""
    _skeleton(conn, "THIN", source="mitre")
    # has a CPE-shaped range -> not thin
    _skeleton(conn, "HASRANGE", source="mitre",
              fixed_raw={"source": "mitre", "ranges": [{"criteria": "cpe:x"}]})
    # has cvss -> not thin
    _skeleton(conn, "HASSCORE", source="mitre", cvss=7.5)
    ids = llm_enrich.thin_defect_ids(conn)
    assert ids == ["THIN"]


def test_thin_selector_excludes_distrusted(conn):
    """A retroactively-distrusted map point is not re-enriched by an LLM."""
    _skeleton(conn, "DIST", source="mitre")
    store.mark_defect_distrust(conn, "DIST", "audit")
    assert "DIST" not in llm_enrich.thin_defect_ids(conn)


# --- upsert: invariant — fill empty, label, never touch trust --------------

def test_upsert_llm_draft_fills_empty_fields_and_labels(conn):
    """A draft fills the empty catalog fields and stamps source='llm:<model>'
    + enrich_state='llm'. Trust columns (distrusted/distrust_reason) and
    first-sighting (discovered_at) are never touched."""
    _skeleton(conn, "CVE-M", source="mitre")
    drafted = {"cvss": 7.5, "severity": "HIGH",
               "cvss_vector": "CVSS:3.1/AV:N/AC:L",
               "description": "llm-drafted desc",
               "refs": ["https://example/d"],
               "fixed_raw": {"ranges": [{"criteria": "cpe:2.3:o:v:p"}],
                              "cpe_heads": ["cpe:2.3:o:v:p"]}}
    ok = llm_enrich.upsert_llm_draft(conn, "CVE-M", drafted, model="stub")
    assert ok is True
    row = store.get_defect(conn, "CVE-M")
    assert row["source"] == "llm:stub"
    assert row["enrich_state"] == "llm"
    assert row["cvss"] == 7.5 and row["severity"] == "HIGH"
    assert row["refs"] == ["https://example/d"]
    assert (row["fixed_raw"] or {}).get("cpe_heads") == ["cpe:2.3:o:v:p"]
    assert llm_enrich.is_llm_draft(row) is True


def test_llm_draft_does_not_overwrite_real_source(conn):
    """If a real source enriched the row between selection and write (source is
    a non-llm real value AND the row is no longer thin), the draft is SKIPPED —
    the foreign-authored map point wins. The LLM never clobbers a real source."""
    _enriched_nvd(conn, cid="CVE-REAL")  # source='nvd', has cvss+ranges
    drafted = {"cvss": 1.1, "severity": "LOW"}
    ok = llm_enrich.upsert_llm_draft(conn, "CVE-REAL", drafted, model="stub")
    assert ok is False
    row = store.get_defect(conn, "CVE-REAL")
    assert row["source"] == "nvd"  # untouched
    assert row["cvss"] == 9.9  # real value kept, not overwritten with 1.1


def test_upsert_llm_draft_never_touches_trust_columns(conn):
    """The LLM may never set distrusted / distrust_reason. A draft over a row
    that was retroactively-distrusted leaves the distrust mark intact."""
    _skeleton(conn, "CVE-M", source="mitre")
    store.mark_defect_distrust(conn, "CVE-M", "audit-reason")
    drafted = {"cvss": 5.0}
    llm_enrich.upsert_llm_draft(conn, "CVE-M", drafted, model="stub")
    row = store.get_defect(conn, "CVE-M")
    assert row["distrusted"] == 1
    assert row["distrust_reason"] == "audit-reason"
    # NOTE: thin_defect_ids excludes distrusted rows, so this draft would not
    # be reached through the tick; the direct call proves the column is honored.


def test_upsert_llm_draft_skips_when_nothing_new(conn):
    """A draft that adds nothing the row lacked (every provided field already
    present) is a no-op."""
    _skeleton(conn, "CVE-M", source="mitre",
              fixed_raw={"source": "mitre", "ranges": [{"criteria": "cpe:x"}]})
    # row has ranges; provide ranges only -> nothing new -> skip
    ok = llm_enrich.upsert_llm_draft(
        conn, "CVE-M", {"fixed_raw": {"ranges": [{"criteria": "cpe:x"}]}},
        model="stub")
    assert ok is False


# --- the STRUCTURAL BAR from the assess decide path ------------------------

def test_llm_draft_barred_from_assess_decide_path(conn):
    """THE INVARIANT: an llm-draft row is structurally barred from
    decide_cve_for_device. defects_for_cpe_head (the offline assess read path)
    selects source='nvd' ONLY, so an llm-draft row for the same CPE head never
    reaches the decision — regardless of the row carrying a matching range."""
    head = _cpe_head("cpe:2.3:o:vendor:product")
    # an llm-draft row that touches the same head as a real NVD row
    _skeleton(conn, "CVE-LLM", source="llm:stub",
              fixed_raw={"source": "llm", "ranges": [{"criteria": head}],
                         "cpe_heads": [head]})
    store.set_enrich_state(conn, "CVE-LLM", "llm")
    _enriched_nvd(conn, cid="CVE-NVD", head=head)
    rows = store.defects_for_cpe_head(conn, head)
    ids = [r["id"] for r in rows]
    assert ids == ["CVE-NVD"]  # the llm draft is excluded by construction
    assert "CVE-LLM" not in ids


def test_llm_draft_barred_from_catalog_defects_prepass(conn):
    """The territory pre-pass (_inject_catalog_defects) that feeds the NVD
    observer also selects source='nvd' only, so an llm-draft row never enters
    device['catalog_defects'] and can never be decided."""
    from posture.cli import _inject_catalog_defects
    head = _cpe_head("cpe:2.3:o:vendor:product")
    _skeleton(conn, "CVE-LLM", source="llm:stub",
              fixed_raw={"source": "llm", "ranges": [{"criteria": head}],
                         "cpe_heads": [head]})
    store.set_enrich_state(conn, "CVE-LLM", "llm")
    _enriched_nvd(conn, cid="CVE-NVD", head=head)
    device = {"id": "host", "matchers": [
        {"type": "nvd_cpe", "cpe": "cpe:2.3:o:vendor:product", "version": "6.2"}]}
    _inject_catalog_defects(device, conn)
    injected = device.get("catalog_defects", {})
    all_ids = [r["id"] for rows in injected.values() for r in rows]
    assert "CVE-NVD" in all_ids
    assert "CVE-LLM" not in all_ids  # barred from the observer's input


# --- real-source precedence over a prior draft -----------------------------

def test_real_enrichment_after_draft_overwrites(conn):
    """After an LLM draft, a real NVD enrichment overwrites the draft fields and
    the row is no longer llm-labeled — a foreign-authored map point always wins
    over an LLM draft."""
    _skeleton(conn, "CVE-M", source="mitre")
    llm_enrich.upsert_llm_draft(conn, "CVE-M",
                                {"cvss": 4.0, "severity": "MEDIUM"}, model="stub")
    assert store.get_defect(conn, "CVE-M")["source"] == "llm:stub"
    # a real NVD enrichment upserts the full row (source='nvd') and flips state
    _enriched_nvd(conn, cid="CVE-M")
    row = store.get_defect(conn, "CVE-M")
    assert row["source"] == "nvd"
    assert row["enrich_state"] == "nvd"
    assert row["cvss"] == 9.9  # real value overwrote the 4.0 draft


# --- no-wipe on draft failure ----------------------------------------------

def test_no_wipe_on_draft_fn_returns_none(conn):
    """A draft_fn that returns None skips the row; the tick never raises, never
    deletes, and the row stays thin for the next tick."""
    _skeleton(conn, "CVE-M", source="mitre")
    stats = llm_enrich.llm_enrich_tick(conn, lambda r: None, model="stub")
    assert stats["drafted"] == 0 and stats["skipped"] == 1
    row = store.get_defect(conn, "CVE-M")
    assert row["source"] == "mitre"  # untouched, not wiped


def test_no_wipe_on_draft_fn_raises(conn):
    """A draft_fn that raises skips the row (counted as an error); the tick
    never raises out and never deletes. Other rows still draft."""
    _skeleton(conn, "BOOM", source="mitre")
    _skeleton(conn, "OK", source="osv", fixed_raw={"source": "osv"})

    def draft(row):
        if row["id"] == "BOOM":
            raise RuntimeError("provider blew up")
        return {"cvss": 5.5, "severity": "MEDIUM"}

    stats = llm_enrich.llm_enrich_tick(conn, draft, model="stub")
    assert stats["errors"] == 1 and stats["drafted"] == 1
    assert store.get_defect(conn, "BOOM")["source"] == "mitre"  # untouched
    assert store.get_defect(conn, "OK")["source"] == "llm:stub"


def test_tick_is_source_agnostic_across_mixed_pool(conn):
    """One tick drafts thin rows from multiple sources at once — the
    source-agnostic claim. Each is labeled with the same llm:<model> source."""
    _skeleton(conn, "CVE-M", source="mitre")
    _skeleton(conn, "GHSA-1", source="ghsa", fixed_raw={"source": "ghsa"})
    _skeleton(conn, "OSV-1", source="osv", fixed_raw={"source": "osv"})

    def draft(row):
        return {"cvss": 6.6, "severity": "MEDIUM",
                "description": "drafted"}

    stats = llm_enrich.llm_enrich_tick(conn, draft, model="stub", cap=10)
    assert stats["drafted"] == 3
    for cid in ("CVE-M", "GHSA-1", "OSV-1"):
        r = store.get_defect(conn, cid)
        assert r["source"] == "llm:stub" and r["enrich_state"] == "llm"
        assert r["cvss"] == 6.6


# --- the off-by-default seam ----------------------------------------------

def test_default_seam_off_by_default_no_posture_llm(monkeypatch):
    """With POSTURE_LLM unset, default_draft_fn returns None — the LLM never
    runs. A tick over it drafts nothing and reports the selected count."""
    monkeypatch.delenv("POSTURE_LLM", raising=False)

    def fake_conn():
        c = store.connect(":memory:")
        _skeleton(c, "CVE-M", source="mitre")
        return c

    c = fake_conn()
    stats = llm_enrich.llm_enrich_tick(c, llm_enrich.default_draft_fn, "stub")
    assert stats["selected"] == 1 and stats["drafted"] == 0
    assert store.get_defect(c, "CVE-M")["source"] == "mitre"  # untouched


def test_default_seam_raises_when_posture_llm_set_unwired(monkeypatch):
    """POSTURE_LLM set but no real provider wired -> the seam raises (per-row
    error), so no draft ever ships until a real draft_fn is supplied."""
    monkeypatch.setenv("POSTURE_LLM", "1")
    with pytest.raises(RuntimeError):
        llm_enrich.default_draft_fn({"id": "x"})
    monkeypatch.delenv("POSTURE_LLM", raising=False)


# --- publish-labeled: export round-trip preserves the llm label -----------

def test_llm_draft_export_roundtrip_preserves_label(conn, tmp_path):
    """Under spine policy B (publish-labeled), an llm-draft row flows through
    export unchanged and re-imports with source='llm:<model>' + enrich_state
    'llm' intact — the label is the honesty mechanism (a draft is never
    mistaken for a foreign-authored map point)."""
    _skeleton(conn, "CVE-M", source="mitre")
    llm_enrich.upsert_llm_draft(conn, "CVE-M",
                                {"cvss": 7.0, "severity": "HIGH"}, model="stub")
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    other = store.connect(":memory:")
    export.import_spine(other, from_dir=out)
    row = store.get_defect(other, "CVE-M")
    assert row["source"] == "llm:stub"
    assert row["enrich_state"] == "llm"
    assert row["cvss"] == 7.0