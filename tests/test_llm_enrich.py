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


# --- the deterministic validator: the provider-independent trust boundary ----

_GOOD = {"cvss": 7.5, "severity": "HIGH",
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "description": "drafted desc", "refs": ["https://example.com/d"],
         "cwe": ["CWE-89"], "ref_tags": ["Vendor Advisory"],
         "fixed_raw": {"ranges": [{"criteria": "cpe:2.3:o:v:p",
                                   "vstart_incl": "1.0", "vend_excl": "1.5"}],
                        "cpe_heads": ["cpe:2.3:o:v:p"]}}


def test_validate_draft_accepts_well_formed():
    """A complete, well-formed draft passes every gate."""
    ok, errors = llm_enrich.validate_draft(dict(_GOOD))
    assert ok is True and errors == []


def test_validate_draft_accepts_partial_draft():
    """Only the fields a draft actually carries are checked; absent fields are
    not errors (a draft may fill a subset)."""
    ok, errors = llm_enrich.validate_draft({"cvss": 5.0})
    assert ok is True and errors == []


@pytest.mark.parametrize("bad,frag", [
    ({"cvss": 99.9}, "out of range"),
    ({"cvss": -0.1}, "out of range"),
    ({"cvss": "7.5"}, "must be a number"),
    ({"cvss": True}, "must be a number"),   # bool is an int subclass
])
def test_validate_draft_rejects_bad_cvss(bad, frag):
    ok, errors = llm_enrich.validate_draft(bad)
    assert ok is False and any(frag in e for e in errors)


def test_validate_draft_severity_vocabulary():
    """Known severity words pass (NVD ∪ OSV); LLM prose is rejected by code."""
    for sev in ("CRITICAL", "high", "Medium", "moderate", "low", "unknown"):
        assert llm_enrich.validate_draft({"severity": sev})[0] is True, sev
    ok, errors = llm_enrich.validate_draft({"severity": "very bad"})
    assert ok is False and any("severity" in e for e in errors)


@pytest.mark.parametrize("vec,good", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", True),
    ("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", True),
    ("CVSS:3.0/AV:N/AC:L", True),
    ("AV:N/AC:L", False),                 # missing CVSS: prefix
    ("CVSS:4.0/AV:N/AC:L", False),         # unsupported major
    ("CVSS:3.1/", False),                 # no metrics
    ("CVSS:3.1/AV:N AC:L", False),        # space not slash
])
def test_validate_draft_cvss_vector(vec, good):
    assert llm_enrich.validate_draft({"cvss_vector": vec})[0] is good, vec


@pytest.mark.parametrize("refs,good", [
    (["https://example.com/x", "http://nvd.nist.gov/y"], True),
    (["ftp://example.com/x"], False),     # non-http scheme
    (["not a url"], False),                # no scheme/netloc
    (["https://example.com/x", 42], False),  # non-string entry
    ([], True),                            # empty list is fine
])
def test_validate_draft_refs(refs, good):
    assert llm_enrich.validate_draft({"refs": refs})[0] is good, refs


@pytest.mark.parametrize("cwe,good", [
    (["CWE-89", "CWE-79"], True),
    (["CWE-1"], True),
    (["CWE-abc"], False),
    (["weakness"], False),
    ([], False),                           # empty cwe list rejected
    (["CWE-89", "NOT-CWE"], False),
])
def test_validate_draft_cwe(cwe, good):
    assert llm_enrich.validate_draft({"cwe": cwe})[0] is good, cwe


def test_validate_draft_ref_tags_must_be_strings():
    assert llm_enrich.validate_draft({"ref_tags": ["Patch"]})[0] is True
    assert llm_enrich.validate_draft({"ref_tags": ["a", 1]})[0] is False


@pytest.mark.parametrize("fr,good", [
    ({"cpe_heads": ["cpe:2.3:o:v:p"]}, True),            # no ranges is fine
    ({"ranges": [{"criteria": "cpe:x"}]}, True),         # range with no bounds
    ({"ranges": [{"vstart_incl": "1.0", "fixed": "1.5"}]}, True),
    ("not a dict", False),
    ({"ranges": "x"}, False),                            # ranges not a list
    ({"ranges": ["x"]}, False),                          # range not a dict
    ({"ranges": [{"vstart_incl": 1.0}]}, False),         # bound not a string
])
def test_validate_draft_fixed_raw(fr, good):
    assert llm_enrich.validate_draft({"fixed_raw": fr})[0] is good, fr


def test_validate_draft_rejects_non_dict():
    ok, errors = llm_enrich.validate_draft("not a dict")
    assert ok is False and errors == ["draft must be a dict"]


def test_tick_rejects_malformed_draft_no_write(conn):
    """A malformed draft is rejected by the tick, counted separately, and
    NEVER written — the row stays thin for the next tick (no-wipe)."""
    _skeleton(conn, "CVE-M", source="mitre")
    stats = llm_enrich.llm_enrich_tick(
        conn, lambda r: {"cvss": 99.9, "severity": "very bad"}, model="stub")
    assert stats["rejected"] == 1 and stats["drafted"] == 0
    row = store.get_defect(conn, "CVE-M")
    assert row["source"] == "mitre"  # untouched, not written, not wiped


def test_tick_rejects_counted_separately_from_skipped_errors(conn):
    """One valid (drafted), one None (skipped), one malformed (rejected), one
    raising (errors) — the four outcomes are distinct counts."""
    _skeleton(conn, "OK", source="mitre")
    _skeleton(conn, "NONE", source="mitre")
    _skeleton(conn, "BAD", source="mitre")
    _skeleton(conn, "BOOM", source="mitre")

    def draft(row):
        if row["id"] == "OK":
            return {"cvss": 5.5, "severity": "MEDIUM"}
        if row["id"] == "NONE":
            return None
        if row["id"] == "BAD":
            return {"cvss": 99.9}  # out of range -> rejected
        raise RuntimeError("provider blew up")

    stats = llm_enrich.llm_enrich_tick(conn, draft, model="stub")
    assert stats["drafted"] == 1
    assert stats["skipped"] == 1
    assert stats["rejected"] == 1
    assert stats["errors"] == 1
    assert store.get_defect(conn, "BAD")["source"] == "mitre"  # not written


def test_upsert_llm_draft_defensive_guard_rejects_invalid(conn):
    """A DIRECT upsert of a malformed draft is rejected (returns False) and
    never written — the trust boundary cannot be bypassed by skipping the
    tick."""
    _skeleton(conn, "CVE-M", source="mitre")
    ok = llm_enrich.upsert_llm_draft(conn, "CVE-M",
                                    {"cvss": 99.9, "severity": "garbage"},
                                    model="stub")
    assert ok is False
    row = store.get_defect(conn, "CVE-M")
    assert row["source"] == "mitre" and row["cvss"] is None


def test_validator_is_provider_independent():
    """The same malformed draft is rejected regardless of the model label —
    the validator, not the prompt, is the trust boundary that makes providers
    interchangeable."""
    bad = {"cvss": 99.9}
    for model in ("gemini-flash", "llama-3.3-70b", "qwen-2.5-32b"):
        c = store.connect(":memory:")
        _skeleton(c, "CVE-M", source="mitre")
        stats = llm_enrich.llm_enrich_tick(c, lambda r: bad, model=model)
        assert stats["rejected"] == 1 and stats["drafted"] == 0, model
        assert store.get_defect(c, "CVE-M")["source"] == "mitre"


# --- per-row provenance: prompt_hash + raw_text_hash (retractability) --------

def test_hash_text_canonical_sha256():
    """hash_text produces the canonical sha256:<hex> form stored in the
    provenance columns — same text, same digest, across providers."""
    assert llm_enrich.hash_text("abc") == llm_enrich.hash_text("abc")
    assert llm_enrich.hash_text("abc").startswith("sha256:")
    assert llm_enrich.hash_text("abc") != llm_enrich.hash_text("abd")
    # the digest is the real sha256 of the utf-8 bytes (no hidden salt/nonce)
    import hashlib
    expected = "sha256:" + hashlib.sha256(b"abc").hexdigest()
    assert llm_enrich.hash_text("abc") == expected


def test_tick_stamps_provenance_from_reserved_key(conn):
    """A draft_fn that attaches _provenance={prompt_hash, raw_text_hash} has
    those digests stamped on the row. The reserved key is STRIPPED before
    validation and field-merge — it is never treated as a catalog field and
    never reaches the validator."""
    _skeleton(conn, "CVE-M", source="mitre")
    ph = llm_enrich.hash_text("prompt-for-CVE-M")
    rth = llm_enrich.hash_text("raw advisory text for CVE-M")

    def draft(row):
        return {"cvss": 7.5, "severity": "HIGH",
                "_provenance": {"prompt_hash": ph, "raw_text_hash": rth}}

    stats = llm_enrich.llm_enrich_tick(conn, draft, model="stub")
    assert stats["drafted"] == 1 and stats["rejected"] == 0
    row = store.get_defect(conn, "CVE-M")
    assert row["prompt_hash"] == ph
    assert row["raw_text_hash"] == rth
    assert row["source"] == "llm:stub"


def test_tick_strips_provenance_before_validator(conn):
    """The _provenance key is stripped before validate_draft, so a draft that
    is valid EXCEPT for the reserved key is not rejected, and a malformed
    draft whose _provenance is fine is still rejected on the real fields.
    Provenance never interferes with the trust boundary."""
    _skeleton(conn, "OK", source="mitre")
    _skeleton(conn, "BAD", source="mitre")

    def draft(row):
        if row["id"] == "OK":
            return {"cvss": 5.0,
                    "_provenance": {"prompt_hash": llm_enrich.hash_text("p")}}
        return {"cvss": 99.9,  # out of range -> rejected
                "_provenance": {"prompt_hash": llm_enrich.hash_text("p2")}}

    stats = llm_enrich.llm_enrich_tick(conn, draft, model="stub")
    assert stats["drafted"] == 1 and stats["rejected"] == 1
    ok_row = store.get_defect(conn, "OK")
    assert ok_row["prompt_hash"] == llm_enrich.hash_text("p")
    assert ok_row["raw_text_hash"] is None  # not reported -> stays NULL
    # the rejected row was never written, so no provenance landed either
    assert store.get_defect(conn, "BAD")["source"] == "mitre"
    assert store.get_defect(conn, "BAD")["prompt_hash"] is None


def test_tick_ignores_malformed_provenance_attachment(conn):
    """A non-dict _provenance attachment is ignored (provenance stays NULL)
    without affecting the draft itself — the strip is defensive."""
    _skeleton(conn, "CVE-M", source="mitre")

    def draft(row):
        return {"cvss": 5.0, "severity": "MEDIUM", "_provenance": "not a dict"}

    stats = llm_enrich.llm_enrich_tick(conn, draft, model="stub")
    assert stats["drafted"] == 1
    row = store.get_defect(conn, "CVE-M")
    assert row["cvss"] == 5.0
    assert row["prompt_hash"] is None and row["raw_text_hash"] is None


def test_tick_ignores_unknown_provenance_keys(conn):
    """Only prompt_hash / raw_text_hash are honored; a provider cannot smuggle
    another column through the provenance attachment."""
    _skeleton(conn, "CVE-M", source="mitre")

    def draft(row):
        return {"cvss": 5.0,
                "_provenance": {"prompt_hash": llm_enrich.hash_text("p"),
                                "distrusted": 1, "source": "nvd"}}

    llm_enrich.llm_enrich_tick(conn, draft, model="stub")
    row = store.get_defect(conn, "CVE-M")
    assert row["prompt_hash"] == llm_enrich.hash_text("p")
    assert row["source"] == "llm:stub"  # not smuggled to 'nvd'
    assert row["distrusted"] in (None, 0)  # not smuggled


def test_provenance_optional_no_attachment(conn):
    """A draft_fn that reports no provenance drafts normally; the provenance
    columns stay NULL (the row is still retractable by provider+model)."""
    _skeleton(conn, "CVE-M", source="mitre")
    llm_enrich.llm_enrich_tick(conn, lambda r: {"cvss": 5.0}, model="stub")
    row = store.get_defect(conn, "CVE-M")
    assert row["source"] == "llm:stub"
    assert row["prompt_hash"] is None and row["raw_text_hash"] is None


def test_provenance_survives_spine_export_roundtrip(conn, tmp_path):
    """The prompt_hash / raw_text_hash columns flow through export and
    re-import intact — per-row provenance is part of the signed map, so a
    retracted provider is still identifiable after a spine round-trip."""
    _skeleton(conn, "CVE-M", source="mitre")
    ph = llm_enrich.hash_text("prompt")
    rth = llm_enrich.hash_text("raw")
    llm_enrich.llm_enrich_tick(
        conn, lambda r: {"cvss": 7.0, "severity": "HIGH",
                         "_provenance": {"prompt_hash": ph,
                                         "raw_text_hash": rth}},
        model="stub")
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    other = store.connect(":memory:")
    export.import_spine(other, from_dir=out)
    row = store.get_defect(other, "CVE-M")
    assert row["source"] == "llm:stub"
    assert row["prompt_hash"] == ph
    assert row["raw_text_hash"] == rth


# --- retroactive provider distrust (one-sweep retraction) --------------------

def test_distrust_provider_marks_exactly_its_rows(conn):
    """distrust_provider marks every row the provider drafted (source=
    llm:<model>) and NO other — a real NVD row and another provider's draft
    are untouched. Real-source precedence: a row a real source later enriched
    carries source='nvd' and is NOT marked."""
    _skeleton(conn, "M-STUB", source="mitre")
    _skeleton(conn, "M-OTHER", source="mitre")
    _skeleton(conn, "M-REAL", source="mitre")

    def stub_only(row):
        return {"cvss": 5.0} if row["id"] == "M-STUB" else None

    def real_only(row):
        # M-REAL is drafted by stub too, then a real source takes it over
        return {"cvss": 5.0} if row["id"] == "M-REAL" else None

    def other_only(row):
        return {"cvss": 6.0} if row["id"] == "M-OTHER" else None

    llm_enrich.llm_enrich_tick(conn, stub_only, model="stub")
    llm_enrich.llm_enrich_tick(conn, real_only, model="stub")
    llm_enrich.llm_enrich_tick(conn, other_only, model="other")
    # M-REAL: drafted by stub, then a real NVD enrichment takes it over
    _enriched_nvd(conn, cid="M-REAL")
    assert store.get_defect(conn, "M-REAL")["source"] == "nvd"

    n = llm_enrich.distrust_provider(conn, "stub", "biased")
    assert n == 1  # only M-STUB is still source='llm:stub'
    stub_row = store.get_defect(conn, "M-STUB")
    other_row = store.get_defect(conn, "M-OTHER")
    real_row = store.get_defect(conn, "M-REAL")
    assert stub_row["distrusted"] == 1
    assert stub_row["distrust_reason"] == "biased"
    assert other_row["distrusted"] in (None, 0)  # different provider
    assert real_row["distrusted"] in (None, 0)   # real source won precedence


def test_distrust_provider_is_idempotent_and_keeps_record(conn):
    """Re-distrusting the same provider marks nothing new (already marked) and
    never deletes — the row is kept, auditable and re-evaluable."""
    _skeleton(conn, "CVE-M", source="mitre")
    llm_enrich.llm_enrich_tick(conn, lambda r: {"cvss": 5.0}, model="stub")
    assert llm_enrich.distrust_provider(conn, "stub", "r1") == 1
    assert llm_enrich.distrust_provider(conn, "stub", "r2") == 0  # already marked
    row = store.get_defect(conn, "CVE-M")
    assert row["distrusted"] == 1
    assert row["distrust_reason"] == "r1"  # first reason kept, not overwritten


def test_audit_provider_lists_only_that_provider(conn):
    """audit_provider returns exactly the rows one provider drafted, each
    carrying its per-row provenance — the audit view before a retraction."""
    _skeleton(conn, "A", source="mitre")
    _skeleton(conn, "B", source="mitre")
    ph = llm_enrich.hash_text("prompt-A")

    def stub_a(row):
        if row["id"] != "A":
            return None
        return {"cvss": 5.0, "_provenance": {"prompt_hash": ph}}

    def other_b(row):
        return {"cvss": 6.0} if row["id"] == "B" else None

    llm_enrich.llm_enrich_tick(conn, stub_a, model="stub")
    llm_enrich.llm_enrich_tick(conn, other_b, model="other")
    rows = llm_enrich.audit_provider(conn, "stub")
    assert [r["id"] for r in rows] == ["A"]
    assert rows[0]["prompt_hash"] == ph
    assert rows[0]["source"] == "llm:stub"


def test_distrusted_provider_row_excluded_from_redraft(conn):
    """A distrusted LLM row is excluded from the thin pool (thin_defect_ids
    filters distrusted), so a retracted provider is not silently re-drafted by
    a later tick — the retraction sticks."""
    _skeleton(conn, "CVE-M", source="mitre")
    llm_enrich.llm_enrich_tick(conn, lambda r: {"cvss": 5.0}, model="stub")
    llm_enrich.distrust_provider(conn, "stub", "retracted")
    assert "CVE-M" not in llm_enrich.thin_defect_ids(conn)