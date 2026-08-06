"""Tests for the CISA KEV overlay threat witness — the first REAL witness on
the threat axis.

These pin five things:
  1. a CVE in the KEV set -> ``targeted`` (HIGH); a CVE not in the set ->
     ``clear``; one Verdict per CVE, keyed on the CVE id;
  2. the witness emits honest verdicts from inline device inputs (cve_candidates
     + kev) and from a ``kev_path`` pointing at the bundled fixture, with
     provenance wired (witness == "kev", raw_ref = kev:<cve>);
  3. the witness is an honest no-op when the device gives no cve_candidates;
  4. the FALSE-SAFE no-op: cve_candidates present but NO KEV overlay supplied ->
     honest no-op (NOT all-clear), because claiming `clear` without the KEV
     catalog would be a false-safe failure; an explicitly-EMPTY KEV set -> all
     clear (a real "nothing matches" answer);
  5. in the engine, the threat axis becomes REAL: ``targeted`` when any CVE is
     KEV-listed, ``clear`` when none are, ``unknown`` when the witness no-ops,
     and the committed per-verdict rows attribute to witness "kev".

SELF-CONTAINED: builds its own WitnessRegistry + Policy inline (no reliance on
the shared default registry / policy file). Mirrors test_cyclonedx_sbom.py's
style.
"""
from pathlib import Path

import yaml

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.witness import WitnessRegistry
from posture.sources.kev_witness import KevThreatWitness

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
KEV_FIXTURE = FIXTURE_DIR / "kev" / "sample.json"   # ["CVE-2026-1001","CVE-2026-9999"]
SAMPLE_DEVICE = FIXTURE_DIR / "sample_device.yaml"


_INLINE_POLICY_YAML = """
version: "2026-08-06.3"
supersedes: "2026-08-06.2"
dated: 2026-08-06
rationale: |
  test policy for the kev threat witness (self-contained test).
witnesses:
  kev:
    axes: [threat]
    weight: high
    bias: false-safe
    order: 10
    conditions: []
"""


def _policy() -> Policy:
    return Policy.from_yaml(_INLINE_POLICY_YAML)


def _registry() -> WitnessRegistry:
    reg = WitnessRegistry()
    reg.register(KevThreatWitness())
    return reg


# ---------------------------------------------------------------------------
# witness (offline): targeted / clear / false-safe no-op
# ---------------------------------------------------------------------------

def test_witness_targeted_for_kev_cve_and_clear_for_the_rest():
    w = KevThreatWitness()
    pol = _policy()
    device = {
        "id": "host",
        "cve_candidates": ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-9999"],
        "kev": ["CVE-2026-1001", "CVE-2026-9999"],
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["CVE-2026-1001"].status == "targeted"
    assert by_key["CVE-2026-1001"].severity == "HIGH"
    assert by_key["CVE-2026-9999"].status == "targeted"
    assert by_key["CVE-2026-1002"].status == "clear"
    assert by_key["CVE-2026-1002"].severity is None
    for v in result.verdicts:
        assert v.axis == Axis.THREAT.value
        assert v.provenance.witness == "kev"
        assert v.provenance.raw_ref == f"kev:{v.key}"


def test_witness_empty_kev_set_means_all_clear():
    """An explicitly-empty KEV set is a real 'nothing is exploited' answer
    (distinct from 'no overlay supplied') -> every candidate is clear."""
    w = KevThreatWitness()
    pol = _policy()
    device = {"id": "host", "cve_candidates": ["CVE-2026-1", "CVE-2026-2"],
              "kev": []}
    result = w.assess(device, pol)
    assert result.complete is True
    assert {v.status for v in result.verdicts} == {"clear"}


def test_witness_kev_path_reads_fixture_file():
    w = KevThreatWitness()
    pol = _policy()
    device = {
        "id": "host",
        "cve_candidates": ["CVE-2026-1001", "CVE-2026-5000"],
        "kev_path": str(KEV_FIXTURE),
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["CVE-2026-1001"].status == "targeted"   # in fixture
    assert by_key["CVE-2026-5000"].status == "clear"       # not in fixture


def test_witness_kev_path_bare_filename_falls_back_to_fixture_dir():
    w = KevThreatWitness()
    pol = _policy()
    device = {"id": "host", "cve_candidates": ["CVE-2026-9999"],
              "kev_path": "sample.json"}
    result = w.assess(device, pol)
    assert result.complete is True
    assert result.verdicts[0].status == "targeted"   # CVE-2026-9999 in fixture


def test_witness_no_candidates_is_honest_noop():
    """No CVEs to score -> honest no-op (the engine keeps the threat axis
    UNKNOWN, loud, never silently 'clear')."""
    w = KevThreatWitness()
    pol = _policy()
    result = w.assess({"id": "host", "kev": ["CVE-2026-1"]}, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no cve candidates supplied" in result.reason


def test_witness_candidates_without_overlay_is_false_safe_noop():
    """Candidates present but NO KEV overlay supplied (neither kev nor
    kev_path) -> honest no-op, NOT all-clear. Claiming `clear` for CVEs we
    could not check against the KEV catalog would be a false-safe failure."""
    w = KevThreatWitness()
    pol = _policy()
    result = w.assess({"id": "host", "cve_candidates": ["CVE-2026-1"]}, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no KEV overlay supplied" in result.reason


def test_witness_missing_kev_path_is_complete_zero_not_failure():
    w = KevThreatWitness()
    pol = _policy()
    result = w.assess({"id": "host", "cve_candidates": ["CVE-2026-1"],
                       "kev_path": "/no/such/kev.json"}, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "kev path not found" in result.reason


def test_witness_inline_kev_takes_precedence_over_path():
    w = KevThreatWitness()
    pol = _policy()
    device = {"id": "host", "cve_candidates": ["CVE-2026-1"],
              "kev": ["CVE-2026-1"], "kev_path": "/no/such/kev.json"}
    result = w.assess(device, pol)
    # inline kev is used; the bogus path is never read
    assert result.verdicts[0].status == "targeted"


# ---------------------------------------------------------------------------
# engine: threat axis becomes REAL (targeted/clear) with input, UNKNOWN without
# ---------------------------------------------------------------------------

def test_engine_threat_axis_targeted_when_any_kev_and_attributed_rows():
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {
        "id": "demo-host",
        "cve_candidates": ["CVE-2026-1001", "CVE-2026-1002"],
        "kev": ["CVE-2026-1001"],
    }
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")

    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "threat")}
    assert sorted(rows) == ["CVE-2026-1001", "CVE-2026-1002"]
    assert rows["CVE-2026-1001"]["witness"] == "kev"
    assert rows["CVE-2026-1001"]["status"] == "targeted"
    assert rows["CVE-2026-1002"]["status"] == "clear"
    for r in rows.values():
        assert r["complete"] == 1

    thr = {a.axis: a for a in dp.axes}["threat"]
    assert thr.status == "targeted"                  # worst present wins
    assert thr.deciding_witness == "kev"
    assert "kev" in dp.used_witnesses

    ap = store.axis_posture(conn, "demo-host", "threat")
    assert ap["status"] == "targeted"
    assert ap["deciding_witness"] == "kev"


def test_engine_threat_axis_clear_when_no_kev_matches():
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {"id": "demo-host", "cve_candidates": ["CVE-2026-1", "CVE-2026-2"],
              "kev": ["CVE-2026-9999"]}
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")
    thr = {a.axis: a for a in dp.axes}["threat"]
    assert thr.status == "clear"                     # no candidate is KEV-listed


def test_engine_threat_axis_unknown_when_witness_no_ops():
    """No candidates (or candidates with no overlay) -> the witness no-ops, so
    the threat axis is UNKNOWN (loud, gap set), not 'clear'. The false-safe
    no-op must NOT read as a clean bill of health."""
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    # candidates present but no overlay -> false-safe no-op
    dp = engine.assess({"id": "demo-host",
                        "cve_candidates": ["CVE-2026-1"]}, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")
    thr = {a.axis: a for a in dp.axes}["threat"]
    assert thr.status == "unknown"
    assert thr.gap is not None
    assert store.verdicts_for_device_axis(conn, "demo-host", "threat") == []
    assert "kev" not in dp.used_witnesses


def test_engine_default_demo_device_threat_stays_unknown():
    """The shipped demo device has no cve_candidates/kev fields -> the witness
    no-ops, so the threat axis is unchanged (UNKNOWN)."""
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = yaml.safe_load(SAMPLE_DEVICE.read_text())
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")
    thr = {a.axis: a for a in dp.axes}["threat"]
    assert thr.status == "unknown"
    assert thr.verdicts == []