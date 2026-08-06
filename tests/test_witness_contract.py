"""Witness-contract tests — the uniform socket is enforced."""
import pytest

from posture.axis import Axis
from posture.witness import (
    FetchResult, Verdict, Provenance, WitnessResult, Witness, WitnessRegistry,
)


def test_fetchresult_absent_is_complete_zero():
    fr = FetchResult.absent()
    assert fr.complete is True
    assert fr.records == []


def test_fetchresult_incomplete_is_not_complete():
    fr = FetchResult(records=[{"x": 1}], complete=False, reason="truncated")
    assert fr.complete is False
    assert fr.reason == "truncated"


def test_verdict_provenance_round_trip():
    p = Provenance(witness="nvd", policy_version="v1", fetched_at="t",
                   complete=True, raw_ref="ref")
    v = Verdict(axis="vulnerability", key="CVE-1", status="unpatched",
                detail="d", severity="HIGH", fixed_in="6.18.5", provenance=p)
    d = v.to_dict()
    assert d["provenance"]["witness"] == "nvd"
    assert d["status"] == "unpatched"


def test_witness_is_abstract():
    with pytest.raises(TypeError):
        Witness(id="x", axes=(Axis.VULNERABILITY,))  # type: ignore[abstract]


def test_registry_register_and_for_axis():
    class W(Witness):
        def __init__(self):
            super().__init__(id="w1", axes=(Axis.VULNERABILITY,), bias="false-alarm")
        def assess(self, device, policy):
            return WitnessResult(verdicts=[], complete=True, reason="ok")

    reg = WitnessRegistry()
    reg.register(W())
    assert reg.get("w1") is not None
    # for_axis without a policy object that has witness entries: use a stub policy
    class P:
        def has_witness(self, wid): return True
        def witness_order(self, wid): return 10
    ws = reg.for_axis(Axis.VULNERABILITY, P())
    assert len(ws) == 1
    ws2 = reg.for_axis(Axis.CONFIGURATION, P())  # w1 doesn't speak to configuration
    assert ws2 == []


def test_registry_duplicate_rejected():
    class W(Witness):
        def __init__(self):
            super().__init__(id="dup", axes=(Axis.VULNERABILITY,))
        def assess(self, device, policy):
            return WitnessResult(verdicts=[], complete=True)
    reg = WitnessRegistry()
    reg.register(W())
    with pytest.raises(ValueError):
        reg.register(W())


def test_used_in_collects_witness_ids():
    p = Provenance(witness="nvd", policy_version="", fetched_at="", complete=True)
    v1 = Verdict(axis="vulnerability", key="A", status="unpatched", provenance=p)
    v2 = Verdict(axis="vulnerability", key="B", status="patched", provenance=p)
    reg = WitnessRegistry()
    assert reg.used_in([v1, v2]) == ["nvd"]