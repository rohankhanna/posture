"""Observer-contract tests — the uniform socket is enforced."""
import pytest

from posture.axis import Axis
from posture.observer import (
    FetchResult, Verdict, Provenance, ObserverResult, Observer, ObserverRegistry,
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
    p = Provenance(observer="nvd", policy_version="v1", fetched_at="t",
                   complete=True, raw_ref="ref")
    v = Verdict(axis="vulnerability", key="CVE-1", status="unpatched",
                detail="d", severity="HIGH", fixed_in="6.18.5", provenance=p)
    d = v.to_dict()
    assert d["provenance"]["observer"] == "nvd"
    assert d["status"] == "unpatched"


def test_observer_is_abstract():
    with pytest.raises(TypeError):
        Observer(id="x", axes=(Axis.VULNERABILITY,))  # type: ignore[abstract]


def test_registry_register_and_for_axis():
    class W(Observer):
        def __init__(self):
            super().__init__(id="w1", axes=(Axis.VULNERABILITY,), bias="false-alarm")
        def assess(self, device, policy):
            return ObserverResult(verdicts=[], complete=True, reason="ok")

    reg = ObserverRegistry()
    reg.register(W())
    assert reg.get("w1") is not None
    # for_axis without a policy object that has observer entries: use a stub policy
    class P:
        def has_observer(self, wid): return True
        def observer_order(self, wid): return 10
    ws = reg.for_axis(Axis.VULNERABILITY, P())
    assert len(ws) == 1
    ws2 = reg.for_axis(Axis.CONFIGURATION, P())  # w1 doesn't speak to configuration
    assert ws2 == []


def test_registry_duplicate_rejected():
    class W(Observer):
        def __init__(self):
            super().__init__(id="dup", axes=(Axis.VULNERABILITY,))
        def assess(self, device, policy):
            return ObserverResult(verdicts=[], complete=True)
    reg = ObserverRegistry()
    reg.register(W())
    with pytest.raises(ValueError):
        reg.register(W())


def test_used_in_collects_observer_ids():
    p = Provenance(observer="nvd", policy_version="", fetched_at="", complete=True)
    v1 = Verdict(axis="vulnerability", key="A", status="unpatched", provenance=p)
    v2 = Verdict(axis="vulnerability", key="B", status="patched", provenance=p)
    reg = ObserverRegistry()
    assert reg.used_in([v1, v2]) == ["nvd"]