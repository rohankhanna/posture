"""Engine tests — the clean core's invariants."""
import pytest

from posture.axis import Axis
from posture.observer import Observer, ObserverResult, Verdict, Provenance, ObserverRegistry
from posture import engine, store, provenance as _prov


class FakePolicy:
    """Minimal policy stub the engine needs (has_observer/order/bias/version)."""
    def __init__(self, observers: dict[str, dict] | None = None, version="2026-08-01.1"):
        self.version = version
        self._w = observers or {}
    def has_observer(self, wid): return wid in self._w
    def observer_order(self, wid): return self._w.get(wid, {}).get("order", 10)
    def observer_bias(self, wid, default="neutral"):
        return self._w.get(wid, {}).get("bias", default)
    def observer_weight(self, wid): return self._w.get(wid, {}).get("weight", "medium")
    def degradation_for(self, wid): return None


class W(Observer):
    """Configurable fake observer for tests."""
    def __init__(self, wid, axis=Axis.VULNERABILITY, verdicts=None, complete=True,
                 reason="", bias="neutral", crash=False):
        super().__init__(id=wid, axes=(axis,), bias=bias)
        self._verdicts = verdicts or []
        self._complete = complete
        self._reason = reason
        self._crash = crash
    def assess(self, device, policy):
        if self._crash:
            raise RuntimeError("boom")
        return ObserverResult(verdicts=list(self._verdicts), complete=self._complete,
                             reason=self._reason)


def _v(key, status, wid="w1", axis="vulnerability", fixed_in=None):
    return Verdict(axis=axis, key=key, status=status, detail="", severity=None,
                   fixed_in=fixed_in,
                   provenance=Provenance(observer=wid, policy_version="",
                                         fetched_at="", complete=True))


def _device():
    return {"id": "dev", "os": "linux", "os_version": "6.18"}


def test_no_observer_for_axis_is_unknown_loud():
    reg = ObserverRegistry()
    # only register a observer for vulnerability; configuration has none
    reg.register(W("w1", Axis.VULNERABILITY, verdicts=[_v("CVE-1", "unpatched")]))
    pol = FakePolicy({"w1": {"order": 10, "bias": "false-alarm"}})
    dp = engine.assess(_device(), reg, pol, conn=None)
    vuln = next(a for a in dp.axes if a.axis == "vulnerability")
    conf = next(a for a in dp.axes if a.axis == "configuration")
    assert vuln.status == "unpatched"
    assert conf.status == "unknown"
    assert conf.gap and "no observer configured" in conf.gap


def test_zero_verdicts_is_unknown_never_clean():
    # a observer configured but returning NO verdicts -> UNKNOWN, not 'clear'
    reg = ObserverRegistry()
    reg.register(W("w1", Axis.VULNERABILITY, verdicts=[], complete=True))
    pol = FakePolicy({"w1": {"order": 10, "bias": "neutral"}})
    dp = engine.assess(_device(), reg, pol, conn=None)
    vuln = next(a for a in dp.axes if a.axis == "vulnerability")
    assert vuln.status == "unknown"
    assert vuln.gap and "not 'clean'" in vuln.gap


def test_provenance_stamped_with_policy_version_and_ts():
    reg = ObserverRegistry()
    reg.register(W("w1", Axis.VULNERABILITY, verdicts=[_v("CVE-1", "unpatched")]))
    pol = FakePolicy({"w1": {"order": 10, "bias": "false-alarm"}}, version="2099-01-01.7")
    dp = engine.assess(_device(), reg, pol, conn=None, now="2099-01-01T00:00:00+00:00")
    assert dp.policy_version == "2099-01-01.7"
    vuln = next(a for a in dp.axes if a.axis == "vulnerability")
    assert vuln.verdicts[0]["provenance"]["policy_version"] == "2099-01-01.7"
    assert vuln.verdicts[0]["provenance"]["fetched_at"] == "2099-01-01T00:00:00+00:00"


def test_higher_order_observer_overrides_lower():
    # w1 order=5 (lower), w2 order=1 (higher -> runs last in ascending order,
    # so it overrides). Both speak to vulnerability on the SAME key.
    reg = ObserverRegistry()
    reg.register(W("w1", Axis.VULNERABILITY, verdicts=[_v("CVE-1", "unpatched", wid="w1")], ))
    reg.register(W("w2", Axis.VULNERABILITY, verdicts=[_v("CVE-1", "patched", wid="w2")]))
    pol = FakePolicy({"w1": {"order": 5, "bias": "false-alarm"},
                      "w2": {"order": 1, "bias": "neutral"}})
    dp = engine.assess(_device(), reg, pol, conn=None)
    vuln = next(a for a in dp.axes if a.axis == "vulnerability")
    # order 1 (w2) runs after order 5 (w1) and overrides -> patched, decided by w2
    assert vuln.status == "patched"
    assert vuln.deciding_observer == "w2"


def test_bias_recorded_from_deciding_observer():
    reg = ObserverRegistry()
    reg.register(W("w1", Axis.VULNERABILITY, verdicts=[_v("CVE-1", "unpatched", wid="w1")]))
    pol = FakePolicy({"w1": {"order": 10, "bias": "false-alarm"}})
    dp = engine.assess(_device(), reg, pol, conn=None)
    vuln = next(a for a in dp.axes if a.axis == "vulnerability")
    assert vuln.bias == "false-alarm"


def test_incomplete_fetch_preserves_stored_verdicts_no_wipe():
    # run 1: complete -> commits unpatched verdicts. run 2: incomplete -> must
    # preserve (not wipe) the stored verdicts.
    conn = store.connect(":memory:")
    reg = ObserverRegistry()
    reg.register(W("w1", Axis.VULNERABILITY,
                   verdicts=[_v("CVE-1", "unpatched")], complete=True))
    pol = FakePolicy({"w1": {"order": 10, "bias": "false-alarm"}})
    engine.assess(_device(), reg, pol, conn=conn, now="2026-01-01T00:00:00+00:00")
    assert len(store.verdicts_for_device_axis(conn, "dev", "vulnerability")) == 1

    # now the observer comes back incomplete with NO verdicts
    reg2 = ObserverRegistry()
    reg2.register(W("w1", Axis.VULNERABILITY, verdicts=[], complete=False,
                     reason="504 timeout"))
    engine.assess(_device(), reg2, pol, conn=conn, now="2026-01-02T00:00:00+00:00")
    rows = store.verdicts_for_device_axis(conn, "dev", "vulnerability")
    assert len(rows) == 1  # preserved — NOT wiped
    assert rows[0]["status"] == "unpatched"


def test_complete_zero_against_existing_is_preserved_empty():
    conn = store.connect(":memory:")
    reg = ObserverRegistry()
    reg.register(W("w1", Axis.VULNERABILITY,
                   verdicts=[_v("CVE-1", "unpatched")], complete=True))
    pol = FakePolicy({"w1": {"order": 10, "bias": "false-alarm"}})
    engine.assess(_device(), reg, pol, conn=conn)
    # second complete run returns zero verdicts -> suspect false-absent -> preserve
    reg2 = ObserverRegistry()
    reg2.register(W("w1", Axis.VULNERABILITY, verdicts=[], complete=True))
    dp = engine.assess(_device(), reg2, pol, conn=conn)
    vuln = next(a for a in dp.axes if a.axis == "vulnerability")
    assert vuln.commit_state == "preserved-empty"
    assert len(store.verdicts_for_device_axis(conn, "dev", "vulnerability")) == 1


def test_observer_crash_does_not_break_engine():
    reg = ObserverRegistry()
    reg.register(W("w1", Axis.VULNERABILITY, crash=True))
    pol = FakePolicy({"w1": {"order": 10, "bias": "neutral"}})
    dp = engine.assess(_device(), reg, pol, conn=None)
    vuln = next(a for a in dp.axes if a.axis == "vulnerability")
    # crash -> incomplete -> zero verdicts -> UNKNOWN (loud), never clean
    assert vuln.status == "unknown"
    assert vuln.complete is False


def test_overall_never_claims_safety_with_unknown_axes():
    reg = ObserverRegistry()
    reg.register(W("w1", Axis.VULNERABILITY, verdicts=[_v("CVE-1", "unpatched")]))
    pol = FakePolicy({"w1": {"order": 10, "bias": "false-alarm"}})
    dp = engine.assess(_device(), reg, pol, conn=None)
    assert "unknown" in dp.overall  # never claims flawless