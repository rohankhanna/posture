"""Tests for the firewall observer — a grounding observer on the exposure axis.

These pin four things:
  1. the observer turns a firewall snapshot into one ``exposed`` / ``closed``
     Verdict per inbound rule, keyed ``proto/port``; deny -> closed, allow ->
     exposed;
  2. the observer overrides local_exposure on the same key (order 5 < 10)
     so a firewalled port is closed even when a socket is listening;
  3. the observer is an honest no-op (zero verdicts, complete=True) when the
     device gives no snapshot and when a ``firewall_path`` file is missing —
     never a crash, never 'clean';
  4. in the engine, the exposure axis gets the firewall-override status when
     both observers are registered, and stays at the local_exposure verdict
     when only local_exposure is present.

SELF-CONTAINED: builds its own ObserverRegistry + Policy inline (no reliance
on the shared default registry / policy file, which a sibling agent may be
editing concurrently). Mirrors test_local_exposure.py's style.
"""

from pathlib import Path

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.observer import ObserverRegistry
from posture.sources.firewall import FirewallObserver
from posture.sources.local_exposure import LocalExposureObserver

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
FIREWALL_FIXTURE = FIXTURE_DIR / "firewall" / "sample.json"
EXPOSURE_FIXTURE = FIXTURE_DIR / "exposure" / "sample.json"


# Inline policy: firewall + local_exposure on the exposure axis. firewall at
# order 5 (higher authority, runs last, overrides local_exposure at order 10).
_INLINE_POLICY_YAML = """
version: "2026-08-31.1"
supersedes: "2026-08-06.3"
dated: 2026-08-31
rationale: |
  test policy for firewall + local_exposure on the exposure axis (self-contained test).
observers:
  local_exposure:
    axes: [exposure]
    weight: medium
    bias: false-safe
    order: 10
    conditions: []
  firewall:
    axes: [exposure]
    weight: high
    bias: false-safe
    order: 5
    conditions: []
"""


def _policy() -> Policy:
    return Policy.from_yaml(_INLINE_POLICY_YAML)


def _registry_firewall_only() -> ObserverRegistry:
    reg = ObserverRegistry()
    reg.register(FirewallObserver())
    return reg


def _registry_both() -> ObserverRegistry:
    reg = ObserverRegistry()
    reg.register(LocalExposureObserver())
    reg.register(FirewallObserver())
    return reg


# ---------------------------------------------------------------------------
# observer (offline): inline snapshot + path fixture + honest no-op
# ---------------------------------------------------------------------------

def test_observer_inline_snapshot_emits_closed_and_exposed():
    w = FirewallObserver()
    pol = _policy()
    device = {
        "id": "host",
        "firewall": {
            "default_policy": "deny",
            "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
                {"action": "deny", "proto": "tcp", "port": 445, "direction": "inbound"},
                {"action": "allow", "proto": "udp", "port": 53, "direction": "inbound"},
            ],
        },
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].status == "exposed"
    assert by_key["tcp/22"].severity == "HIGH"        # ssh on dangerous port
    assert by_key["tcp/445"].status == "closed"
    assert by_key["tcp/445"].severity is None
    assert by_key["udp/53"].status == "exposed"
    assert by_key["udp/53"].severity == "MEDIUM"     # not a dangerous port
    for v in result.verdicts:
        assert v.axis == Axis.EXPOSURE.value
        assert v.provenance.observer == "firewall"
        assert v.provenance.raw_ref == "inline:device.firewall"


def test_observer_deny_rule_is_closed():
    w = FirewallObserver()
    pol = _policy()
    device = {
        "id": "host",
        "firewall": {
            "rules": [
                {"action": "deny", "proto": "tcp", "port": 3306, "direction": "inbound"},
            ],
        },
    }
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/3306"].status == "closed"
    assert "denied by firewall" in by_key["tcp/3306"].detail


def test_observer_allow_rule_on_dangerous_port_is_high():
    w = FirewallObserver()
    pol = _policy()
    device = {
        "id": "host",
        "firewall": {
            "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
                {"action": "allow", "proto": "tcp", "port": 8080, "direction": "inbound"},
                {"action": "allow", "proto": "tcp", "port": 6379, "direction": "inbound"},
            ],
        },
    }
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].severity == "HIGH"
    assert by_key["tcp/6379"].severity == "HIGH"      # redis
    assert by_key["tcp/8080"].severity == "MEDIUM"    # not dangerous


def test_observer_firewall_path_reads_fixture_file():
    w = FirewallObserver()
    pol = _policy()
    device = {"id": "host", "firewall_path": str(FIREWALL_FIXTURE)}
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].status == "exposed"       # allow
    assert by_key["tcp/443"].status == "exposed"      # allow
    assert by_key["tcp/445"].status == "closed"       # deny
    assert by_key["tcp/3306"].status == "closed"      # deny
    assert by_key["udp/53"].status == "exposed"       # allow
    assert by_key["tcp/6379"].status == "closed"      # deny, no direction
    for v in result.verdicts:
        assert v.provenance.observer == "firewall"
        assert v.provenance.raw_ref == str(FIREWALL_FIXTURE)


def test_observer_firewall_path_bare_filename_falls_back_to_fixture_dir():
    w = FirewallObserver()
    pol = _policy()
    device = {"id": "host", "firewall_path": "sample.json"}
    result = w.assess(device, pol)
    assert result.complete is True
    assert {v.key for v in result.verdicts} == {
        "tcp/22", "tcp/443", "tcp/445", "tcp/3306", "udp/53", "tcp/6379",
    }


def test_observer_no_firewall_is_honest_noop():
    """A device with no firewall snapshot gives the observer nothing to say.
    Returns ZERO verdicts (complete=True) so the engine's loud-degradation
    rule lets the exposure axis depend on local_exposure alone, and never
    crashes."""
    w = FirewallObserver()
    pol = _policy()
    device = {"id": "host"}
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no firewall snapshot supplied" in result.reason


def test_observer_missing_firewall_path_is_complete_zero_not_failure():
    """A missing firewall_path file is a local no-input, not a source failure:
    complete=True, zero verdicts (must NOT trip the no-wipe gate)."""
    w = FirewallObserver()
    pol = _policy()
    device = {"id": "host", "firewall_path": "/no/such/firewall.json"}
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "firewall path not found" in result.reason


def test_observer_skips_outbound_rules():
    """Outbound rules are firewall state but do not describe inbound
    reachability — they should not produce exposure verdicts."""
    w = FirewallObserver()
    pol = _policy()
    device = {
        "id": "host",
        "firewall": {
            "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
                {"action": "deny", "proto": "tcp", "port": 9999, "direction": "outbound"},
                {"action": "allow", "proto": "tcp", "port": 8080, "direction": "outbound"},
            ],
        },
    }
    result = w.assess(device, pol)
    keys = {v.key for v in result.verdicts}
    assert keys == {"tcp/22"}   # outbound rules skipped


def test_observer_skips_rules_without_proto_or_port():
    w = FirewallObserver()
    pol = _policy()
    device = {
        "id": "host",
        "firewall": {
            "rules": [
                {"action": "deny", "port": 22, "direction": "inbound"},         # no proto
                {"action": "deny", "proto": "tcp", "direction": "inbound"},     # no port
                {"action": "deny", "proto": "tcp", "port": "bad", "direction": "inbound"},  # bad port
                {"action": "deny", "proto": "tcp", "port": 22, "direction": "inbound"},
            ],
        },
    }
    result = w.assess(device, pol)
    assert [v.key for v in result.verdicts] == ["tcp/22"]


def test_observer_skips_unknown_action():
    """An unrecognized action is silently skipped (no verdict emitted)."""
    w = FirewallObserver()
    pol = _policy()
    device = {
        "id": "host",
        "firewall": {
            "rules": [
                {"action": "reject", "proto": "tcp", "port": 22, "direction": "inbound"},
                {"action": "deny", "proto": "tcp", "port": 80, "direction": "inbound"},
            ],
        },
    }
    result = w.assess(device, pol)
    assert [v.key for v in result.verdicts] == ["tcp/80"]


def test_observer_default_direction_is_inbound():
    """A rule with no 'direction' field defaults to 'inbound'."""
    w = FirewallObserver()
    pol = _policy()
    device = {
        "id": "host",
        "firewall": {
            "rules": [
                {"action": "deny", "proto": "tcp", "port": 22},  # no direction
            ],
        },
    }
    result = w.assess(device, pol)
    assert len(result.verdicts) == 1
    assert result.verdicts[0].key == "tcp/22"
    assert result.verdicts[0].status == "closed"


# ---------------------------------------------------------------------------
# engine: firewall overrides local_exposure on the same key
# ---------------------------------------------------------------------------

def test_engine_firewall_overrides_local_exposure_on_denied_port():
    """When both local_exposure and firewall are registered, a firewall deny
    on tcp/445 overrides local_exposure's 'exposed' on the same key — the
    socket is listening but the firewall blocks it, so the port is 'closed'.

    This is the grounding-probe value: the attack graph can suppress a chain
    that requires SMB access because the firewall denies tcp/445."""
    reg = _registry_both()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {
        "id": "demo-host",
        "exposure": [
            {"proto": "tcp", "port": 22, "bind": "0.0.0.0", "service": "ssh"},
            {"proto": "tcp", "port": 445, "bind": "0.0.0.0", "service": "smb"},
        ],
        "firewall": {
            "default_policy": "deny",
            "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
                {"action": "deny", "proto": "tcp", "port": 445, "direction": "inbound"},
            ],
        },
    }
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")

    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "exposure")}
    # tcp/22: local_exposure says exposed, firewall says allow (exposed) -> exposed
    assert rows["tcp/22"]["status"] == "exposed"
    # tcp/445: local_exposure says exposed, firewall says deny (closed) -> closed (override!)
    assert rows["tcp/445"]["status"] == "closed"
    # The deciding observer for tcp/445 should be firewall (higher authority)
    assert rows["tcp/445"]["observer"] == "firewall"

    exp = {a.axis: a for a in dp.axes}["exposure"]
    # tcp/22 is exposed -> the axis status is 'exposed'
    assert exp.status == "exposed"
    assert "firewall" in dp.used_observers
    # local_exposure is NOT in used_observers because firewall overrode every
    # key it produced a verdict for — the engine only lists deciding observers.


def test_engine_firewall_all_closed_overrides_to_closed():
    """When the firewall denies all inbound traffic, the exposure axis becomes
    'closed' even if local_exposure says 'exposed' on every port."""
    reg = _registry_both()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {
        "id": "demo-host",
        "exposure": [
            {"proto": "tcp", "port": 22, "bind": "0.0.0.0"},
            {"proto": "tcp", "port": 80, "bind": "0.0.0.0"},
        ],
        "firewall": {
            "default_policy": "deny",
            "rules": [
                {"action": "deny", "proto": "tcp", "port": 22, "direction": "inbound"},
                {"action": "deny", "proto": "tcp", "port": 80, "direction": "inbound"},
            ],
        },
    }
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    exp = {a.axis: a for a in dp.axes}["exposure"]
    assert exp.status == "closed"


def test_engine_exposure_axis_unknown_without_any_snapshot():
    """With neither local_exposure capture nor firewall snapshot, the exposure
    axis has zero verdicts from both observers -> status 'unknown' (loud)."""
    reg = _registry_both()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {"id": "demo-host"}   # no exposure, no firewall
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    exp = {a.axis: a for a in dp.axes}["exposure"]
    assert exp.status == "unknown"
    assert exp.verdicts == []
    assert exp.gap is not None
    assert "local_exposure" not in dp.used_observers
    assert "firewall" not in dp.used_observers


def test_engine_firewall_only_exposed_on_allow():
    """With only the firewall observer (no local_exposure), an allow rule
    produces 'exposed' and a deny rule produces 'closed'."""
    reg = _registry_firewall_only()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {
        "id": "demo-host",
        "firewall": {
            "rules": [
                {"action": "allow", "proto": "tcp", "port": 443, "direction": "inbound"},
                {"action": "deny", "proto": "tcp", "port": 22, "direction": "inbound"},
            ],
        },
    }
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "exposure")}
    assert rows["tcp/443"]["status"] == "exposed"
    assert rows["tcp/22"]["status"] == "closed"
    assert rows["tcp/443"]["observer"] == "firewall"
    assert rows["tcp/22"]["observer"] == "firewall"


def test_engine_firewall_does_not_override_local_exposure_on_ports_not_in_firewall():
    """When the firewall has no rule for a port, local_exposure's verdict
    stands — the firewall observer does not emit a verdict for that key."""
    reg = _registry_both()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {
        "id": "demo-host",
        "exposure": [
            {"proto": "tcp", "port": 8080, "bind": "0.0.0.0"},
        ],
        "firewall": {
            "rules": [
                {"action": "deny", "proto": "tcp", "port": 22, "direction": "inbound"},
            ],
        },
    }
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "exposure")}
    # tcp/8080: no firewall rule -> local_exposure's 'exposed' stands
    assert rows["tcp/8080"]["status"] == "exposed"
    assert rows["tcp/8080"]["observer"] == "local_exposure"
    # tcp/22: firewall deny -> closed (firewall observer wins)
    assert rows["tcp/22"]["status"] == "closed"
    assert rows["tcp/22"]["observer"] == "firewall"
