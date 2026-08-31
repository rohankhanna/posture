"""Tests for the network-interfaces observer — a grounding observer on the
exposure axis.

These pin five things:
  1. the observer turns an interface snapshot into one ``reachable`` /
     ``loopback`` Verdict per UP interface address, keyed by subnet CIDR;
     DOWN interfaces emit nothing;
  2. the observer reads from an inline list and from an ``interfaces_path``
     pointing at the bundled fixture, with provenance wired (observer ==
     "network_interfaces", raw_ref set);
  3. the observer is an honest no-op (zero verdicts, complete=True) when the
     device gives no snapshot and when an ``interfaces_path`` file is missing
     — never a crash, never 'clean';
  4. loopback detection works both by interface name (``lo``) and by IP
     (127/8, ::1); a misnamed loopback still classifies as loopback;
  5. in the engine, the exposure axis gets subnet-reachability verdicts
     alongside port-level verdicts without conflict (different key kinds).

SELF-CONTAINED: builds its own ObserverRegistry + Policy inline (no reliance
on the shared default registry / policy file, which a sibling agent may be
editing concurrently). Mirrors test_firewall.py's style.
"""

from pathlib import Path

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.observer import ObserverRegistry
from posture.sources.network_interfaces import NetworkInterfacesObserver
from posture.sources.local_exposure import LocalExposureObserver

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
IFACE_FIXTURE = FIXTURE_DIR / "network_interfaces" / "sample.json"
EXPOSURE_FIXTURE = FIXTURE_DIR / "exposure" / "sample.json"


# Inline policy: network_interfaces + local_exposure on the exposure axis.
# network_interfaces at order 15 (lower authority; supplementary context),
# local_exposure at order 10 (port-level), firewall at order 5 (highest).
_INLINE_POLICY_YAML = """
version: "2026-08-31.2"
supersedes: "2026-08-31.1"
dated: 2026-08-31
rationale: |
  test policy for network_interfaces + local_exposure on the exposure axis (self-contained test).
observers:
  local_exposure:
    axes: [exposure]
    weight: medium
    bias: false-safe
    order: 10
    conditions: []
  network_interfaces:
    axes: [exposure]
    weight: low
    bias: false-safe
    order: 15
    conditions: []
"""


def _policy() -> Policy:
    return Policy.from_yaml(_INLINE_POLICY_YAML)


def _registry_iface_only() -> ObserverRegistry:
    reg = ObserverRegistry()
    reg.register(NetworkInterfacesObserver())
    return reg


def _registry_both() -> ObserverRegistry:
    reg = ObserverRegistry()
    reg.register(LocalExposureObserver())
    reg.register(NetworkInterfacesObserver())
    return reg


# ---------------------------------------------------------------------------
# observer (offline): inline snapshot + path fixture + honest no-op
# ---------------------------------------------------------------------------

def test_observer_inline_emits_reachable_and_loopback():
    """An inline interface list emits one Verdict per UP address."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "lo", "state": "up",
             "addresses": [{"ip": "127.0.0.1", "prefix": 8, "family": "ipv4"}]},
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "192.168.1.42", "prefix": 24, "family": "ipv4"}]},
            {"name": "wlan0", "state": "down",
             "addresses": [{"ip": "172.16.0.10", "prefix": 16, "family": "ipv4"}]},
        ],
    }
    result = obs.assess(device, _policy())
    assert result.complete is True
    assert len(result.verdicts) == 2   # lo + eth0; wlan0 is down -> no verdict

    keys = {v.key for v in result.verdicts}
    assert "127.0.0.0/8" in keys
    assert "192.168.1.0/24" in keys
    assert "172.16.0.0/16" not in keys   # down interface excluded

    statuses = {v.key: v.status for v in result.verdicts}
    assert statuses["127.0.0.0/8"] == "loopback"
    assert statuses["192.168.1.0/24"] == "reachable"


def test_observer_loopback_severity_is_none_reachable_is_low():
    """Loopback verdicts have severity None; reachable verdicts have LOW."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "lo", "state": "up",
             "addresses": [{"ip": "127.0.0.1", "prefix": 8}]},
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "10.0.0.5", "prefix": 8}]},
        ],
    }
    result = obs.assess(device, _policy())
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["127.0.0.0/8"].severity is None
    assert by_key["10.0.0.0/8"].severity == "LOW"


def test_observer_provenance_wired():
    """Every verdict carries provenance with observer == 'network_interfaces'."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "192.168.1.1", "prefix": 24}]},
        ],
    }
    result = obs.assess(device, _policy())
    assert len(result.verdicts) == 1
    v = result.verdicts[0]
    assert v.provenance is not None
    assert v.provenance.observer == "network_interfaces"
    assert v.provenance.raw_ref == "inline:device.interfaces"


def test_observer_path_fixture_reads_file():
    """An interfaces_path pointing at the bundled fixture is read correctly."""
    obs = NetworkInterfacesObserver()
    device = {"id": "host-1", "interfaces_path": str(IFACE_FIXTURE)}
    result = obs.assess(device, _policy())
    assert result.complete is True
    # Fixture has lo (2 addrs) + eth0 (1 addr) + eth1 (2 addrs) + wlan0 (down, 0)
    # = 5 verdicts from UP interfaces
    assert len(result.verdicts) == 5
    keys = {v.key for v in result.verdicts}
    assert "127.0.0.0/8" in keys
    assert "::1/128" in keys
    assert "192.168.1.0/24" in keys
    assert "10.0.0.0/8" in keys
    assert "fd00::/64" in keys
    # wlan0 is down -> its subnet must NOT appear
    assert "172.16.0.0/16" not in keys


def test_observer_path_fixture_provenance_has_path():
    """Verdicts from a file read carry the path in raw_ref."""
    obs = NetworkInterfacesObserver()
    device = {"id": "host-1", "interfaces_path": str(IFACE_FIXTURE)}
    result = obs.assess(device, _policy())
    assert len(result.verdicts) >= 1
    assert result.verdicts[0].provenance.raw_ref == str(IFACE_FIXTURE)


def test_observer_bare_filename_falls_back_to_fixture_dir():
    """A bare filename (no directory) is also tried in the bundled fixture dir."""
    obs = NetworkInterfacesObserver()
    device = {"id": "host-1", "interfaces_path": "sample.json"}
    result = obs.assess(device, _policy())
    assert result.complete is True
    assert len(result.verdicts) == 5   # same fixture


def test_observer_no_snapshot_is_honest_noop():
    """No interfaces or interfaces_path -> zero verdicts, complete=True."""
    obs = NetworkInterfacesObserver()
    result = obs.assess({"id": "host-1"}, _policy())
    assert result.verdicts == []
    assert result.complete is True
    assert "no interface" in result.reason


def test_observer_missing_path_is_honest_noop():
    """A non-existent interfaces_path -> zero verdicts, complete=True."""
    obs = NetworkInterfacesObserver()
    device = {"id": "host-1", "interfaces_path": "/nonexistent/interfaces.json"}
    result = obs.assess(device, _policy())
    assert result.verdicts == []
    assert result.complete is True
    assert "not found" in result.reason


def test_observer_down_interface_emits_nothing():
    """A DOWN interface with addresses produces zero verdicts."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "down",
             "addresses": [{"ip": "10.0.0.1", "prefix": 24}]},
        ],
    }
    result = obs.assess(device, _policy())
    assert result.verdicts == []
    assert result.complete is True


def test_observer_unknown_state_emits_nothing():
    """An interface with state 'unknown' or missing state emits nothing."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "unknown",
             "addresses": [{"ip": "10.0.0.1", "prefix": 24}]},
            {"name": "eth1",
             "addresses": [{"ip": "10.0.0.2", "prefix": 24}]},
        ],
    }
    result = obs.assess(device, _policy())
    assert result.verdicts == []


def test_observer_loopback_by_ip_not_name():
    """An interface NOT named 'lo' but with a 127/8 IP is still loopback."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "weird0", "state": "up",
             "addresses": [{"ip": "127.0.0.1", "prefix": 8}]},
        ],
    }
    result = obs.assess(device, _policy())
    assert len(result.verdicts) == 1
    assert result.verdicts[0].status == "loopback"


def test_observer_ipv6_loopback():
    """An ::1 address is detected as loopback regardless of interface name."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "::1", "prefix": 128}]},
        ],
    }
    result = obs.assess(device, _policy())
    assert len(result.verdicts) == 1
    assert result.verdicts[0].status == "loopback"
    assert result.verdicts[0].key == "::1/128"


def test_observer_invalid_ip_skipped():
    """An invalid IP address is skipped, not crashed."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [
                 {"ip": "not-an-ip", "prefix": 24},
                 {"ip": "192.168.1.1", "prefix": 24},
             ]},
        ],
    }
    result = obs.assess(device, _policy())
    assert len(result.verdicts) == 1
    assert result.verdicts[0].key == "192.168.1.0/24"


def test_observer_invalid_prefix_skipped():
    """An invalid prefix is skipped, not crashed."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [
                 {"ip": "192.168.1.1", "prefix": "not-a-number"},
                 {"ip": "192.168.1.2", "prefix": 24},
             ]},
        ],
    }
    result = obs.assess(device, _policy())
    assert len(result.verdicts) == 1
    assert result.verdicts[0].key == "192.168.1.0/24"


def test_observer_missing_ip_or_prefix_skipped():
    """An address dict without ip or prefix is skipped."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [
                 {"prefix": 24},
                 {"ip": "10.0.0.1"},
                 {},
                 {"ip": "10.0.0.1", "prefix": 8},
             ]},
        ],
    }
    result = obs.assess(device, _policy())
    assert len(result.verdicts) == 1
    assert result.verdicts[0].key == "10.0.0.0/8"


def test_observer_empty_interfaces_list_is_noop():
    """An empty interfaces list -> zero verdicts, complete=True."""
    obs = NetworkInterfacesObserver()
    device = {"id": "host-1", "interfaces": []}
    result = obs.assess(device, _policy())
    assert result.verdicts == []
    assert result.complete is True


def test_observer_interface_without_addresses_skipped():
    """An UP interface with no addresses list emits nothing."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up"},
            {"name": "eth1", "state": "up", "addresses": []},
        ],
    }
    result = obs.assess(device, _policy())
    assert result.verdicts == []


def test_observer_multiple_addresses_same_interface():
    """One interface with multiple addresses emits one verdict per address."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [
                 {"ip": "192.168.1.5", "prefix": 24},
                 {"ip": "fd00::5", "prefix": 64},
             ]},
        ],
    }
    result = obs.assess(device, _policy())
    assert len(result.verdicts) == 2
    keys = {v.key for v in result.verdicts}
    assert "192.168.1.0/24" in keys
    assert "fd00::/64" in keys


def test_observer_subnet_cidr_computation():
    """The subnet CIDR is computed from IP + prefix, not the raw IP."""
    obs = NetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "192.168.50.200", "prefix": 24}]},
            {"name": "eth1", "state": "up",
             "addresses": [{"ip": "10.20.30.40", "prefix": 16}]},
        ],
    }
    result = obs.assess(device, _policy())
    keys = {v.key for v in result.verdicts}
    assert "192.168.50.0/24" in keys
    assert "10.20.0.0/16" in keys


# ---------------------------------------------------------------------------
# engine integration: exposure axis with network_interfaces
# ---------------------------------------------------------------------------

def test_engine_exposure_axis_gets_iface_verdicts():
    """With only network_interfaces registered, the exposure axis gets
    reachable/loopback verdicts (not UNKNOWN)."""
    reg = _registry_iface_only()
    pol = _policy()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "lo", "state": "up",
             "addresses": [{"ip": "127.0.0.1", "prefix": 8}]},
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "192.168.1.42", "prefix": 24}]},
        ],
    }
    conn = store.connect(":memory:")
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    exp = next(a for a in dp.axes if a.axis == "exposure")
    assert exp.status != "unknown"
    assert exp.complete is True
    assert len(exp.verdicts) == 2
    assert exp.deciding_observer == "network_interfaces"


def test_engine_exposure_axis_unknown_without_interfaces():
    """Without any interface data, the exposure axis stays UNKNOWN (loud)."""
    reg = _registry_iface_only()
    pol = _policy()
    device = {"id": "host-1"}
    conn = store.connect(":memory:")
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    exp = next(a for a in dp.axes if a.axis == "exposure")
    assert exp.status == "unknown"


def test_engine_both_observers_no_key_conflict():
    """local_exposure (proto/port keys) and network_interfaces (subnet keys)
    coexist on the exposure axis without overriding each other."""
    reg = _registry_both()
    pol = _policy()
    device = {
        "id": "host-1",
        "exposure": [
            {"proto": "tcp", "port": 22, "bind": "0.0.0.0", "service": "ssh"},
        ],
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "192.168.1.42", "prefix": 24}]},
        ],
    }
    conn = store.connect(":memory:")
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    exp = next(a for a in dp.axes if a.axis == "exposure")
    # Both observers emitted verdicts; port-level + subnet-level keys coexist
    assert len(exp.verdicts) == 2
    keys = {v["key"] for v in exp.verdicts}
    assert "tcp/22" in keys
    assert "192.168.1.0/24" in keys
    # The deciding observer is the one with lowest order that emitted:
    # local_exposure (order 10) < network_interfaces (order 15)
    assert exp.deciding_observer == "local_exposure"


def test_engine_committed_verdicts_attribute_to_observer():
    """Committed per-verdict rows attribute to the correct observer id."""
    reg = _registry_iface_only()
    pol = _policy()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "192.168.1.42", "prefix": 24}]},
        ],
    }
    conn = store.connect(":memory:")
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    assert "network_interfaces" in dp.used_observers
