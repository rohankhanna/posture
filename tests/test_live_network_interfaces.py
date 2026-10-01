"""Tests for the live network-interfaces observer and its pure parser.

These pin five things:
  1. ``parse_ip_addr_json`` converts ``ip -j addr`` JSON to the snapshot
     format correctly — operstate/flags to state, addr_info to addresses,
     inet/inet6 to ipv4/ipv6, DOWN interfaces preserved with empty addresses;
  2. ``LiveNetworkInterfacesObserver`` produces correct verdicts from live
     data (subprocess mocked) — same loopback/reachable semantics as the
     snapshot observer;
  3. the observer falls back to the device-supplied snapshot when
     ``ip -j addr`` is unavailable (no binary / non-zero exit / bad JSON);
  4. the observer is an honest no-op when neither live data nor a snapshot
     is available;
  5. in the engine, the live observer (order 14) overrides the snapshot
     observer (order 15) on the same subnet key.

SELF-CONTAINED: builds its own ObserverRegistry + Policy inline (no reliance
on the shared default registry / policy file, which a sibling agent may be
editing concurrently). Mirrors test_network_interfaces.py's style.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.observer import ObserverRegistry
from posture.sources.network_interfaces import NetworkInterfacesObserver
from posture.sources.live_network_interfaces import (
    LiveNetworkInterfacesObserver,
    parse_ip_addr_json,
)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
LIVE_FIXTURE = FIXTURE_DIR / "live_network_interfaces" / "sample.json"
SNAPSHOT_FIXTURE = FIXTURE_DIR / "network_interfaces" / "sample.json"


_INLINE_POLICY_YAML = """
version: "2026-08-31.3"
supersedes: "2026-08-31.2"
dated: 2026-08-31
rationale: |
  test policy for live_network_interfaces + network_interfaces on the exposure axis.
observers:
  network_interfaces:
    axes: [exposure]
    weight: low
    bias: false-safe
    order: 15
    conditions: []
  live_network_interfaces:
    axes: [exposure]
    weight: low
    bias: false-safe
    order: 14
    conditions: []
"""


def _policy() -> Policy:
    return Policy.from_yaml(_INLINE_POLICY_YAML)


def _load_live_fixture() -> list[dict]:
    return json.loads(LIVE_FIXTURE.read_text())


# ---------------------------------------------------------------------------
# parse_ip_addr_json — pure function, deterministic
# ---------------------------------------------------------------------------

def test_parser_basic_conversion():
    """ip -j addr JSON is converted to the snapshot format."""
    data = _load_live_fixture()
    result = parse_ip_addr_json(data)
    assert isinstance(result, list)
    assert len(result) == 5

    # lo: operstate UNKNOWN + UP flag -> state "up"
    lo = next(r for r in result if r["name"] == "lo")
    assert lo["state"] == "up"
    assert len(lo["addresses"]) == 2
    assert lo["addresses"][0]["ip"] == "127.0.0.1"
    assert lo["addresses"][0]["prefix"] == 8
    assert lo["addresses"][0]["family"] == "ipv4"
    assert lo["addresses"][1]["ip"] == "::1"
    assert lo["addresses"][1]["prefix"] == 128
    assert lo["addresses"][1]["family"] == "ipv6"

    # eth0: operstate UP -> state "up"
    eth0 = next(r for r in result if r["name"] == "eth0")
    assert eth0["state"] == "up"
    assert len(eth0["addresses"]) == 2

    # eth1: operstate DOWN -> state "down"
    eth1 = next(r for r in result if r["name"] == "eth1")
    assert eth1["state"] == "down"
    assert eth1["addresses"] == []

    # docker0: operstate DOWN but has addr_info -> state "down", addresses preserved
    docker0 = next(r for r in result if r["name"] == "docker0")
    assert docker0["state"] == "down"
    assert len(docker0["addresses"]) == 1


def test_parser_operstate_up():
    """operstate UP maps to state 'up'."""
    result = parse_ip_addr_json([
        {"ifname": "eth0", "operstate": "UP", "addr_info": [
            {"family": "inet", "local": "10.0.0.1", "prefixlen": 24}]}
    ])
    assert result[0]["state"] == "up"


def test_parser_operstate_down():
    """operstate DOWN maps to state 'down'."""
    result = parse_ip_addr_json([
        {"ifname": "eth0", "operstate": "DOWN", "addr_info": [
            {"family": "inet", "local": "10.0.0.1", "prefixlen": 24}]}
    ])
    assert result[0]["state"] == "down"


def test_parser_operstate_unknown_with_up_flag():
    """operstate UNKNOWN + UP flag -> state 'up' (loopback convention)."""
    result = parse_ip_addr_json([
        {"ifname": "lo", "operstate": "UNKNOWN", "flags": ["LOOPBACK", "UP"],
         "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]}
    ])
    assert result[0]["state"] == "up"


def test_parser_operstate_unknown_without_up_flag():
    """operstate UNKNOWN without UP flag -> state 'down'."""
    result = parse_ip_addr_json([
        {"ifname": "weird0", "operstate": "UNKNOWN", "flags": ["BROADCAST"],
         "addr_info": [{"family": "inet", "local": "10.0.0.1", "prefixlen": 24}]}
    ])
    assert result[0]["state"] == "down"


def test_parser_family_mapping():
    """inet -> ipv4, inet6 -> ipv6, unknown family preserved as-is."""
    result = parse_ip_addr_json([
        {"ifname": "eth0", "operstate": "UP", "addr_info": [
            {"family": "inet", "local": "10.0.0.1", "prefixlen": 24},
            {"family": "inet6", "local": "fd00::1", "prefixlen": 64},
            {"family": "other", "local": "x", "prefixlen": 1},
        ]}
    ])
    families = [a["family"] for a in result[0]["addresses"]]
    assert families == ["ipv4", "ipv6", "other"]


def test_parser_skips_missing_local():
    """addr_info entries without 'local' are skipped."""
    result = parse_ip_addr_json([
        {"ifname": "eth0", "operstate": "UP", "addr_info": [
            {"family": "inet", "prefixlen": 24},
            {"family": "inet", "local": "10.0.0.1", "prefixlen": 24},
        ]}
    ])
    assert len(result[0]["addresses"]) == 1


def test_parser_skips_missing_prefixlen():
    """addr_info entries without 'prefixlen' are skipped."""
    result = parse_ip_addr_json([
        {"ifname": "eth0", "operstate": "UP", "addr_info": [
            {"family": "inet", "local": "10.0.0.1"},
            {"family": "inet", "local": "10.0.0.2", "prefixlen": 24},
        ]}
    ])
    assert len(result[0]["addresses"]) == 1


def test_parser_empty_addr_info():
    """An interface with no addr_info produces an empty addresses list."""
    result = parse_ip_addr_json([
        {"ifname": "eth0", "operstate": "UP", "addr_info": []}
    ])
    assert result[0]["addresses"] == []


def test_parser_missing_addr_info():
    """An interface without addr_info key produces an empty addresses list."""
    result = parse_ip_addr_json([
        {"ifname": "eth0", "operstate": "UP"}
    ])
    assert result[0]["addresses"] == []


def test_parser_skips_non_dict_entries():
    """Non-dict elements in the list are skipped."""
    result = parse_ip_addr_json([
        "not a dict",
        {"ifname": "eth0", "operstate": "UP", "addr_info": []},
        42,
    ])
    assert len(result) == 1
    assert result[0]["name"] == "eth0"


def test_parser_skips_missing_ifname():
    """Entries without ifname are skipped."""
    result = parse_ip_addr_json([
        {"operstate": "UP", "addr_info": []},
        {"ifname": "eth0", "operstate": "UP", "addr_info": []},
    ])
    assert len(result) == 1
    assert result[0]["name"] == "eth0"


def test_parser_empty_list():
    """An empty list produces an empty result."""
    assert parse_ip_addr_json([]) == []


def test_parser_non_list_input():
    """A non-list input produces an empty result."""
    assert parse_ip_addr_json({}) == []
    assert parse_ip_addr_json("not a list") == []
    assert parse_ip_addr_json(None) == []


def test_parser_missing_operstate():
    """Missing operstate defaults to 'down' (no reachability signal)."""
    result = parse_ip_addr_json([
        {"ifname": "eth0", "addr_info": [
            {"family": "inet", "local": "10.0.0.1", "prefixlen": 24}]}
    ])
    assert result[0]["state"] == "down"


# ---------------------------------------------------------------------------
# LiveNetworkInterfacesObserver — live probing (subprocess mocked)
# ---------------------------------------------------------------------------

def _mock_ip_addr_success(data: list[dict]):
    """Create a mock subprocess.run that returns the given JSON as stdout."""
    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = json.dumps(data)
    proc.stderr = ""
    return patch("posture.sources.live_network_interfaces.subprocess.run", return_value=proc)


def test_observer_live_produces_correct_verdicts():
    """With live ip -j addr data, the observer emits the same verdicts as the
    snapshot observer would from the converted data."""
    data = _load_live_fixture()
    obs = LiveNetworkInterfacesObserver()
    device = {"id": "host-1"}

    with _mock_ip_addr_success(data):
        result = obs.assess(device, _policy())

    assert result.complete is True
    # lo (2 addrs) + eth0 (2 addrs) + wlan0 (1 addr) + eth1 (down, 0) + docker0 (down, 0)
    # = 5 verdicts from UP interfaces
    assert len(result.verdicts) == 5

    keys = {v.key for v in result.verdicts}
    assert "127.0.0.0/8" in keys
    assert "::1/128" in keys
    assert "192.168.1.0/24" in keys
    assert "fd00::/64" in keys
    assert "10.20.0.0/16" in keys
    # docker0 is down -> its subnet must NOT appear
    assert "172.17.0.0/16" not in keys


def test_observer_live_loopback_detection():
    """Live data: loopback interface (operstate UNKNOWN + UP flag) is detected."""
    data = [
        {"ifname": "lo", "operstate": "UNKNOWN", "flags": ["LOOPBACK", "UP"],
         "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        {"ifname": "eth0", "operstate": "UP",
         "addr_info": [{"family": "inet", "local": "192.168.1.1", "prefixlen": 24}]},
    ]
    obs = LiveNetworkInterfacesObserver()
    with _mock_ip_addr_success(data):
        result = obs.assess({"id": "host-1"}, _policy())

    statuses = {v.key: v.status for v in result.verdicts}
    assert statuses["127.0.0.0/8"] == "loopback"
    assert statuses["192.168.1.0/24"] == "reachable"


def test_observer_live_provenance_is_live():
    """Verdicts from live data carry observer='live_network_interfaces' and
    raw_ref='live:ip -j addr'."""
    data = [
        {"ifname": "eth0", "operstate": "UP",
         "addr_info": [{"family": "inet", "local": "192.168.1.1", "prefixlen": 24}]},
    ]
    obs = LiveNetworkInterfacesObserver()
    with _mock_ip_addr_success(data):
        result = obs.assess({"id": "host-1"}, _policy())

    assert len(result.verdicts) == 1
    v = result.verdicts[0]
    assert v.provenance.observer == "live_network_interfaces"
    assert v.provenance.raw_ref == "live:ip -j addr"


def test_observer_live_severity():
    """Loopback -> severity None; reachable -> severity LOW."""
    data = [
        {"ifname": "lo", "operstate": "UNKNOWN", "flags": ["UP"],
         "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        {"ifname": "eth0", "operstate": "UP",
         "addr_info": [{"family": "inet", "local": "10.0.0.1", "prefixlen": 8}]},
    ]
    obs = LiveNetworkInterfacesObserver()
    with _mock_ip_addr_success(data):
        result = obs.assess({"id": "host-1"}, _policy())

    by_key = {v.key: v for v in result.verdicts}
    assert by_key["127.0.0.0/8"].severity is None
    assert by_key["10.0.0.0/8"].severity == "LOW"


# ---------------------------------------------------------------------------
# LiveNetworkInterfacesObserver — fallback to device-supplied snapshot
# ---------------------------------------------------------------------------

def test_observer_fallback_to_inline_snapshot():
    """When ip -j addr fails, the observer falls back to device['interfaces']."""
    obs = LiveNetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "lo", "state": "up",
             "addresses": [{"ip": "127.0.0.1", "prefix": 8}]},
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "192.168.1.42", "prefix": 24}]},
        ],
    }

    with patch("posture.sources.live_network_interfaces.subprocess.run",
               side_effect=FileNotFoundError("no ip binary")):
        result = obs.assess(device, _policy())

    assert result.complete is True
    assert len(result.verdicts) == 2
    keys = {v.key for v in result.verdicts}
    assert "127.0.0.0/8" in keys
    assert "192.168.1.0/24" in keys
    # Provenance shows fallback
    assert result.verdicts[0].provenance.observer == "live_network_interfaces"
    assert "fallback" in result.verdicts[0].provenance.raw_ref


def test_observer_fallback_to_path_fixture():
    """When ip -j addr fails, the observer falls back to interfaces_path."""
    obs = LiveNetworkInterfacesObserver()
    device = {"id": "host-1", "interfaces_path": str(SNAPSHOT_FIXTURE)}

    with patch("posture.sources.live_network_interfaces.subprocess.run",
               side_effect=FileNotFoundError("no ip binary")):
        result = obs.assess(device, _policy())

    assert result.complete is True
    # Same fixture as test_network_interfaces: 5 verdicts
    assert len(result.verdicts) == 5
    assert result.verdicts[0].provenance.observer == "live_network_interfaces"
    assert "fallback" in result.verdicts[0].provenance.raw_ref


def test_observer_fallback_when_ip_returns_nonzero():
    """When ip -j addr returns non-zero exit, fall back to snapshot."""
    obs = LiveNetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "10.0.0.1", "prefix": 8}]},
        ],
    }

    proc = MagicMock()
    proc.returncode = 1
    proc.stdout = ""
    proc.stderr = "RTNETLINK answers: Operation not permitted"

    with patch("posture.sources.live_network_interfaces.subprocess.run", return_value=proc):
        result = obs.assess(device, _policy())

    assert result.complete is True
    assert len(result.verdicts) == 1
    assert result.verdicts[0].key == "10.0.0.0/8"
    assert "fallback" in result.verdicts[0].provenance.raw_ref


def test_observer_fallback_when_ip_returns_invalid_json():
    """When ip -j addr returns invalid JSON, fall back to snapshot."""
    obs = LiveNetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "10.0.0.1", "prefix": 8}]},
        ],
    }

    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = "not json at all"
    proc.stderr = ""

    with patch("posture.sources.live_network_interfaces.subprocess.run", return_value=proc):
        result = obs.assess(device, _policy())

    assert result.complete is True
    assert len(result.verdicts) == 1


def test_observer_fallback_when_ip_times_out():
    """When ip -j addr times out, fall back to snapshot."""
    obs = LiveNetworkInterfacesObserver()
    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "10.0.0.1", "prefix": 8}]},
        ],
    }

    with patch("posture.sources.live_network_interfaces.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="ip", timeout=10)):
        result = obs.assess(device, _policy())

    assert result.complete is True
    assert len(result.verdicts) == 1


def test_observer_no_live_no_snapshot_is_honest_noop():
    """When ip -j addr fails and no device snapshot is supplied -> honest no-op."""
    obs = LiveNetworkInterfacesObserver()
    with patch("posture.sources.live_network_interfaces.subprocess.run",
               side_effect=FileNotFoundError("no ip binary")):
        result = obs.assess({"id": "host-1"}, _policy())

    assert result.verdicts == []
    assert result.complete is True
    assert "no live" in result.reason


def test_observer_no_live_missing_path_is_honest_noop():
    """When ip -j addr fails and interfaces_path points to a missing file ->
    honest no-op."""
    obs = LiveNetworkInterfacesObserver()
    device = {"id": "host-1", "interfaces_path": "/nonexistent/interfaces.json"}
    with patch("posture.sources.live_network_interfaces.subprocess.run",
               side_effect=FileNotFoundError("no ip binary")):
        result = obs.assess(device, _policy())

    assert result.verdicts == []
    assert result.complete is True


# ---------------------------------------------------------------------------
# Engine integration: live + snapshot coexist
# ---------------------------------------------------------------------------

def test_engine_live_overrides_snapshot_on_same_key():
    """When both live_network_interfaces (order 14) and network_interfaces
    (order 15) are registered, the live one's verdicts override on the same
    subnet key."""
    reg = ObserverRegistry()
    reg.register(NetworkInterfacesObserver())
    reg.register(LiveNetworkInterfacesObserver())
    pol = _policy()

    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "192.168.1.42", "prefix": 24}]},
        ],
    }

    live_data = [
        {"ifname": "eth0", "operstate": "UP",
         "addr_info": [{"family": "inet", "local": "192.168.1.99", "prefixlen": 24}]},
    ]

    with _mock_ip_addr_success(live_data):
        conn = store.connect(":memory:")
        dp = engine.assess(device, reg, pol, conn=conn,
                           now="2026-08-31T00:00:00+00:00")

    exp = next(a for a in dp.axes if a.axis == "exposure")
    assert exp.status != "unknown"
    assert exp.complete is True
    # Both observers produced a verdict for 192.168.1.0/24, but the live one
    # (order 14) wins — the deciding observer is live_network_interfaces.
    assert exp.deciding_observer == "live_network_interfaces"
    assert "live_network_interfaces" in dp.used_observers


def test_engine_live_only_when_snapshot_has_no_data():
    """When only the live observer has data (no device snapshot), it still
    produces verdicts."""
    reg = ObserverRegistry()
    reg.register(LiveNetworkInterfacesObserver())
    pol = _policy()

    live_data = [
        {"ifname": "eth0", "operstate": "UP",
         "addr_info": [{"family": "inet", "local": "192.168.1.1", "prefixlen": 24}]},
    ]

    with _mock_ip_addr_success(live_data):
        conn = store.connect(":memory:")
        dp = engine.assess({"id": "host-1"}, reg, pol, conn=conn,
                           now="2026-08-31T00:00:00+00:00")

    exp = next(a for a in dp.axes if a.axis == "exposure")
    assert exp.status != "unknown"
    assert exp.deciding_observer == "live_network_interfaces"


def test_engine_snapshot_only_when_live_unavailable():
    """When live ip -j addr fails but the device snapshot is available, the
    live observer falls back to the snapshot and its verdicts (order 14)
    override the snapshot observer (order 15)."""
    reg = ObserverRegistry()
    reg.register(NetworkInterfacesObserver())
    reg.register(LiveNetworkInterfacesObserver())
    pol = _policy()

    device = {
        "id": "host-1",
        "interfaces": [
            {"name": "eth0", "state": "up",
             "addresses": [{"ip": "192.168.1.42", "prefix": 24}]},
        ],
    }

    with patch("posture.sources.live_network_interfaces.subprocess.run",
               side_effect=FileNotFoundError("no ip binary")):
        conn = store.connect(":memory:")
        dp = engine.assess(device, reg, pol, conn=conn,
                           now="2026-08-31T00:00:00+00:00")

    exp = next(a for a in dp.axes if a.axis == "exposure")
    assert exp.status != "unknown"
    # The live observer fell back to the snapshot and, at order 14, overrides
    # the snapshot observer (order 15) on the same subnet key.
    assert exp.deciding_observer == "live_network_interfaces"
    assert "live_network_interfaces" in dp.used_observers
    # Verdict data comes from the device snapshot (fallback provenance)
    assert len(exp.verdicts) == 1
    assert exp.verdicts[0]["key"] == "192.168.1.0/24"


def test_engine_both_unknown_when_neither_has_data():
    """When neither live nor snapshot data is available, exposure axis stays
    UNKNOWN (loud)."""
    reg = ObserverRegistry()
    reg.register(NetworkInterfacesObserver())
    reg.register(LiveNetworkInterfacesObserver())
    pol = _policy()

    with patch("posture.sources.live_network_interfaces.subprocess.run",
               side_effect=FileNotFoundError("no ip binary")):
        conn = store.connect(":memory:")
        dp = engine.assess({"id": "host-1"}, reg, pol, conn=conn,
                           now="2026-08-31T00:00:00+00:00")

    exp = next(a for a in dp.axes if a.axis == "exposure")
    assert exp.status == "unknown"
