"""Tests for the live firewall observer — a grounding observer on the
exposure axis.

These pin five things:
  1. the pure parsers (parse_ufw_status, parse_iptables_rules) convert live
     command output into the snapshot format that FirewallObserver consumes;
  2. the observer delegates to FirewallObserver and re-stamps provenance
     (live_firewall, not firewall);
  3. the observer falls back to the device-supplied snapshot when no live
     tool is available;
  4. the observer is an honest no-op (zero verdicts, complete=True) when
     neither live data nor a snapshot is available;
  5. in the engine, live_firewall overrides the snapshot firewall on the
     same proto/port key (order 4 < order 5).

SELF-CONTAINED: builds its own ObserverRegistry + Policy inline (no reliance
on the shared default registry / policy file, which a sibling agent may be
editing concurrently).  Mirrors test_firewall.py's style.
"""

import json
from pathlib import Path

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.observer import ObserverRegistry
from posture.sources.firewall import FirewallObserver
from posture.sources.live_firewall import (
    LiveFirewallObserver,
    parse_ufw_status,
    parse_iptables_rules,
    parse_nft_ruleset,
)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
FIREWALL_FIXTURE = FIXTURE_DIR / "firewall" / "sample.json"

_INLINE_POLICY_YAML = """
version: "2026-08-31.1"
supersedes: "2026-08-06.3"
dated: 2026-08-31
rationale: |
  test policy for live_firewall + firewall + local_exposure on the exposure axis.
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
  live_firewall:
    axes: [exposure]
    weight: high
    bias: false-safe
    order: 4
    conditions: []
"""


def _policy() -> Policy:
    return Policy.from_yaml(_INLINE_POLICY_YAML)


def _registry_live_only() -> ObserverRegistry:
    reg = ObserverRegistry()
    reg.register(LiveFirewallObserver())
    return reg


def _registry_both_firewalls() -> ObserverRegistry:
    reg = ObserverRegistry()
    reg.register(FirewallObserver())
    reg.register(LiveFirewallObserver())
    return reg


# ---------------------------------------------------------------------------
# parse_ufw_status — pure function
# ---------------------------------------------------------------------------

_UFW_VERBOSE_OUTPUT = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
445/tcp                    DENY        Anywhere
53/udp                     ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
80/tcp (v6)                ALLOW       Anywhere (v6)
"""

_UFW_INACTIVE = "Status: inactive\n"


def test_parse_ufw_status_active_with_rules():
    snap = parse_ufw_status(_UFW_VERBOSE_OUTPUT)
    assert snap is not None
    assert snap["default_policy"] == "deny"
    rules = snap["rules"]
    # IPv6 duplicates should be excluded (the (v6) suffix rules are skipped)
    # Actually, the regex matches both — the v6 rules are duplicates of the
    # v4 rules. The snapshot observer will emit duplicate verdicts for the
    # same key, which is fine (last one wins in the engine). Let's check
    # the non-v6 rules are present.
    keys = {(r["proto"], r["port"], r["action"]) for r in rules}
    assert ("tcp", 22, "allow") in keys
    assert ("tcp", 80, "allow") in keys
    assert ("tcp", 443, "allow") in keys
    assert ("tcp", 445, "deny") in keys
    assert ("udp", 53, "allow") in keys
    for r in rules:
        assert r["direction"] == "inbound"


def test_parse_ufw_status_inactive_returns_none():
    snap = parse_ufw_status(_UFW_INACTIVE)
    assert snap is None


def test_parse_ufw_status_empty_returns_none():
    assert parse_ufw_status("") is None
    assert parse_ufw_status(None) is None


def test_parse_ufw_status_active_no_rules():
    text = "Status: active\nDefault: deny (incoming), allow (outgoing)\n"
    snap = parse_ufw_status(text)
    assert snap is not None
    assert snap["default_policy"] == "deny"
    assert snap["rules"] == []


def test_parse_ufw_status_no_default_line():
    """An older ufw without a Default: line gives empty default_policy."""
    text = "Status: active\n\nTo                         Action      From\n22/tcp                     ALLOW       Anywhere\n"
    snap = parse_ufw_status(text)
    assert snap is not None
    assert snap["default_policy"] == ""
    assert len(snap["rules"]) == 1


# ---------------------------------------------------------------------------
# parse_iptables_rules — pure function
# ---------------------------------------------------------------------------

_IPTABLES_OUTPUT = """-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 445 -j DROP
-A INPUT -p udp --dport 53 -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -j REJECT
"""


def test_parse_iptables_rules_with_default_and_rules():
    snap = parse_iptables_rules(_IPTABLES_OUTPUT)
    assert snap is not None
    assert snap["default_policy"] == "deny"
    rules = snap["rules"]
    keys = {(r["proto"], r["port"], r["action"]) for r in rules}
    assert ("tcp", 22, "allow") in keys
    assert ("tcp", 445, "deny") in keys
    assert ("udp", 53, "allow") in keys
    for r in rules:
        assert r["direction"] == "inbound"
    # Catch-all REJECT without --dport is skipped
    assert all(r["proto"] and r["port"] for r in rules)


def test_parse_iptables_rules_empty_returns_none():
    assert parse_iptables_rules("") is None
    assert parse_iptables_rules(None) is None


def test_parse_iptables_rules_accept_default():
    text = "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j DROP\n"
    snap = parse_iptables_rules(text)
    assert snap is not None
    assert snap["default_policy"] == "allow"
    assert len(snap["rules"]) == 1
    assert snap["rules"][0]["action"] == "deny"


def test_parse_iptables_rules_skip_non_input_chain():
    text = "-P INPUT DROP\n-A FORWARD -p tcp --dport 22 -j ACCEPT\n"
    snap = parse_iptables_rules(text)
    assert snap is not None
    assert len(snap["rules"]) == 0


def test_parse_iptables_rules_skip_unknown_target():
    text = "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j LOG\n"
    snap = parse_iptables_rules(text)
    assert snap is not None
    assert len(snap["rules"]) == 0


def test_parse_iptables_rules_reject_is_deny():
    text = "-P INPUT DROP\n-A INPUT -p tcp --dport 445 -j REJECT\n"
    snap = parse_iptables_rules(text)
    assert snap is not None
    assert snap["rules"][0]["action"] == "deny"


# ---------------------------------------------------------------------------
# LiveFirewallObserver — delegation + provenance + fallback
# ---------------------------------------------------------------------------

def test_observer_delegates_to_snapshot_and_restamps_provenance(monkeypatch):
    """When live ufw data is available, the observer delegates verdict
    emission to FirewallObserver and re-stamps provenance as live_firewall."""
    obs = LiveFirewallObserver()
    pol = _policy()

    # Patch _probe_ufw to return known data
    monkeypatch.setattr(obs, "_probe_ufw", lambda: parse_ufw_status(_UFW_VERBOSE_OUTPUT))
    monkeypatch.setattr(obs, "_probe_iptables", lambda: None)

    device = {"id": "host"}
    result = obs.assess(device, pol)
    assert result.complete is True
    assert len(result.verdicts) > 0
    for v in result.verdicts:
        assert v.provenance.observer == "live_firewall"
        assert v.provenance.raw_ref == "live:ufw status verbose"
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].status == "exposed"
    assert by_key["tcp/445"].status == "closed"


def test_observer_iptables_fallback_when_ufw_inactive(monkeypatch):
    """When ufw returns None (inactive), the observer tries iptables."""
    obs = LiveFirewallObserver()
    pol = _policy()

    monkeypatch.setattr(obs, "_probe_ufw", lambda: None)
    monkeypatch.setattr(obs, "_probe_iptables", lambda: parse_iptables_rules(_IPTABLES_OUTPUT))

    device = {"id": "host"}
    result = obs.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].status == "exposed"
    assert by_key["tcp/445"].status == "closed"
    for v in result.verdicts:
        assert v.provenance.observer == "live_firewall"
        assert v.provenance.raw_ref == "live:iptables -S"


def test_observer_falls_back_to_device_snapshot(monkeypatch):
    """When no live tool is available, the observer falls back to the
    device-supplied inline firewall snapshot."""
    obs = LiveFirewallObserver()
    pol = _policy()

    monkeypatch.setattr(obs, "_probe_ufw", lambda: None)
    monkeypatch.setattr(obs, "_probe_iptables", lambda: None)

    device = {
        "id": "host",
        "firewall": {
            "default_policy": "deny",
            "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
                {"action": "deny", "proto": "tcp", "port": 445, "direction": "inbound"},
            ],
        },
    }
    result = obs.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].status == "exposed"
    assert by_key["tcp/445"].status == "closed"
    for v in result.verdicts:
        assert v.provenance.observer == "live_firewall"
        assert v.provenance.raw_ref == "inline:device.firewall (fallback)"


def test_observer_falls_back_to_firewall_path(monkeypatch):
    """When no live tool is available and no inline snapshot, the observer
    falls back to the firewall_path file."""
    obs = LiveFirewallObserver()
    pol = _policy()

    monkeypatch.setattr(obs, "_probe_ufw", lambda: None)
    monkeypatch.setattr(obs, "_probe_iptables", lambda: None)

    device = {"id": "host", "firewall_path": str(FIREWALL_FIXTURE)}
    result = obs.assess(device, pol)
    assert result.complete is True
    assert len(result.verdicts) > 0
    for v in result.verdicts:
        assert v.provenance.observer == "live_firewall"
        assert "fallback" in v.provenance.raw_ref


def test_observer_honest_noop_when_no_data_anywhere(monkeypatch):
    """When no live tool, no inline snapshot, and no firewall_path — honest
    no-op (zero verdicts, complete=True)."""
    obs = LiveFirewallObserver()
    pol = _policy()

    monkeypatch.setattr(obs, "_probe_ufw", lambda: None)
    monkeypatch.setattr(obs, "_probe_iptables", lambda: None)

    device = {"id": "host"}
    result = obs.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no live firewall data" in result.reason


def test_observer_missing_firewall_path_is_complete_zero(monkeypatch):
    """A missing firewall_path file is a local no-input, not a source failure:
    complete=True, zero verdicts."""
    obs = LiveFirewallObserver()
    pol = _policy()

    monkeypatch.setattr(obs, "_probe_ufw", lambda: None)
    monkeypatch.setattr(obs, "_probe_iptables", lambda: None)

    device = {"id": "host", "firewall_path": "/no/such/firewall.json"}
    result = obs.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no live firewall data" in result.reason


# ---------------------------------------------------------------------------
# Engine: live_firewall overrides snapshot firewall on same key
# ---------------------------------------------------------------------------

def test_engine_live_firewall_overrides_snapshot_firewall(monkeypatch):
    """When both firewall and live_firewall are registered, a live deny on
    tcp/445 overrides the snapshot firewall's allow on the same key — live
    ground truth wins (order 4 < order 5)."""
    reg = _registry_both_firewalls()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {
        "id": "demo-host",
        "firewall": {
            "default_policy": "allow",
            "rules": [
                {"action": "allow", "proto": "tcp", "port": 445, "direction": "inbound"},
            ],
        },
    }

    # Patch the live_firewall observer inside the registry to return known data
    for obs in reg._by_id.values():
        if isinstance(obs, LiveFirewallObserver):
            monkeypatch.setattr(obs, "_probe_ufw", lambda: parse_ufw_status(_UFW_VERBOSE_OUTPUT))
            monkeypatch.setattr(obs, "_probe_iptables", lambda: None)

    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "exposure")}
    # tcp/445: snapshot says allow (exposed), live says deny (closed) -> closed
    assert rows["tcp/445"]["status"] == "closed"
    assert rows["tcp/445"]["observer"] == "live_firewall"
    # tcp/22: live says allow (exposed) -> exposed
    assert rows["tcp/22"]["status"] == "exposed"
    assert rows["tcp/22"]["observer"] == "live_firewall"
    assert "live_firewall" in dp.used_observers


def test_engine_live_firewall_only_works_standalone(monkeypatch):
    """With only the live_firewall observer (no snapshot firewall), it
    produces the same verdicts as a snapshot would."""
    reg = _registry_live_only()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {"id": "demo-host"}

    for obs in reg._by_id.values():
        if isinstance(obs, LiveFirewallObserver):
            monkeypatch.setattr(obs, "_probe_ufw", lambda: parse_ufw_status(_UFW_VERBOSE_OUTPUT))
            monkeypatch.setattr(obs, "_probe_iptables", lambda: None)

    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "exposure")}
    assert rows["tcp/22"]["status"] == "exposed"
    assert rows["tcp/445"]["status"] == "closed"
    assert rows["tcp/22"]["observer"] == "live_firewall"
    assert "live_firewall" in dp.used_observers


# ---------------------------------------------------------------------------
# parse_nft_ruleset — pure function
# ---------------------------------------------------------------------------

_NFT_OUTPUT = """[
  {"metainfo": {"version": "1.0.0", "release": "nftables 1.0.6"}},
  {"table": {"family": "inet", "name": "filter", "handle": 1}},
  {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 2, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
  {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 3, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
  {"chain": {"family": "inet", "table": "filter", "name": "output", "handle": 4, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}},
  {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 10, "expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 22}}, {"accept": null}]}},
  {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 11, "expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 445}}, {"drop": null}]}},
  {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 12, "expr": [{"match": {"left": {"payload": {"protocol": "udp", "field": "dport"}}, "op": "==", "right": 53}}, {"accept": null}]}},
  {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 13, "expr": [{"match": {"left": {"ct": {"key": "state", "dir": "original"}}, "op": "in", "right": "established"}}, {"accept": null}]}},
  {"rule": {"family": "inet", "table": "filter", "chain": "forward", "handle": 14, "expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 80}}, {"accept": null}]}}
]"""

_NFT_OUTPUT_REJECT = """[
  {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 2, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
  {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 11, "expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 445}}, {"reject": null}]}}
]"""

_NFT_OUTPUT_ACCEPT_DEFAULT = """[
  {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 2, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
  {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 10, "expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 445}}, {"drop": null}]}}
]"""

_NFT_OUTPUT_EMPTY = "[]"
_NFT_OUTPUT_NOT_JSON = "not json at all"
_NFT_OUTPUT_NO_INPUT_CHAIN = """[
  {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 3, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}}
]"""


def test_parse_nft_ruleset_with_rules():
    snap = parse_nft_ruleset(_NFT_OUTPUT)
    assert snap is not None
    assert snap["default_policy"] == "deny"
    rules = snap["rules"]
    keys = {(r["proto"], r["port"], r["action"]) for r in rules}
    assert ("tcp", 22, "allow") in keys
    assert ("tcp", 445, "deny") in keys
    assert ("udp", 53, "allow") in keys
    for r in rules:
        assert r["direction"] == "inbound"
    # established-connection matcher (no dport) is skipped
    assert all(r["proto"] and r["port"] for r in rules)
    # forward-chain rule is excluded (only input chain)
    assert ("tcp", 80, "allow") not in keys


def test_parse_nft_ruleset_reject_is_deny():
    snap = parse_nft_ruleset(_NFT_OUTPUT_REJECT)
    assert snap is not None
    assert snap["rules"][0]["action"] == "deny"


def test_parse_nft_ruleset_accept_default():
    snap = parse_nft_ruleset(_NFT_OUTPUT_ACCEPT_DEFAULT)
    assert snap is not None
    assert snap["default_policy"] == "allow"
    assert len(snap["rules"]) == 1
    assert snap["rules"][0]["action"] == "deny"


def test_parse_nft_ruleset_empty_returns_none():
    assert parse_nft_ruleset(_NFT_OUTPUT_EMPTY) is None


def test_parse_nft_ruleset_not_json_returns_none():
    assert parse_nft_ruleset(_NFT_OUTPUT_NOT_JSON) is None


def test_parse_nft_ruleset_none_returns_none():
    assert parse_nft_ruleset(None) is None
    assert parse_nft_ruleset("") is None


def test_parse_nft_ruleset_no_input_chain_returns_none():
    assert parse_nft_ruleset(_NFT_OUTPUT_NO_INPUT_CHAIN) is None


def test_parse_nft_ruleset_multiple_input_chains_most_restrictive_wins():
    """Two input chains (different tables) — deny policy dominates."""
    text = json.dumps([
        {"chain": {"family": "inet", "table": "filter", "name": "input", "hook": "input", "policy": "accept"}},
        {"chain": {"family": "ip", "table": "other", "name": "input", "hook": "input", "policy": "drop"}},
    ])
    snap = parse_nft_ruleset(text)
    assert snap is not None
    assert snap["default_policy"] == "deny"


# ---------------------------------------------------------------------------
# LiveFirewallObserver — nft probe integration
# ---------------------------------------------------------------------------

def test_observer_nft_fallback_when_ufw_and_iptables_unavailable(monkeypatch):
    """When ufw and iptables return None, the observer tries nft."""
    obs = LiveFirewallObserver()
    pol = _policy()

    monkeypatch.setattr(obs, "_probe_ufw", lambda: None)
    monkeypatch.setattr(obs, "_probe_iptables", lambda: None)
    monkeypatch.setattr(obs, "_probe_nft", lambda: parse_nft_ruleset(_NFT_OUTPUT))

    device = {"id": "host"}
    result = obs.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].status == "exposed"
    assert by_key["tcp/445"].status == "closed"
    assert by_key["udp/53"].status == "exposed"
    for v in result.verdicts:
        assert v.provenance.observer == "live_firewall"
        assert v.provenance.raw_ref == "live:nft list ruleset --json"


def test_observer_nft_skipped_when_ufw_succeeds(monkeypatch):
    """When ufw succeeds, nft is never tried (probe priority)."""
    obs = LiveFirewallObserver()
    pol = _policy()

    nft_called = []

    def _nft_should_not_be_called():
        nft_called.append(True)
        return None

    monkeypatch.setattr(obs, "_probe_ufw", lambda: parse_ufw_status(_UFW_VERBOSE_OUTPUT))
    monkeypatch.setattr(obs, "_probe_iptables", lambda: None)
    monkeypatch.setattr(obs, "_probe_nft", _nft_should_not_be_called)

    device = {"id": "host"}
    result = obs.assess(device, pol)
    assert result.complete is True
    assert len(nft_called) == 0
    for v in result.verdicts:
        assert v.provenance.raw_ref == "live:ufw status verbose"


def test_observer_nft_skipped_when_iptables_succeeds(monkeypatch):
    """When iptables succeeds, nft is never tried (probe priority)."""
    obs = LiveFirewallObserver()
    pol = _policy()

    nft_called = []

    def _nft_should_not_be_called():
        nft_called.append(True)
        return None

    monkeypatch.setattr(obs, "_probe_ufw", lambda: None)
    monkeypatch.setattr(obs, "_probe_iptables", lambda: parse_iptables_rules(_IPTABLES_OUTPUT))
    monkeypatch.setattr(obs, "_probe_nft", _nft_should_not_be_called)

    device = {"id": "host"}
    result = obs.assess(device, pol)
    assert result.complete is True
    assert len(nft_called) == 0
    for v in result.verdicts:
        assert v.provenance.raw_ref == "live:iptables -S"


def test_observer_nft_then_device_fallback(monkeypatch):
    """When all three live probes fail, the observer falls back to device
    snapshot."""
    obs = LiveFirewallObserver()
    pol = _policy()

    monkeypatch.setattr(obs, "_probe_ufw", lambda: None)
    monkeypatch.setattr(obs, "_probe_iptables", lambda: None)
    monkeypatch.setattr(obs, "_probe_nft", lambda: None)

    device = {
        "id": "host",
        "firewall": {
            "default_policy": "deny",
            "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
            ],
        },
    }
    result = obs.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].status == "exposed"
    for v in result.verdicts:
        assert v.provenance.raw_ref == "inline:device.firewall (fallback)"


def test_engine_live_firewall_with_nft_overrides_snapshot(monkeypatch):
    """In the engine, nft-sourced live_firewall verdicts override the
    snapshot firewall on the same proto/port key (order 4 < order 5)."""
    reg = _registry_both_firewalls()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {
        "id": "demo-host",
        "firewall": {
            "default_policy": "allow",
            "rules": [
                {"action": "allow", "proto": "tcp", "port": 445, "direction": "inbound"},
            ],
        },
    }

    for obs in reg._by_id.values():
        if isinstance(obs, LiveFirewallObserver):
            monkeypatch.setattr(obs, "_probe_ufw", lambda: None)
            monkeypatch.setattr(obs, "_probe_iptables", lambda: None)
            monkeypatch.setattr(obs, "_probe_nft", lambda: parse_nft_ruleset(_NFT_OUTPUT))

    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-31T00:00:00+00:00")
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "exposure")}
    # tcp/445: snapshot says allow (exposed), nft says drop (closed) -> closed
    assert rows["tcp/445"]["status"] == "closed"
    assert rows["tcp/445"]["observer"] == "live_firewall"
    # tcp/22: nft says accept (exposed) -> exposed
    assert rows["tcp/22"]["status"] == "exposed"
    assert rows["tcp/22"]["observer"] == "live_firewall"
    assert "live_firewall" in dp.used_observers
