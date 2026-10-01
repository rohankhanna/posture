"""Tests for posture.grounding.device_grounding — the composite grounding
assessment that combines firewall, local exposure, network interfaces, and
CPE-to-port mapping into a single dict.

Design principles under test:
- Truly exposed = listening (non-loopback) AND firewall-allowed (or default allow).
- Missing snapshots degrade gracefully (empty sets, False, empty lists).
- The composite function is pure: no network, no I/O beyond local JSON files.
- CPE ports are derived from matchers via grounding_for_matchers.
- Loopback-bound sockets are never in truly_exposed_ports.
- Firewall deny overrides a listening socket even under default-allow.
"""
from posture.grounding import device_grounding


# ---------------------------------------------------------------------------
# Truly-exposed-ports: the intersection of firewall + listening
# ---------------------------------------------------------------------------

class TestTrulyExposedPorts:
    def test_firewall_allow_and_listening(self):
        """Port is both firewall-allowed and listening on 0.0.0.0 -> truly exposed."""
        g = device_grounding({
            "firewall": {"default_policy": "deny", "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
            ]},
            "exposure": [
                {"proto": "tcp", "port": 22, "bind": "0.0.0.0"},
            ],
        })
        assert g["truly_exposed_ports"] == {"tcp/22"}

    def test_firewall_deny_and_listening_not_exposed(self):
        """Port is listening but firewall denies -> NOT truly exposed."""
        g = device_grounding({
            "firewall": {"default_policy": "allow", "rules": [
                {"action": "deny", "proto": "tcp", "port": 445, "direction": "inbound"},
            ]},
            "exposure": [
                {"proto": "tcp", "port": 445, "bind": "0.0.0.0"},
            ],
        })
        assert "tcp/445" not in g["truly_exposed_ports"]

    def test_firewall_allow_but_not_listening_not_exposed(self):
        """Port is firewall-allowed but nothing is listening -> NOT truly exposed."""
        g = device_grounding({
            "firewall": {"default_policy": "deny", "rules": [
                {"action": "allow", "proto": "tcp", "port": 80, "direction": "inbound"},
            ]},
            # no exposure data
        })
        assert g["truly_exposed_ports"] == set()

    def test_default_allow_listening_not_denied_is_exposed(self):
        """Under default-allow, a listening port without explicit deny is exposed."""
        g = device_grounding({
            "firewall": {"default_policy": "allow", "rules": []},
            "exposure": [
                {"proto": "tcp", "port": 8080, "bind": "0.0.0.0"},
            ],
        })
        assert g["truly_exposed_ports"] == {"tcp/8080"}

    def test_default_deny_listening_without_allow_not_exposed(self):
        """Under default-deny, a listening port without explicit allow is NOT exposed."""
        g = device_grounding({
            "firewall": {"default_policy": "deny", "rules": []},
            "exposure": [
                {"proto": "tcp", "port": 8080, "bind": "0.0.0.0"},
            ],
        })
        assert g["truly_exposed_ports"] == set()

    def test_no_firewall_listening_not_exposed(self):
        """No firewall data at all -> listening ports are not truly exposed
        (we cannot prove the firewall allows them)."""
        g = device_grounding({
            "exposure": [
                {"proto": "tcp", "port": 22, "bind": "0.0.0.0"},
            ],
        })
        assert g["truly_exposed_ports"] == set()

    def test_loopback_listen_never_truly_exposed(self):
        """A socket bound to 127.0.0.1 is never truly exposed, even with
        firewall allow."""
        g = device_grounding({
            "firewall": {"default_policy": "allow", "rules": [
                {"action": "allow", "proto": "tcp", "port": 5432, "direction": "inbound"},
            ]},
            "exposure": [
                {"proto": "tcp", "port": 5432, "bind": "127.0.0.1"},
            ],
        })
        assert g["truly_exposed_ports"] == set()
        assert "tcp/5432" in g["listening_loopback"]

    def test_multiple_ports_mixed(self):
        """Several ports with mixed firewall + exposure states."""
        g = device_grounding({
            "firewall": {"default_policy": "deny", "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
                {"action": "allow", "proto": "tcp", "port": 443, "direction": "inbound"},
                {"action": "deny", "proto": "tcp", "port": 3306, "direction": "inbound"},
            ]},
            "exposure": [
                {"proto": "tcp", "port": 22, "bind": "0.0.0.0"},
                {"proto": "tcp", "port": 443, "bind": "::"},
                {"proto": "tcp", "port": 3306, "bind": "0.0.0.0"},
                {"proto": "tcp", "port": 8080, "bind": "0.0.0.0"},
                {"proto": "tcp", "port": 5432, "bind": "127.0.0.1"},
            ],
        })
        assert g["truly_exposed_ports"] == {"tcp/22", "tcp/443"}
        assert "tcp/3306" not in g["truly_exposed_ports"]  # firewall denies
        assert "tcp/8080" not in g["truly_exposed_ports"]  # no firewall allow
        assert "tcp/5432" not in g["truly_exposed_ports"]  # loopback

    def test_udp_port_truly_exposed(self):
        """UDP ports work the same way."""
        g = device_grounding({
            "firewall": {"default_policy": "deny", "rules": [
                {"action": "allow", "proto": "udp", "port": 53, "direction": "inbound"},
            ]},
            "exposure": [
                {"proto": "udp", "port": 53, "bind": "0.0.0.0"},
            ],
        })
        assert g["truly_exposed_ports"] == {"udp/53"}

    def test_missing_bind_treated_as_exposed(self):
        """A socket with no bind field is false-safe: treated as non-loopback."""
        g = device_grounding({
            "firewall": {"default_policy": "allow", "rules": []},
            "exposure": [
                {"proto": "tcp", "port": 22},
            ],
        })
        assert "tcp/22" in g["listening_exposed"]
        assert "tcp/22" in g["truly_exposed_ports"]


# ---------------------------------------------------------------------------
# Firewall parsing
# ---------------------------------------------------------------------------

class TestFirewallParsing:
    def test_allowed_and_denied_sets(self):
        g = device_grounding({
            "firewall": {"default_policy": "deny", "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
                {"action": "deny", "proto": "tcp", "port": 445, "direction": "inbound"},
            ]},
        })
        assert g["firewall_allowed"] == {"tcp/22"}
        assert g["firewall_denied"] == {"tcp/445"}
        assert g["firewall_default_policy"] == "deny"

    def test_outbound_rules_ignored(self):
        g = device_grounding({
            "firewall": {"default_policy": "deny", "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "outbound"},
            ]},
        })
        assert g["firewall_allowed"] == set()

    def test_no_firewall_data(self):
        g = device_grounding({})
        assert g["firewall_allowed"] == set()
        assert g["firewall_denied"] == set()
        assert g["firewall_default_policy"] == ""

    def test_empty_rules_list(self):
        g = device_grounding({
            "firewall": {"default_policy": "allow", "rules": []},
        })
        assert g["firewall_allowed"] == set()
        assert g["firewall_default_policy"] == "allow"


# ---------------------------------------------------------------------------
# Local exposure parsing
# ---------------------------------------------------------------------------

class TestLocalExposureParsing:
    def test_exposed_and_loopback_split(self):
        g = device_grounding({
            "exposure": [
                {"proto": "tcp", "port": 22, "bind": "0.0.0.0"},
                {"proto": "tcp", "port": 5432, "bind": "127.0.0.1"},
                {"proto": "tcp", "port": 8080, "bind": "::1"},
            ],
        })
        assert g["listening_exposed"] == {"tcp/22"}
        assert g["listening_loopback"] == {"tcp/5432", "tcp/8080"}

    def test_no_exposure_data(self):
        g = device_grounding({})
        assert g["listening_exposed"] == set()
        assert g["listening_loopback"] == set()

    def test_localhost_bind_is_loopback(self):
        g = device_grounding({
            "exposure": [
                {"proto": "tcp", "port": 80, "bind": "localhost"},
            ],
        })
        assert "tcp/80" in g["listening_loopback"]
        assert "tcp/80" not in g["listening_exposed"]


# ---------------------------------------------------------------------------
# Network interfaces parsing
# ---------------------------------------------------------------------------

class TestNetworkInterfaces:
    def test_has_network_access_with_eth0(self):
        g = device_grounding({
            "interfaces": [
                {"name": "lo", "state": "up", "addresses": [
                    {"ip": "127.0.0.1", "prefix": 8},
                ]},
                {"name": "eth0", "state": "up", "addresses": [
                    {"ip": "192.168.1.42", "prefix": 24},
                ]},
            ],
        })
        assert g["has_network_access"] is True
        assert "192.168.1.0/24" in g["reachable_subnets"]

    def test_no_network_access_loopback_only(self):
        g = device_grounding({
            "interfaces": [
                {"name": "lo", "state": "up", "addresses": [
                    {"ip": "127.0.0.1", "prefix": 8},
                ]},
            ],
        })
        assert g["has_network_access"] is False
        assert g["reachable_subnets"] == []

    def test_down_interface_not_reachable(self):
        g = device_grounding({
            "interfaces": [
                {"name": "wlan0", "state": "down", "addresses": [
                    {"ip": "172.16.0.10", "prefix": 16},
                ]},
            ],
        })
        assert g["has_network_access"] is False
        assert g["reachable_subnets"] == []

    def test_no_interfaces_data(self):
        g = device_grounding({})
        assert g["has_network_access"] is False
        assert g["reachable_subnets"] == []

    def test_multiple_non_loopback_interfaces(self):
        g = device_grounding({
            "interfaces": [
                {"name": "eth0", "state": "up", "addresses": [
                    {"ip": "192.168.1.42", "prefix": 24},
                ]},
                {"name": "eth1", "state": "up", "addresses": [
                    {"ip": "10.0.0.5", "prefix": 8},
                ]},
            ],
        })
        assert g["has_network_access"] is True
        assert "192.168.1.0/24" in g["reachable_subnets"]
        assert "10.0.0.0/8" in g["reachable_subnets"]

    def test_ipv6_non_loopback(self):
        g = device_grounding({
            "interfaces": [
                {"name": "eth0", "state": "up", "addresses": [
                    {"ip": "fd00::5", "prefix": 64},
                ]},
            ],
        })
        assert g["has_network_access"] is True
        assert "fd00::/64" in g["reachable_subnets"]


# ---------------------------------------------------------------------------
# CPE ports in composite
# ---------------------------------------------------------------------------

class TestCpePortsInComposite:
    def test_cpe_ports_from_matchers(self):
        g = device_grounding({
            "matchers": [
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1"},
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.25.3"},
            ],
        })
        assert g["cpe_ports"]["cpe:2.3:a:openssh:openssh:9.6p1"] == [22]
        assert g["cpe_ports"]["cpe:2.3:a:nginx:nginx:1.25.3"] == [80, 443]

    def test_no_matchers_empty_cpe_ports(self):
        g = device_grounding({})
        assert g["cpe_ports"] == {}


# ---------------------------------------------------------------------------
# Full integration with all axes present
# ---------------------------------------------------------------------------

class TestFullComposite:
    def test_all_axes_present(self):
        g = device_grounding({
            "firewall": {"default_policy": "deny", "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
                {"action": "allow", "proto": "tcp", "port": 443, "direction": "inbound"},
                {"action": "deny", "proto": "tcp", "port": 445, "direction": "inbound"},
            ]},
            "exposure": [
                {"proto": "tcp", "port": 22, "bind": "0.0.0.0", "service": "ssh"},
                {"proto": "tcp", "port": 443, "bind": "0.0.0.0", "service": "nginx"},
                {"proto": "tcp", "port": 5432, "bind": "127.0.0.1", "service": "postgres"},
            ],
            "interfaces": [
                {"name": "lo", "state": "up", "addresses": [
                    {"ip": "127.0.0.1", "prefix": 8},
                ]},
                {"name": "eth0", "state": "up", "addresses": [
                    {"ip": "192.168.1.42", "prefix": 24},
                ]},
            ],
            "matchers": [
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1"},
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.25.3"},
            ],
        })
        assert g["truly_exposed_ports"] == {"tcp/22", "tcp/443"}
        assert g["firewall_allowed"] == {"tcp/22", "tcp/443"}
        assert g["firewall_denied"] == {"tcp/445"}
        assert g["firewall_default_policy"] == "deny"
        assert g["listening_exposed"] == {"tcp/22", "tcp/443"}
        assert g["listening_loopback"] == {"tcp/5432"}
        assert g["has_network_access"] is True
        assert "192.168.1.0/24" in g["reachable_subnets"]
        assert len(g["cpe_ports"]) == 2

    def test_empty_device(self):
        """A device with no grounding data at all produces safe defaults."""
        g = device_grounding({})
        assert g["truly_exposed_ports"] == set()
        assert g["firewall_allowed"] == set()
        assert g["firewall_denied"] == set()
        assert g["firewall_default_policy"] == ""
        assert g["listening_exposed"] == set()
        assert g["listening_loopback"] == set()
        assert g["has_network_access"] is False
        assert g["reachable_subnets"] == []
        assert g["cpe_ports"] == {}

    def test_returns_dict_with_all_keys(self):
        g = device_grounding({})
        expected_keys = {
            "truly_exposed_ports", "firewall_allowed", "firewall_denied",
            "firewall_default_policy", "listening_exposed", "listening_loopback",
            "has_network_access", "reachable_subnets", "cpe_ports",
        }
        assert set(g.keys()) == expected_keys
