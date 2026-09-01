"""Tests for the live CPE discovery module.

These pin five things:
  1. the pure parsers (parse_dpkg_query, parse_rpm_query) convert live
     command output into package-entry dicts;
  2. package_to_cpe constructs correct CPE 2.3 strings from package names +
     versions, including version normalization (epoch stripping, release
     suffix stripping);
  3. packages_to_cpe_matchers converts package lists to matcher dicts and
     skips unmapped packages;
  4. enrich_device_matchers merges live CPE with existing matchers without
     duplicating CPEs already present;
  5. device_grounding(use_live_cpe=True) integrates live CPE matchers into the
     grounding assessment when the flag is set, and stays unchanged when it is
     not.

SELF-CONTAINED: no subprocess calls — all probe functions are mocked or
bypassed.  Mirrors test_live_firewall.py's style.
"""

from unittest.mock import patch

from posture.grounding import device_grounding, grounding_for_matchers
from posture.sources.live_cpe import (
    parse_dpkg_query,
    parse_rpm_query,
    package_to_cpe,
    packages_to_cpe_matchers,
    _DPKG_TO_CPE,
    _RPM_TO_CPE,
    enrich_device_matchers,
    discover_live_cpe,
    _normalize_version,
    known_dpkg_packages,
    known_rpm_packages,
)


# ---------------------------------------------------------------------------
# 1. Pure parsers
# ---------------------------------------------------------------------------

class TestParseDpkgQuery:
    def test_basic(self):
        text = "openssh-server\t1:9.6p1-3ubuntu13.4\nnginx\t1.24.0-2ubuntu7\n"
        result = parse_dpkg_query(text)
        assert len(result) == 2
        assert result[0] == {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.4"}
        assert result[1] == {"name": "nginx", "version": "1.24.0-2ubuntu7"}

    def test_empty(self):
        assert parse_dpkg_query("") == []
        assert parse_dpkg_query(None) == []  # type: ignore[arg-type]

    def test_whitespace_only(self):
        assert parse_dpkg_query("   \n\n  \n") == []

    def test_lines_without_version_skipped(self):
        text = "openssh-server\t1:9.6p1\njust-a-name\nnginx\t1.24.0\n"
        result = parse_dpkg_query(text)
        assert len(result) == 2
        assert result[0]["name"] == "openssh-server"
        assert result[1]["name"] == "nginx"

    def test_space_separated(self):
        """dpkg-query with space formatting (no tab) should still parse."""
        text = "openssh-server 1:9.6p1-3\nnginx 1.24.0\n"
        result = parse_dpkg_query(text)
        assert len(result) == 2
        assert result[0] == {"name": "openssh-server", "version": "1:9.6p1-3"}

    def test_many_packages(self):
        lines = [f"pkg{i}\t1.0.{i}" for i in range(100)]
        text = "\n".join(lines) + "\n"
        result = parse_dpkg_query(text)
        assert len(result) == 100
        assert result[50] == {"name": "pkg50", "version": "1.0.50"}


class TestParseRpmQuery:
    def test_basic(self):
        text = "openssh-server\t9.6p1-1.el9\nnginx\t1.24.0-1.el9\n"
        result = parse_rpm_query(text)
        assert len(result) == 2
        assert result[0] == {"name": "openssh-server", "version": "9.6p1-1.el9"}
        assert result[1] == {"name": "nginx", "version": "1.24.0-1.el9"}

    def test_empty(self):
        assert parse_rpm_query("") == []


# ---------------------------------------------------------------------------
# 2. Version normalization
# ---------------------------------------------------------------------------

class TestNormalizeVersion:
    def test_strips_epoch(self):
        assert _normalize_version("1:9.6p1-3ubuntu13.4") == "9.6p1"

    def test_strips_release(self):
        assert _normalize_version("1.24.0-2ubuntu7") == "1.24.0"

    def test_strips_epoch_and_release(self):
        assert _normalize_version("2:1.18.0-1ubuntu3.4") == "1.18.0"

    def test_no_epoch_no_release(self):
        assert _normalize_version("9.6p1") == "9.6p1"

    def test_empty(self):
        assert _normalize_version("") == ""

    def test_epoch_only(self):
        assert _normalize_version("3:1.0") == "1.0"

    def test_release_with_multiple_dashes(self):
        # Version with dash inside (rare but valid): "1.2.3-rc1-1.el9"
        # We split on first dash
        assert _normalize_version("1.2.3-rc1-1.el9") == "1.2.3"


# ---------------------------------------------------------------------------
# 3. package_to_cpe
# ---------------------------------------------------------------------------

class TestPackageToCpe:
    def test_known_package(self):
        cpe = package_to_cpe("openssh-server", "1:9.6p1-3ubuntu13.4")
        assert cpe == "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*"

    def test_known_package_case_insensitive(self):
        cpe = package_to_cpe("OpenSSH-Server", "1:9.6p1")
        assert cpe == "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*"

    def test_unknown_package(self):
        assert package_to_cpe("unknown-package", "1.0") is None

    def test_custom_table(self):
        cpe = package_to_cpe("httpd", "2.4.62-1.el9", table=_RPM_TO_CPE)
        assert cpe == "cpe:2.3:a:apache:httpd:2.4.62:*:*:*:*:*:*"

    def test_custom_table_dpkg_fallback(self):
        # nginx is in both tables, but we pass the rpm table
        cpe = package_to_cpe("nginx", "1.24.0", table=_RPM_TO_CPE)
        assert cpe is not None
        assert "nginx:nginx" in cpe

    def test_empty_name(self):
        assert package_to_cpe("", "1.0") is None

    def test_empty_version(self):
        # Empty version still produces a CPE with empty version field
        cpe = package_to_cpe("nginx", "")
        assert cpe == "cpe:2.3:a:nginx:nginx::*:*:*:*:*:*"


# ---------------------------------------------------------------------------
# 4. packages_to_cpe_matchers
# ---------------------------------------------------------------------------

class TestPackagesToCpeMatchers:
    def test_basic(self):
        packages = [
            {"name": "openssh-server", "version": "1:9.6p1-3"},
            {"name": "nginx", "version": "1.24.0"},
            {"name": "unknown-pkg", "version": "1.0"},
        ]
        matchers = packages_to_cpe_matchers(packages)
        assert len(matchers) == 2
        assert matchers[0] == {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*"}
        assert matchers[1] == {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*"}

    def test_empty(self):
        assert packages_to_cpe_matchers([]) == []

    def test_all_unknown(self):
        packages = [{"name": "foo", "version": "1.0"}, {"name": "bar", "version": "2.0"}]
        assert packages_to_cpe_matchers(packages) == []

    def test_rpm_table(self):
        packages = [
            {"name": "httpd", "version": "2.4.62-1.el9"},
            {"name": "bind", "version": "9.18.0-1.el9"},
        ]
        matchers = packages_to_cpe_matchers(packages, table=_RPM_TO_CPE)
        assert len(matchers) == 2
        assert "apache:httpd" in matchers[0]["cpe"]
        assert "isc:bind" in matchers[1]["cpe"]

    def test_matcher_type(self):
        matchers = packages_to_cpe_matchers([{"name": "nginx", "version": "1.0"}])
        assert all(m["type"] == "nvd_cpe" for m in matchers)


# ---------------------------------------------------------------------------
# 5. enrich_device_matchers
# ---------------------------------------------------------------------------

class TestEnrichDeviceMatchers:
    def test_merges_live_with_existing(self):
        device = {
            "matchers": [
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*"},
            ]
        }
        live = [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*"},
        ]
        with patch("posture.sources.live_cpe.discover_live_cpe", return_value=live):
            result = enrich_device_matchers(device)
        assert len(result) == 2
        cpe_values = {m["cpe"] for m in result}
        assert "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*" in cpe_values
        assert "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*" in cpe_values

    def test_deduplicates_existing(self):
        device = {
            "matchers": [
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*"},
            ]
        }
        live = [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*"},
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*"},
        ]
        with patch("posture.sources.live_cpe.discover_live_cpe", return_value=live):
            result = enrich_device_matchers(device)
        assert len(result) == 2  # nginx not duplicated

    def test_no_existing_matchers(self):
        device = {}
        live = [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*"},
        ]
        with patch("posture.sources.live_cpe.discover_live_cpe", return_value=live):
            result = enrich_device_matchers(device)
        assert len(result) == 1
        assert result[0]["cpe"] == "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*"

    def test_no_live_data_returns_existing(self):
        device = {
            "matchers": [
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*"},
            ]
        }
        with patch("posture.sources.live_cpe.discover_live_cpe", return_value=[]):
            result = enrich_device_matchers(device)
        assert len(result) == 1
        assert result[0]["cpe"] == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*"

    def test_empty_device_no_live(self):
        with patch("posture.sources.live_cpe.discover_live_cpe", return_value=[]):
            result = enrich_device_matchers({})
        assert result == []


# ---------------------------------------------------------------------------
# 6. device_grounding with live CPE integration
# ---------------------------------------------------------------------------

class TestDeviceGroundingLiveCpe:
    def test_use_live_cpe_true(self):
        device = {
            "matchers": [
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*"},
            ],
            "firewall": {"default_policy": "deny", "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
            ]},
            "exposure": [
                {"proto": "tcp", "port": 22, "bind": "0.0.0.0"},
            ],
        }
        live = [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*"},
        ]
        with patch("posture.sources.live_cpe.discover_live_cpe", return_value=live):
            grounding = device_grounding(device, use_live_cpe=True)
        # Should have both nginx (port 80/443) and openssh (port 22)
        all_ports = set()
        for ports in grounding["cpe_ports"].values():
            all_ports.update(ports)
        assert 22 in all_ports
        assert 80 in all_ports or 443 in all_ports

    def test_use_live_cpe_false_does_not_enrich(self):
        device = {
            "matchers": [
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*"},
            ],
        }
        live = [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*"},
        ]
        with patch("posture.sources.live_cpe.discover_live_cpe", return_value=live):
            grounding = device_grounding(device, use_live_cpe=False)
        # Only nginx's ports
        all_cpes = set(grounding["cpe_ports"].keys())
        assert len(all_cpes) == 1
        assert "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*" in all_cpes

    def test_use_live_cpe_default_false(self):
        device = {
            "matchers": [
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*"},
            ],
        }
        live = [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*"},
        ]
        with patch("posture.sources.live_cpe.discover_live_cpe", return_value=live):
            grounding = device_grounding(device)
        all_cpes = set(grounding["cpe_ports"].keys())
        assert len(all_cpes) == 1

    def test_no_matchers_no_live(self):
        device = {}
        with patch("posture.sources.live_cpe.discover_live_cpe", return_value=[]):
            grounding = device_grounding(device, use_live_cpe=True)
        assert grounding["cpe_ports"] == {}


# ---------------------------------------------------------------------------
# 7. discover_live_cpe (mocked probes)
# ---------------------------------------------------------------------------

class TestDiscoverLiveCpe:
    def test_dpkg_available(self):
        with patch("posture.sources.live_cpe.probe_dpkg", return_value=[
            {"name": "openssh-server", "version": "1:9.6p1-3"},
            {"name": "nginx", "version": "1.24.0"},
        ]):
            matchers = discover_live_cpe()
        assert len(matchers) == 2
        assert all(m["type"] == "nvd_cpe" for m in matchers)

    def test_dpkg_none_rpm_available(self):
        with patch("posture.sources.live_cpe.probe_dpkg", return_value=None), \
             patch("posture.sources.live_cpe.probe_rpm", return_value=[
                 {"name": "httpd", "version": "2.4.62-1.el9"},
             ]):
            matchers = discover_live_cpe()
        assert len(matchers) == 1
        assert "apache:httpd" in matchers[0]["cpe"]

    def test_neither_available(self):
        with patch("posture.sources.live_cpe.probe_dpkg", return_value=None), \
             patch("posture.sources.live_cpe.probe_rpm", return_value=None):
            assert discover_live_cpe() == []

    def test_dpkg_empty_list(self):
        # dpkg returns empty list (no packages) — should NOT fall through to rpm
        with patch("posture.sources.live_cpe.probe_dpkg", return_value=[]), \
             patch("posture.sources.live_cpe.probe_rpm", return_value=[
                 {"name": "httpd", "version": "2.4.62"},
             ]):
            matchers = discover_live_cpe()
        # dpkg returned [] (not None), so we used dpkg and got no CPE matchers
        assert matchers == []


# ---------------------------------------------------------------------------
# 8. Mapping table coverage
# ---------------------------------------------------------------------------

class TestMappingTables:
    def test_dpkg_table_nonempty(self):
        assert len(_DPKG_TO_CPE) > 30

    def test_rpm_table_nonempty(self):
        assert len(_RPM_TO_CPE) > 20

    def test_known_dpkg_packages(self):
        pkgs = known_dpkg_packages()
        assert "openssh-server" in pkgs
        assert "nginx" in pkgs
        assert "postgresql" in pkgs

    def test_known_rpm_packages(self):
        pkgs = known_rpm_packages()
        assert "httpd" in pkgs
        assert "nginx" in pkgs

    def test_all_cpe_keys_in_port_table(self):
        """Every CPE key produced by the mapping should be in the
        _CPE_PORTS table (otherwise the CPE matcher is useless for
        port grounding)."""
        from posture.grounding import _CPE_PORTS
        for part, vendor, product in _DPKG_TO_CPE.values():
            key = f"{part}:{vendor}:{product}"
            assert key in _CPE_PORTS, f"DPKG CPE key {key} not in _CPE_PORTS"
        for part, vendor, product in _RPM_TO_CPE.values():
            key = f"{part}:{vendor}:{product}"
            assert key in _CPE_PORTS, f"RPM CPE key {key} not in _CPE_PORTS"
