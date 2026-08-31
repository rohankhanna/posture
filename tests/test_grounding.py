"""Tests for posture.grounding — the CPE-to-service-port mapping that
supports finer port-to-CVE suppression on the forebode side.

Design principles under test:
- Only software with a strong default-port convention is mapped (high precision).
- Unknown / unmapped CPEs return an empty list (graceful degradation).
- OS-level CPEs (part=o) are not mapped (no specific listening port).
- The mapping key is part:vendor:product, case-insensitive.
- grounding_for_matchers filters to nvd_cpe matchers and omits unmapped CPEs.
"""
from posture.grounding import (
    cpe_port_key,
    ports_for_cpe,
    grounding_for_matchers,
    known_cpe_keys,
)


# ---------------------------------------------------------------------------
# cpe_port_key
# ---------------------------------------------------------------------------

class TestCpePortKey:
    def test_standard_cpe(self):
        assert cpe_port_key("cpe:2.3:a:openssh:openssh:9.6p1") == "a:openssh:openssh"

    def test_os_cpe(self):
        assert cpe_port_key("cpe:2.3:o:linux:linux_kernel:6.18") == "o:linux:linux_kernel"

    def test_case_insensitive(self):
        assert cpe_port_key("cpe:2.3:a:OpenSSH:OpenSSH:9.6p1") == "a:openssh:openssh"

    def test_minimal_valid(self):
        # Exactly 5 parts: cpe:2.3:a:vendor:product
        assert cpe_port_key("cpe:2.3:a:vendor:product") == "a:vendor:product"

    def test_too_short(self):
        assert cpe_port_key("cpe:2.3:a:vendor") == ""

    def test_empty_string(self):
        assert cpe_port_key("") == ""

    def test_full_cpe_with_all_fields(self):
        key = cpe_port_key(
            "cpe:2.3:a:openssh:openssh:9.6p1:p1:*:*:*:*:*:*"
        )
        assert key == "a:openssh:openssh"


# ---------------------------------------------------------------------------
# ports_for_cpe
# ---------------------------------------------------------------------------

class TestPortsForCpe:
    def test_ssh(self):
        assert ports_for_cpe("cpe:2.3:a:openssh:openssh:9.6p1") == [22]

    def test_web_server_two_ports(self):
        assert ports_for_cpe("cpe:2.3:a:nginx:nginx:1.25.3") == [80, 443]

    def test_database_single_port(self):
        assert ports_for_cpe("cpe:2.3:a:postgresql:postgresql:16.2") == [5432]

    def test_rabbitmq_two_ports(self):
        ports = ports_for_cpe("cpe:2.3:a:rabbitmq:rabbitmq:3.13.0")
        assert 5672 in ports
        assert 15672 in ports

    def test_os_cpe_no_ports(self):
        # OS-level CPEs are not mapped (the kernel does not listen on a port)
        assert ports_for_cpe("cpe:2.3:o:linux:linux_kernel:6.18") == []

    def test_unmapped_application(self):
        # A CPE that exists in the right format but is not in our mapping
        assert ports_for_cpe("cpe:2.3:a:acme:custom_app:1.0") == []

    def test_malformed_cpe(self):
        assert ports_for_cpe("not-a-cpe") == []

    def test_empty_string(self):
        assert ports_for_cpe("") == []

    def test_returns_copy_not_internal_list(self):
        # Mutating the returned list must not corrupt the static table
        ports1 = ports_for_cpe("cpe:2.3:a:openssh:openssh:9.6p1")
        ports1.append(9999)
        ports2 = ports_for_cpe("cpe:2.3:a:openssh:openssh:9.6p1")
        assert ports2 == [22]

    def test_case_insensitive_lookup(self):
        assert ports_for_cpe("cpe:2.3:a:OpenSSH:OpenSSH:9.6p1") == [22]


# ---------------------------------------------------------------------------
# grounding_for_matchers
# ---------------------------------------------------------------------------

class TestGroundingForMatchers:
    def test_mixed_matchers(self):
        matchers = [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1"},
            {"type": "nvd_cpe", "cpe": "cpe:2.3:o:linux:linux_kernel:6.18"},
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:nginx:nginx:1.25.3"},
        ]
        result = grounding_for_matchers(matchers)
        assert result == {
            "cpe:2.3:a:openssh:openssh:9.6p1": [22],
            "cpe:2.3:a:nginx:nginx:1.25.3": [80, 443],
        }

    def test_unmapped_cpe_omitted(self):
        # Unmapped CPEs are not in the result (not included with empty list)
        matchers = [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:o:linux:linux_kernel:6.18"},
        ]
        assert grounding_for_matchers(matchers) == {}

    def test_non_nvd_cpe_matchers_ignored(self):
        matchers = [
            {"type": "ubuntu_release", "release": "noble"},
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1"},
        ]
        result = grounding_for_matchers(matchers)
        assert result == {"cpe:2.3:a:openssh:openssh:9.6p1": [22]}

    def test_empty_matchers(self):
        assert grounding_for_matchers([]) == {}

    def test_matcher_missing_cpe_field(self):
        matchers = [{"type": "nvd_cpe"}]
        assert grounding_for_matchers(matchers) == {}

    def test_matcher_missing_type(self):
        matchers = [{"cpe": "cpe:2.3:a:openssh:openssh:9.6p1"}]
        assert grounding_for_matchers(matchers) == {}

    def test_empty_cpe_string(self):
        matchers = [{"type": "nvd_cpe", "cpe": ""}]
        assert grounding_for_matchers(matchers) == {}

    def test_real_device_yaml_shape(self):
        # Shape from posture/fixtures/sample_device.yaml
        matchers = [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:o:linux:linux_kernel", "version": "6.18"},
        ]
        # linux_kernel has no port mapping
        assert grounding_for_matchers(matchers) == {}

    def test_multiple_mapped_services(self):
        matchers = [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1"},
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:postgresql:postgresql:16.2"},
            {"type": "nvd_cpe", "cpe": "cpe:2.3:a:redis:redis:7.2.4"},
        ]
        result = grounding_for_matchers(matchers)
        assert len(result) == 3
        assert result["cpe:2.3:a:openssh:openssh:9.6p1"] == [22]
        assert result["cpe:2.3:a:postgresql:postgresql:16.2"] == [5432]
        assert result["cpe:2.3:a:redis:redis:7.2.4"] == [6379]


# ---------------------------------------------------------------------------
# known_cpe_keys
# ---------------------------------------------------------------------------

class TestKnownCpeKeys:
    def test_returns_sorted_list(self):
        keys = known_cpe_keys()
        assert keys == sorted(keys)

    def test_includes_ssh(self):
        assert "a:openssh:openssh" in known_cpe_keys()

    def test_includes_nginx(self):
        assert "a:nginx:nginx" in known_cpe_keys()

    def test_all_keys_have_three_parts(self):
        for key in known_cpe_keys():
            assert key.count(":") == 2, f"bad key: {key}"

    def test_all_keys_lowercase(self):
        for key in known_cpe_keys():
            assert key == key.lower(), f"key not lower: {key}"
