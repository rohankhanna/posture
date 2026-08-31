"""Policy tests — versioned trust policy loading + validation."""
import pytest
from posture.policy import Policy, PolicyError, default_policy_path


VALID = """
version: "2026-08-01.1"
supersedes: null
dated: 2026-08-01
rationale: test
observers:
  nvd: {axes: [vulnerability], weight: high, bias: false-alarm, order: 10, conditions: []}
degradation:
  nvd: {if_silent_for_days: 14, fallback: [osv]}
spine:
  primary_key: cve
  crosswalk: [[cve, ghsa]]
"""


def test_load_valid_policy():
    p = Policy.from_yaml(VALID)
    assert p.version == "2026-08-01.1"
    assert p.supersedes is None
    assert p.has_observer("nvd")
    assert p.observer_order("nvd") == 10
    assert p.observer_bias("nvd") == "false-alarm"
    assert p.degradation_for("nvd").if_silent_for_days == 14
    # the spine is the alias graph now: no primary_key/role, crosswalk is advisory
    assert not hasattr(p.spine, "primary_key")
    assert ("cve", "ghsa") in p.spine.crosswalk


def test_bad_version_rejected():
    bad = VALID.replace('version: "2026-08-01.1"', 'version: "v1"')
    with pytest.raises(PolicyError):
        Policy.from_yaml(bad)


def test_unknown_axis_rejected():
    bad = VALID.replace("axes: [vulnerability]", "axes: [weather]")
    with pytest.raises(PolicyError):
        Policy.from_yaml(bad)


def test_bad_bias_rejected():
    bad = VALID.replace("bias: false-alarm", "bias: optimistic")
    with pytest.raises(PolicyError):
        Policy.from_yaml(bad)


def test_missing_dated_rejected():
    bad = VALID.replace("dated: 2026-08-01\n", "")
    with pytest.raises(PolicyError):
        Policy.from_yaml(bad)


def test_bundled_default_policy_loads():
    p = Policy.from_file(default_policy_path())
    assert p.version == "2026-08-31.2"
    # all six axes are covered by the bundled observer entries
    covered = {a for wp in p.observers.values() for a in wp.axes}
    assert covered == {"vulnerability", "configuration", "exposure",
                       "inventory", "threat", "trust"}


def test_to_summary_roundtrip_shape():
    p = Policy.from_yaml(VALID)
    s = p.to_summary()
    assert s["version"] == "2026-08-01.1"
    assert "observers" in s and "degradation" in s and "spine" in s


def test_date_literal_coerced_from_yaml_date_object():
    # YAML parses bare 2026-08-01 as a date object; loader must coerce to str
    p = Policy.from_yaml(VALID.replace("dated: 2026-08-01", "dated: 2026-08-01"))
    assert isinstance(p.dated, str)
    assert p.dated == "2026-08-01"