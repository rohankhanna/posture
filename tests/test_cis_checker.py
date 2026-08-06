"""Tests for the CIS-style configuration witness — the first REAL witness on
the configuration axis.

These pin four things:
  1. the bundled benchmark (CIS_BENCHMARK) has the expected checks;
  2. the decide logic: pass/fail per check, the numeric >= / <= comparators,
     and the documented missing-setting decision (FAIL — a missing control is
     not a pass);
  3. the witness emits honest configuration-axis Verdicts from a device config
     snapshot, honors cis_checks scoping, and is an honest no-op with no config;
  4. in the engine, the witness's verdicts are committed to the store with
     witness=cis_checker, the configuration axis status is fail when any check
     fails, pass when all pass, and stays unknown when no config is supplied
     (all three directions proven); witness attribution is per-verdict row.
"""
import json
from pathlib import Path

import yaml

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.witness import WitnessRegistry
from posture.sources.cis_checker import (
    CisCheckerWitness, CIS_BENCHMARK, _compare,
)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
SAMPLE_CONFIG = FIXTURE_DIR / "cis" / "sample_config.json"


# Self-contained inline policy: cis_checker on the configuration axis only.
# Built via Policy.from_yaml(<inline string>) so NO shared-file change is
# required to run these tests.
_INLINE_POLICY_YAML = """
version: "2026-08-02.3"
dated: 2026-08-02
rationale: |
  Inline test policy for cis_checker (configuration axis). Self-contained.
witnesses:
  cis_checker:
    axes: [configuration]
    weight: medium
    bias: false-safe
    order: 10
    conditions: []
"""


def _policy() -> Policy:
    return Policy.from_yaml(_INLINE_POLICY_YAML)


def _registry() -> WitnessRegistry:
    reg = WitnessRegistry()
    reg.register(CisCheckerWitness())
    return reg


# ---------------------------------------------------------------------------
# benchmark sanity
# ---------------------------------------------------------------------------

def test_benchmark_has_expected_checks():
    """The broadened benchmark carries the documented Linux/server checks
    (original demo-scope set plus the expanded SSH/password/audit/sysctl/tmp
    coverage)."""
    assert set(CIS_BENCHMARK.keys()) == {
        # original demo-scope checks
        "CIS-6.2.1", "CIS-1.1.2", "CIS-4.1.3",
        "CIS-5.4.1", "CIS-6.1.2", "CIS-5.4.2",
        # expanded coverage
        "CIS-6.2.2", "CIS-6.2.3", "CIS-6.2.4", "CIS-6.2.5", "CIS-6.2.6",
        "CIS-5.4.3", "CIS-5.4.4",
        "CIS-4.1.1", "CIS-4.1.2",
        "CIS-3.1.1", "CIS-3.1.2", "CIS-3.2.1",
        "CIS-1.1.3", "CIS-1.1.4",
    }
    # spot-check a representative entry's shape
    ssh = CIS_BENCHMARK["CIS-6.2.1"]
    assert ssh["setting"] == "sshd_permit_root_login"
    assert ssh["expected"] == "no"
    assert ssh["severity"] == "high"
    assert ssh["comparator"] == "eq"
    # numeric comparator check
    pwd = CIS_BENCHMARK["CIS-5.4.1"]
    assert pwd["expected"] == 12
    assert pwd["comparator"] == "ge"
    # spot-check one of the new eq checks (numeric value compared as str)
    fwd = CIS_BENCHMARK["CIS-3.1.1"]
    assert fwd["setting"] == "sysctl_ipv4_forwarding"
    assert fwd["expected"] == 0
    assert fwd["comparator"] == "eq"
    # spot-check one of the new le checks
    tries = CIS_BENCHMARK["CIS-6.2.3"]
    assert tries["expected"] == 4
    assert tries["comparator"] == "le"


# ---------------------------------------------------------------------------
# comparators (string eq + numeric ge / le)
# ---------------------------------------------------------------------------

def test_compare_eq_string_equality():
    assert _compare("no", "no", "eq") is True
    assert _compare("yes", "no", "eq") is False
    # numbers compared as strings under eq
    assert _compare("12", "12", "eq") is True
    assert _compare(12, "12", "eq") is True


def test_compare_ge_numeric_floor():
    assert _compare(14, 12, "ge") is True
    assert _compare(12, 12, "ge") is True
    assert _compare(8, 12, "ge") is False
    # non-numeric value against a numeric comparator -> fail (never raises)
    assert _compare("unset", 12, "ge") is False


def test_compare_le_numeric_ceiling():
    assert _compare(60, 90, "le") is True
    assert _compare(90, 90, "le") is True
    assert _compare(120, 90, "le") is False
    assert _compare("unset", 90, "le") is False


def test_compare_unknown_comparator_is_safe_fail():
    assert _compare("x", "x", "weird") is False


# ---------------------------------------------------------------------------
# witness decide logic
# ---------------------------------------------------------------------------

def test_decide_pass_on_matching_value():
    w = CisCheckerWitness()
    pol = _policy()
    device = {
        "id": "h",
        "config": {"sshd_permit_root_login": "no"},
        "cis_checks": ["CIS-6.2.1"],
    }
    result = w.assess(device, pol)
    assert len(result.verdicts) == 1
    v = result.verdicts[0]
    assert v.axis == Axis.CONFIGURATION.value
    assert v.key == "CIS-6.2.1"
    assert v.status == "pass"
    assert v.severity == "high"
    assert v.provenance.witness == "cis_checker"
    assert v.provenance.raw_ref == "cis:CIS-6.2.1"


def test_decide_fail_on_mismatched_value():
    w = CisCheckerWitness()
    pol = _policy()
    device = {
        "id": "h",
        "config": {"sshd_permit_root_login": "yes"},  # expected "no"
        "cis_checks": ["CIS-6.2.1"],
    }
    result = w.assess(device, pol)
    assert len(result.verdicts) == 1
    assert result.verdicts[0].status == "fail"
    assert "expected 'no'" in result.verdicts[0].detail


def test_decide_missing_setting_is_fail():
    """Documented behavior: a setting absent from the config is FAIL — a missing
    control is not a pass (false-safe direction)."""
    w = CisCheckerWitness()
    pol = _policy()
    device = {
        "id": "h",
        "config": {},   # no sshd_permit_root_login key
        "cis_checks": ["CIS-6.2.1"],
    }
    result = w.assess(device, pol)
    assert len(result.verdicts) == 1
    assert result.verdicts[0].status == "fail"
    assert "not supplied" in result.verdicts[0].detail
    assert result.verdicts[0].provenance.raw_ref == "cis:CIS-6.2.1"


def test_decide_numeric_ge_pass_and_fail():
    w = CisCheckerWitness()
    pol = _policy()
    # pass: 14 >= 12
    ok = w.assess({"id": "h", "config": {"password_min_len": 14},
                   "cis_checks": ["CIS-5.4.1"]}, pol)
    assert ok.verdicts[0].status == "pass"
    # fail: 8 < 12
    bad = w.assess({"id": "h", "config": {"password_min_len": 8},
                    "cis_checks": ["CIS-5.4.1"]}, pol)
    assert bad.verdicts[0].status == "fail"
    # fail: non-numeric value (control not demonstrably in place)
    ugly = w.assess({"id": "h", "config": {"password_min_len": "unset"},
                     "cis_checks": ["CIS-5.4.1"]}, pol)
    assert ugly.verdicts[0].status == "fail"


def test_decide_numeric_le_pass_and_fail():
    w = CisCheckerWitness()
    pol = _policy()
    ok = w.assess({"id": "h", "config": {"password_max_days": 60},
                   "cis_checks": ["CIS-5.4.2"]}, pol)
    assert ok.verdicts[0].status == "pass"
    bad = w.assess({"id": "h", "config": {"password_max_days": 120},
                    "cis_checks": ["CIS-5.4.2"]}, pol)
    assert bad.verdicts[0].status == "fail"


# ---------------------------------------------------------------------------
# expanded-coverage checks: new eq / ge / le checks
# ---------------------------------------------------------------------------

def test_decide_new_eq_sshd_password_authentication_pass_and_fail():
    """New eq check CIS-6.2.2 (sshd_password_authentication): pass on 'no',
    fail on 'yes'."""
    w = CisCheckerWitness()
    pol = _policy()
    ok = w.assess({"id": "h",
                   "config": {"sshd_password_authentication": "no"},
                   "cis_checks": ["CIS-6.2.2"]}, pol)
    assert len(ok.verdicts) == 1
    assert ok.verdicts[0].status == "pass"
    assert ok.verdicts[0].severity == "high"
    assert ok.verdicts[0].provenance.raw_ref == "cis:CIS-6.2.2"
    bad = w.assess({"id": "h",
                    "config": {"sshd_password_authentication": "yes"},
                    "cis_checks": ["CIS-6.2.2"]}, pol)
    assert bad.verdicts[0].status == "fail"
    assert "expected 'no'" in bad.verdicts[0].detail


def test_decide_new_ge_password_min_days_pass_and_fail():
    """New ge check CIS-5.4.3 (password_min_days): pass at >= 1, fail at 0,
    fail on a non-numeric value (control not demonstrably in place)."""
    w = CisCheckerWitness()
    pol = _policy()
    # pass: 1 >= 1
    ok = w.assess({"id": "h", "config": {"password_min_days": 1},
                   "cis_checks": ["CIS-5.4.3"]}, pol)
    assert len(ok.verdicts) == 1
    assert ok.verdicts[0].status == "pass"
    # pass: 7 >= 1
    high = w.assess({"id": "h", "config": {"password_min_days": 7},
                     "cis_checks": ["CIS-5.4.3"]}, pol)
    assert high.verdicts[0].status == "pass"
    # fail: 0 < 1
    bad = w.assess({"id": "h", "config": {"password_min_days": 0},
                    "cis_checks": ["CIS-5.4.3"]}, pol)
    assert bad.verdicts[0].status == "fail"
    # fail: non-numeric value
    ugly = w.assess({"id": "h", "config": {"password_min_days": "unset"},
                     "cis_checks": ["CIS-5.4.3"]}, pol)
    assert ugly.verdicts[0].status == "fail"


def test_decide_new_le_sshd_max_auth_tries_pass_and_fail():
    """New le check CIS-6.2.3 (sshd_max_auth_tries): pass at <= 4, fail above."""
    w = CisCheckerWitness()
    pol = _policy()
    ok = w.assess({"id": "h", "config": {"sshd_max_auth_tries": 3},
                   "cis_checks": ["CIS-6.2.3"]}, pol)
    assert ok.verdicts[0].status == "pass"
    bad = w.assess({"id": "h", "config": {"sshd_max_auth_tries": 6},
                    "cis_checks": ["CIS-6.2.3"]}, pol)
    assert bad.verdicts[0].status == "fail"


def test_decide_new_eq_sysctl_numeric_value_pass_and_fail():
    """New eq check CIS-3.1.1 (sysctl_ipv4_forwarding): expected 0 — pass when
    the device supplies 0 (int or str), fail when forwarding is enabled (1)."""
    w = CisCheckerWitness()
    pol = _policy()
    # int 0 -> str "0" == str(0) -> pass
    ok_int = w.assess({"id": "h", "config": {"sysctl_ipv4_forwarding": 0},
                       "cis_checks": ["CIS-3.1.1"]}, pol)
    assert ok_int.verdicts[0].status == "pass"
    # str "0" -> pass
    ok_str = w.assess({"id": "h", "config": {"sysctl_ipv4_forwarding": "0"},
                       "cis_checks": ["CIS-3.1.1"]}, pol)
    assert ok_str.verdicts[0].status == "pass"
    # 1 -> fail (forwarding enabled)
    bad = w.assess({"id": "h", "config": {"sysctl_ipv4_forwarding": 1},
                    "cis_checks": ["CIS-3.1.1"]}, pol)
    assert bad.verdicts[0].status == "fail"


def test_decide_new_check_missing_setting_is_fail():
    """Missing-setting decision holds for the new checks too: a setting absent
    from the config is FAIL (a missing control is not a pass)."""
    w = CisCheckerWitness()
    pol = _policy()
    device = {
        "id": "h",
        "config": {},   # no sshd_password_authentication key
        "cis_checks": ["CIS-6.2.2"],
    }
    result = w.assess(device, pol)
    assert len(result.verdicts) == 1
    assert result.verdicts[0].status == "fail"
    assert "not supplied" in result.verdicts[0].detail
    assert result.verdicts[0].provenance.raw_ref == "cis:CIS-6.2.2"


# ---------------------------------------------------------------------------
# witness: full benchmark run + cis_checks scoping
# ---------------------------------------------------------------------------

def test_witness_full_config_emits_verdict_per_check():
    w = CisCheckerWitness()
    pol = _policy()
    device = {
        "id": "h",
        "config": {
            "sshd_permit_root_login": "no",
            "tmp_nosuid": "no",            # FAIL (expected yes)
            "audit_log_files": "yes",
            "password_min_len": 8,          # FAIL (expected >=12)
            "world_writable_files": "none",
            "password_max_days": 60,
        },
        # no cis_checks -> run the whole benchmark
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert set(by_key.keys()) == set(CIS_BENCHMARK.keys())
    assert by_key["CIS-6.2.1"].status == "pass"
    assert by_key["CIS-1.1.2"].status == "fail"
    assert by_key["CIS-5.4.1"].status == "fail"
    assert by_key["CIS-6.1.2"].status == "pass"
    for v in result.verdicts:
        assert v.provenance.witness == "cis_checker"
        assert v.provenance.raw_ref.startswith("cis:CIS-")
        assert v.axis == Axis.CONFIGURATION.value


def test_witness_cis_checks_scopes_to_subset():
    w = CisCheckerWitness()
    pol = _policy()
    device = {
        "id": "h",
        "config": {
            "sshd_permit_root_login": "no",
            "tmp_nosuid": "yes",
            "world_writable_files": "none",
        },
        "cis_checks": ["CIS-6.2.1", "CIS-6.1.2"],   # only these two run
    }
    result = w.assess(device, pol)
    assert sorted(v.key for v in result.verdicts) == ["CIS-6.1.2", "CIS-6.2.1"]
    assert all(v.status == "pass" for v in result.verdicts)


def test_witness_cis_checks_filters_unknown_ids():
    w = CisCheckerWitness()
    pol = _policy()
    device = {
        "id": "h",
        "config": {"sshd_permit_root_login": "no"},
        "cis_checks": ["CIS-6.2.1", "CIS-9.9.9", "not-a-check"],
    }
    result = w.assess(device, pol)
    assert [v.key for v in result.verdicts] == ["CIS-6.2.1"]


def test_witness_loads_offline_fixture():
    """The bundled sample_config.json fixture loads and yields verdicts."""
    w = CisCheckerWitness()
    pol = _policy()
    device = json.loads(SAMPLE_CONFIG.read_text())
    result = w.assess(device, pol)
    # fixture scopes to three checks
    assert sorted(v.key for v in result.verdicts) == [
        "CIS-1.1.2", "CIS-5.4.1", "CIS-6.2.1",
    ]
    # sshd no -> pass; tmp_nosuid no -> fail; password_min_len 8 -> fail
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["CIS-6.2.1"].status == "pass"
    assert by_key["CIS-1.1.2"].status == "fail"
    assert by_key["CIS-5.4.1"].status == "fail"


# ---------------------------------------------------------------------------
# honest no-op (no config supplied)
# ---------------------------------------------------------------------------

def test_witness_no_config_is_honest_noop():
    """A device with no config snapshot gives the witness nothing to say. It
    returns ZERO verdicts (complete) so the configuration axis stays UNKNOWN
    (loud) — never a crash, never silently clean."""
    w = CisCheckerWitness()
    pol = _policy()
    for device in (
        {"id": "h"},                          # no config key at all
        {"id": "h", "config": None},          # config explicitly None
        {"id": "h", "config": "not-a-dict"},  # wrong type
    ):
        result = w.assess(device, pol)
        assert result.verdicts == []
        assert result.complete is True
        assert "no config supplied" in result.reason


# ---------------------------------------------------------------------------
# engine: verdicts committed, axis status, witness attribution
# ---------------------------------------------------------------------------

def _run_engine(device, conn):
    reg = _registry()
    pol = _policy()
    return engine.assess(device, reg, pol, conn=conn,
                         now="2026-08-02T00:00:00+00:00")


def _config_axis(dp):
    return {a.axis: a for a in dp.axes}["configuration"]


def test_engine_commits_verdicts_with_witness_attribution():
    """A failing config drives committed configuration verdicts, all carrying
    witness=cis_checker at the per-verdict row level."""
    conn = store.connect(":memory:")
    device = {
        "id": "cfg-host",
        "config": {
            "sshd_permit_root_login": "yes",   # FAIL
            "tmp_nosuid": "yes",
            "audit_log_files": "yes",
            "password_min_len": 14,
            "world_writable_files": "none",
            "password_max_days": 60,
        },
    }
    dp = _run_engine(device, conn)
    assert _config_axis(dp).status == "fail"
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "cfg-host", "configuration")}
    assert rows["CIS-6.2.1"]["status"] == "fail"
    assert rows["CIS-6.2.1"]["witness"] == "cis_checker"
    assert rows["CIS-6.2.1"]["raw_ref"] == "cis:CIS-6.2.1"
    # every committed row rests on cis_checker
    assert all(r["witness"] == "cis_checker" for r in rows.values())
    # deciding witness for the axis is cis_checker
    assert _config_axis(dp).deciding_witness == "cis_checker"


def test_engine_all_pass_axis_status_pass():
    """When every applicable check passes, the configuration axis status is
    pass (worst present = pass)."""
    conn = store.connect(":memory:")
    device = {
        "id": "clean-host",
        "config": {
            # original demo-scope checks (all pass)
            "sshd_permit_root_login": "no",
            "tmp_nosuid": "yes",
            "audit_log_files": "yes",
            "password_min_len": 14,
            "world_writable_files": "none",
            "password_max_days": 60,
            # expanded coverage (all pass)
            "sshd_password_authentication": "no",
            "sshd_max_auth_tries": 4,            # le 4 -> pass
            "sshd_login_grace_time": 60,         # le 60 -> pass
            "sshd_permit_empty_passwords": "no",
            "sshd_x11_forwarding": "no",
            "password_min_days": 1,              # ge 1 -> pass
            "password_warn_age": 7,              # ge 7 -> pass
            "auditd_enabled": "yes",
            "audit_log_size": 100,               # ge 100 -> pass
            "sysctl_ipv4_forwarding": 0,         # eq 0 -> pass
            "sysctl_ipv6_forwarding": 0,         # eq 0 -> pass
            "sysctl_tcp_syncookies": 1,          # eq 1 -> pass
            "tmp_nodev": "yes",
            "tmp_noexec": "yes",
        },
    }
    dp = _run_engine(device, conn)
    cfg = _config_axis(dp)
    assert cfg.status == "pass"
    assert cfg.deciding_witness == "cis_checker"


def test_engine_no_config_axis_stays_unknown():
    """No config supplied -> zero verdicts -> the configuration axis is UNKNOWN
    (loud), NOT silently clean. Proves the unknown direction."""
    conn = store.connect(":memory:")
    device = {"id": "blank-host"}   # no config
    dp = _run_engine(device, conn)
    cfg = _config_axis(dp)
    assert cfg.status == "unknown"
    assert cfg.deciding_witness is None
    # no verdict rows committed
    assert store.verdicts_for_device_axis(conn, "blank-host",
                                          "configuration") == []
    # and the witness is NOT a 'used' witness (it produced no verdicts)
    assert "cis_checker" not in dp.used_witnesses


def test_engine_partial_fail_drives_axis_fail():
    """A config that fails at least one check makes the whole configuration axis
    fail (worst present wins), even if most checks pass."""
    conn = store.connect(":memory:")
    device = {
        "id": "mixed-host",
        "config": {
            "sshd_permit_root_login": "no",     # pass
            "tmp_nosuid": "yes",                # pass
            "audit_log_files": "yes",           # pass
            "password_min_len": 14,             # pass
            "world_writable_files": "/tmp/f",   # FAIL (expected none)
            "password_max_days": 60,            # pass
        },
    }
    dp = _run_engine(device, conn)
    assert _config_axis(dp).status == "fail"
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "mixed-host", "configuration")}
    assert rows["CIS-6.1.2"]["status"] == "fail"
    assert rows["CIS-6.2.1"]["status"] == "pass"


def test_engine_scoped_cis_checks_commit_only_subset():
    """device['cis_checks'] scopes which checks run; only those verdicts are
    committed."""
    conn = store.connect(":memory:")
    device = {
        "id": "scoped-host",
        "config": {
            "sshd_permit_root_login": "no",
            "tmp_nosuid": "no",
            "world_writable_files": "none",
        },
        "cis_checks": ["CIS-6.2.1", "CIS-6.1.2"],
    }
    dp = _run_engine(device, conn)
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "scoped-host", "configuration")}
    assert sorted(rows) == ["CIS-6.1.2", "CIS-6.2.1"]
    assert all(r["witness"] == "cis_checker" for r in rows.values())
    # CIS-6.2.1 pass, CIS-6.1.2 pass -> axis pass
    assert _config_axis(dp).status == "pass"