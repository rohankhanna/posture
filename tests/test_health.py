"""Health tests — source-health operational + dossier + degradation."""
import datetime as _dt
import pytest

from posture.policy import Policy, default_policy_path
from posture import store, health


def _now_offset(days: int) -> str:
    base = _dt.datetime(2026, 8, 1, tzinfo=_dt.timezone.utc)
    return (base - _dt.timedelta(days=days)).isoformat()


def _conn_with_samples():
    conn = store.connect(":memory:")
    # 3 complete + 2 incomplete samples for nvd
    for complete in (True, True, True, False, False):
        store.record_health_sample(conn, "nvd", "dev", "vulnerability",
                                    complete, 100, "" if complete else "504",
                                    _now_offset(0))
    conn.commit()
    return conn


def test_operational_health_success_rate():
    conn = _conn_with_samples()
    op = health.operational_health(conn, "nvd")
    assert op.samples == 5
    assert op.success_rate == pytest.approx(0.6)
    assert op.mean_latency_ms == 100.0


def test_dossier_add_and_read():
    conn = store.connect(":memory:")
    health.add_dossier_entry(conn, "nvd", "2026-08-01", "vulnerability",
                              "backlog growing", "https://nvd.nist.gov", "funding")
    conn.commit()
    d = health.dossier(conn, "nvd")
    assert len(d) == 1
    assert d[0]["claim"] == "backlog growing"
    assert d[0]["direction"] == "funding"


def test_dossier_bad_direction_rejected():
    conn = store.connect(":memory:")
    with pytest.raises(ValueError):
        health.add_dossier_entry(conn, "nvd", "2026-08-01", "vulnerability",
                                  "x", "y", "optimistic")


def test_degradation_ok_within_window():
    conn = store.connect(":memory:")
    policy = Policy.from_file(default_policy_path())
    # record a fresh complete sample (now)
    store.record_health_sample(conn, "nvd", "dev", "vulnerability", True, 50,
                                "ok", _now_offset(0))
    conn.commit()
    assert health.degradation_action(conn, "nvd", policy,
                                      _now_offset(0)) == "ok"


def test_degradation_fallback_when_silent_too_long():
    conn = store.connect(":memory:")
    policy = Policy.from_file(default_policy_path())
    # last complete fetch 30 days ago — past the 14-day window, with fallback
    store.record_health_sample(conn, "nvd", "dev", "vulnerability", True, 50,
                                "ok", _now_offset(30))
    conn.commit()
    assert health.degradation_action(conn, "nvd", policy,
                                      _now_offset(0)) == "fallback"


def test_degradation_offline_when_silent_no_fallback():
    conn = store.connect(":memory:")
    policy = Policy.from_file(default_policy_path())
    # mitre_cve has if_silent_for_days=30 but fallback=[ghsa, osv_id] -> still
    # 'fallback'; instead craft a policy with no fallback for a witness.
    custom = Policy.from_yaml(f"""
version: "2026-08-01.1"
dated: 2026-08-01
witnesses:
  nvd: {{axes: [vulnerability], bias: false-alarm}}
degradation:
  nvd: {{if_silent_for_days: 1, fallback: []}}
""")
    store.record_health_sample(conn, "nvd", "dev", "vulnerability", True, 50,
                                "ok", _now_offset(10))
    conn.commit()
    assert health.degradation_action(conn, "nvd", custom,
                                      _now_offset(0)) == "offline"


def test_drift_flag_insufficient_then_stable():
    conn = store.connect(":memory:")
    assert health.drift_flag(conn, "nvd") == "insufficient"
    # add two identical snapshots
    for _ in range(2):
        health.record_distribution_snapshot(conn, "nvd", "dev", "vulnerability",
                                             [{"status": "unpatched"}],
                                             _now_offset(0))
    conn.commit()
    assert health.drift_flag(conn, "nvd") == "stable"
    # now a different snapshot
    health.record_distribution_snapshot(conn, "nvd", "dev", "vulnerability",
                                         [{"status": "patched"}], _now_offset(0))
    conn.commit()
    assert health.drift_flag(conn, "nvd") == "shifted"