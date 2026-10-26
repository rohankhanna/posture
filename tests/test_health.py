"""Health tests — source-health operational + dossier + degradation."""
import datetime as _dt

import pytest

from posture import health, store
from posture.policy import Policy, default_policy_path


def _now_offset(days: int) -> str:
    base = _dt.datetime(2026, 8, 1, tzinfo=_dt.UTC)
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
    # 'fallback'; instead craft a policy with no fallback for a observer.
    custom = Policy.from_yaml("""
version: "2026-08-01.1"
dated: 2026-08-01
observers:
  nvd: {axes: [vulnerability], bias: false-alarm}
degradation:
  nvd: {if_silent_for_days: 1, fallback: []}
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

# --- slice (c): ledger -> degradation action / report wiring --------------

def test_degradation_action_ledger_forces_fallback_when_fresh():
    """An active upstream degradation event means the source's output is
    degraded even when freshly fetched -> fallback engages regardless of
    measured freshness."""
    from posture.source_history import (
        EVENT_DEGRADATION,
        STATUS_ACTIVE,
        EventLedger,
        SourceEvent,
    )
    conn = store.connect(":memory:")
    policy = Policy.from_file(default_policy_path())
    # record a fresh complete sample (now) — operationally healthy
    store.record_health_sample(conn, "nvd", "dev", "vulnerability", True, 50,
                                "ok", _now_offset(0))
    conn.commit()
    ledger = EventLedger()
    ledger.add(SourceEvent(
        id="nvd-gap", date="2026-04-15", source="nvd",
        event_type=EVENT_DEGRADATION, summary="enrichment gap",
        map_layer="enrichment", status=STATUS_ACTIVE,
        interpretation="fill with OSV+EPSS overlays",
    ))
    assert health.degradation_action(conn, "nvd", policy, _now_offset(0),
                                      ledger=ledger) == "fallback"


def test_degradation_action_ledger_offline_when_no_fallback():
    from posture.source_history import (
        EVENT_DEGRADATION,
        STATUS_ACTIVE,
        EventLedger,
        SourceEvent,
    )
    custom = Policy.from_yaml("""
version: "2026-08-01.1"
dated: 2026-08-01
observers:
  nvd: {axes: [vulnerability], bias: false-alarm}
degradation:
  nvd: {if_silent_for_days: 14, fallback: []}
""")
    conn = store.connect(":memory:")
    store.record_health_sample(conn, "nvd", "dev", "vulnerability", True, 50,
                                "ok", _now_offset(0))
    conn.commit()
    ledger = EventLedger()
    ledger.add(SourceEvent(
        id="nvd-gap", date="2026-04-15", source="nvd",
        event_type=EVENT_DEGRADATION, summary="enrichment gap",
        map_layer="enrichment", status=STATUS_ACTIVE,
        interpretation="no fallback declared",
    ))
    assert health.degradation_action(conn, "nvd", custom, _now_offset(0),
                                      ledger=ledger) == "offline"


def test_degradation_action_ledger_none_preserves_old_contract():
    """ledger=None must keep the pre-slice-(c) behavior exactly."""
    conn = store.connect(":memory:")
    policy = Policy.from_file(default_policy_path())
    store.record_health_sample(conn, "nvd", "dev", "vulnerability", True, 50,
                                "ok", _now_offset(0))
    conn.commit()
    assert health.degradation_action(conn, "nvd", policy, _now_offset(0)) == "ok"


def test_degradation_action_non_degrading_event_does_not_force():
    from posture.source_history import (
        EVENT_RATE_LIMIT,
        STATUS_ACTIVE,
        EventLedger,
        SourceEvent,
    )
    conn = store.connect(":memory:")
    policy = Policy.from_file(default_policy_path())
    store.record_health_sample(conn, "nvd", "dev", "vulnerability", True, 50,
                                "ok", _now_offset(0))
    conn.commit()
    ledger = EventLedger()
    ledger.add(SourceEvent(
        id="nvd-rl", date="2026-09-01", source="nvd",
        event_type=EVENT_RATE_LIMIT, summary="rate limits",
        map_layer="identifier", status=STATUS_ACTIVE,
        interpretation="paced ingestion",
    ))
    # rate-limit is context, not a degrading type -> operational ok stands
    assert health.degradation_action(conn, "nvd", policy, _now_offset(0),
                                      ledger=ledger) == "ok"


def test_degradation_action_seed_ledger_nvd_forces_fallback():
    from posture.source_history import default_ledger
    conn = store.connect(":memory:")
    policy = Policy.from_file(default_policy_path())
    store.record_health_sample(conn, "nvd", "dev", "vulnerability", True, 50,
                                "ok", _now_offset(0))
    conn.commit()
    assert health.degradation_action(conn, "nvd", policy, _now_offset(0),
                                      ledger=default_ledger()) == "fallback"


def test_health_report_surfaces_source_history_signal():
    from posture.source_history import default_ledger
    conn = _conn_with_samples()
    policy = Policy.from_file(default_policy_path())
    rep = health.health_report(conn, "nvd", policy, _now_offset(0),
                                ledger=default_ledger())
    assert "source_history" in rep
    sh = rep["source_history"]
    assert sh["observer"] == "nvd"
    assert sh["source"] == "nvd"
    assert sh["degraded"] is True
    assert sh["interpretation"]  # the seam text flows through
    assert any(e["event_type"] == "degradation" for e in sh["active_events"])
    # the action is consistent with the signal
    assert rep["degradation"] == "fallback"


def test_health_report_no_ledger_has_empty_signal():
    conn = _conn_with_samples()
    policy = Policy.from_file(default_policy_path())
    rep = health.health_report(conn, "nvd", policy, _now_offset(0))
    assert rep["source_history"]["degraded"] is False
    assert rep["source_history"]["active_events"] == []
