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
    assert p.version == "2026-08-31.5"
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

# --- slice (c): ledger -> degradation signal wiring -----------------------

def test_degradation_signal_no_ledger_is_empty():
    p = Policy.from_yaml(VALID)
    sig = p.degradation_signal("nvd", None)
    assert sig.observer == "nvd"
    assert sig.source == "nvd"
    assert sig.degraded is False
    assert sig.active_events == []
    assert sig.interpretation == ""


def test_degradation_signal_observes_active_degrading_event():
    from posture.source_history import (
        EVENT_DEGRADATION,
        STATUS_ACTIVE,
        EventLedger,
        SourceEvent,
    )
    p = Policy.from_yaml(VALID)
    ledger = EventLedger()
    ledger.add(SourceEvent(
        id="nvd-gap", date="2026-04-15", source="nvd",
        event_type=EVENT_DEGRADATION, summary="enrichment gap",
        map_layer="enrichment", status=STATUS_ACTIVE,
        interpretation="fill with OSV+EPSS overlays",
    ))
    sig = p.degradation_signal("nvd", ledger)
    assert sig.degraded is True
    assert len(sig.active_events) == 1
    assert sig.active_events[0]["interpretation"] == "fill with OSV+EPSS overlays"
    assert "fill with OSV+EPSS overlays" in sig.interpretation


def test_degradation_signal_resolved_event_is_not_degraded():
    from posture.source_history import (
        EVENT_DEGRADATION,
        STATUS_RESOLVED,
        EventLedger,
        SourceEvent,
    )
    p = Policy.from_yaml(VALID)
    ledger = EventLedger()
    ledger.add(SourceEvent(
        id="nvd-gap", date="2026-04-15", source="nvd",
        event_type=EVENT_DEGRADATION, summary="enrichment gap",
        map_layer="enrichment", status=STATUS_RESOLVED,
        interpretation="resolved upstream",
    ))
    sig = p.degradation_signal("nvd", ledger)
    assert sig.degraded is False
    assert sig.active_events == []


def test_degradation_signal_non_degrading_type_does_not_set_degraded():
    from posture.source_history import (
        EVENT_RATE_LIMIT,
        STATUS_ACTIVE,
        EventLedger,
        SourceEvent,
    )
    p = Policy.from_yaml(VALID)
    ledger = EventLedger()
    ledger.add(SourceEvent(
        id="nvd-rl", date="2026-09-01", source="nvd",
        event_type=EVENT_RATE_LIMIT, summary="rate limits tightened",
        map_layer="identifier", status=STATUS_ACTIVE,
        interpretation="ingestion is paced",
    ))
    sig = p.degradation_signal("nvd", ledger)
    # surfaced as context, but does not force degraded
    assert sig.degraded is False
    assert len(sig.active_events) == 1
    assert "ingestion is paced" in sig.interpretation


def test_degradation_signal_alias_maps_observer_to_source():
    from posture.source_history import (
        EVENT_FORMAT_CHANGE,
        STATUS_ACTIVE,
        EventLedger,
        SourceEvent,
    )
    p = Policy.from_yaml(VALID)
    ledger = EventLedger()
    ledger.add(SourceEvent(
        id="mitre-fmt", date="2026-01-01", source="mitre",
        event_type=EVENT_FORMAT_CHANGE, summary="cvelistV5",
        map_layer="identifier", status=STATUS_ACTIVE,
        interpretation="consume cvelistV5",
    ))
    sig = p.degradation_signal("mitre_cve", ledger)
    # observer id mitre_cve maps to ledger source id mitre
    assert sig.source == "mitre"
    assert len(sig.active_events) == 1
    # format-change is not a degrading type
    assert sig.degraded is False


def test_degradation_signal_unknown_observer_empty():
    from posture.source_history import default_ledger
    p = Policy.from_file(default_policy_path())
    sig = p.degradation_signal("kev", default_ledger())
    assert sig.degraded is False
    assert sig.active_events == []


def test_degradation_signal_seed_ledger_nvd_degraded():
    # the bundled seed ledger records an active NVD enrichment degradation
    from posture.source_history import default_ledger
    p = Policy.from_file(default_policy_path())
    sig = p.degradation_signal("nvd", default_ledger())
    assert sig.degraded is True
    assert any(e["event_type"] == "degradation" for e in sig.active_events)
    assert sig.interpretation  # non-empty seam text


def test_to_dict_roundtrip_shape():
    from posture.source_history import default_ledger
    p = Policy.from_file(default_policy_path())
    d = p.degradation_signal("nvd", default_ledger()).to_dict()
    assert set(d) == {"observer", "source", "degraded", "active_events", "interpretation"}
    assert d["source"] == "nvd"
