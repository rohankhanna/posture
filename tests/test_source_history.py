"""Tests for posture.source_history — the public-infrastructure event ledger.

Covers: schema validation (structure rejected, open vocabulary accepted),
seed shape, ledger filters, JSONL round-trip persistence, and the CLI
subcommands. Offline + deterministic (no network, no wall-clock).
"""
import json

import pytest

from posture.cli import main as cli_main
from posture.source_history import (
    KNOWN_EVENT_TYPES,
    KNOWN_LAYERS,
    KNOWN_STATUSES,
    SEED_DATA_PATH,
    STATUS_ACTIVE,
    STATUS_RESOLVED,
    EventLedger,
    SourceEvent,
    SourceHistoryError,
    default_ledger,
    seed_events,
    validate_event,
)

# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def _good_fields(**over):
    f = {"id": "x-1", "date": "2026-01-01", "source": "nvd", "event_type": "degradation",
         "summary": "something changed", "map_layer": "identifier", "status": "active"}
    f.update(over)
    return f


def test_valid_event_constructs():
    e = SourceEvent(**_good_fields())
    assert e.id == "x-1" and e.interpretation == "" and e.supersedes is None


@pytest.mark.parametrize("missing", ["id", "date", "source", "event_type", "summary", "map_layer", "status"])
def test_missing_required_field_rejected(missing):
    d = _good_fields()
    d.pop(missing)
    with pytest.raises(SourceHistoryError):
        SourceEvent.from_dict(d)


def test_empty_summary_rejected():
    with pytest.raises(SourceHistoryError):
        SourceEvent(**_good_fields(summary="   "))


def test_bad_date_rejected():
    with pytest.raises(SourceHistoryError):
        SourceEvent(**_good_fields(date="2026-13-99"))


def test_non_iso_date_rejected():
    with pytest.raises(SourceHistoryError):
        SourceEvent(**_good_fields(date="yesterday"))


def test_unknown_event_type_accepted_open_vocab():
    e = SourceEvent(**_good_fields(event_type="brand-new-kind"))
    assert e.event_type == "brand-new-kind"


def test_unknown_map_layer_accepted_open_vocab():
    e = SourceEvent(**_good_fields(map_layer="exotic-layer"))
    assert e.map_layer == "exotic-layer"


def test_unknown_status_accepted_open_vocab():
    e = SourceEvent(**_good_fields(status="weird"))
    assert e.status == "weird"


def test_known_constants_nonempty():
    assert KNOWN_EVENT_TYPES and KNOWN_LAYERS and KNOWN_STATUSES
    assert STATUS_ACTIVE in KNOWN_STATUSES and STATUS_RESOLVED in KNOWN_STATUSES


# ---------------------------------------------------------------------------
# seed shape
# ---------------------------------------------------------------------------

def test_seed_events_have_unique_ids():
    ids = [e.id for e in seed_events()]
    assert len(ids) == len(set(ids))


def test_seed_events_cover_known_sources():
    sources = {e.source for e in seed_events()}
    assert {"nvd", "mitre", "osv", "epss"} <= sources


def test_seed_events_valid_and_dated():
    for e in seed_events():
        validate_event(e.to_dict())  # does not raise
        assert len(e.date) == 10      # ISO YYYY-MM-DD


def test_seed_includes_nvd_enrichment_gap_and_fleet_wipe():
    ids = {e.id for e in seed_events()}
    assert "nvd-2026-04-15-enrichment-gap" in ids
    assert "nvd-2026-07-31-apikey-query-404-masquerade" in ids


def test_default_ledger_matches_seed():
    led = default_ledger()
    assert {e.id for e in led.events} == {e.id for e in seed_events()}


# ---------------------------------------------------------------------------
# ledger filters + mutation
# ---------------------------------------------------------------------------

def _populated():
    led = EventLedger()
    led.add(SourceEvent(**_good_fields(id="a", date="2026-01-01", source="nvd")))
    led.add(SourceEvent(**_good_fields(id="b", date="2026-02-01", source="osv",
                                       event_type="outage", map_layer="scoring",
                                       status="resolved")))
    led.add(SourceEvent(**_good_fields(id="c", date="2026-03-01", source="nvd",
                                       event_type="rate-limit")))
    return led


def test_for_source_filters():
    led = _populated()
    assert [e.id for e in led.for_source("nvd")] == ["a", "c"]
    assert led.for_source("mitre") == []


def test_for_layer_and_for_type_filters():
    led = _populated()
    assert [e.id for e in led.for_layer("scoring")] == ["b"]
    assert [e.id for e in led.for_type("rate-limit")] == ["c"]


def test_active_excludes_resolved():
    led = _populated()
    assert {e.id for e in led.active()} == {"a", "c"}


def test_get_returns_event_or_none():
    led = _populated()
    assert led.get("a").source == "nvd"
    assert led.get("nope") is None


def test_sorted_by_date_orders_chronologically():
    led = _populated()
    assert [e.id for e in led.sorted_by_date()] == ["a", "b", "c"]


def test_duplicate_id_rejected():
    led = EventLedger()
    led.add(SourceEvent(**_good_fields(id="dup")))
    with pytest.raises(SourceHistoryError):
        led.add(SourceEvent(**_good_fields(id="dup", date="2026-09-09")))


def test_extend_adds_all():
    led = EventLedger()
    led.extend([SourceEvent(**_good_fields(id="a")),
                SourceEvent(**_good_fields(id="b", date="2026-02-02"))])
    assert {e.id for e in led.events} == {"a", "b"}


# ---------------------------------------------------------------------------
# JSONL persistence
# ---------------------------------------------------------------------------

def test_jsonl_roundtrip_preserves_events(tmp_path):
    led = _populated()
    path = tmp_path / "ledger.jsonl"
    led.save(path)
    loaded = EventLedger.load(path)
    assert {e.id for e in loaded.events} == {e.id for e in led.events}
    # field-level fidelity
    for orig, got in zip(led.sorted_by_date(), loaded.events):
        assert got.to_dict() == orig.to_dict()


def test_jsonl_is_one_json_object_per_line_sorted(tmp_path):
    led = _populated()
    path = tmp_path / "ledger.jsonl"
    led.save(path)
    lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
    assert len(lines) == len(led.events)
    dates = [json.loads(ln)["date"] for ln in lines]
    assert dates == sorted(dates)


def test_from_jsonl_skips_blank_lines():
    text = json.dumps(_good_fields(id="a")) + "\n\n" + json.dumps(_good_fields(id="b", date="2026-02-02")) + "\n"
    led = EventLedger.from_jsonl(text)
    assert {e.id for e in led.events} == {"a", "b"}


def test_to_dict_drops_none_payloads():
    e = SourceEvent(**_good_fields(id="a"))
    d = e.to_dict()
    assert "evidence_url" not in d and "supersedes" not in d
    assert "interpretation" in d          # "" is kept (not None)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _run(argv, capsys):
    rc = cli_main(argv)
    out, err = capsys.readouterr()
    return rc, out, err


def test_cli_list(capsys):
    rc, out, _ = _run(["source-history", "list"], capsys)
    assert rc == 0
    assert "nvd-2026-04-15-enrichment-gap" in out
    assert "events (" in out


def test_cli_show(capsys):
    rc, out, _ = _run(["source-history", "show", "nvd-2026-04-15-enrichment-gap"], capsys)
    assert rc == 0
    obj = json.loads(out)
    assert obj["id"] == "nvd-2026-04-15-enrichment-gap"
    assert obj["map_layer"] == "enrichment"


def test_cli_show_missing(capsys):
    rc, out, _ = _run(["source-history", "show", "no-such-event"], capsys)
    assert rc == 1
    assert "not in ledger" in out


def test_cli_source(capsys):
    rc, out, _ = _run(["source-history", "source", "nvd"], capsys)
    assert rc == 0
    assert "nvd-2026-07-31-apikey-query-404-masquerade" in out
    assert "->" in out  # interpretation rendered


def test_cli_source_empty(capsys):
    rc, out, _ = _run(["source-history", "source", "no-such-source"], capsys)
    assert rc == 1
    assert "no events" in out


def test_cli_loads_file(tmp_path, capsys):
    led = _populated()
    path = tmp_path / "ledger.jsonl"
    led.save(path)
    rc, out, _ = _run(["source-history", "list", "--file", str(path)], capsys)
    assert rc == 0
    assert "a" in out and "b" in out and "c" in out


# ---------------------------------------------------------------------------
# the seed history is a versioned DATA file (trust-as-data), not code
# ---------------------------------------------------------------------------

def test_bundled_seed_data_file_exists():
    assert SEED_DATA_PATH.exists()
    assert SEED_DATA_PATH.name == "source_history.json"
    assert SEED_DATA_PATH.parent.name == "policy"   # beside policy.yaml


def test_bundled_data_file_is_a_valid_versioned_document():
    from posture.source_history import load_document
    doc = load_document(SEED_DATA_PATH)
    assert doc["schema_version"] == 1
    assert isinstance(doc["version"], str) and doc["version"]
    assert isinstance(doc["dated"], str) and doc["dated"]
    assert isinstance(doc["events"], list) and doc["events"]


def test_seed_events_are_read_from_the_data_file():
    """seed_events() is a view of the file, not a hardcoded list."""
    from posture.source_history import SEED_DATA_PATH, load_document
    doc = load_document(SEED_DATA_PATH)
    from_file = {e["id"] for e in doc["events"]}
    assert from_file == {e.id for e in seed_events()}


def test_default_ledger_carries_the_document_version():
    led = default_ledger()
    assert led.version
    assert led.dated
    from posture.source_history import seed_version
    assert led.version == seed_version()


def test_document_round_trip_through_jsonl(tmp_path):
    led = EventLedger.load_document(SEED_DATA_PATH)
    out = tmp_path / "ledger.jsonl"
    led.save(out)
    again = EventLedger.load(out)
    assert {e.id for e in again.events} == {e.id for e in led.events}
    assert again.version is None  # JSONL carries events only


def test_load_any_dispatches_on_suffix(tmp_path):
    doc = EventLedger.load_any(SEED_DATA_PATH)
    assert doc.version
    jsonl = tmp_path / "l.jsonl"
    doc.save(jsonl)
    assert EventLedger.load_any(jsonl).version is None


def test_load_document_rejects_missing_file(tmp_path):
    from posture.source_history import load_document
    with pytest.raises(SourceHistoryError):
        load_document(tmp_path / "nope.json")


def test_load_document_rejects_invalid_json(tmp_path):
    from posture.source_history import load_document
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SourceHistoryError):
        load_document(bad)


def test_load_document_rejects_unknown_schema_version(tmp_path):
    from posture.source_history import load_document
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": 99, "events": []}), encoding="utf-8")
    with pytest.raises(SourceHistoryError):
        load_document(bad)


def test_load_document_rejects_missing_events_list(tmp_path):
    from posture.source_history import load_document
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    with pytest.raises(SourceHistoryError):
        load_document(bad)


def test_from_document_rejects_non_mapping_event(tmp_path):
    with pytest.raises(SourceHistoryError):
        EventLedger.from_document({"schema_version": 1, "events": ["nope"]})


def test_package_data_ships_the_seed_data_file():
    import pathlib
    pyproject = (pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    assert 'policy/*.json' in pyproject


def test_cli_reports_the_ledger_version(capsys):
    rc, out, _ = _run(["source-history", "list"], capsys)
    assert rc == 0
    assert "ledger version:" in out


def test_cli_reads_the_canonical_document_file(capsys):
    rc, out, _ = _run(["source-history", "list", "--file", str(SEED_DATA_PATH)], capsys)
    assert rc == 0
    assert "ledger version:" in out
    assert "events" in out
