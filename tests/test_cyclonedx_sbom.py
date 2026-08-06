"""Tests for the CycloneDX SBOM witness — the first REAL witness on the
inventory axis.

These pin four things:
  1. the parser turns an inline CycloneDX components list into one ``present``
     Verdict per component, keyed ``<name>@<version>``, and skips nameless
     components;
  2. the witness emits honest ``present`` verdicts from a device's inline SBOM
     and from a ``sbom_path`` pointing at the bundled fixture, with provenance
     wired (witness == "cyclonedx_sbom", raw_ref set);
  3. the witness is an honest no-op (zero verdicts, complete=True) when the
     device gives no SBOM and when a ``sbom_path`` file is missing — never a
     crash, never 'clean';
  4. in the engine, the inventory axis gets a REAL status ("present", not
     "unknown") when an SBOM is supplied, stays "unknown" when none is, and the
     committed per-verdict rows attribute to witness "cyclonedx_sbom".

SELF-CONTAINED: builds its own WitnessRegistry + Policy inline (no reliance on
the shared default registry / policy file, which a sibling agent may be
editing concurrently). Mirrors test_ubuntu_tracker.py's style.
"""
from pathlib import Path

import yaml

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.witness import WitnessRegistry
from posture.sources.cyclonedx_sbom import CyclonedxSbomWitness

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
SBOM_FIXTURE = FIXTURE_DIR / "sbom" / "sample.json"
SAMPLE_DEVICE = FIXTURE_DIR / "sample_device.yaml"


# Inline policy: cyclonedx_sbom on the inventory axis only. Built from a YAML
# string so this test does NOT depend on the shared policy.yaml file (a sibling
# agent may be editing it concurrently).
_INLINE_POLICY_YAML = """
version: "2026-08-02.3"
supersedes: "2026-08-02.2"
dated: 2026-08-02
rationale: |
  test policy for the cyclonedx_sbom inventory witness (self-contained test).
witnesses:
  cyclonedx_sbom:
    axes: [inventory]
    weight: high
    bias: neutral
    order: 10
    conditions: []
"""


def _policy() -> Policy:
    return Policy.from_yaml(_INLINE_POLICY_YAML)


def _registry() -> WitnessRegistry:
    reg = WitnessRegistry()
    reg.register(CyclonedxSbomWitness())
    return reg


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def test_parse_components_emits_present_verdicts_keyed_name_at_version():
    components = [
        {"name": "openssl", "version": "3.0.2"},
        {"name": "nginx", "version": "1.25.3"},
        {"name": "busybox", "version": "1.36"},
    ]
    w = CyclonedxSbomWitness()
    verdicts = w.parse(components, {"id": "h"}, _policy())
    assert [(v.key, v.status) for v in verdicts] == [
        ("openssl@3.0.2", "present"),
        ("nginx@1.25.3", "present"),
        ("busybox@1.36", "present"),
    ]
    for v in verdicts:
        assert v.axis == Axis.INVENTORY.value
        assert v.provenance.witness == "cyclonedx_sbom"
        assert v.provenance.raw_ref == "inline:device.sbom"


def test_parse_skips_nameless_components_and_defaults_empty_version():
    components = [
        {"name": "openssl", "version": "3.0.2"},
        {"version": "9.9"},            # no name -> skipped
        {"name": "libc"},              # no version -> key "libc@"
        {"foo": "bar"},                # not a component dict shape, but has no name -> skipped
    ]
    w = CyclonedxSbomWitness()
    verdicts = w.parse(components, {"id": "h"}, _policy())
    assert [v.key for v in verdicts] == ["openssl@3.0.2", "libc@"]
    assert verdicts[1].detail == "libc installed (SBOM)"


# ---------------------------------------------------------------------------
# witness (offline): inline sbom + sbom_path fixture + honest no-op
# ---------------------------------------------------------------------------

def test_witness_inline_sbom_emits_present_verdicts():
    w = CyclonedxSbomWitness()
    pol = _policy()
    device = {
        "id": "host",
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "openssl", "version": "3.0.2"},
                {"name": "nginx", "version": "1.25.3"},
                {"name": "busybox", "version": "1.36"},
            ],
        },
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert sorted(by_key) == ["busybox@1.36", "nginx@1.25.3", "openssl@3.0.2"]
    for v in result.verdicts:
        assert v.status == "present"
        assert v.provenance.witness == "cyclonedx_sbom"
        assert v.provenance.raw_ref == "inline:device.sbom"


def test_witness_sbom_path_reads_fixture_file():
    w = CyclonedxSbomWitness()
    pol = _policy()
    device = {"id": "host", "sbom_path": str(SBOM_FIXTURE)}
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert sorted(by_key) == ["busybox@1.36", "nginx@1.25.3", "openssl@3.0.2"]
    for v in result.verdicts:
        assert v.status == "present"
        assert v.provenance.witness == "cyclonedx_sbom"
        assert v.provenance.raw_ref == str(SBOM_FIXTURE)


def test_witness_sbom_path_bare_filename_falls_back_to_fixture_dir():
    """A bare filename in device['sbom_path'] is resolved against the bundled
    fixture dir (offline-test fallback) — 'sample.json' lands on the fixture."""
    w = CyclonedxSbomWitness()
    pol = _policy()
    device = {"id": "host", "sbom_path": "sample.json"}
    result = w.assess(device, pol)
    assert result.complete is True
    assert {v.key for v in result.verdicts} == {
        "openssl@3.0.2", "nginx@1.25.3", "busybox@1.36",
    }


def test_witness_no_sbom_is_honest_noop():
    """A device with no SBOM gives the witness nothing to say. It returns ZERO
    verdicts (complete=True) so the engine's loud-degradation rule makes the
    inventory axis UNKNOWN, never silently 'clean' — and never crashes."""
    w = CyclonedxSbomWitness()
    pol = _policy()
    device = {"id": "host"}
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no sbom supplied" in result.reason


def test_witness_missing_sbom_path_is_complete_zero_not_failure():
    """A missing sbom_path file is a local no-input, not a source failure:
    complete=True, zero verdicts (must NOT trip the no-wipe gate)."""
    w = CyclonedxSbomWitness()
    pol = _policy()
    device = {"id": "host", "sbom_path": "/no/such/sbom.json"}
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "sbom path not found" in result.reason


# ---------------------------------------------------------------------------
# engine: inventory axis becomes REAL (present) with an SBOM, UNKNOWN without
# ---------------------------------------------------------------------------

def test_engine_inventory_axis_present_with_sbom_and_attributed_rows():
    """With cyclonedx_sbom registered and an inline SBOM, the engine commits
    per-package verdicts (witness=cyclonedx_sbom, status=present) and the
    inventory AxisPosture status becomes 'present' — not 'unknown'. Proven at
    the per-verdict row level for witness attribution."""
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {
        "id": "demo-host",
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "openssl", "version": "3.0.2"},
                {"name": "nginx", "version": "1.25.3"},
            ],
        },
    }
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-02T00:00:00+00:00")

    # per-verdict rows committed through the no-wipe gate
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "inventory")}
    assert sorted(rows) == ["nginx@1.25.3", "openssl@3.0.2"]
    for r in rows.values():
        assert r["witness"] == "cyclonedx_sbom"
        assert r["status"] == "present"
        assert r["complete"] == 1   # the SBOM fetch is provably whole

    # axis posture: 'present' (a real status), not 'unknown'
    inv = {a.axis: a for a in dp.axes}["inventory"]
    assert inv.status == "present"
    assert inv.deciding_witness == "cyclonedx_sbom"
    assert "cyclonedx_sbom" in dp.used_witnesses

    # persisted axis posture row agrees
    ap = store.axis_posture(conn, "demo-host", "inventory")
    assert ap["status"] == "present"
    assert ap["deciding_witness"] == "cyclonedx_sbom"


def test_engine_inventory_axis_unknown_without_sbom():
    """The other direction: with no SBOM the witness no-ops, the inventory axis
    has zero verdicts -> status 'unknown' (loud), gap set, not 'present' or
    'clear'. Proves the loud-degradation rule holds for inventory."""
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {"id": "demo-host"}   # no sbom, no sbom_path
    dp = engine.assess(device, reg, pol, conn=conn,
                      now="2026-08-02T00:00:00+00:00")
    inv = {a.axis: a for a in dp.axes}["inventory"]
    assert inv.status == "unknown"
    assert inv.verdicts == []
    assert inv.gap is not None       # loud, not silent-clean
    # no verdict rows committed for inventory
    assert store.verdicts_for_device_axis(conn, "demo-host", "inventory") == []
    # the witness ran but produced no verdicts -> not a 'used' witness
    assert "cyclonedx_sbom" not in dp.used_witnesses


def test_engine_default_demo_device_inventory_stays_unknown():
    """The shipped demo device has no sbom fields -> the new witness no-ops, so
    the inventory axis is unchanged (UNKNOWN). Guards against the registration
    accidentally altering the demo's behavior on this axis."""
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = yaml.safe_load(SAMPLE_DEVICE.read_text())
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-02T00:00:00+00:00")
    inv = {a.axis: a for a in dp.axes}["inventory"]
    assert inv.status == "unknown"
    assert inv.verdicts == []