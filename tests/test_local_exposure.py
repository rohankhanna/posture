"""Tests for the local exposure observer — the first REAL observer on the
exposure axis.

These pin four things:
  1. the observer turns an inline socket capture into one ``exposed`` / ``closed``
     Verdict per socket, keyed ``proto/port``; loopback bind = closed, wildcard
     or non-loopback = exposed, missing bind = exposed (false-safe);
  2. the observer emits honest verdicts from a device's inline capture and from
     an ``exposure_path`` pointing at the bundled fixture, with provenance
     wired (observer == "local_exposure", raw_ref set);
  3. the observer is an honest no-op (zero verdicts, complete=True) when the
     device gives no capture and when an ``exposure_path`` file is missing —
     never a crash, never 'clean';
  4. in the engine, the exposure axis gets a REAL status ("exposed" / "closed",
     not "unknown") when a capture is supplied, stays "unknown" when none is,
     and the committed per-verdict rows attribute to observer "local_exposure".

SELF-CONTAINED: builds its own ObserverRegistry + Policy inline (no reliance on
the shared default registry / policy file, which a sibling agent may be
editing concurrently). Mirrors test_cyclonedx_sbom.py's style.
"""
from pathlib import Path

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.observer import ObserverRegistry
from posture.sources.local_exposure import LocalExposureObserver

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
EXPOSURE_FIXTURE = FIXTURE_DIR / "exposure" / "sample.json"
SAMPLE_DEVICE = FIXTURE_DIR / "sample_device.yaml"


# Inline policy: local_exposure on the exposure axis only. Built from a YAML
# string so this test does NOT depend on the shared policy.yaml file.
_INLINE_POLICY_YAML = """
version: "2026-08-06.3"
supersedes: "2026-08-06.2"
dated: 2026-08-06
rationale: |
  test policy for the local_exposure exposure observer (self-contained test).
observers:
  local_exposure:
    axes: [exposure]
    weight: medium
    bias: false-safe
    order: 10
    conditions: []
"""


def _policy() -> Policy:
    return Policy.from_yaml(_INLINE_POLICY_YAML)


def _registry() -> ObserverRegistry:
    reg = ObserverRegistry()
    reg.register(LocalExposureObserver())
    return reg


# ---------------------------------------------------------------------------
# observer (offline): inline capture + path fixture + honest no-op
# ---------------------------------------------------------------------------

def test_observer_inline_capture_emits_exposed_and_closed():
    w = LocalExposureObserver()
    pol = _policy()
    device = {
        "id": "host",
        "exposure": [
            {"proto": "tcp", "port": 22, "bind": "0.0.0.0", "service": "ssh"},
            {"proto": "tcp", "port": 5432, "bind": "127.0.0.1", "service": "postgres"},
            {"proto": "tcp", "port": 8080, "bind": "::1", "service": "app"},
        ],
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].status == "exposed"
    assert by_key["tcp/22"].severity == "HIGH"        # ssh on a dangerous port
    assert by_key["tcp/5432"].status == "closed"
    assert by_key["tcp/5432"].severity is None
    assert by_key["tcp/8080"].status == "closed"      # ::1 is loopback
    for v in result.verdicts:
        assert v.axis == Axis.EXPOSURE.value
        assert v.provenance.observer == "local_exposure"
        assert v.provenance.raw_ref == "inline:device.exposure"


def test_observer_wildcard_and_non_loopback_are_exposed():
    w = LocalExposureObserver()
    pol = _policy()
    device = {
        "id": "host",
        "exposure": [
            {"proto": "tcp", "port": 80, "bind": "0.0.0.0"},     # wildcard
            {"proto": "tcp", "port": 443, "bind": "203.0.113.5"},  # public IP
            {"proto": "tcp", "port": 6379, "bind": "::"},          # ipv6 wildcard, dangerous
            {"proto": "tcp", "port": 3306, "bind": "127.0.0.2"},   # 127/8 loopback
        ],
    }
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/80"].status == "exposed"
    assert by_key["tcp/80"].severity == "MEDIUM"       # not a dangerous port
    assert by_key["tcp/443"].status == "exposed"
    assert by_key["tcp/6379"].status == "exposed"
    assert by_key["tcp/6379"].severity == "HIGH"       # redis on dangerous port
    assert by_key["tcp/3306"].status == "closed"        # 127.0.0.2 is 127/8 loopback


def test_observer_missing_bind_is_exposed_false_safe():
    """A socket with no bind field cannot be proven loopback -> exposed (the
    false-safe direction: a missing control is not a pass)."""
    w = LocalExposureObserver()
    pol = _policy()
    device = {"id": "host", "exposure": [
        {"proto": "tcp", "port": 22},          # no bind -> exposed, HIGH
        {"proto": "udp", "port": 53, "bind": "127.0.0.1"},
    ]}
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].status == "exposed"
    assert by_key["tcp/22"].severity == "HIGH"
    assert "bind unknown" in by_key["tcp/22"].detail
    assert by_key["udp/53"].status == "closed"


def test_observer_exposure_path_reads_fixture_file():
    w = LocalExposureObserver()
    pol = _policy()
    device = {"id": "host", "exposure_path": str(EXPOSURE_FIXTURE)}
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["tcp/22"].status == "exposed"        # 0.0.0.0
    assert by_key["tcp/5432"].status == "closed"        # 127.0.0.1
    assert by_key["tcp/8080"].status == "closed"        # ::1
    for v in result.verdicts:
        assert v.provenance.observer == "local_exposure"
        assert v.provenance.raw_ref == str(EXPOSURE_FIXTURE)


def test_observer_exposure_path_bare_filename_falls_back_to_fixture_dir():
    """A bare filename in device['exposure_path'] resolves against the bundled
    fixture dir (offline-test fallback) — 'sample.json' lands on the fixture."""
    w = LocalExposureObserver()
    pol = _policy()
    device = {"id": "host", "exposure_path": "sample.json"}
    result = w.assess(device, pol)
    assert result.complete is True
    assert {v.key for v in result.verdicts} == {"tcp/22", "tcp/5432", "tcp/8080"}


def test_observer_no_exposure_is_honest_noop():
    """A device with no capture gives the observer nothing to say. It returns
    ZERO verdicts (complete=True) so the engine's loud-degradation rule makes
    the exposure axis UNKNOWN, never silently 'clean' — and never crashes."""
    w = LocalExposureObserver()
    pol = _policy()
    device = {"id": "host"}
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no exposure surface supplied" in result.reason


def test_observer_missing_exposure_path_is_complete_zero_not_failure():
    """A missing exposure_path file is a local no-input, not a source failure:
    complete=True, zero verdicts (must NOT trip the no-wipe gate)."""
    w = LocalExposureObserver()
    pol = _policy()
    device = {"id": "host", "exposure_path": "/no/such/exposure.json"}
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "exposure path not found" in result.reason


def test_observer_skips_sockets_without_proto_or_port():
    w = LocalExposureObserver()
    pol = _policy()
    device = {"id": "host", "exposure": [
        {"port": 22, "bind": "0.0.0.0"},             # no proto -> skipped
        {"proto": "tcp", "bind": "0.0.0.0"},          # no port -> skipped
        {"proto": "tcp", "port": "not-a-number"},    # bad port -> skipped
        {"proto": "tcp", "port": 22, "bind": "0.0.0.0"},
    ]}
    result = w.assess(device, pol)
    assert [v.key for v in result.verdicts] == ["tcp/22"]


# ---------------------------------------------------------------------------
# engine: exposure axis becomes REAL (exposed/closed) with a capture, UNKNOWN
# without
# ---------------------------------------------------------------------------

def test_engine_exposure_axis_exposed_with_capture_and_attributed_rows():
    """With local_exposure registered and an inline capture containing an
    exposed socket, the engine commits per-socket verdicts
    (observer=local_exposure, status=exposed) and the exposure AxisPosture
    status becomes 'exposed' — not 'unknown'. Proven at the per-verdict row
    level for observer attribution."""
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {
        "id": "demo-host",
        "exposure": [
            {"proto": "tcp", "port": 22, "bind": "0.0.0.0", "service": "ssh"},
            {"proto": "tcp", "port": 5432, "bind": "127.0.0.1"},
        ],
    }
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")

    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "exposure")}
    assert sorted(rows) == ["tcp/22", "tcp/5432"]
    assert rows["tcp/22"]["observer"] == "local_exposure"
    assert rows["tcp/22"]["status"] == "exposed"
    assert rows["tcp/5432"]["status"] == "closed"
    for r in rows.values():
        assert r["complete"] == 1   # the capture is a provably whole local read

    exp = {a.axis: a for a in dp.axes}["exposure"]
    assert exp.status == "exposed"                  # worst present wins
    assert exp.deciding_observer == "local_exposure"
    assert "local_exposure" in dp.used_observers

    ap = store.axis_posture(conn, "demo-host", "exposure")
    assert ap["status"] == "exposed"
    assert ap["deciding_observer"] == "local_exposure"


def test_engine_exposure_axis_closed_when_all_sockets_loopback():
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {"id": "demo-host", "exposure": [
        {"proto": "tcp", "port": 5432, "bind": "127.0.0.1"},
        {"proto": "tcp", "port": 6379, "bind": "::1"},
    ]}
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")
    exp = {a.axis: a for a in dp.axes}["exposure"]
    assert exp.status == "closed"                   # all closed -> best status


def test_engine_exposure_axis_unknown_without_capture():
    """The other direction: with no capture the observer no-ops, the exposure
    axis has zero verdicts -> status 'unknown' (loud), gap set, not 'clean'.
    Proves the loud-degradation rule holds for exposure."""
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = {"id": "demo-host"}   # no exposure, no exposure_path
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")
    exp = {a.axis: a for a in dp.axes}["exposure"]
    assert exp.status == "unknown"
    assert exp.verdicts == []
    assert exp.gap is not None       # loud, not silent-clean
    assert store.verdicts_for_device_axis(conn, "demo-host", "exposure") == []
    assert "local_exposure" not in dp.used_observers


def test_engine_default_demo_device_exposure_stays_unknown():
    """The shipped demo device has no exposure fields -> the observer no-ops, so
    the exposure axis is unchanged (UNKNOWN). Guards against the registration
    accidentally altering the demo's behavior on this axis."""
    import yaml
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = yaml.safe_load(SAMPLE_DEVICE.read_text())
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")
    exp = {a.axis: a for a in dp.axes}["exposure"]
    assert exp.status == "unknown"
    assert exp.verdicts == []