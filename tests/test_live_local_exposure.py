"""Tests for the live local-exposure observer — a grounding observer on the
exposure axis.

These pin five things:
  1. the pure parser (parse_ss_output) converts live ``ss -tulpn`` output into
     the socket-capture list that ``LocalExposureObserver`` consumes;
  2. the observer delegates to ``LocalExposureObserver`` and re-stamps
     provenance (live_local_exposure, not local_exposure);
  3. the observer falls back to the device-supplied snapshot when ``ss`` is
     unavailable;
  4. the observer is an honest no-op (zero verdicts, complete=True) when
     neither live data nor a snapshot is available;
  5. in the engine, live_local_exposure overrides local_exposure on the same
     proto/port key (order 9 < order 10).

SELF-CONTAINED: builds its own ObserverRegistry + Policy inline (no reliance
on the shared default registry / policy file, which a sibling agent may be
editing concurrently).  Mirrors test_live_firewall.py's style.
"""

from pathlib import Path

from posture import engine, store
from posture.observer import ObserverRegistry
from posture.policy import Policy
from posture.sources.live_local_exposure import (
    LiveLocalExposureObserver,
    parse_ss_output,
)
from posture.sources.local_exposure import LocalExposureObserver

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
EXPOSURE_FIXTURE = FIXTURE_DIR / "exposure" / "sample.json"

_INLINE_POLICY_YAML = """
version: "2026-08-31.4"
supersedes: "2026-08-31.3"
dated: 2026-08-31
rationale: |
  test policy for live_local_exposure + local_exposure on the exposure axis.
observers:
  local_exposure:
    axes: [exposure]
    weight: medium
    bias: false-safe
    order: 10
    conditions: []
  live_local_exposure:
    axes: [exposure]
    weight: medium
    bias: false-safe
    order: 9
    conditions: []
"""


def _policy():
    return Policy.from_yaml(_INLINE_POLICY_YAML)


# ---------------------------------------------------------------------------
# parse_ss_output — the pure parser
# ---------------------------------------------------------------------------

SS_OUTPUT_BASIC = """\
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process
tcp   LISTEN 0      128    127.0.0.1:22       0.0.0.0:*          users:(("sshd",pid=1234,fd=3))
tcp   LISTEN 0      128    0.0.0.0:80         0.0.0.0:*          users:(("nginx",pid=5678,fd=6))
tcp   LISTEN 0      128    [::]:443           [::]:*
tcp   LISTEN 0      128    [::1]:5432         [::]:*             users:(("postgres",pid=9999,fd=7))
udp   UNCONN 0      0      0.0.0.0:53         0.0.0.0:*          users:(("dnsmasq",pid=4321,fd=4))
"""


class TestParseSsOutput:
    def test_basic_output(self):
        result = parse_ss_output(SS_OUTPUT_BASIC)
        assert result is not None
        assert len(result) == 5
        assert result[0] == {"proto": "tcp", "port": 22, "bind": "127.0.0.1", "service": "sshd"}
        assert result[1] == {"proto": "tcp", "port": 80, "bind": "0.0.0.0", "service": "nginx"}
        assert result[2] == {"proto": "tcp", "port": 443, "bind": "::", "service": None}
        assert result[3] == {"proto": "tcp", "port": 5432, "bind": "::1", "service": "postgres"}
        assert result[4] == {"proto": "udp", "port": 53, "bind": "0.0.0.0", "service": "dnsmasq"}

    def test_empty_string(self):
        assert parse_ss_output("") is None

    def test_none_input(self):
        assert parse_ss_output(None) is None

    def test_header_only(self):
        assert parse_ss_output(
            "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process"
        ) is None

    def test_no_listening_sockets(self):
        # Lines that don't match the LISTEN/UNCONN pattern are skipped
        text = "tcp   ESTAB  0      0      127.0.0.1:22       127.0.0.1:54321"
        assert parse_ss_output(text) is None

    def test_wildcard_bind(self):
        result = parse_ss_output("tcp   LISTEN 0      128    *:8080  0.0.0.0:*")
        assert result == [{"proto": "tcp", "port": 8080, "bind": "0.0.0.0", "service": None}]

    def test_interface_qualifier_stripped(self):
        result = parse_ss_output("tcp   LISTEN 0      128    192.168.1.5%eth0:80  0.0.0.0:*")
        assert result == [{"proto": "tcp", "port": 80, "bind": "192.168.1.5", "service": None}]

    def test_tcp6_normalized_to_tcp(self):
        result = parse_ss_output("tcp6  LISTEN 0      128    [::]:443  [::]:*")
        assert result == [{"proto": "tcp", "port": 443, "bind": "::", "service": None}]

    def test_udp6_normalized_to_udp(self):
        result = parse_ss_output("udp6  UNCONN 0      0      [::1]:53  [::]:*")
        assert result == [{"proto": "udp", "port": 53, "bind": "::1", "service": None}]

    def test_process_without_users_prefix(self):
        # A row with no process info at all
        result = parse_ss_output("tcp   LISTEN 0      128    0.0.0.0:3000  0.0.0.0:*")
        assert result == [{"proto": "tcp", "port": 3000, "bind": "0.0.0.0", "service": None}]

    def test_multiple_sockets_same_port_different_proto(self):
        text = (
            'tcp   LISTEN 0      128    0.0.0.0:53  0.0.0.0:*          users:(("dns",pid=1,fd=3))\n'
            'udp   UNCONN 0      0      0.0.0.0:53  0.0.0.0:*          users:(("dns",pid=1,fd=4))'
        )
        result = parse_ss_output(text)
        assert len(result) == 2
        assert result[0]["proto"] == "tcp" and result[0]["port"] == 53
        assert result[1]["proto"] == "udp" and result[1]["port"] == 53

    def test_returns_none_for_garbage(self):
        assert parse_ss_output("this is not ss output\nrandom text") is None

    def test_loopback_127_range(self):
        result = parse_ss_output("tcp   LISTEN 0      128    127.0.0.1:6379  0.0.0.0:*")
        assert result == [{"proto": "tcp", "port": 6379, "bind": "127.0.0.1", "service": None}]

    def test_mixed_case_proto(self):
        # ss always emits lowercase, but the regex is case-insensitive
        result = parse_ss_output("TCP   LISTEN 0      128    0.0.0.0:443  0.0.0.0:*")
        assert result == [{"proto": "tcp", "port": 443, "bind": "0.0.0.0", "service": None}]


# ---------------------------------------------------------------------------
# LiveLocalExposureObserver — delegation + provenance re-stamping
# ---------------------------------------------------------------------------

class TestDelegationAndProvenance:
    def test_delegates_to_local_exposure_and_restamps_provenance(self):
        observer = LiveLocalExposureObserver()
        # Supply live ss output via a mock — patch _probe_ss to return data
        live_sockets = [
            {"proto": "tcp", "port": 22, "bind": "0.0.0.0", "service": "sshd"},
            {"proto": "tcp", "port": 80, "bind": "127.0.0.1", "service": None},
        ]
        observer._probe_ss = lambda: live_sockets
        result = observer.assess({"id": "host1"}, _policy())

        assert result.complete is True
        assert len(result.verdicts) == 2
        # tcp/22 bound to 0.0.0.0 -> exposed (HIGH, ssh is dangerous port)
        v22 = next(v for v in result.verdicts if v.key == "tcp/22")
        assert v22.status == "exposed"
        assert v22.severity == "HIGH"
        assert v22.provenance is not None
        assert v22.provenance.observer == "live_local_exposure"
        assert v22.provenance.raw_ref == "live:ss -tulpn"
        # tcp/80 bound to 127.0.0.1 -> closed (loopback)
        v80 = next(v for v in result.verdicts if v.key == "tcp/80")
        assert v80.status == "closed"
        assert v80.severity is None
        assert v80.provenance.observer == "live_local_exposure"

    def test_reason_prefix(self):
        observer = LiveLocalExposureObserver()
        observer._probe_ss = lambda: [
            {"proto": "tcp", "port": 443, "bind": "0.0.0.0", "service": None}
        ]
        result = observer.assess({"id": "host1"}, _policy())
        assert result.reason.startswith("live local exposure:")

    def test_loopback_socket_closed(self):
        observer = LiveLocalExposureObserver()
        observer._probe_ss = lambda: [
            {"proto": "tcp", "port": 3306, "bind": "127.0.0.1", "service": "mysql"}
        ]
        result = observer.assess({"id": "host1"}, _policy())
        assert len(result.verdicts) == 1
        assert result.verdicts[0].status == "closed"
        assert result.verdicts[0].severity is None

    def test_dangerous_port_exposed_high(self):
        observer = LiveLocalExposureObserver()
        observer._probe_ss = lambda: [
            {"proto": "tcp", "port": 23, "bind": "0.0.0.0", "service": "telnet"}
        ]
        result = observer.assess({"id": "host1"}, _policy())
        assert len(result.verdicts) == 1
        assert result.verdicts[0].status == "exposed"
        assert result.verdicts[0].severity == "HIGH"

    def test_normal_port_exposed_medium(self):
        observer = LiveLocalExposureObserver()
        observer._probe_ss = lambda: [
            {"proto": "tcp", "port": 8080, "bind": "0.0.0.0", "service": None}
        ]
        result = observer.assess({"id": "host1"}, _policy())
        assert len(result.verdicts) == 1
        assert result.verdicts[0].status == "exposed"
        assert result.verdicts[0].severity == "MEDIUM"


# ---------------------------------------------------------------------------
# Fallback to device-supplied snapshot
# ---------------------------------------------------------------------------

class TestFallback:
    def test_fallback_to_inline_snapshot(self):
        observer = LiveLocalExposureObserver()
        observer._probe_ss = lambda: None  # ss unavailable
        device = {
            "id": "host1",
            "exposure": [
                {"proto": "tcp", "port": 22, "bind": "0.0.0.0"},
                {"proto": "tcp", "port": 80, "bind": "127.0.0.1"},
            ],
        }
        result = observer.assess(device, _policy())
        assert result.complete is True
        assert len(result.verdicts) == 2
        assert result.verdicts[0].provenance.raw_ref == "inline:device.exposure (fallback)"

    def test_fallback_to_json_file(self, tmp_path):
        observer = LiveLocalExposureObserver()
        observer._probe_ss = lambda: None
        import json
        exposure_file = tmp_path / "sockets.json"
        exposure_file.write_text(json.dumps([
            {"proto": "tcp", "port": 443, "bind": "0.0.0.0"},
        ]))
        device = {"id": "host1", "exposure_path": str(exposure_file)}
        result = observer.assess(device, _policy())
        assert result.complete is True
        assert len(result.verdicts) == 1
        assert result.verdicts[0].provenance.raw_ref.endswith("(fallback)")

    def test_fallback_file_not_found(self):
        observer = LiveLocalExposureObserver()
        observer._probe_ss = lambda: None
        device = {"id": "host1", "exposure_path": "/nonexistent/path.json"}
        result = observer.assess(device, _policy())
        assert result.complete is True
        assert len(result.verdicts) == 0
        assert "no live socket data" in result.reason

    def test_no_live_no_snapshot_noop(self):
        observer = LiveLocalExposureObserver()
        observer._probe_ss = lambda: None
        device = {"id": "host1"}
        result = observer.assess(device, _policy())
        assert result.complete is True
        assert len(result.verdicts) == 0
        assert "no live socket data" in result.reason

    def test_live_overrides_snapshot_when_both_present(self):
        """When ss returns data, the inline snapshot is ignored."""
        observer = LiveLocalExposureObserver()
        observer._probe_ss = lambda: [
            {"proto": "tcp", "port": 22, "bind": "127.0.0.1", "service": "sshd"}
        ]
        device = {
            "id": "host1",
            "exposure": [
                {"proto": "tcp", "port": 22, "bind": "0.0.0.0"},  # different bind!
            ],
        }
        result = observer.assess(device, _policy())
        assert len(result.verdicts) == 1
        # Live says loopback -> closed, snapshot says wildcard -> exposed.
        # Live should win.
        assert result.verdicts[0].status == "closed"
        assert result.verdicts[0].provenance.raw_ref == "live:ss -tulpn"


# ---------------------------------------------------------------------------
# Engine-level override: live_local_exposure (order 9) overrides
# local_exposure (order 10) on the same proto/port key
# ---------------------------------------------------------------------------

class TestEngineOverride:
    def test_live_overrides_snapshot_in_engine(self):
        """In the engine, live_local_exposure at order 9 runs last and
        overrides local_exposure at order 10 on the same proto/port key."""
        reg = ObserverRegistry()
        reg.register(LocalExposureObserver())
        reg.register(LiveLocalExposureObserver())

        policy = _policy()
        conn = store.connect(":memory:")
        device = {
            "id": "demo-host",
            # Snapshot says 22 is exposed (wildcard bind)
            "exposure": [{"proto": "tcp", "port": 22, "bind": "0.0.0.0"}],
        }
        # Live says 22 is closed (loopback bind) — patch the live observer
        # in the registry to return live data
        live_obs = reg.get("live_local_exposure")
        live_obs._probe_ss = lambda: [
            {"proto": "tcp", "port": 22, "bind": "127.0.0.1", "service": "sshd"}
        ]

        engine.assess(device, reg, policy, conn=conn,
                      now="2026-08-31T00:00:00+00:00")
        rows = {r["key"]: r for r in
                store.verdicts_for_device_axis(conn, "demo-host", "exposure")}
        # local_exposure (order 10) runs first -> exposed
        # live_local_exposure (order 9) runs last -> closed (overrides)
        assert rows["tcp/22"]["status"] == "closed"
        assert rows["tcp/22"]["observer"] == "live_local_exposure"

    def test_live_unavailable_falls_back_to_snapshot(self):
        """When live ss is unavailable, the live observer falls back to the
        device-supplied snapshot and emits its own verdicts (same data, same
        status, attributed to live_local_exposure with a fallback raw_ref)."""
        reg = ObserverRegistry()
        reg.register(LocalExposureObserver())
        reg.register(LiveLocalExposureObserver())

        policy = _policy()
        conn = store.connect(":memory:")
        device = {
            "id": "demo-host",
            "exposure": [{"proto": "tcp", "port": 80, "bind": "0.0.0.0"}],
        }
        # Live observer returns None (ss unavailable)
        live_obs = reg.get("live_local_exposure")
        live_obs._probe_ss = lambda: None

        engine.assess(device, reg, policy, conn=conn,
                      now="2026-08-31T00:00:00+00:00")
        rows = {r["key"]: r for r in
                store.verdicts_for_device_axis(conn, "demo-host", "exposure")}
        assert rows["tcp/80"]["status"] == "exposed"
        # The live observer (order 9) overrides the snapshot observer (order 10)
        # even in fallback mode — same data, same status, attributed to live.
        assert rows["tcp/80"]["observer"] == "live_local_exposure"

    def test_no_data_at_all_unknown_axis(self):
        """When neither live ss nor a device snapshot is available, both
        observers are honest no-ops and the exposure axis falls to UNKNOWN."""
        reg = ObserverRegistry()
        reg.register(LocalExposureObserver())
        reg.register(LiveLocalExposureObserver())

        policy = _policy()
        conn = store.connect(":memory:")
        device = {"id": "demo-host"}

        live_obs = reg.get("live_local_exposure")
        live_obs._probe_ss = lambda: None

        engine.assess(device, reg, policy, conn=conn,
                      now="2026-08-31T00:00:00+00:00")
        rows = list(store.verdicts_for_device_axis(conn, "demo-host", "exposure"))
        assert rows == []  # no verdicts -> axis is UNKNOWN via loud degradation


# ---------------------------------------------------------------------------
# Default registry — both live + snapshot are registered
# ---------------------------------------------------------------------------

class TestDefaultRegistry:
    def test_both_registered(self):
        from posture.sources.base import default_registry
        reg = default_registry(fresh=True)
        assert reg.get("local_exposure") is not None
        assert reg.get("live_local_exposure") is not None

    def test_live_firewall_also_registered(self):
        """Verify the retro-wiring of live_firewall from slice 6."""
        from posture.sources.base import default_registry
        reg = default_registry(fresh=True)
        assert reg.get("live_firewall") is not None
        assert reg.get("firewall") is not None
