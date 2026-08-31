"""Live listening-surface reader — a grounding observer on the exposure axis.

This is the live counterpart to ``local_exposure``: instead of reading a
device-supplied socket capture (inline list or JSON file), it shells out to
``ss -tulpn`` (the standard Linux socket-statistics command, available on
any modern distribution) and converts the result into the same socket-list
shape that ``LocalExposureObserver`` consumes.  The Verdict emission logic
is shared — this observer delegates to the snapshot observer after
translating the live output — so the grounding semantics (loopback bind
→ closed, wildcard/non-loopback/missing bind → exposed, dangerous-port
severity) stay identical.

Why live?  The snapshot observer is honest about what the device *reports*,
but the device report can be stale, hand-edited, or missing.  ``ss -tulpn``
reads the kernel's actual socket table — the measured ground truth for
"which sockets are listening right now and where do they bind".  When live
data is available it overrides the snapshot (order 9 < local_exposure
order 10); when it is not (no ``ss`` binary, permission denied, non-Linux),
the observer is an honest no-op and the snapshot observer's verdicts stand.

This observer is separately-id'd (``live_local_exposure``), not a replacement
for ``local_exposure`` — both coexist in the registry.  The live one wins on
shared keys when it has data; the snapshot one fills the gap when it does not.

The pure function ``parse_ss_output`` is exported for deterministic testing
without subprocess calls.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ..axis import Axis
from ..observer import Observer, ObserverResult
from .local_exposure import LocalExposureObserver

# ---------------------------------------------------------------------------
# Pure parser — exported for deterministic testing (no subprocess, no I/O)
# ---------------------------------------------------------------------------

# ``ss -tulpn`` emits a header line followed by rows like:
#
#   Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process
#   tcp   LISTEN 0      128    127.0.0.1:22        0.0.0.0:*          users:(("sshd",pid=1234,fd=3))
#   tcp   LISTEN 0      128    0.0.0.0:80          0.0.0.0:*          users:(("nginx",pid=5678,fd=6))
#   tcp   LISTEN 0      128    [::]:443            [::]:*
#   tcp   LISTEN 0      128    [::1]:5432          [::]:*             users:(("postgres",pid=9999,fd=7))
#   udp   UNCONN 0      0      0.0.0.0:53          0.0.0.0:*          users:(("dnsmasq",pid=4321,fd=4))
#
# The columns are whitespace-separated.  The interesting fields are:
#   - Netid  → proto (tcp/udp/etc.)
#   - Local Address:Port → bind address + port
#   - Process (optional) → service name from the process name in users:(("name",...))

# Match a listening row.  We capture:
#   group 1 = proto (tcp, udp, etc.)
#   group 2 = local address (everything before the last :Port)
#   group 3 = port
#   group 4 = optional process name
#
# Address forms ss emits:
#   127.0.0.1:22       → bind=127.0.0.1
#   0.0.0.0:80         → bind=0.0.0.0
#   [::]:443           → bind=::
#   [::1]:5432         → bind=::1
#   *:80               → bind=* (wildcard)
#   192.168.1.5%eth0:80 → bind=192.168.1.5 (strip interface qualifier)
#
# We need the LAST colon to be the port separator, not part of an IPv6
# address.  IPv6 addresses are always wrapped in [...], so the last un-bracketed
# colon is the port separator.

# A row that starts with a protocol word, has a LISTEN/UNCONN state, and
# contains a local address ending in :port.
_SS_ROW_RE = re.compile(
    r"^\s*"
    r"(tcp|udp|tcp6|udp6|raw|raw6|sctp|sctp6)"  # proto
    r"\s+"
    r"(?:LISTEN|UNCONN)"                        # state (LISTEN for TCP, UNCONN for UDP)
    r"\s+"
    r"\d+\s+\d+\s+"                             # Recv-Q Send-Q
    r"(\S+)\s+"                                  # Local Address:Port (group 2)
    r"\S+"                                        # Peer Address:Port
    r"(?:\s+users:\(\(\"(\w+)\".*\)\))?"         # optional process name (group 3)
    r"\s*$",
    re.IGNORECASE,
)

# Parse the local address field into (bind, port).  The local address field
# can be:
#   127.0.0.1:22
#   0.0.0.0:80
#   [::]:443
#   [::1]:5432
#   *:80
#   192.168.1.5%eth0:80
_ADDR_PORT_RE = re.compile(
    r"^(?:\[([^\]]*)\]|([^:]+)):(\d+)$"  # [ipv6]:port  or  ipv4:port  or  *:port
)


def _parse_addr_port(field: str) -> tuple[str | None, int | None]:
    """Extract (bind, port) from a ``ss`` local-address field.

    Returns (None, None) when the field doesn't match the expected shape.
    Strips interface qualifiers like ``%eth0`` from the bind address.
    Converts ``*`` wildcard to ``0.0.0.0`` (matching the snapshot format).
    """
    if not field:
        return None, None
    m = _ADDR_PORT_RE.match(field.strip())
    if not m:
        return None, None
    # group 1 = IPv6 inside brackets, group 2 = IPv4 or *
    raw_addr = m.group(1) if m.group(1) is not None else m.group(2)
    if raw_addr is None:
        return None, None
    # Strip interface qualifier: 192.168.1.5%eth0 -> 192.168.1.5
    addr = raw_addr.split("%")[0] if "%" in raw_addr else raw_addr
    # Normalize wildcard * to 0.0.0.0 (matching the snapshot format the
    # LocalExposureObserver expects).
    if addr == "*":
        addr = "0.0.0.0"
    try:
        port = int(m.group(3))
    except (TypeError, ValueError):
        return None, None
    return addr, port


def parse_ss_output(text: str) -> list[dict] | None:
    """Convert ``ss -tulpn`` text output to the socket-capture list that
    ``LocalExposureObserver`` expects.

    Returns a list of ``{"proto": str, "port": int, "bind": str, "service": str | None}``
    dicts — the same shape ``LocalExposureObserver.assess`` consumes from
    ``device["exposure"]``.

    Returns ``None`` when the text is empty or has no listening sockets — this
    signals the caller to try the fallback (device-supplied snapshot).

    Pure: no subprocess, no I/O.  Deterministic and testable.
    """
    if not text or not isinstance(text, str):
        return None

    sockets: list[dict] = []
    for line in text.strip().splitlines():
        m = _SS_ROW_RE.match(line)
        if not m:
            continue

        proto_raw = m.group(1).lower()
        # Normalize tcp6/udp6 → tcp/udp (the address carries the IPv6 info).
        proto = proto_raw.replace("6", "")
        addr_field = m.group(2)
        bind, port = _parse_addr_port(addr_field)
        if port is None:
            continue

        service = m.group(3) if m.group(3) else None

        sockets.append({
            "proto": proto,
            "port": port,
            "bind": bind,
            "service": service,
        })

    if not sockets:
        return None

    return sockets


# ---------------------------------------------------------------------------
# Observer
# ---------------------------------------------------------------------------

class LiveLocalExposureObserver(Observer):
    """Live listening-surface reader on the exposure axis.

    Shells out to ``ss -tulpn`` to read the kernel's actual socket table,
    converts the text to the socket-capture format, and delegates Verdict
    emission to ``LocalExposureObserver``.  When ``ss -tulpn`` is unavailable
    (no binary, permission denied, non-Linux), falls back to the device-
    supplied snapshot (inline ``device["exposure"]`` or
    ``device["exposure_path"]``).  When neither live data nor a snapshot is
    available, returns an honest no-op (zero verdicts, complete=True).

    Order 9 on the exposure axis (higher authority than ``local_exposure``
    at order 10): live ground truth overrides the snapshot when both produce
    verdicts for the same proto/port key.  Keys are ``proto/port``, same
    as the snapshot observer and the firewall observers.
    """

    id = "live_local_exposure"
    axes = (Axis.EXPOSURE,)
    bias = "false-safe"
    key_kind = "port"

    def __init__(self, fixture_dir: Path | str | None = None) -> None:
        super().__init__(
            id=self.id, axes=self.axes, bias=self.bias, key_kind=self.key_kind,
        )
        self._snapshot = LocalExposureObserver(fixture_dir=fixture_dir)

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> ObserverResult:
        sockets, src_ref = self._get_sockets(device)

        if sockets is None:
            return ObserverResult(
                verdicts=[], complete=True,
                reason="no live socket data and no device snapshot",
            )

        # Delegate Verdict emission to the snapshot observer, then re-stamp
        # provenance so attribution is correct (live_local_exposure, not
        # local_exposure).
        synthetic_device = {"id": device.get("id", "unknown"), "exposure": sockets}
        result = self._snapshot.assess(synthetic_device, policy)

        for v in result.verdicts:
            if v.provenance is not None:
                v.provenance = type(v.provenance)(
                    observer=self.id,
                    policy_version=v.provenance.policy_version,
                    fetched_at=v.provenance.fetched_at,
                    complete=v.provenance.complete,
                    raw_ref=src_ref,
                )

        if result.reason:
            result.reason = f"live local exposure: {result.reason}"
        else:
            result.reason = f"live local exposure: {len(result.verdicts)} socket(s) evaluated"

        return result

    # -- live probing --------------------------------------------------------

    def _get_sockets(self, device: dict) -> tuple[list[dict] | None, str]:
        """Try live ``ss -tulpn`` first; fall back to the device-supplied
        snapshot.  Returns (sockets, source_ref) or (None, "") when no data
        is available."""
        live = self._probe_ss()
        if live is not None:
            return live, "live:ss -tulpn"

        # Fall back to the device-supplied snapshot.
        surface = device.get("exposure")
        if isinstance(surface, list):
            return surface, "inline:device.exposure (fallback)"

        path = device.get("exposure_path")
        if path:
            data = self._snapshot._read_file(path)
            if data is not None:
                return data, f"{path} (fallback)"
            return None, ""

        return None, ""

    def _probe_ss(self) -> list[dict] | None:
        """Run ``ss -tulpn`` and return the parsed socket-capture list, or
        None when ``ss`` is unavailable or fails.  None means "no live data,
        try fallback" — never raises."""
        try:
            proc = subprocess.run(
                ["ss", "-tulpn"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

        if proc.returncode != 0 or not proc.stdout.strip():
            return None

        return parse_ss_output(proc.stdout)
