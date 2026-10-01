"""Live network-interface reader — a grounding observer on the exposure axis.

This is the live counterpart to ``network_interfaces``: instead of reading a
device-supplied snapshot (inline or JSON file), it shells out to
``ip -j addr`` (JSON output, available on modern Linux via iproute2) and
converts the result into the same interface-snapshot shape that
``NetworkInterfacesObserver`` consumes.  The Verdict emission logic is shared
— this observer delegates to the snapshot observer after translating the live
output — so the grounding semantics (loopback detection, subnet CIDR
computation, DOWN-interface suppression) stay identical.

Why live?  The snapshot observers are honest about what the device *reports*,
but the device report can be stale, hand-edited, or missing.  ``ip -j addr``
reads the kernel's actual interface table — the measured ground truth for
"which subnets is this device on right now".  When live data is available it
overrides the snapshot (order 14 < network_interfaces order 15); when it is
not (no ``ip`` binary, permission denied, non-Linux), the observer is an
honest no-op and the snapshot observer's verdicts stand.

This observer is separately-id'd (``live_network_interfaces``), not a
replacement for ``network_interfaces`` — both coexist in the registry.  The
live one wins on shared keys when it has data; the snapshot one fills the gap
when it does not.

The pure function ``parse_ip_addr_json`` is exported for deterministic testing
without subprocess calls.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..axis import Axis
from ..observer import Observer, ObserverResult, Verdict
from .network_interfaces import NetworkInterfacesObserver


def parse_ip_addr_json(data: list[dict]) -> list[dict]:
    """Convert ``ip -j addr`` JSON output to the device-snapshot format.

    ``ip -j addr`` emits a list of interface objects::

        [
          {"ifname": "lo", "operstate": "UNKNOWN",
           "flags": ["LOOPBACK", "UP", "LOWER_UP"],
           "addr_info": [{"family": "inet", "local": "127.0.0.1",
                           "prefixlen": 8, ...}]},
          ...
        ]

    This function produces the snapshot shape that
    ``NetworkInterfacesObserver`` expects::

        [
          {"name": "lo", "state": "up",
           "addresses": [{"ip": "127.0.0.1", "prefix": 8, "family": "ipv4"}]},
          ...
        ]

    State mapping:
      - ``operstate == "UP"`` -> ``"up"``
      - ``operstate == "DOWN"`` -> ``"down"``
      - ``operstate == "UNKNOWN"`` (loopback convention) -> ``"up"`` if
        ``"UP"`` is in ``flags``, else ``"down"``.

    Address mapping:
      - ``local`` -> ``ip``
      - ``prefixlen`` -> ``prefix``
      - ``family`` -> ``family`` (``"inet"`` -> ``"ipv4"``, ``"inet6"`` ->
        ``"ipv6"``)

    Pure: no subprocess, no I/O.  Deterministic and testable.
    """
    if not isinstance(data, list):
        return []

    interfaces: list[dict] = []
    for iface in data:
        if not isinstance(iface, dict):
            continue
        name = str(iface.get("ifname") or "").strip()
        if not name:
            continue

        operstate = str(iface.get("operstate") or "").strip().upper()
        flags = iface.get("flags")
        flag_set = {str(f).upper() for f in flags} if isinstance(flags, list) else set()

        if operstate == "UP":
            state = "up"
        elif operstate == "DOWN":
            state = "down"
        elif operstate == "UNKNOWN":
            # Loopback interfaces report operstate "UNKNOWN" but are
            # functionally UP when the UP flag is set.
            state = "up" if "UP" in flag_set else "down"
        else:
            # Missing or unrecognized operstate: treat as down (no
            # reachability signal).
            state = "down"

        addr_info = iface.get("addr_info")
        addresses: list[dict] = []
        if isinstance(addr_info, list):
            for ai in addr_info:
                if not isinstance(ai, dict):
                    continue
                ip = str(ai.get("local") or "").strip()
                if not ip:
                    continue
                prefix = ai.get("prefixlen")
                if prefix is None:
                    continue
                try:
                    prefix_i = int(prefix)
                except (TypeError, ValueError):
                    continue
                family_raw = str(ai.get("family") or "").strip().lower()
                if family_raw == "inet":
                    family = "ipv4"
                elif family_raw == "inet6":
                    family = "ipv6"
                else:
                    family = family_raw
                addresses.append({"ip": ip, "prefix": prefix_i, "family": family})

        interfaces.append({"name": name, "state": state, "addresses": addresses})

    return interfaces


class LiveNetworkInterfacesObserver(Observer):
    """Live network-interface reader on the exposure axis.

    Shells out to ``ip -j addr`` to read the kernel's actual interface table,
    converts the JSON to the snapshot format, and delegates Verdict emission
    to ``NetworkInterfacesObserver``.  When ``ip -j addr`` is unavailable
    (no binary, permission denied, non-Linux), falls back to the device-
    supplied snapshot (inline ``device["interfaces"]`` or
    ``device["interfaces_path"]``).  When neither live data nor a snapshot
    is available, returns an honest no-op (zero verdicts, complete=True).

    Order 14 on the exposure axis (higher authority than ``network_interfaces``
    at order 15): live ground truth overrides the snapshot when both produce
    verdicts for the same subnet.  Keys are subnet CIDRs, so it never
    conflicts with the port-level observers.
    """

    id = "live_network_interfaces"
    axes = (Axis.EXPOSURE,)
    bias = "false-safe"
    key_kind = "subnet"

    def __init__(self, fixture_dir: Path | str | None = None) -> None:
        super().__init__(
            id=self.id, axes=self.axes, bias=self.bias, key_kind=self.key_kind,
        )
        # Reuse the snapshot observer for Verdict emission (delegation, not
        # inheritance — avoids coupling the two class hierarchies).
        self._snapshot = NetworkInterfacesObserver(fixture_dir=fixture_dir)

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> ObserverResult:
        interfaces, src_ref = self._get_interfaces(device)

        if interfaces is None:
            return ObserverResult(
                verdicts=[], complete=True,
                reason="no live interface data and no device snapshot",
            )

        # Delegate Verdict emission to the snapshot observer, then re-stamp
        # provenance so attribution is correct (live_network_interfaces, not
        # network_interfaces).
        synthetic_device = {"id": device.get("id", "unknown"), "interfaces": interfaces}
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
            result.reason = f"live network interfaces: {result.reason}"
        else:
            result.reason = f"live network interfaces: {len(result.verdicts)} address(es) evaluated"

        return result

    # -- live probing --------------------------------------------------------

    def _get_interfaces(self, device: dict) -> tuple[list[dict] | None, str]:
        """Try live ``ip -j addr`` first; fall back to the device-supplied
        snapshot.  Returns (interfaces, source_ref) or (None, "") when no
        data is available."""
        live = self._probe_ip_addr()
        if live is not None:
            return live, "live:ip -j addr"

        # Fall back to the device-supplied snapshot.
        interfaces = device.get("interfaces")
        if isinstance(interfaces, list):
            return interfaces, "inline:device.interfaces (fallback)"

        path = device.get("interfaces_path")
        if path:
            data = self._snapshot._read_file(path)
            if data is not None:
                return data, f"{path} (fallback)"
            # Path was given but file not found — return None so the caller
            # emits an honest no-op (matching snapshot observer behavior).
            return None, ""

        return None, ""

    def _probe_ip_addr(self) -> list[dict] | None:
        """Run ``ip -j addr`` and return the parsed snapshot-format list, or
        None when the command is unavailable or fails.  None means "no live
        data, try fallback" — never raises."""
        try:
            proc = subprocess.run(
                ["ip", "-j", "addr"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

        if proc.returncode != 0 or not proc.stdout.strip():
            return None

        try:
            data = json.loads(proc.stdout)
        except (ValueError, TypeError):
            return None

        if not isinstance(data, list):
            return None

        return parse_ip_addr_json(data)
