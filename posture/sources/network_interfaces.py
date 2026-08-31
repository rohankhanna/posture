"""Network-interface reader — a grounding observer on the exposure axis.

The exposure axis answers "what is network-reachable on this device".
``local_exposure`` tells you which sockets are *listening* and ``firewall``
tells you which ports the firewall blocks or permits.  This observer adds a
third layer of grounding: *which subnets this device is actually on* — the
network topology the attack graph needs to suppress cross-network chains.

A CVE that requires reaching a host on ``10.0.0.0/8`` is unreachable when the
device has no interface on that subnet.  Conversely, a device on
``192.168.1.0/24`` can reach every other host on that subnet, so a chain
requiring lateral movement inside ``192.168.1.0/24`` is plausible.  This
observer emits one exposure-axis ``Verdict`` per UP interface address, keyed
by subnet CIDR (e.g. ``192.168.1.0/24``):

  - a **non-loopback** UP interface address -> ``reachable`` (the device can
    send and receive on this subnet; the attack graph may chain through it).
  - a **loopback** UP interface address -> ``loopback`` (the device can only
    reach itself on this subnet; chains requiring external access via this
    subnet are impossible, but it proves the stack is up).
  - a **DOWN** interface -> no verdict (a down interface contributes no
    reachability signal — it is neither reachable nor evidence of absence).

This observer sits at **order 15** on the exposure axis (lower authority than
``local_exposure`` at order 10 and ``firewall`` at order 5).  Its keys are
subnet CIDRs, not proto/port keys, so it never overrides the port-level
observers — it adds topology context alongside them.  The engine's per-axis
loud-degradation rule turns "no verdicts" into UNKNOWN (never "clean").

This is a LOCAL observer — it reads an interface snapshot the device supplies
(inline via ``device["interfaces"]`` or a local JSON file via
``device["interfaces_path"]``).  NO network, NO live mode.  The snapshot is a
DEVICE INPUT, so the fan-out stays pure and the observer stays offline +
deterministic.  A future live ``ip addr`` / ``ifconfig`` runner is a deferred,
separately-id'd observer, not a replacement.

Contract mirrors firewall / local_exposure: inline data takes precedence; a
bare/relative ``interfaces_path`` filename is also tried in the bundled fixture
dir (offline tests); a missing file is an honest no-op (complete=True, zero)
— a local missing file is no input, not a source failure, so it must NOT trip
the no-wipe gate.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from ..axis import Axis
from ..observer import Observer, ObserverResult, Verdict

# Bundled offline fixture dir.  Tests point device["interfaces_path"] here (or
# rely on the fixture-dir fallback in _read_file) for deterministic,
# network-free runs.
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "network_interfaces"


def _is_loopback_name(name: str) -> bool:
    """Heuristic: the loopback interface is conventionally named ``lo``."""
    return str(name).strip().lower() == "lo"


def _subnet_cidr(ip: str, prefix: int) -> str | None:
    """Compute the subnet CIDR string (e.g. ``192.168.1.0/24``) from an IP
    address and prefix length.  Returns None when the IP or prefix is invalid."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except ValueError:
        return None
    return str(net)


class NetworkInterfacesObserver(Observer):
    """Network-interface reader on the exposure axis.

    Reads an interface snapshot the device supplies (inline list or local JSON
    file) and emits one ``reachable`` / ``loopback`` Verdict per UP interface
    address, keyed by subnet CIDR.  Honest no-op (zero verdicts, complete=True)
    when the device gives no interface snapshot — never crashes, never 'clean'.
    Local only: no network, no live mode.
    """

    id = "network_interfaces"
    axes = (Axis.EXPOSURE,)
    bias = "false-safe"   # a missing interface snapshot is not "clean"
    key_kind = "subnet"

    def __init__(self, fixture_dir: Path | str | None = None) -> None:
        super().__init__(
            id=self.id, axes=self.axes, bias=self.bias, key_kind=self.key_kind,
        )
        self.fixture_dir = Path(fixture_dir) if fixture_dir else FIXTURE_DIR

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> ObserverResult:
        interfaces = device.get("interfaces")
        if isinstance(interfaces, list):
            ifaces = interfaces
            src_ref = "inline:device.interfaces"
        else:
            path = device.get("interfaces_path")
            if path:
                ifaces = self._read_file(path)
                if ifaces is None:
                    return ObserverResult(
                        verdicts=[], complete=True, reason="interfaces path not found",
                    )
                src_ref = str(path)
            else:
                return ObserverResult(
                    verdicts=[], complete=True, reason="no interface snapshot supplied",
                )

        verdicts: list[Verdict] = []

        for iface in ifaces:
            if not isinstance(iface, dict):
                continue
            state = str(iface.get("state") or "").strip().lower()
            if state != "up":
                continue   # down or unknown state -> no reachability signal

            name = str(iface.get("name") or "").strip()
            addresses = iface.get("addresses")
            if not isinstance(addresses, list):
                continue

            is_lo = _is_loopback_name(name)

            for addr in addresses:
                if not isinstance(addr, dict):
                    continue
                ip = str(addr.get("ip") or "").strip()
                prefix = addr.get("prefix")
                if not ip or prefix is None:
                    continue
                try:
                    prefix_i = int(prefix)
                except (TypeError, ValueError):
                    continue

                cidr = _subnet_cidr(ip, prefix_i)
                if cidr is None:
                    continue

                # A loopback interface name wins; also detect 127/8 and ::1
                # directly so a misnamed loopback still classifies.
                loopback = is_lo or self._is_loopback_ip(ip)

                if loopback:
                    verdicts.append(Verdict(
                        axis=Axis.EXPOSURE.value,
                        key=cidr,
                        status="loopback",
                        severity=None,
                        detail=f"{cidr} via {name or 'unnamed'} (loopback — host-only)",
                        provenance=self._prov(complete=True, raw_ref=src_ref),
                    ))
                else:
                    verdicts.append(Verdict(
                        axis=Axis.EXPOSURE.value,
                        key=cidr,
                        status="reachable",
                        severity="LOW",
                        detail=f"{cidr} via {name or 'unnamed'} (subnet reachable)",
                        provenance=self._prov(complete=True, raw_ref=src_ref),
                    ))

        return ObserverResult(
            verdicts=verdicts, complete=True,
            reason=f"network interfaces: {len(verdicts)} address(es) evaluated",
        )

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _is_loopback_ip(ip: str) -> bool:
        """True when the IP is in the 127/8 IPv4 loopback range or is ::1."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return addr.is_loopback

    def _read_file(self, path: str | Path) -> list[dict] | None:
        """Read a JSON file holding the interface list.  Try the literal path
        first, then fall back to the bundled fixture dir (offline tests).
        Returns the list (possibly empty) on success, or None if the file is
        not found in either place."""
        p = Path(path)
        candidates: list[Path] = [p]
        if not p.is_absolute():
            candidates.append(self.fixture_dir / p.name)
        for c in candidates:
            try:
                data = json.loads(c.read_text())
            except (OSError, ValueError):
                continue
            return data if isinstance(data, list) else []
        return None
