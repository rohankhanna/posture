"""Local listening-surface reader — the first REAL witness on the exposure axis.

Advances retcon node a96c3f0fd49c: wire real witnesses for the remaining
stubbed axes (exposure/threat/trust). The exposure axis answers "what is
network-reachable on this device". A real host carries a *socket capture*
(``device["exposure"]`` — a list of ``{proto, port, bind, service?}`` dicts,
e.g. from ``ss -tulpn``) that says which sockets are listening and where they
bind; nothing was reading it. This witness reads that capture and emits one
exposure-axis ``Verdict`` per socket, keyed ``proto/port`` (e.g. ``tcp/22``),
with status ``exposed`` / ``closed``:

  - bind loopback (127.0.0.1, the 127/8 range, ::1, localhost) -> ``closed``
    (reachable only from the host itself).
  - bind any/wildcard (0.0.0.0, ::) or a non-loopback address -> ``exposed``
    (network-reachable).
  - bind missing -> ``exposed`` (false-safe: a socket we can't prove loopback
    is assumed reachable — a missing control is not a pass, matching
    cis_checker's missing-setting decision).

``severity`` is ``HIGH`` for an exposed socket on a known-dangerous port
(ssh/rdp/telnet + the common exposed databases), ``MEDIUM`` for an exposed
socket on any other port, and ``None`` for a closed socket. The engine's
per-axis loud-degradation rule turns "no verdicts" into UNKNOWN (never
"clean"), and an exposed socket drives the exposure axis to ``exposed``
(worst present); all-closed drives it to ``closed``.

This is a LOCAL witness — it reads a socket capture the device supplies. NO
network, NO curl_get, NO live mode. The capture is a DEVICE INPUT
(``device["exposure"]`` inline or ``device["exposure_path"]`` to a local JSON
file), so the fan-out stays pure and the witness stays offline + deterministic.
A future live ``ss`` runner is a deferred, separately-id'd witness, not a
replacement.

Contract mirrors cyclonedx_sbom: inline dict takes precedence; a bare/relative
``exposure_path`` filename is also tried in the bundled fixture dir (offline
tests); a missing file is an honest no-op (complete=True, zero) — a local
missing file is no input, not a source failure, so it must NOT trip the
no-wipe gate.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..axis import Axis
from ..witness import Witness, WitnessResult, Verdict

# Bundled offline fixture dir. Tests point device["exposure_path"] here (or
# rely on the fixture-dir fallback in _read_file) for deterministic, network-
# free runs.
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "exposure"

# Ports an exposed socket on is treated as HIGH severity: remote-admin
# (ssh/rdp/telnet) + the common databases that are catastrophic when
# internet-exposed.
_DANGEROUS_PORTS = {22, 23, 3389, 3306, 5432, 6379, 27017}


def _is_loopback(bind) -> bool:
    """A socket bound here is reachable only from the host itself -> closed,
    not exposed. Covers the 127/8 IPv4 loopback range, ::1, and 'localhost'.
    A missing/None/empty bind is NOT loopback (callers treat that as exposed)."""
    if not bind:
        return False
    b = str(bind).strip().lower()
    if b in ("localhost", "::1"):
        return True
    # 127.0.0.0/8 is all loopback in IPv4.
    if b.startswith("127."):
        return True
    return False


class LocalExposureWitness(Witness):
    """Local listening-surface reader on the exposure axis.

    Reads a socket capture the device supplies (inline list or local JSON file)
    and emits one ``exposed`` / ``closed`` Verdict per socket, keyed
    ``proto/port``. Honest no-op (zero verdicts, complete=True) when the device
    gives no capture — the axis falls to UNKNOWN via loud degradation, never
    silently 'clear'. Local only: no network, no live mode.
    """

    id = "local_exposure"
    axes = (Axis.EXPOSURE,)
    bias = "false-safe"   # a missing bind is assumed exposed, not closed
    # Declares the identifier kind this witness emits, so the vocab monitor
    # records "proto/port" keys under a known kind ("port") cleanly instead of
    # surfacing them as an unknown scheme.
    key_kind = "port"

    def __init__(self, fixture_dir: Path | str | None = None) -> None:
        # `Witness` is a dataclass; pass the identity fields (incl. key_kind)
        # up so they are stamped on the INSTANCE, not just the class — the
        # dataclass-generated __init__ would otherwise shadow the class-level
        # key_kind with None.
        super().__init__(
            id=self.id, axes=self.axes, bias=self.bias, key_kind=self.key_kind,
        )
        self.fixture_dir = Path(fixture_dir) if fixture_dir else FIXTURE_DIR

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> WitnessResult:
        surface = device.get("exposure")
        if isinstance(surface, list):
            sockets = surface
            src_ref = "inline:device.exposure"
        else:
            path = device.get("exposure_path")
            if path:
                sockets = self._read_file(path)
                if sockets is None:
                    return WitnessResult(
                        verdicts=[], complete=True, reason="exposure path not found",
                    )
                src_ref = str(path)
            else:
                # No capture supplied -> honest no-op. Zero verdicts,
                # complete=True so the engine keeps the exposure axis UNKNOWN
                # (loud), never silently 'clean' — and never crashes.
                return WitnessResult(
                    verdicts=[], complete=True, reason="no exposure surface supplied",
                )

        verdicts: list[Verdict] = []
        for s in sockets:
            if not isinstance(s, dict):
                continue
            proto = str(s.get("proto") or "").strip().lower()
            port = s.get("port")
            if not proto or port is None:
                continue   # no join key within the exposure axis
            try:
                port_i = int(port)
            except (TypeError, ValueError):
                continue
            key = f"{proto}/{port_i}"
            bind = s.get("bind")
            service = s.get("service")
            svc = f" [{service}]" if service else ""

            if _is_loopback(bind):
                verdicts.append(Verdict(
                    axis=Axis.EXPOSURE.value,
                    key=key,
                    status="closed",
                    severity=None,
                    detail=f"{key} bound to {bind} (loopback){svc}",
                    provenance=self._prov(complete=True, raw_ref=src_ref),
                ))
            else:
                # exposed: wildcard/non-loopback bind, OR a missing bind
                # (false-safe — can't prove it loopback).
                bind_label = bind if bind else "bind unknown"
                severity = "HIGH" if port_i in _DANGEROUS_PORTS else "MEDIUM"
                verdicts.append(Verdict(
                    axis=Axis.EXPOSURE.value,
                    key=key,
                    status="exposed",
                    severity=severity,
                    detail=f"{key} bound to {bind_label}{svc} (network-reachable)",
                    provenance=self._prov(complete=True, raw_ref=src_ref),
                ))

        return WitnessResult(
            verdicts=verdicts, complete=True,
            reason=f"local exposure: {len(verdicts)} socket(s) read",
        )

    # -- helpers -------------------------------------------------------------

    def _read_file(self, path: str | Path) -> list[dict] | None:
        """Read a JSON file holding the socket list. Try the literal path first,
        then fall back to the bundled fixture dir (offline tests). Returns the
        list (possibly empty) on success, or None if the file is not found in
        either place."""
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