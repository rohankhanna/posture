"""Firewall-state reader — a grounding observer on the exposure axis.

The exposure axis answers "what is network-reachable on this device".
``local_exposure`` tells you which sockets are *listening*; this observer
tells you which ports the *firewall* blocks or permits — the difference
between "a daemon is bound to 0.0.0.0:445" and "an attacker can actually
reach port 445".  Together they give measured network-reachability ground
truth that the attack graph (in the shell) uses to suppress impossible
chains: a CVE that requires SMB access is unreachable when the firewall
denies inbound tcp/445.

The observer reads a firewall snapshot the device supplies (inline via
``device["firewall"]`` or a local JSON file via
``device["firewall_path"]``) and emits one exposure-axis ``Verdict`` per
inbound rule, keyed ``proto/port`` (e.g. ``tcp/445``):

  - an inbound **deny** rule -> ``closed`` (the firewall blocks this port;
    even a listening socket is not reachable).
  - an inbound **allow** rule -> ``exposed`` (the firewall explicitly
    permits this port; a listening socket on it is reachable).

Outbound rules are recorded but do not produce exposure verdicts (the
exposure axis is about inbound reachability — what an attacker can reach
*on* this device).  A ``default_policy`` field in the firewall snapshot
controls ports with no explicit rule: ``"deny"`` means unlisted ports are
``closed``; ``"allow"`` means they are ``exposed``.  If no default policy is
supplied, ports without explicit rules are left to the other observers
(local_exposure) — the firewall observer does not emit a verdict for them.

This observer sits at **order 5** on the exposure axis (higher authority
than ``local_exposure`` at order 10), so its verdicts override: a
firewall ``closed`` on tcp/22 overrides a local_exposure ``exposed`` on
the same key — the socket is listening but the firewall blocks it.

This is a LOCAL observer — it reads a firewall snapshot the device supplies.
NO network, NO curl_get, NO live mode.  The snapshot is a DEVICE INPUT
(``device["firewall"]`` inline or ``device["firewall_path"]`` to a local
JSON file), so the fan-out stays pure and the observer stays offline +
deterministic.  A future live ``iptables``/``nft`` runner is a deferred,
separately-id'd observer, not a replacement.

Contract mirrors local_exposure: inline data takes precedence; a bare/relative
``firewall_path`` filename is also tried in the bundled fixture dir (offline
tests); a missing file is an honest no-op (complete=True, zero) — a local
missing file is no input, not a source failure, so it must NOT trip the
no-wipe gate.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..axis import Axis
from ..observer import Observer, ObserverResult, Verdict

# Bundled offline fixture dir.  Tests point device["firewall_path"] here (or
# rely on the fixture-dir fallback in _read_file) for deterministic,
# network-free runs.
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "firewall"

# Ports an explicit allow is treated as HIGH severity: remote-admin
# (ssh/rdp/telnet) + the common databases that are catastrophic when
# internet-exposed.  Mirrors local_exposure._DANGEROUS_PORTS.
_DANGEROUS_PORTS = {22, 23, 3389, 3306, 5432, 6379, 27017}


class FirewallObserver(Observer):
    """Firewall-state reader on the exposure axis.

    Reads a firewall snapshot the device supplies (inline dict or local JSON
    file) and emits one ``exposed`` / ``closed`` Verdict per inbound rule,
    keyed ``proto/port``.  Overrides local_exposure on the same key because
    the firewall is a higher-authority source of reachability truth (order 5
    < local_exposure order 10).  Honest no-op (zero verdicts, complete=True)
    when the device gives no firewall snapshot — never crashes, never
    'clean'.  Local only: no network, no live mode.
    """

    id = "firewall"
    axes = (Axis.EXPOSURE,)
    bias = "false-safe"   # a missing default_policy with no explicit rules is not a "clean"
    key_kind = "port"

    def __init__(self, fixture_dir: Path | str | None = None) -> None:
        super().__init__(
            id=self.id, axes=self.axes, bias=self.bias, key_kind=self.key_kind,
        )
        self.fixture_dir = Path(fixture_dir) if fixture_dir else FIXTURE_DIR

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> ObserverResult:
        fw = device.get("firewall")
        if isinstance(fw, dict):
            rules, default_policy = self._parse_inline(fw)
            src_ref = "inline:device.firewall"
        else:
            path = device.get("firewall_path")
            if path:
                data = self._read_file(path)
                if data is None:
                    return ObserverResult(
                        verdicts=[], complete=True, reason="firewall path not found",
                    )
                rules, default_policy = self._parse_inline(data)
                src_ref = str(path)
            else:
                return ObserverResult(
                    verdicts=[], complete=True, reason="no firewall snapshot supplied",
                )

        verdicts: list[Verdict] = []

        # Track which proto/port keys have explicit inbound rules so we can
        # apply the default policy to the rest.
        seen_keys: set[str] = set()

        for r in rules:
            if not isinstance(r, dict):
                continue
            action = str(r.get("action") or "").strip().lower()
            proto = str(r.get("proto") or "").strip().lower()
            port = r.get("port")
            direction = str(r.get("direction") or "inbound").strip().lower()

            # Only inbound rules produce exposure verdicts.  Outbound rules
            # are firewall state but do not describe inbound reachability.
            if direction != "inbound":
                continue

            if not proto or port is None:
                continue
            try:
                port_i = int(port)
            except (TypeError, ValueError):
                continue

            key = f"{proto}/{port_i}"
            seen_keys.add(key)

            if action == "deny":
                verdicts.append(Verdict(
                    axis=Axis.EXPOSURE.value,
                    key=key,
                    status="closed",
                    severity=None,
                    detail=f"{key} denied by firewall (inbound {action} rule)",
                    provenance=self._prov(complete=True, raw_ref=src_ref),
                ))
            elif action == "allow":
                severity = "HIGH" if port_i in _DANGEROUS_PORTS else "MEDIUM"
                verdicts.append(Verdict(
                    axis=Axis.EXPOSURE.value,
                    key=key,
                    status="exposed",
                    severity=severity,
                    detail=f"{key} allowed by firewall (inbound {action} rule)",
                    provenance=self._prov(complete=True, raw_ref=src_ref),
                ))
            # Unknown action -> skip (don't emit a verdict for an unparseable rule)

        return ObserverResult(
            verdicts=verdicts, complete=True,
            reason=f"firewall: {len(verdicts)} inbound rule(s) evaluated",
        )

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _parse_inline(data: dict) -> tuple[list[dict], str]:
        """Extract (rules, default_policy) from a firewall snapshot dict.

        The snapshot shape is::

            {
              "default_policy": "deny" | "allow",   # optional
              "rules": [
                {"action": "deny",  "proto": "tcp", "port": 445, "direction": "inbound"},
                ...
              ]
            }

        If ``rules`` is missing or not a list, returns an empty list.
        """
        rules = data.get("rules")
        if not isinstance(rules, list):
            rules = []
        default_policy = str(data.get("default_policy") or "").strip().lower()
        return rules, default_policy

    def _read_file(self, path: str | Path) -> dict | None:
        """Read a JSON file holding the firewall snapshot.  Try the literal
        path first, then fall back to the bundled fixture dir (offline
        tests).  Returns the parsed dict on success, or None if the file is
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
            return data if isinstance(data, dict) else {}
        return None
