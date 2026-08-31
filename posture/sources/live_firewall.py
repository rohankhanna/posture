"""Live firewall-state reader — a grounding observer on the exposure axis.

This is the live counterpart to ``firewall``: instead of reading a
device-supplied snapshot (inline dict or JSON file), it shells out to
``ufw status verbose`` (Ubuntu's default firewall manager) or
``iptables -S`` (available everywhere iptables is installed) and converts
the result into the same firewall-snapshot shape that ``FirewallObserver``
consumes.  The Verdict emission logic is shared — this observer delegates to
the snapshot observer after translating the live output — so the grounding
semantics (deny → closed, allow → exposed, dangerous-port severity, outbound
skipping) stay identical.

Why live?  The snapshot observers are honest about what the device *reports*,
but the device report can be stale, hand-edited, or missing.  ``ufw status``
or ``iptables -S`` reads the kernel's actual firewall state — the measured
ground truth for "which ports does the firewall block right now".  When live
data is available it overrides the snapshot (order 4 < firewall order 5);
when it is not (no ``ufw``/``iptables`` binary, permission denied, non-Linux),
the observer is an honest no-op and the snapshot observer's verdicts stand.

This observer is separately-id'd (``live_firewall``), not a replacement for
``firewall`` — both coexist in the registry.  The live one wins on shared
keys when it has data; the snapshot one fills the gap when it does not.

The pure functions ``parse_ufw_status`` and ``parse_iptables_rules`` are
exported for deterministic testing without subprocess calls.

Probe priority: ``ufw`` first (simplest, most common on Ubuntu desktop),
then ``iptables`` (universal on Linux).  ``nft`` (nftables) is a future
addition — its JSON output is complex and nft is less common on the fleet
devices; it can be added as a third probe without changing the delegation
pattern.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ..axis import Axis
from ..observer import Observer, ObserverResult, Verdict
from .firewall import FirewallObserver


# ---------------------------------------------------------------------------
# Pure parsers — exported for deterministic testing (no subprocess, no I/O)
# ---------------------------------------------------------------------------

def parse_ufw_status(text: str) -> dict | None:
    """Convert ``ufw status verbose`` text output to the firewall snapshot
    dict that ``FirewallObserver`` expects.

    ``ufw status verbose`` emits::

        Status: active
        Logging: on (low)
        Default: deny (incoming), allow (outgoing), deny (routed)

        To                         Action      From
        --                         ------      ----
        22/tcp                     ALLOW       Anywhere
        80/tcp                     ALLOW       Anywhere
        445/tcp                    DENY        Anywhere
        53/udp                     ALLOW       Anywhere

    Returns a dict shaped ``{"default_policy": "deny"|"allow"|"", "rules": [...]}``
    where each rule is ``{"action": "allow"|"deny", "proto": "tcp"|"udp",
    "port": int, "direction": "inbound"}``.

    Returns ``None`` when ufw is inactive (``Status: inactive``) — this
    signals the caller to try the next probe.  An active ufw with no rules
    returns a complete snapshot with an empty rules list.

    Pure: no subprocess, no I/O.  Deterministic and testable.
    """
    if not text or not isinstance(text, str):
        return None

    # Status line: "Status: active" or "Status: inactive"
    status_match = re.search(r"^Status:\s*(\w+)", text, re.MULTILINE)
    if not status_match:
        return None
    status = status_match.group(1).strip().lower()
    if status != "active":
        return None  # ufw inactive — let caller try next probe

    # Default policy: "Default: deny (incoming), allow (outgoing), deny (routed)"
    default_policy = ""
    default_match = re.search(
        r"^Default:\s*(\w+)\s*\(incoming\)", text, re.MULTILINE,
    )
    if default_match:
        default_policy = default_match.group(1).strip().lower()

    rules: list[dict] = []

    # Rule lines come after the header "To ... Action ... From".
    # Each rule line looks like:
    #   22/tcp                     ALLOW       Anywhere
    #   53/udp                     ALLOW       Anywhere
    #   22/tcp (v6)                ALLOW       Anywhere (v6)
    #
    # We match "PORT/PROTO" followed by whitespace and "ALLOW"/"DENY".
    rule_pattern = re.compile(
        r"^\s*(\d+)/(\w+)(?:\s+\(v6\))?\s+(ALLOW|DENY)\b",
        re.MULTILINE,
    )
    for m in rule_pattern.finditer(text):
        port_str, proto, action = m.group(1), m.group(2), m.group(3)
        try:
            port_i = int(port_str)
        except ValueError:
            continue
        rules.append({
            "action": action.lower(),
            "proto": proto.lower(),
            "port": port_i,
            "direction": "inbound",
        })

    return {"default_policy": default_policy, "rules": rules}


def parse_iptables_rules(text: str) -> dict | None:
    """Convert ``iptables -S`` text output to the firewall snapshot dict.

    ``iptables -S`` emits::

        -P INPUT DROP
        -P FORWARD DROP
        -P OUTPUT ACCEPT
        -A INPUT -p tcp --dport 22 -j ACCEPT
        -A INPUT -p tcp --dport 445 -j DROP
        -A INPUT -p udp --dport 53 -j ACCEPT
        -A INPUT -j REJECT

    Returns a dict shaped ``{"default_policy": "deny"|"allow"|"", "rules": [...]}``
    where each rule is ``{"action": "allow"|"deny", "proto": "tcp"|"udp",
    "port": int, "direction": "inbound"}``.

    Only INPUT chain rules and the INPUT default policy are extracted (the
    exposure axis is about inbound reachability).  Rules without an explicit
    ``--dport`` (e.g. catch-all REJECT, ESTABLISHED matchers) are skipped —
    they don't map to a specific port key.

    Returns ``None`` when the text is empty or has no iptables rules — this
    signals the caller to try the next probe.

    Pure: no subprocess, no I/O.  Deterministic and testable.
    """
    if not text or not isinstance(text, str):
        return None

    # Default policy from "-P INPUT <target>"
    default_policy = ""
    policy_match = re.search(r"^-P\s+INPUT\s+(\w+)", text, re.MULTILINE)
    if policy_match:
        target = policy_match.group(1).strip().upper()
        if target in ("DROP", "REJECT"):
            default_policy = "deny"
        elif target == "ACCEPT":
            default_policy = "allow"

    rules: list[dict] = []

    # INPUT chain rules: "-A INPUT -p <proto> --dport <port> -j <target>"
    # We need both -p and --dport to emit a port-level verdict.
    rule_pattern = re.compile(
        r"^-A\s+INPUT\s+.*?-p\s+(\w+)\s+.*?--dport\s+(\d+)\s+-j\s+(\w+)",
        re.MULTILINE,
    )
    for m in rule_pattern.finditer(text):
        proto, port_str, target = m.group(1), m.group(2), m.group(3)
        target = target.strip().upper()
        if target in ("ACCEPT",):
            action = "allow"
        elif target in ("DROP", "REJECT"):
            action = "deny"
        else:
            continue  # LOG, RETURN, etc. — not a verdict

        try:
            port_i = int(port_str)
        except ValueError:
            continue

        rules.append({
            "action": action,
            "proto": proto.lower(),
            "port": port_i,
            "direction": "inbound",
        })

    # If we found nothing at all (no policy, no rules), return None so the
    # caller knows iptables produced no useful data.
    if not default_policy and not rules:
        return None

    return {"default_policy": default_policy, "rules": rules}


# ---------------------------------------------------------------------------
# Observer
# ---------------------------------------------------------------------------

class LiveFirewallObserver(Observer):
    """Live firewall-state reader on the exposure axis.

    Shells out to ``ufw status verbose`` (Ubuntu's default firewall manager)
    or ``iptables -S`` (universal Linux fallback) to read the kernel's actual
    firewall rules, converts the text to the snapshot format, and delegates
    Verdict emission to ``FirewallObserver``.  When no live tool is available
    (no binary, permission denied, non-Linux), falls back to the device-
    supplied snapshot (inline ``device["firewall"]`` or
    ``device["firewall_path"]``).  When neither live data nor a snapshot is
    available, returns an honest no-op (zero verdicts, complete=True).

    Order 4 on the exposure axis (higher authority than ``firewall`` at
    order 5): live ground truth overrides the snapshot when both produce
    verdicts for the same proto/port key.  Keys are ``proto/port``, same
    as the snapshot observer.
    """

    id = "live_firewall"
    axes = (Axis.EXPOSURE,)
    bias = "false-safe"
    key_kind = "port"

    def __init__(self, fixture_dir: Path | str | None = None) -> None:
        super().__init__(
            id=self.id, axes=self.axes, bias=self.bias, key_kind=self.key_kind,
        )
        self._snapshot = FirewallObserver(fixture_dir=fixture_dir)

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> ObserverResult:
        fw_snapshot, src_ref = self._get_firewall(device)

        if fw_snapshot is None:
            return ObserverResult(
                verdicts=[], complete=True,
                reason="no live firewall data and no device snapshot",
            )

        # Delegate Verdict emission to the snapshot observer, then re-stamp
        # provenance so attribution is correct (live_firewall, not firewall).
        synthetic_device = {"id": device.get("id", "unknown"), "firewall": fw_snapshot}
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
            result.reason = f"live firewall: {result.reason}"
        else:
            result.reason = f"live firewall: {len(result.verdicts)} inbound rule(s) evaluated"

        return result

    # -- live probing --------------------------------------------------------

    def _get_firewall(self, device: dict) -> tuple[dict | None, str]:
        """Try live ``ufw status verbose`` then ``iptables -S``; fall back to
        the device-supplied snapshot.  Returns (snapshot_dict, source_ref) or
        (None, "") when no data is available."""
        # Try ufw first (simplest output, most common on Ubuntu).
        ufw = self._probe_ufw()
        if ufw is not None:
            return ufw, "live:ufw status verbose"

        # Try iptables as fallback (universal on Linux).
        ipt = self._probe_iptables()
        if ipt is not None:
            return ipt, "live:iptables -S"

        # Fall back to the device-supplied snapshot.
        fw = device.get("firewall")
        if isinstance(fw, dict):
            return fw, "inline:device.firewall (fallback)"

        path = device.get("firewall_path")
        if path:
            data = self._snapshot._read_file(path)
            if data is not None:
                return data, f"{path} (fallback)"
            return None, ""

        return None, ""

    def _probe_ufw(self) -> dict | None:
        """Run ``ufw status verbose`` and return the parsed snapshot dict, or
        None when ufw is unavailable, inactive, or fails.  None means "no live
        data, try fallback" — never raises."""
        try:
            proc = subprocess.run(
                ["ufw", "status", "verbose"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

        if proc.returncode != 0 or not proc.stdout.strip():
            return None

        return parse_ufw_status(proc.stdout)

    def _probe_iptables(self) -> dict | None:
        """Run ``iptables -S`` and return the parsed snapshot dict, or None
        when iptables is unavailable or fails.  None means "no live data, try
        fallback" — never raises."""
        try:
            proc = subprocess.run(
                ["iptables", "-S"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

        if proc.returncode != 0 or not proc.stdout.strip():
            return None

        return parse_iptables_rules(proc.stdout)
