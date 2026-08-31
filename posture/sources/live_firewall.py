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
then ``iptables`` (universal on Linux).  ``nft`` (nftables) is the third probe — the modern
Linux firewall, default on Debian 10+, Fedora, and Arch.  Its JSON output
(``nft list ruleset --json``) is parsed by ``parse_nft_ruleset`` into the same
snapshot shape; it joins the delegation chain without changing the pattern.
"""

from __future__ import annotations

import json
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




def parse_nft_ruleset(text: str) -> dict | None:
    """Convert ``nft list ruleset --json`` output to the firewall snapshot
    dict that ``FirewallObserver`` expects.

    ``nft list ruleset --json`` emits a top-level JSON array of objects.
    Each object has one key — ``"metainfo"``, ``"table"``, ``"chain"``, or
    ``"rule"`` — describing an element of the ruleset.  This parser extracts
    only inbound-filter semantics relevant to the exposure axis:

      - chains with ``hook == "input"`` supply the ``default_policy``
        (``accept`` -> ``allow``, ``drop`` -> ``deny``); the most restrictive
        policy across all input chains wins (``deny`` > ``allow`` > ``""``).
      - rules on input chains that match a destination port (``dport``)
        and terminate with ``accept`` / ``drop`` / ``reject`` become
        per-port ``allow`` / ``deny`` entries.

    Rules without a dport match (catch-all, established-connection
    matchers, etc.) are skipped — they don't map to a specific port key.

    Returns ``None`` when the text is empty, not valid JSON, or contains
    no chains/rules — this signals the caller that nft produced no useful
    data.

    Pure: no subprocess, no I/O.  Deterministic and testable.
    """
    if not text or not isinstance(text, str):
        return None

    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None

    if not isinstance(data, list):
        return None

    # Collect input-chain names and their policies.
    # Key: chain name -> policy string ("allow" | "deny" | "")
    input_chains: dict[str, str] = {}

    for obj in data:
        if not isinstance(obj, dict):
            continue
        chain = obj.get("chain")
        if not isinstance(chain, dict):
            continue
        hook = str(chain.get("hook") or "").strip().lower()
        if hook != "input":
            continue
        name = str(chain.get("name") or "").strip()
        if not name:
            continue
        policy_raw = str(chain.get("policy") or "").strip().lower()
        if policy_raw == "accept":
            policy = "allow"
        elif policy_raw == "drop":
            policy = "deny"
        else:
            policy = ""
        # Most restrictive wins: deny > allow > ""
        existing = input_chains.get(name, "")
        if policy == "deny" or (policy == "allow" and existing == ""):
            input_chains[name] = policy

    # Determine the overall default policy from all input chains.
    default_policy = ""
    for p in input_chains.values():
        if p == "deny":
            default_policy = "deny"
            break
        if p == "allow":
            default_policy = "allow"

    rules: list[dict] = []

    for obj in data:
        if not isinstance(obj, dict):
            continue
        rule = obj.get("rule")
        if not isinstance(rule, dict):
            continue
        chain_name = str(rule.get("chain") or "").strip()
        # Only consider rules on input chains.
        if chain_name not in input_chains:
            continue

        exprs = rule.get("expr")
        if not isinstance(exprs, list):
            continue

        # Walk the expression list to find a dport match + terminal verdict.
        dport_proto: str | None = None
        dport_num: int | None = None
        verdict: str | None = None  # "allow" | "deny"

        for expr in exprs:
            if not isinstance(expr, dict):
                continue

            # Match expression: {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}
            match = expr.get("match")
            if isinstance(match, dict):
                left = match.get("left")
                right = match.get("right")
                if isinstance(left, dict):
                    payload = left.get("payload")
                    if isinstance(payload, dict):
                        field = str(payload.get("field") or "").strip().lower()
                        proto = str(payload.get("protocol") or "").strip().lower()
                        if field == "dport" and right is not None:
                            try:
                                dport_num = int(right)
                                dport_proto = proto
                            except (TypeError, ValueError):
                                pass

            # Terminal verdicts: {"accept": null}, {"drop": null}, {"reject": null}
            if "accept" in expr:
                verdict = "allow"
            elif "drop" in expr or "reject" in expr:
                verdict = "deny"

        # Only emit a rule if we found both a dport and a verdict.
        if dport_proto and dport_num is not None and verdict:
            rules.append({
                "action": verdict,
                "proto": dport_proto,
                "port": dport_num,
                "direction": "inbound",
            })

    # If we found nothing at all, return None.
    if not default_policy and not rules:
        return None

    return {"default_policy": default_policy, "rules": rules}

# ---------------------------------------------------------------------------
# Observer
# ---------------------------------------------------------------------------

class LiveFirewallObserver(Observer):
    """Live firewall-state reader on the exposure axis.

    Shells out to ``ufw status verbose`` (Ubuntu's default firewall manager),
    ``iptables -S`` (universal Linux fallback), or ``nft list ruleset --json``
    (nftables, modern Linux) to read the kernel's actual firewall rules, converts the text to the snapshot format, and delegates
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
        """Try live ``ufw status verbose``, then ``iptables -S``, then
        ``nft list ruleset --json``; fall back to the device-supplied
        snapshot.  Returns (snapshot_dict, source_ref) or (None, "") when
        no data is available."""
        # Try ufw first (simplest output, most common on Ubuntu).
        ufw = self._probe_ufw()
        if ufw is not None:
            return ufw, "live:ufw status verbose"

        # Try iptables as fallback (universal on Linux).
        ipt = self._probe_iptables()
        if ipt is not None:
            return ipt, "live:iptables -S"

        # Try nft (nftables) — the modern Linux firewall, default on
        # Debian 10+, Fedora, and Arch.  Its JSON output is richer but
        # parse_nft_ruleset extracts the same snapshot shape.
        nft = self._probe_nft()
        if nft is not None:
            return nft, "live:nft list ruleset --json"

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

    def _probe_nft(self) -> dict | None:
        """Run ``nft list ruleset --json`` and return the parsed snapshot
        dict, or None when nft is unavailable or fails.  None means "no live
        data, try fallback" — never raises."""
        try:
            proc = subprocess.run(
                ["nft", "list", "ruleset", "--json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

        if proc.returncode != 0 or not proc.stdout.strip():
            return None

        return parse_nft_ruleset(proc.stdout)
