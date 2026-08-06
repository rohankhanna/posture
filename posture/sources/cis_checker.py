"""CIS-style configuration checker — the first REAL witness on the
configuration axis.

Why this witness exists (the gap it closes): the configuration axis has been
stubbed/UNKNOWN since the skeleton. A real host carries a *config snapshot*
(``device["config"]`` — a flat dict of setting->value) that says how the box is
actually set up, but nothing was reading it. This witness reads that snapshot
against a small CIS-style benchmark (``CIS_BENCHMARK`` below) and emits one
configuration-axis ``Verdict`` per check, keyed by check id (e.g.
``CIS-6.2.1``), with status ``fail`` / ``pass``. The engine's per-axis loud-
degradation rule then turns "no verdicts" into UNKNOWN (never "clean"), and a
failed check drives the configuration axis to ``fail`` (worst present).

This is a LOCAL witness — it reads a config the device supplies. NO network,
NO curl_get, NO live mode. The benchmark itself is a module constant (a
broadened CIS-style subset covering SSH server, /tmp mount, audit logging,
password policy, sysctl hardening, and world-writable-file checks — fuller
than the original demo-scope set, though still NOT the complete CIS Benchmark).

Contract: Forebode had a hardcoded "CIS check" pass over /etc config files.
Posture keeps the same decide logic (compare observed setting to expected) but
the config is a DEVICE INPUT (``device["config"]``), not a live filesystem
read, so the fan-out stays pure and the witness stays offline + deterministic.

Missing-setting decision: a check whose setting is absent from
``device["config"]`` is recorded as ``fail`` (a missing control is not a pass
— you cannot confirm the control is in place). This is the false-safe direction:
community/vendor checklists may understate, and we'd rather flag a missing
setting than silently pass it. See ``assess`` for the explicit branch.
"""

from __future__ import annotations

from ..axis import Axis
from ..witness import Witness, WitnessResult, Verdict

# ---------------------------------------------------------------------------
# The benchmark — a broadened CIS-style subset (NOT the full CIS Benchmark).
#
# This is NOT the complete CIS Benchmark suite. It is a realistic, broader
# Linux/server check set (sshd, /tmp mount, audit logging, password policy,
# sysctl hardening, world-writable files) so the configuration axis has a real
# witness driving it. Each entry is keyed by check id and carries:
#   setting    -> the config key to look up in device["config"]
#   expected   -> the expected value (string, or a number for numeric compares)
#   severity   -> high | medium | low
#   description-> human-readable check title
#   comparator -> "eq" (string equality, default), "ge" (numeric >=),
#                 or "le" (numeric <=)
#
# Comparator use:
#   "eq" -> string equality (both sides coerced to str); used for the bulk of
#           flag-style settings (yes/no) and exact-value sysctl knobs.
#   "ge" -> numeric: observed >= expected (a FLOOR, e.g. password min length,
#           password min age, audit log size).
#   "le" -> numeric: observed <= expected (a CEILING, e.g. password max age,
#           SSH MaxAuthTries, SSH LoginGraceTime).
# ---------------------------------------------------------------------------

CIS_BENCHMARK: dict[str, dict] = {
    "CIS-6.2.1": {
        "setting": "sshd_permit_root_login",
        "expected": "no",
        "severity": "high",
        "description": "Ensure SSH PermitRootLogin is disabled",
        "comparator": "eq",
    },
    "CIS-1.1.2": {
        "setting": "tmp_nosuid",
        "expected": "yes",
        "severity": "medium",
        "description": "Ensure /tmp is mounted nosuid",
        "comparator": "eq",
    },
    "CIS-4.1.3": {
        "setting": "audit_log_files",
        "expected": "yes",
        "severity": "medium",
        "description": "Ensure audit log files mode is 0640",
        "comparator": "eq",
    },
    "CIS-5.4.1": {
        "setting": "password_min_len",
        "expected": 12,
        "severity": "medium",
        "description": "Ensure password minimum length >= 12",
        "comparator": "ge",
    },
    "CIS-6.1.2": {
        "setting": "world_writable_files",
        "expected": "none",
        "severity": "high",
        "description": "Ensure no world-writable files",
        "comparator": "eq",
    },
    "CIS-5.4.2": {
        "setting": "password_max_days",
        "expected": 90,
        "severity": "low",
        "description": "Ensure password maximum age <= 90 days",
        "comparator": "le",
    },
    # -- SSH server hardening (expanded coverage) -----------------------------
    "CIS-6.2.2": {
        "setting": "sshd_password_authentication",
        "expected": "no",
        "severity": "high",
        "description": "Ensure SSH PasswordAuthentication is disabled",
        "comparator": "eq",
    },
    "CIS-6.2.3": {
        "setting": "sshd_max_auth_tries",
        "expected": 4,
        "severity": "medium",
        "description": "Ensure SSH MaxAuthTries is <= 4",
        "comparator": "le",
    },
    "CIS-6.2.4": {
        "setting": "sshd_login_grace_time",
        "expected": 60,
        "severity": "medium",
        "description": "Ensure SSH LoginGraceTime is <= 60 seconds",
        "comparator": "le",
    },
    "CIS-6.2.5": {
        "setting": "sshd_permit_empty_passwords",
        "expected": "no",
        "severity": "high",
        "description": "Ensure SSH PermitEmptyPasswords is disabled",
        "comparator": "eq",
    },
    "CIS-6.2.6": {
        "setting": "sshd_x11_forwarding",
        "expected": "no",
        "severity": "low",
        "description": "Ensure SSH X11Forwarding is disabled",
        "comparator": "eq",
    },
    # -- Password policy (expanded coverage) ---------------------------------
    "CIS-5.4.3": {
        "setting": "password_min_days",
        "expected": 1,
        "severity": "low",
        "description": "Ensure password minimum age >= 1 day",
        "comparator": "ge",
    },
    "CIS-5.4.4": {
        "setting": "password_warn_age",
        "expected": 7,
        "severity": "low",
        "description": "Ensure password warning period >= 7 days",
        "comparator": "ge",
    },
    # -- Audit / logging (expanded coverage) ---------------------------------
    "CIS-4.1.1": {
        "setting": "auditd_enabled",
        "expected": "yes",
        "severity": "high",
        "description": "Ensure auditing (auditd) is enabled",
        "comparator": "eq",
    },
    "CIS-4.1.2": {
        "setting": "audit_log_size",
        "expected": 100,
        "severity": "medium",
        "description": "Ensure audit log file size >= 100 MB",
        "comparator": "ge",
    },
    # -- sysctl network hardening --------------------------------------------
    "CIS-3.1.1": {
        "setting": "sysctl_ipv4_forwarding",
        "expected": 0,
        "severity": "high",
        "description": "Ensure IPv4 packet forwarding is disabled",
        "comparator": "eq",
    },
    "CIS-3.1.2": {
        "setting": "sysctl_ipv6_forwarding",
        "expected": 0,
        "severity": "medium",
        "description": "Ensure IPv6 packet forwarding is disabled",
        "comparator": "eq",
    },
    "CIS-3.2.1": {
        "setting": "sysctl_tcp_syncookies",
        "expected": 1,
        "severity": "medium",
        "description": "Ensure TCP SYN cookies are enabled",
        "comparator": "eq",
    },
    # -- /tmp mount options (expanded coverage) ------------------------------
    "CIS-1.1.3": {
        "setting": "tmp_nodev",
        "expected": "yes",
        "severity": "medium",
        "description": "Ensure /tmp is mounted nodev",
        "comparator": "eq",
    },
    "CIS-1.1.4": {
        "setting": "tmp_noexec",
        "expected": "yes",
        "severity": "medium",
        "description": "Ensure /tmp is mounted noexec",
        "comparator": "eq",
    },
}


def _compare(actual, expected: str, comparator: str) -> bool:
    """Return True if `actual` satisfies `expected` under the comparator.

    Comparators:
      "eq" -> string equality (default; coerces both sides to str)
      "ge" -> numeric: actual >= expected (password min length floor)
      "le" -> numeric: actual <= expected (password max age ceiling)

    Never raises: a non-numeric value against a numeric comparator is a fail
    (the control is not demonstrably in place).
    """
    if comparator == "eq":
        return str(actual) == str(expected)
    if comparator in ("ge", "le"):
        try:
            a = float(actual)
            e = float(expected)
        except (TypeError, ValueError):
            return False
        return a >= e if comparator == "ge" else a <= e
    # unknown comparator: be safe, fail
    return False


class CisCheckerWitness(Witness):
    """The CIS-style configuration witness on the configuration axis.

    Reads ``device["config"]`` (a dict of setting->value) and emits one
    configuration-axis ``Verdict`` per benchmark check, keyed by check id.
    Honest no-op when the device supplies no config (zero verdicts, complete,
    a reason string). Never crashes.
    """

    id = "cis_checker"
    axes = (Axis.CONFIGURATION,)
    bias = "false-safe"   # community/vendor checks may understate
    key_kind = "cis_check"  # emits CIS check ids -> the vocab monitor sees a known kind

    def __init__(self) -> None:
        super().__init__(id=self.id, axes=self.axes, bias=self.bias,
                         key_kind=self.key_kind)

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> WitnessResult:
        config = device.get("config")
        # No config snapshot -> honest no-op. Zero verdicts, complete=True, a
        # reason. The engine keeps the configuration axis UNKNOWN (loud), never
        # silently clean. A device that didn't supply a config simply has
        # nothing for this witness to say. Note: an empty dict {} IS a supplied
        # config (just an empty one) — every requested setting is missing -> all
        # fail (a missing control is not a pass). Only a missing/None/non-dict
        # config is the honest no-op.
        if config is None or not isinstance(config, dict):
            return WitnessResult(
                verdicts=[], complete=True,
                reason="no config supplied (device lacks a 'config' dict)",
            )

        # Which checks to run: device may restrict via cis_checks; default = all.
        requested = device.get("cis_checks")
        if requested:
            check_ids = [c for c in requested if c in CIS_BENCHMARK]
        else:
            check_ids = list(CIS_BENCHMARK.keys())

        verdicts: list[Verdict] = []
        for check_id in check_ids:
            spec = CIS_BENCHMARK[check_id]
            setting = spec["setting"]
            expected = spec["expected"]
            severity = spec["severity"]
            description = spec["description"]
            comparator = spec.get("comparator", "eq")
            raw_ref = f"cis:{check_id}"

            if setting not in config:
                # Missing-setting decision: FAIL. A control whose value the
                # device did not supply cannot be confirmed in place, so we
                # treat it as a fail (false-safe direction). The detail names
                # the missing setting explicitly so an operator can see it.
                verdicts.append(Verdict(
                    axis=Axis.CONFIGURATION.value,
                    key=check_id,
                    status="fail",
                    severity=severity,
                    detail=(f"{description} (config setting {setting!r} not "
                            f"supplied; expected {expected!r})"),
                    provenance=self._prov(complete=True, raw_ref=raw_ref),
                ))
                continue

            actual = config[setting]
            ok = _compare(actual, expected, comparator)
            verdicts.append(Verdict(
                axis=Axis.CONFIGURATION.value,
                key=check_id,
                status="pass" if ok else "fail",
                severity=severity,
                detail=(f"{description} (config {setting}={actual!r}, "
                        f"expected {expected!r} [{comparator}])"),
                provenance=self._prov(complete=True, raw_ref=raw_ref),
            ))

        return WitnessResult(
            verdicts=verdicts, complete=True,
            reason=f"cis benchmark: {len(verdicts)} check(s) evaluated",
        )