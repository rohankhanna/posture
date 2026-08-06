"""The six axes — the stable body of the posture map.

The single most important design fact in this package: **axes are stable,
sources churn**. The system reasons about axes; a source is one *witness* to
an axis. When a source is captured, defunded, or superseded, you swap the
witness; the axis and its verdict logic stay.

The six axes are the categories of posture signal a real security pillar
tracks. CVEs (the spine) feed exactly one of them (vulnerability); the other
five are the territory a CVE-only tool is blind to — misconfiguration, network
exposure, what's installed, what's being attacked, and whether you can trust
what you installed.

A clean axis is NEVER read as "flawless". An axis with no witness is UNKNOWN
and loud, not silent/clean. (See engine.py's loud-degradation rule.)
"""

from __future__ import annotations
from enum import StrEnum
from typing import Iterator


class Axis(StrEnum):
    """The six stable posture axes. StrEnum so an axis serializes as its string
    value in policy YAML, the store, and CLI output."""

    VULNERABILITY = "vulnerability"   # what's broken      — CVE spine (REAL today)
    CONFIGURATION = "configuration"   # what's misconfigured — CIS/STIG (stub)
    EXPOSURE = "exposure"             # what's reachable    — Shodan/local (stub)
    INVENTORY = "inventory"            # what's installed    — SBOM (stub)
    THREAT = "threat"                  # what's being attacked — KEV/IOC (stub)
    TRUST = "trust"                    # can you trust what's installed — SLSA/Sigstore (stub)


# Metadata: one-line plain-English meaning + the kind of "key" each axis's
# verdicts are keyed by (the join key within the axis).
AXIS_META: dict[Axis, dict[str, str]] = {
    Axis.VULNERABILITY: {
        "desc": "Known flaws (CVEs + advisories).",
        "key_kind": "cve id (the spine)",
        "status_set": "unpatched | patched | not_affected | unknown",
    },
    Axis.CONFIGURATION: {
        "desc": "Misconfiguration (open SSH, default creds, world-readable keys).",
        "key_kind": "check id (e.g. CIS-1.1.1)",
        "status_set": "fail | pass | unknown",
    },
    Axis.EXPOSURE: {
        "desc": "Network reachability (is this service on the open internet).",
        "key_kind": "port / service id",
        "status_set": "exposed | closed | unknown",
    },
    Axis.INVENTORY: {
        "desc": "What is installed (the SBOM — the measured floor under everything).",
        "key_kind": "package name + version",
        "status_set": "present | absent | unknown",
    },
    Axis.THREAT: {
        "desc": "What is being exploited in the wild (KEV / IOC).",
        "key_kind": "indicator / cve id",
        "status_set": "targeted | clear | unknown",
    },
    Axis.TRUST: {
        "desc": "Can you trust what's installed (provenance / signatures / SLSA).",
        "key_kind": "artifact id",
        "status_set": "untrusted | trusted | unknown",
    },
}


def AXES() -> tuple[Axis, ...]:
    """The full axis set, in canonical order."""
    return tuple(Axis)


def all_axis_values() -> Iterator[str]:
    return (a.value for a in Axis)


def is_axis(s: str) -> bool:
    try:
        Axis(s)
        return True
    except ValueError:
        return False