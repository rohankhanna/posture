"""Versioned trust policy — trust as data, not code.

"Who is authoritative, for what, in what order, with what bias, and what
fallback if they go silent" is a POLICY. In Forebode that policy lived as
call-order + filters inside a 974-line file — and that's exactly how a
missing lookup-table line silently disabled an overlay for weeks, and how
"only check the unknown-fix set" became a hidden filter (both bugs this
session). Here the policy is a dated, versioned YAML file with a changelog.
Changing trust = editing YAML + bumping the version = auditable. The engine
reads it; it never hardcodes trust.

The policy is the artifact the `source-alignment` repo is meant to produce
(re-evaluated against evidence on a cadence). This module is the consumer.
"""

from __future__ import annotations
import datetime as _dt
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .axis import Axis, is_axis


def _to_str(v: Any) -> str | None:
    """YAML parses bare dates (2026-08-01) as datetime.date; coerce to a string
    so policy fields stay plain strings."""
    if v is None:
        return None
    if isinstance(v, (_dt.date, _dt.datetime)):
        return v.isoformat()
    return str(v)

VALID_BIAS = {"false-alarm", "false-safe", "neutral"}
VALID_WEIGHT = {"none", "low", "medium", "high"}
_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.\d+$")


class PolicyError(ValueError):
    pass


@dataclass
class WitnessPolicy:
    id: str
    axes: tuple[str, ...]
    weight: str = "medium"
    bias: str = "neutral"
    order: int = 10
    conditions: list[str] = field(default_factory=list)


@dataclass
class DegradationRule:
    witness: str
    if_silent_for_days: int
    fallback: list[str] = field(default_factory=list)


@dataclass
class SpinePolicy:
    primary_key: str = "cve"
    role: str = "vulnerability_join_key"   # resolved via the glossary (rebindable)
    crosswalk: list[tuple[str, str]] = field(default_factory=list)  # (kind_a, kind_b)


@dataclass
class Policy:
    """A loaded, validated trust policy."""
    version: str
    supersedes: str | None
    dated: str
    rationale: str
    witnesses: dict[str, WitnessPolicy]
    degradation: dict[str, DegradationRule]
    spine: SpinePolicy
    raw_yaml: str = ""

    # -- accessors the engine/registry use ----------------------------------

    def has_witness(self, wid: str) -> bool:
        return wid in self.witnesses

    def witness_order(self, wid: str) -> int:
        wp = self.witnesses.get(wid)
        return wp.order if wp else 10**9  # unknown witnesses sort last

    def witness_bias(self, wid: str, default: str = "neutral") -> str:
        wp = self.witnesses.get(wid)
        return wp.bias if wp else default

    def witness_weight(self, wid: str) -> str:
        wp = self.witnesses.get(wid)
        return wp.weight if wp else "none"

    def witnesses_for_axis(self, axis: str) -> list[WitnessPolicy]:
        return [wp for wp in self.witnesses.values() if axis in wp.axes]

    def degradation_for(self, wid: str) -> DegradationRule | None:
        return self.degradation.get(wid)

    # -- loading ------------------------------------------------------------

    @classmethod
    def from_yaml(cls, text: str) -> "Policy":
        data = yaml.safe_load(text) or {}
        return cls._build(data, raw_yaml=text)

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        p = Path(path)
        return cls.from_yaml(p.read_text())

    @classmethod
    def _build(cls, data: dict, raw_yaml: str) -> "Policy":
        version = _to_str(data.get("version"))
        if not version or not _VERSION_RE.match(version):
            raise PolicyError(
                f"policy.version must match YYYY-MM-DD.N (got {version!r})"
            )
        supersedes = _to_str(data.get("supersedes"))
        dated = _to_str(data.get("dated"))
        if not dated:
            raise PolicyError("policy.dated is required (YYYY-MM-DD)")
        rationale = data.get("rationale", "") or ""

        witnesses: dict[str, WitnessPolicy] = {}
        for wid, cfg in (data.get("witnesses") or {}).items():
            if not isinstance(cfg, dict):
                raise PolicyError(f"witness {wid!r}: config must be a mapping")
            axes = cfg.get("axes") or []
            if not isinstance(axes, list) or not axes:
                raise PolicyError(f"witness {wid!r}: needs a non-empty axes list")
            for a in axes:
                if not is_axis(a):
                    raise PolicyError(
                        f"witness {wid!r}: unknown axis {a!r} (known: "
                        f"{[x.value for x in Axis]})"
                    )
            weight = cfg.get("weight", "medium")
            if weight not in VALID_WEIGHT:
                raise PolicyError(f"witness {wid!r}: bad weight {weight!r}")
            bias = cfg.get("bias", "neutral")
            if bias not in VALID_BIAS:
                raise PolicyError(
                    f"witness {wid!r}: bad bias {bias!r} (use {sorted(VALID_BIAS)})"
                )
            order = int(cfg.get("order", 10))
            conditions = list(cfg.get("conditions") or [])
            witnesses[wid] = WitnessPolicy(
                id=wid, axes=tuple(axes), weight=weight, bias=bias,
                order=order, conditions=conditions,
            )

        degradation: dict[str, DegradationRule] = {}
        for wid, cfg in (data.get("degradation") or {}).items():
            if not isinstance(cfg, dict):
                raise PolicyError(f"degradation {wid!r}: must be a mapping")
            days = int(cfg.get("if_silent_for_days", 0))
            fallback = list(cfg.get("fallback") or [])
            degradation[wid] = DegradationRule(witness=wid, if_silent_for_days=days,
                                              fallback=fallback)

        spine_cfg = data.get("spine") or {}
        spine = SpinePolicy(
            primary_key=spine_cfg.get("primary_key", "cve"),
            role=spine_cfg.get("role", "vulnerability_join_key"),
            crosswalk=[tuple(pair) for pair in spine_cfg.get("crosswalk", [])],
        )

        return cls(
            version=version, supersedes=supersedes, dated=dated,
            rationale=rationale, witnesses=witnesses, degradation=degradation,
            spine=spine, raw_yaml=raw_yaml,
        )

    def to_summary(self) -> dict:
        return {
            "version": self.version,
            "supersedes": self.supersedes,
            "dated": self.dated,
            "rationale": self.rationale,
            "witnesses": {
                wid: {"axes": list(wp.axes), "weight": wp.weight, "bias": wp.bias,
                      "order": wp.order, "conditions": wp.conditions}
                for wid, wp in self.witnesses.items()
            },
            "degradation": {
                wid: {"if_silent_for_days": d.if_silent_for_days,
                      "fallback": d.fallback}
                for wid, d in self.degradation.items()
            },
            "spine": {"primary_key": self.spine.primary_key,
                      "role": self.spine.role,
                      "crosswalk": [list(p) for p in self.spine.crosswalk]},
        }


def default_policy_path() -> Path:
    return Path(__file__).resolve().parent / "policy" / "policy.yaml"