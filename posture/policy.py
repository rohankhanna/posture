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

# Source-history ledger is trust-policy-adjacent: source reliability is an
# engine-level concern, so the policy consumes the public-infrastructure event
# ledger (see posture/source_history.py). The ledger is data; the policy is
# the consumer. The seam is the ledger event's interpretation field — it
# carries posture's read of what an upstream event means, and the degradation
# signal below surfaces it next to the pre-declared fallback rule.
from .source_history import (
    EventLedger,
    EVENT_DEGRADATION,
    EVENT_OUTAGE,
)

# Observer ids in the policy need not equal the ledger's source ids. This
# alias map is the canonical bridge: where they differ, the policy observer id
# maps to the ledger source id. Unlisted observers use their own id as the
# source id (so nvd -> nvd; only mitre_cve -> mitre differs
# today). Append-only: add an alias when a new observer/ledger-source mismatch
# is introduced, never rewrite an existing one.
OBSERVER_SOURCE_ALIASES: dict[str, str] = {
    "mitre_cve": "mitre",
}


def observer_source_id(observer_id: str) -> str:
    """Map a policy observer id to the ledger's canonical source id."""
    return OBSERVER_SOURCE_ALIASES.get(observer_id, observer_id)


# Ledger event types that mean the source's *output* is currently degraded —
# not merely an operational condition posture has engineered around. A
# degradation event (coverage/quality lost) or an outage (source
# unreachable) means a freshly-fetched verdict still comes from a degraded
# source, so the pre-declared fallback rule should engage regardless of
# measured freshness. Other event types (rate-limit, feed-relocated,
# format-change, data-correction, policy-change) are surfaced in the signal as
# context — posture has adapted to them per their interpretation — but they
# do not by themselves force the fallback action.
DEGRADING_EVENT_TYPES = frozenset({EVENT_DEGRADATION, EVENT_OUTAGE})


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
class ObserverPolicy:
    id: str
    axes: tuple[str, ...]
    weight: str = "medium"
    bias: str = "neutral"
    order: int = 10
    conditions: list[str] = field(default_factory=list)


@dataclass
class DegradationRule:
    observer: str
    if_silent_for_days: int
    fallback: list[str] = field(default_factory=list)


@dataclass
class DegradationSignal:
    """The source-reliability signal for one observer, read from the ledger.

    The ledger's interpretation field is the seam: it carries posture's
    read of what each active upstream event means for this source. This
    dataclass surfaces that read next to the pre-declared degradation rule so
    the fallback decision and the health report can consume it. degraded
    is True iff at least one *active* event of a degrading type
    (degradation/outage) is recorded for the observer's source — i.e. the
    source's output is currently degraded even when freshly fetched.
    """
    observer: str
    source: str
    degraded: bool
    active_events: list[dict] = field(default_factory=list)
    interpretation: str = ""

    def to_dict(self) -> dict:
        return {
            "observer": self.observer,
            "source": self.source,
            "degraded": self.degraded,
            "active_events": list(self.active_events),
            "interpretation": self.interpretation,
        }


@dataclass
class SpinePolicy:
    # The spine is the alias↔alias graph (see spine.py) — there is no single
    # primary join key and no rebindable role. `crosswalk` is advisory only: the
    # alias-kind pairs the operator declares they maintain (e.g. [(cve,ghsa),
    # (cve,usn)]). It documents intent; the engine resolves aliases from the
    # crosswalk graph itself, not from this list.
    crosswalk: list[tuple[str, str]] = field(default_factory=list)  # (kind_a, kind_b)


@dataclass
class Policy:
    """A loaded, validated trust policy."""
    version: str
    supersedes: str | None
    dated: str
    rationale: str
    observers: dict[str, ObserverPolicy]
    degradation: dict[str, DegradationRule]
    spine: SpinePolicy
    raw_yaml: str = ""

    # -- accessors the engine/registry use ----------------------------------

    def has_observer(self, wid: str) -> bool:
        return wid in self.observers

    def observer_order(self, wid: str) -> int:
        wp = self.observers.get(wid)
        return wp.order if wp else 10**9  # unknown observers sort last

    def observer_bias(self, wid: str, default: str = "neutral") -> str:
        wp = self.observers.get(wid)
        return wp.bias if wp else default

    def observer_weight(self, wid: str) -> str:
        wp = self.observers.get(wid)
        return wp.weight if wp else "none"

    def observers_for_axis(self, axis: str) -> list[ObserverPolicy]:
        return [wp for wp in self.observers.values() if axis in wp.axes]

    def degradation_for(self, wid: str) -> DegradationRule | None:
        return self.degradation.get(wid)

    def degradation_signal(self, observer: str, ledger: EventLedger | None) -> DegradationSignal:
        """Read the source-reliability signal for observer from ledger.

        Returns a :class:`DegradationSignal` carrying the active source-history
        events for the observer's source and the combined interpretation
        text (the seam). When ledger is None or carries no active events
        for the source, the signal is empty and degraded is False — the
        fallback decision then rests solely on measured freshness, as before.
        Only *active* events of a degrading type (degradation/outage) set
        degraded; other active events are surfaced as context.
        """
        obs = observer
        src = observer_source_id(obs)
        if ledger is None:
            return DegradationSignal(observer=obs, source=src, degraded=False)
        active = [
            {
                "id": e.id,
                "date": e.date,
                "event_type": e.event_type,
                "summary": e.summary,
                "status": e.status,
                "interpretation": e.interpretation,
            }
            for e in ledger.active() if e.source == src
        ]
        degraded = any(e["event_type"] in DEGRADING_EVENT_TYPES for e in active)
        interpretation = " | ".join(
            e["interpretation"] for e in active if e["interpretation"]
        )
        return DegradationSignal(
            observer=obs, source=src, degraded=degraded,
            active_events=active, interpretation=interpretation,
        )

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

        observers: dict[str, ObserverPolicy] = {}
        for wid, cfg in (data.get("observers") or {}).items():
            if not isinstance(cfg, dict):
                raise PolicyError(f"observer {wid!r}: config must be a mapping")
            axes = cfg.get("axes") or []
            if not isinstance(axes, list) or not axes:
                raise PolicyError(f"observer {wid!r}: needs a non-empty axes list")
            for a in axes:
                if not is_axis(a):
                    raise PolicyError(
                        f"observer {wid!r}: unknown axis {a!r} (known: "
                        f"{[x.value for x in Axis]})"
                    )
            weight = cfg.get("weight", "medium")
            if weight not in VALID_WEIGHT:
                raise PolicyError(f"observer {wid!r}: bad weight {weight!r}")
            bias = cfg.get("bias", "neutral")
            if bias not in VALID_BIAS:
                raise PolicyError(
                    f"observer {wid!r}: bad bias {bias!r} (use {sorted(VALID_BIAS)})"
                )
            order = int(cfg.get("order", 10))
            conditions = list(cfg.get("conditions") or [])
            observers[wid] = ObserverPolicy(
                id=wid, axes=tuple(axes), weight=weight, bias=bias,
                order=order, conditions=conditions,
            )

        degradation: dict[str, DegradationRule] = {}
        for wid, cfg in (data.get("degradation") or {}).items():
            if not isinstance(cfg, dict):
                raise PolicyError(f"degradation {wid!r}: must be a mapping")
            days = int(cfg.get("if_silent_for_days", 0))
            fallback = list(cfg.get("fallback") or [])
            degradation[wid] = DegradationRule(observer=wid, if_silent_for_days=days,
                                              fallback=fallback)

        spine_cfg = data.get("spine") or {}
        # legacy `primary_key`/`role` keys (the retired swappable-spine fields)
        # are tolerated if present in older policy YAML but ignored — the spine
        # is the alias graph now, not a rebindable word.
        spine = SpinePolicy(
            crosswalk=[tuple(pair) for pair in spine_cfg.get("crosswalk", [])],
        )

        return cls(
            version=version, supersedes=supersedes, dated=dated,
            rationale=rationale, observers=observers, degradation=degradation,
            spine=spine, raw_yaml=raw_yaml,
        )

    def to_summary(self) -> dict:
        return {
            "version": self.version,
            "supersedes": self.supersedes,
            "dated": self.dated,
            "rationale": self.rationale,
            "observers": {
                wid: {"axes": list(wp.axes), "weight": wp.weight, "bias": wp.bias,
                      "order": wp.order, "conditions": wp.conditions}
                for wid, wp in self.observers.items()
            },
            "degradation": {
                wid: {"if_silent_for_days": d.if_silent_for_days,
                      "fallback": d.fallback}
                for wid, d in self.degradation.items()
            },
            "spine": {"crosswalk": [list(p) for p in self.spine.crosswalk]},
        }


def default_policy_path() -> Path:
    return Path(__file__).resolve().parent / "policy" / "policy.yaml"