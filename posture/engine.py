"""The clean core — a source-agnostic, one-step-after-another posture engine.

This is the Forebode `refresh_device` shape generalized:

  Forebode:  matchers -> aggregate -> decide -> ordered overrides -> commit
  posture:   observers -> per-axis aggregate -> loud degradation -> commit

The differences that make it resilient:

  - AXES replace "device_cve". A observer speaks to one or more of the six
    stable axes; the engine reasons per-axis, not per-source.
  - OBSERVERS replace matchers, behind one uniform contract (observer.py). The
    engine never imports a source by name.
  - POLICY replaces hardcoded call order + filters. Which observers run, in
    what order, with what bias, is read from the versioned policy — so
    "who's authoritative" is a config edit, not a code hunt (Forebode's
    policy-as-code failure mode).
  - LOUD DEGRADATION: an axis with no observer, or no verdicts, is UNKNOWN and
    loud — NEVER silently "clean". An incomplete fetch degrades loudly AND
    preserves stored verdicts (no-wipe). "0 unpatched" never reads as
    "flawless" (project rule).
  - PROVENANCE is stamped on every verdict so trust can be unwound
    retroactively; health samples are recorded for the observer monitor.

The five steps of `assess(device)`:

  1. fan-out: gather policy-authorized observers per axis, in policy order
  2. observer: call assess() on each; time it; stamp provenance; record health
  3. per-axis aggregate: higher-order observer overrides lower (policy order)
  4. loud degradation: no/zero/incomplete -> UNKNOWN + preserve (no-wipe)
  5. commit: per-axis posture + verdicts through the completeness gate
"""

from __future__ import annotations
import datetime as _dt
import sqlite3
from dataclasses import dataclass, field

from .axis import Axis, AXES, AXIS_META
from .observer import Observer, ObserverResult, Verdict, ObserverRegistry
from . import policy as _policy_mod
from . import provenance as _prov
from . import health as _health
from . import store as _store
from . import glossary as _glossary
from . import vocab_monitor as _vocab


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class AxisPosture:
    axis: str
    status: str                  # clear | fail | exposed | unpatched | patched | unknown | ...
    deciding_observer: str | None
    bias: str | None
    verdicts: list[dict]
    gap: str | None              # None if healthy; else the loud reason
    complete: bool
    commit_state: str            # swapped | preserved-incomplete | preserved-empty | not-committed

    def to_dict(self) -> dict:
        return {
            "axis": self.axis,
            "status": self.status,
            "deciding_observer": self.deciding_observer,
            "bias": self.bias,
            "gap": self.gap,
            "complete": self.complete,
            "commit_state": self.commit_state,
            "verdict_count": len(self.verdicts),
            "verdicts": self.verdicts,
        }


@dataclass
class DevicePosture:
    device_id: str
    policy_version: str
    computed_at: str
    axes: list[AxisPosture]
    used_observers: list[str]
    overall: str                  # a coarse roll-up, never a "safety" claim

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "policy_version": self.policy_version,
            "computed_at": self.computed_at,
            "overall": self.overall,
            "used_observers": self.used_observers,
            "axes": [a.to_dict() for a in self.axes],
        }


def _status_for_empty_axis(axis: Axis) -> str:
    """The loud status an axis gets when it has no verdicts: UNKNOWN — never
    'clear'. A clean axis is not safety; the map is blank there, not green."""
    return "unknown"


def _roll_up(axis_postures: list[AxisPosture]) -> str:
    """A coarse overall label. DELIBERATELY not a 'safety' verdict — a clean
    posture is not invulnerability (the map is not the territory, and several
    axes are UNKNOWN)."""
    if any(a.status == "unknown" for a in axis_postures):
        return "incomplete (axis(es) unknown)"
    bad = {a.status for a in axis_postures if a.status not in {"clear", "pass",
            "closed", "patched", "trusted", "present"}}
    if not bad:
        return "no signal raised (map-relative)"
    return f"signal on: {','.join(sorted(bad))}"


# ---------------------------------------------------------------------------
# assess — the one entry point
# ---------------------------------------------------------------------------

def assess(
    device: dict,
    registry: ObserverRegistry,
    policy,
    conn: sqlite3.Connection | None = None,
    now: str | None = None,
) -> DevicePosture:
    """Assess one device across all six axes. Pure if conn is None (no commit);
    with conn, commits per-axis posture + verdicts through the no-wipe gate."""
    ts = now or _now()
    policy_version = policy.version
    device_id = device["id"]
    axis_postures: list[AxisPosture] = []
    used: list[str] = []

    # The dimensions of the event space come from the glossary (known axes),
    # not a hardcoded enum. With no store (pure mode) fall back to the seed.
    # The six are the seed, not the law — n is variable by construction.
    if conn is not None:
        _glossary.ensure_seeded(conn, now=ts)
        axes = _glossary.known_axes(conn)
    else:
        axes = list(AXES())

    for axis in axes:
        ap = _assess_axis(device, axis, registry, policy, conn,
                          policy_version, device_id, ts)
        if ap.deciding_observer and ap.deciding_observer not in used:
            used.append(ap.deciding_observer)
        axis_postures.append(ap)

    overall = _roll_up(axis_postures)

    if conn is not None:
        for ap in axis_postures:
            _store.upsert_axis_posture(
                conn, device_id, ap.axis, ap.status, ap.deciding_observer,
                ap.bias, ap.gap, policy_version, ts,
            )
        conn.commit()

    return DevicePosture(
        device_id=device_id, policy_version=policy_version,
        computed_at=ts, axes=axis_postures, used_observers=used,
        overall=overall,
    )


def _assess_axis(
    device: dict,
    axis,
    registry: ObserverRegistry,
    policy,
    conn: sqlite3.Connection | None,
    policy_version: str,
    device_id: str,
    ts: str,
) -> AxisPosture:
    axis_value = axis.value if isinstance(axis, Axis) else str(axis)
    observers = registry.for_axis(axis, policy)

    # Step 1 — loud degradation: no observer configured for this axis.
    if not observers:
        return AxisPosture(
            axis=axis_value, status="unknown", deciding_observer=None,
            bias=None, verdicts=[], gap="no observer configured for this axis",
            complete=True, commit_state="not-committed",
        )

    # Steps 2+3 — run each observer in authority order: LOWER order = HIGHER
    # authority, so the lowest-order observer runs LAST and overrides the others
    # on the same key. Track overall completeness (all observers must be
    # complete for the axis fetch to be considered complete, mirroring
    # Forebode's PRIMARY_MATCHERS all-complete gate).
    by_key: dict[str, dict] = {}      # key -> committed verdict dict
    deciding: dict[str, str] = {}      # key -> observer id that decided it
    deciding_bias: dict[str, str] = {}
    axis_complete = True
    axis_gap: str | None = None
    any_incomplete_reason: str | None = None

    for w in observers:
        result = _run_observer(w, device, policy, conn, axis, device_id, ts)
        if not result.complete:
            axis_complete = False
            any_incomplete_reason = result.reason or f"{w.id} incomplete"
        # emergent vocab scan: a observer emitting an UNKNOWN identifier kind is
        # auto-recorded as a candidate term (the map grows on its own). The
        # verdicts are still emitted and committed; nothing breaks.
        if conn is not None and getattr(w, "key_kind", None):
            _vocab.scan_emergent(conn, w.id, w.key_kind,
                                 [v.key for v in result.verdicts], now=ts)
        # later observers (lower order = higher authority) override earlier
        for v in result.verdicts:
            by_key[v.key] = v.to_dict() | {"_observer": w.id}
            deciding[v.key] = w.id
            deciding_bias[v.key] = policy.observer_bias(w.id, default=w.bias)

    verdict_dicts = list(by_key.values())

    # Step 4 — loud degradation: zero verdicts -> UNKNOWN (never clear), even
    # if complete. This is the "0 reads as flawless" guard. We do NOT early-
    # return here: a complete-but-empty fetch must still go through the commit
    # gate so existing rows are preserved and the state is reported honestly
    # as 'preserved-empty' (suspect false-absent), not silently wiped.
    if not verdict_dicts:
        status = "unknown"
        dec_w = None
        bias = None
        gap = ("incomplete: " + any_incomplete_reason) if any_incomplete_reason \
            else "no observer produced any signal (axis blank — not 'clean')"
    else:
        status = _axis_status(axis_value, verdict_dicts)
        dec_w = _deciding_observer_for_status(axis_value, verdict_dicts, deciding)
        bias = deciding_bias.get(next(iter(deciding))) if deciding else None
        gap = any_incomplete_reason

    # Step 5 — commit through the no-wipe gate. Incomplete -> preserve; complete
    # + zero against existing rows -> preserved-empty; complete + verdicts ->
    # swapped. Only commit when we have a store.
    commit_state = "not-committed"
    if conn is not None:
        commit_payload = [_to_commit_dict(v, policy_version, ts, axis_complete)
                           for v in verdict_dicts]
        commit_state = _store.commit_device_verdicts(
            conn, device_id, axis_value, commit_payload, axis_complete,
            policy_version, ts,
        )

    return AxisPosture(
        axis=axis_value, status=status, deciding_observer=dec_w, bias=bias,
        verdicts=verdict_dicts, gap=gap, complete=axis_complete,
        commit_state=commit_state,
    )


def _run_observer(w: Observer, device: dict, policy, conn, axis,
                 device_id: str, ts: str) -> ObserverResult:
    import time as _time
    axis_value = axis.value if isinstance(axis, Axis) else str(axis)
    t0 = _time.monotonic()
    try:
        result = w.assess(device, policy)
    except Exception as e:  # a observer crashing must never break the engine
        return ObserverResult(verdicts=[], complete=False,
                              reason=f"{w.id} raised {type(e).__name__}: {e}")
    latency_ms = int((_time.monotonic() - t0) * 1000)
    # stamp engine-controlled provenance on every verdict (the observer sets
    # its id + raw_ref; the engine fills policy_version/fetched_at/complete)
    stamped = _prov.stamp(result.verdicts, policy_version=policy.version,
                           fetched_at=ts, complete=result.complete)
    result.verdicts = stamped
    # record a health sample if we have a store
    if conn is not None:
        _health.record_sample(conn, w.id, device_id, axis_value,
                              result.complete, latency_ms, result.reason, ts)
    return result


def _to_commit_dict(v: dict, policy_version: str, ts: str, complete: bool) -> dict:
    """Take a verdict dict (already has provenance from stamp()) and ensure the
    provenance carries policy_version/fetched_at/complete for the store."""
    prov = v.get("provenance") or {}
    prov = {
        "observer": prov.get("observer") or v.get("_observer", ""),
        "policy_version": prov.get("policy_version") or policy_version,
        "fetched_at": prov.get("fetched_at") or ts,
        "complete": bool(prov.get("complete", complete)),
        "raw_ref": prov.get("raw_ref"),
    }
    out = dict(v)
    out.pop("_observer", None)
    out["provenance"] = prov
    return out


# Axis-appropriate "bad" statuses, in dominance order (worst first). A verdict
# in a worse bucket makes the axis that status.
_BAD_BY_AXIS: dict[str, list[str]] = {
    "vulnerability": ["unpatched", "not_affected", "patched"],
    "configuration": ["fail", "pass"],
    "exposure": ["exposed", "closed"],
    "inventory": ["absent", "present"],
    "threat": ["targeted", "clear"],
    "trust": ["untrusted", "trusted"],
}


def _axis_status(axis_value: str, verdicts: list[dict]) -> str:
    bad_order = _BAD_BY_AXIS.get(axis_value, [])
    present = {v["status"] for v in verdicts}
    for s in bad_order:
        if s in present:
            return s
    # any verdict status not in the known set -> report it as-is (loud)
    for v in verdicts:
        if v["status"] not in bad_order:
            return v["status"]
    return "unknown"


def _deciding_observer_for_status(axis_value: str, verdicts: list[dict],
                                  deciding: dict[str, str]) -> str | None:
    bad_order = _BAD_BY_AXIS.get(axis_value, [])
    for s in bad_order:
        for v in verdicts:
            if v["status"] == s:
                return deciding.get(v["key"]) or v.get("_observer")
    # fall back to the observer that decided the first verdict
    if verdicts:
        return deciding.get(verdicts[0]["key"]) or verdicts[0].get("_observer")
    return None