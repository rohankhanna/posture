"""Source-health as a living thing — the witness monitor.

The trust in the spine (and every other witness) is a moving target, not a
one-time decision. This subsystem watches the WITNESSES, not the
vulnerabilities. Three signal types, mirroring the `source-alignment`
rubric:

  1. Operational health — MEASURED continuously by posture itself, from each
     fetch (completeness, latency, reason). A source that starts 504-ing more,
     or whose freshness lags (NVD enrichment falling behind = a funding
     symptom), is a measured early warning. The 2024 NVD backlog would have
     shown up here as "enrichment lag growing" weeks before the press noticed.
  2. Funding/governance/capture dossier — GATHERED + CITED, dated, human or
     LLM-assisted. Public record: NIST/MITRE appropriations, CISA contract
     renewals, FIRST.org reports, vendor earnings/acquisitions. The LLM
     gathers; the citation does the trusting.
  3. Drift — a source's verdict distribution shifting over time is a capture
     signal (the disagreement-map technique: sources that used to disagree
     suddenly converging, or one drifting vs the others). Skeleton stores
     per-witness distribution snapshots and flags movement; full statistics is
     an extension point with a clear interface.

Plus: pre-declared degradation/fallback decided from the policy BEFORE a
crisis, evaluated against operational freshness.
"""

from __future__ import annotations
import sqlite3
from dataclasses import dataclass
from typing import Iterable


@dataclass
class OperationalHealth:
    witness: str
    samples: int
    success_rate: float          # fraction of recent samples with complete=True
    mean_latency_ms: float
    last_complete_at: str | None  # freshness
    last_reason: str             # reason from the most recent sample


def record_sample(conn, witness: str, device_id: str, axis: str,
                  complete: bool, latency_ms: int, reason: str,
                  fetched_at: str) -> None:
    from . import store as _store
    _store.record_health_sample(conn, witness, device_id, axis, complete,
                                 latency_ms, reason, fetched_at)


def operational_health(conn, witness: str, window: int = 50) -> OperationalHealth:
    from . import store as _store
    samples = _store.health_samples(conn, witness, limit=window)
    n = len(samples)
    if n == 0:
        return OperationalHealth(witness=witness, samples=0, success_rate=0.0,
                                  mean_latency_ms=0.0, last_complete_at=None,
                                  last_reason="no samples yet")
    complete = sum(1 for s in samples if s["complete"])
    lat = [s["latency_ms"] or 0 for s in samples]
    last_complete = _store.last_complete_sample(conn, witness)
    last = samples[0]  # most recent (samples ordered DESC)
    return OperationalHealth(
        witness=witness, samples=n,
        success_rate=complete / n,
        mean_latency_ms=sum(lat) / n,
        last_complete_at=last_complete["fetched_at"] if last_complete else None,
        last_reason=last["reason"] or "",
    )


def add_dossier_entry(conn, witness: str, date: str, axis: str, claim: str,
                       citation: str, direction: str) -> None:
    if direction not in {"false-alarm", "false-safe", "neutral", "capture",
                         "funding", "governance", "other"}:
        raise ValueError(f"bad direction {direction!r}")
    from . import store as _store
    _store.add_dossier_entry(conn, witness, date, axis, claim, citation, direction)


def dossier(conn, witness: str) -> list[dict]:
    from . import store as _store
    return _store.dossier(conn, witness)


def degradation_action(conn, witness: str, policy, now_iso: str) -> str:
    """Decide the witness's state from the policy's pre-declared degradation
    rule + measured freshness. Returns 'ok' | 'fallback' | 'offline'.

    Decided from policy (the rule was written BEFORE a crisis), not ad-hoc:
      - 'ok'        — fetched completely within the silence window.
      - 'fallback'  — silent longer than if_silent_for_days; policy.fallback
                       lists alternates to consult.
      - 'offline'   — silent with no declared fallback.
    """
    rule = policy.degradation_for(witness)
    if rule is None or rule.if_silent_for_days <= 0:
        return "ok"
    from . import store as _store
    import datetime as _dt
    last = _store.last_complete_sample(conn, witness)
    if not last:
        # No successful fetch ever recorded. If the witness has any samples,
        # they were all incomplete -> treat as failing its window.
        samples = _store.health_samples(conn, witness, limit=1)
        if not samples:
            return "ok"  # never tried; not yet degraded
        return "fallback" if rule.fallback else "offline"
    last_ts = _dt.datetime.fromisoformat(last["fetched_at"].replace("Z", "+00:00"))
    now = _dt.datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    age_days = (now - last_ts).days
    if age_days <= rule.if_silent_for_days:
        return "ok"
    return "fallback" if rule.fallback else "offline"


def health_report(conn, witness: str, policy, now_iso: str) -> dict:
    op = operational_health(conn, witness)
    return {
        "witness": witness,
        "operational": {
            "samples": op.samples,
            "success_rate": round(op.success_rate, 3),
            "mean_latency_ms": round(op.mean_latency_ms, 1),
            "last_complete_at": op.last_complete_at,
            "last_reason": op.last_reason,
        },
        "dossier": dossier(conn, witness),
        "degradation": degradation_action(conn, witness, policy, now_iso),
        "policy_degradation": _rule_view(policy, witness),
    }


def _rule_view(policy, witness: str) -> dict | None:
    r = policy.degradation_for(witness)
    if not r:
        return None
    return {"if_silent_for_days": r.if_silent_for_days, "fallback": r.fallback}


# ---------------------------------------------------------------------------
# Drift — verdict-distribution snapshot + movement flag (skeleton)
# ---------------------------------------------------------------------------

def record_distribution_snapshot(conn, witness: str, device_id: str,
                                 axis: str, verdicts: Iterable[dict],
                                 ts: str) -> None:
    """Store a compact status-count snapshot for a witness's verdicts on a
    device/axis. Used by drift_flag to detect distribution shifts over time.

    Stored in the health_dossier table with direction='drift-snapshot' and a
    JSON-encoded claim so it rides on existing infrastructure. Full
    statistical drift (KL-divergence etc.) is an extension point; the interface
    is what matters here.
    """
    import json as _json
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v.get("status", "?")] = counts.get(v.get("status", "?"), 0) + 1
    claim = _json.dumps({"device": device_id, "axis": axis, "counts": counts},
                        sort_keys=True)
    add_dossier_entry(conn, witness, ts[:10], axis, claim,
                      "(internal snapshot)", "other")


def drift_flag(conn, witness: str) -> str:
    """Skeleton drift detector: compare the two most recent snapshot claims.
    Returns 'stable' | 'shifted' | 'insufficient'. A real implementation would
    use a statistical test; this flags any change in the status-count dict as
    a shift — a deliberately conservative signal that something moved."""
    entries = [e for e in dossier(conn, witness)
               if e["direction"] == "other" and e["citation"] == "(internal snapshot)"]
    if len(entries) < 2:
        return "insufficient"
    if entries[0]["claim"] != entries[1]["claim"]:
        return "shifted"
    return "stable"