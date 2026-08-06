"""Self-repair — the system noticing its own drift and raising a flag.

Two kinds of repair:

  - **AUTO repairs** (already in the engine/store/policy; not handled here):
    no-wipe preservation, graceful-unknown, fallback per `policy.degradation`.
    These run on every assess and touch no trust.

  - **TRUST repairs** (raised here, applied by a human): when a source drifts
    silent, when the policy goes stale, or when a distrusted witness is still
    policy-authorized. `reconcile()` produces versioned `RepairProposal`s;
    `apply()` marks the human-approved one handled. The system never applies a
    trust repair on its own.

(The old CVE-replacement / spine-rebind course-correction has been retired: the
spine is the alias↔alias graph now, not a rebindable join key. Deprecated-term
handling for the remaining roles lives in the glossary's `resolve_role`, which
follows a deprecated term to its known successor automatically.)
"""

from __future__ import annotations
import datetime as _dt
import sqlite3
from dataclasses import dataclass, field


@dataclass
class RepairProposal:
    id: str
    kind: str            # source_drifted | stale_policy | orphan_distrusted
    detail: str
    proposed_action: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    raised_at: str = ""
    status: str = "open"

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "detail": self.detail,
                "proposed_action": self.proposed_action,
                "evidence": self.evidence, "raised_at": self.raised_at,
                "status": self.status}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


# policy review cadence (days) before a stale-policy proposal is raised
STALE_POLICY_DAYS = 90


def reconcile(conn: sqlite3.Connection, policy, now_iso: str | None = None) -> list[RepairProposal]:
    """Scan the system state for drift and raise proposals. AUTO to raise;
    HUMAN to apply any that touch trust. Returns open+new proposals (does not
    re-raise ones already stored)."""
    from . import glossary as _glossary
    from . import store as _store
    from . import health as _health
    ts = now_iso or _now()
    existing = {p["id"] for p in _store.all_repair_proposals(conn)}
    props: list[RepairProposal] = []

    # 1. a policy-authorized witness has drifted silent -> propose re-evaluate.
    for wid, wp in policy.witnesses.items():
        deg = _health.degradation_action(conn, wid, policy, ts)
        if deg in {"fallback", "offline"}:
            pid = f"source_drifted:{wid}"
            if pid not in existing:
                props.append(RepairProposal(
                    id=pid, kind="source_drifted",
                    detail=f"witness {wid!r} is {deg} (silent past its "
                           f"degradation window)",
                    proposed_action={"re_evaluate": wid,
                                     "fallback": policy.degradation_for(wid).fallback
                                     if policy.degradation_for(wid) else []},
                    evidence={"witness": wid, "state": deg},
                    raised_at=ts,
                ))

    # 2. stale policy (older than the review cadence) -> propose re-evaluate.
    try:
        dated = _dt.date.fromisoformat(policy.dated[:10])
        age = (_dt.date.fromisoformat(ts[:10]) - dated).days
    except Exception:
        age = 0
    if age > STALE_POLICY_DAYS:
        pid = "stale_policy"
        if pid not in existing:
            props.append(RepairProposal(
                id=pid, kind="stale_policy",
                detail=f"policy version {policy.version!r} is {age} days old "
                       f"(> {STALE_POLICY_DAYS}); re-evaluate against evidence",
                proposed_action={"re_evaluate_policy": policy.version},
                evidence={"policy_version": policy.version, "age_days": age},
                raised_at=ts,
            ))

    # 3. a distrusted witness still policy-authorized -> propose removal.
    for m in _store.distrust_marks(conn):
        if policy.has_witness(m["witness"]):
            pid = f"orphan_distrusted:{m['witness']}"
            if pid not in existing:
                props.append(RepairProposal(
                    id=pid, kind="orphan_distrusted",
                    detail=f"witness {m['witness']!r} is distrusted but still "
                           f"policy-authorized",
                    proposed_action={"remove_from_policy": m["witness"]},
                    evidence={"witness": m["witness"], "reason": m["reason"]},
                    raised_at=ts,
                ))

    # persist new proposals
    for p in props:
        _store.upsert_repair_proposal(conn, p.id, p.kind, p.detail,
                                      p.proposed_action, p.evidence, p.raised_at)
    return props


def apply(conn: sqlite3.Connection, proposal_id: str, actor: str = "human",
          version: str = "", now: str | None = None) -> dict:
    """HUMAN-gated: mark a trust repair applied. All remaining proposals
    (source_drifted / stale_policy / orphan_distrusted) are advisory — the
    operator handles them out of band (re-evaluate the source, refresh the
    policy, remove the witness) and this just records the decision. Returns a
    summary. No-wipe throughout (the alias graph preserves joins)."""
    from . import store as _store
    ts = now or _now()
    p = _store.repair_proposal(conn, proposal_id)
    if p is None:
        raise KeyError(f"unknown proposal: {proposal_id}")
    if p["status"] == "applied":
        return {"id": proposal_id, "already": "applied"}
    summary: dict = {"id": proposal_id, "kind": p["kind"], "done": ["advisory (marked applied)"]}
    _store.set_repair_proposal_status(conn, proposal_id, "applied")
    return summary


def list_open(conn: sqlite3.Connection) -> list[dict]:
    from . import store as _store
    return _store.all_repair_proposals(conn, status="open")


def dismiss(conn: sqlite3.Connection, proposal_id: str) -> None:
    from . import store as _store
    _store.set_repair_proposal_status(conn, proposal_id, "dismissed")