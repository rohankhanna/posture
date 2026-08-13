"""Provenance stamping + retroactive distrust.

Every stored verdict carries full Provenance (who said it, under which policy
version, when, how completely, and a citable reference). This is the
mechanism that lets trust be UNWOUND: when a source is later found captured
or defunded, `audit(observer)` lists every verdict that rests on it, and
`distrust(observer, reason)` MARKS them (never silently deletes) so they can be
re-evaluated. You keep the record that you no longer trust it — auditable.

This is the concrete answer to "keep an eye on the funding/capture risk of
the sources": you can't trust-and-forget; you must be able to ask, later, what
a source ever told you and whether it still holds.
"""

from __future__ import annotations
import sqlite3

from .observer import Provenance, Verdict


def stamp(verdicts: list[Verdict], policy_version: str, fetched_at: str,
          complete: bool) -> list[Verdict]:
    """Fill in the engine-controlled provenance fields on a batch of verdicts
    (policy_version, fetched_at, complete). Observer + raw_ref are already set
    by the observer; complete reflects the underlying fetch completeness."""
    out: list[Verdict] = []
    for v in verdicts:
        if v.provenance is None:
            v = Verdict(axis=v.axis, key=v.key, status=v.status, detail=v.detail,
                        severity=v.severity, fixed_in=v.fixed_in,
                        provenance=Provenance(observer="", policy_version=policy_version,
                                              fetched_at=fetched_at, complete=complete))
        else:
            p = v.provenance
            v = Verdict(
                axis=v.axis, key=v.key, status=v.status, detail=v.detail,
                severity=v.severity, fixed_in=v.fixed_in,
                provenance=Provenance(
                    observer=p.observer,
                    policy_version=policy_version or p.policy_version,
                    fetched_at=fetched_at or p.fetched_at,
                    complete=complete if not p.complete else p.complete,
                    raw_ref=p.raw_ref,
                ),
            )
        out.append(v)
    return out


def audit(conn: sqlite3.Connection, observer: str) -> list[dict]:
    """All stored verdicts whose provenance rests on `observer`."""
    from . import store as _store
    return _store.audit_observer(conn, observer)


def distrust(conn: sqlite3.Connection, observer: str, reason: str) -> int:
    """Mark (not delete) every verdict resting on `observer` as distrusted.
    Returns the count of newly-marked verdicts."""
    from . import store as _store
    return _store.mark_distrust(conn, observer, reason)


def distrust_log(conn: sqlite3.Connection) -> list[dict]:
    from . import store as _store
    return _store.distrust_marks(conn)


def verdicts_to_commit_dicts(verdicts: list[Verdict]) -> list[dict]:
    """Convert Verdict objects to the dict shape store.commit_device_verdicts
    expects (each carrying a 'provenance' sub-dict)."""
    out: list[dict] = []
    for v in verdicts:
        d = v.to_dict()
        prov = v.provenance
        d["provenance"] = (prov.to_dict() if prov else
                           {"observer": "", "policy_version": "", "fetched_at": "",
                            "complete": False, "raw_ref": None})
        out.append(d)
    return out