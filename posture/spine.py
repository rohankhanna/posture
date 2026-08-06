"""The join-key spine + crosswalk.

CVE is the spine today: it's the universal join key that lets you ask several
sources about the same flaw. But the spine already nearly broke once — MITRE's
CVE-numbering contract almost lapsed in April 2024. So the spine is kept
*redundant*: a crosswalk table maps a cve id to its aliases in other schemes
(ghsa, usn, dsa, rhsa, apsb, osv_id). If CVE numbering stalls, joins still
resolve via aliases. The crosswalk is built before it's needed — you maintain
it while CVE is healthy so it's muscle memory when it isn't.

This module is the thin store-backed API; the heavy lifting (joining across
witnesses by alias) lives in the engine.
"""

from __future__ import annotations
import sqlite3


def register(conn: sqlite3.Connection, cve: str, alias: str, kind: str) -> None:
    """Record that `cve` is also known as `alias` under scheme `kind`
    (ghsa/usn/dsa/rhsa/apsb/osv_id). Idempotent."""
    from . import store as _store
    _store.add_crosswalk(conn, cve, alias, kind)


def resolve(conn: sqlite3.Connection, cve: str) -> list[dict]:
    """All known aliases of a cve id (each {alias, kind})."""
    from . import store as _store
    return _store.resolve_crosswalk(conn, cve)


def reverse_resolve(conn: sqlite3.Connection, alias: str) -> list[dict]:
    """All cve ids known to share this alias (each {cve, kind})."""
    from . import store as _store
    return _store.reverse_crosswalk(conn, alias)


def primary_key(policy, conn: sqlite3.Connection | None = None) -> str:
    """The configured spine primary join key (today: 'cve').

    Resolved by ROLE via the glossary when a connection is available
    (vulnerability_join_key -> the term currently filling it, rebindable). With
    no connection (pure mode) it falls back to the policy's literal
    `spine.primary_key` — so callers without a store still get 'cve'.
    """
    if conn is not None:
        from . import glossary as _glossary
        role = getattr(policy.spine, "role", None) or "vulnerability_join_key"
        term = _glossary.resolve_role(conn, role)
        if term is not None:
            return term.id
    return policy.spine.primary_key


def resolve_role(conn: sqlite3.Connection, role: str):
    """Resolve a spine role to its bound term (via the glossary)."""
    from . import glossary as _glossary
    return _glossary.resolve_role(conn, role)


def rebind(conn: sqlite3.Connection, role: str, term_id: str,
           actor: str = "human", version: str = "",
           now: str | None = None) -> None:
    """HUMAN-gated: point a spine role at a different term. The CVE-replacement
    course-correction — the role stays, the word filling it swaps, old joins
    resolve via the crosswalk. No code rewritten."""
    from . import glossary as _glossary
    _glossary.rebind_role(conn, role, term_id, actor=actor, version=version, now=now)


def crosswalk_kinds(policy) -> list[tuple[str, str]]:
    """The configured alias pairs to maintain (e.g. [(cve,ghsa), (cve,usa)])."""
    return policy.spine.crosswalk