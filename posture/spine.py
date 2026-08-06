"""The alias graph — the spine as alias↔alias, not a swappable join key.

The spine is **all flaws**: every flaw_id is a peer, across every flaw_type,
simultaneously. cve is one peer among many — NOT a primary key, and NOT
rebindable. The spine entity (the equivalence class of flaw_ids that denote one
flaw) is a LOGICAL view over the crosswalk alias graph, not a single physical
row: a `cve` row, a `ghsa` row, and an `osv` row that all denote the same flaw
each anchor their own catalog row, and the crosswalk edges between them are what
joins resolve.

This module is the thin store-backed API over that graph; the heavy lifting
(joining across witnesses by alias) lives in the engine. Ingestion peers
(`stream`/`osv`/`ghsa`/`kev`) write equivalence edges via :func:`register_alias`
(the symmetric double-edge), not the old single-direction :func:`register`.

There is no `primary_key` / `rebind` / `resolve_role` here anymore — the
swappable-spine mechanism the alias graph replaces has been retired. The
glossary's role machinery (`resolve_role`/`rebind_role`) remains for the
*other* roles (severity_coordinate, exploitability_signal, weakness_category);
only the `vulnerability_join_key` role — the "cve is the spine" indirection —
is gone, because the spine is no longer a single rebindable word.
"""

from __future__ import annotations
import sqlite3


def register(conn: sqlite3.Connection, flaw_id: str, alias: str, kind: str) -> None:
    """Record ONE directed edge: `flaw_id` is also known as `alias` under scheme
    `kind` (ghsa/usn/dsa/rhsa/apsb/osv/cve/...). Idempotent. Prefer
    :func:`register_alias` for ingestion — it writes both directions so resolve
    is correct either way."""
    from . import store as _store
    _store.add_crosswalk(conn, flaw_id, alias, kind)


def register_alias(conn: sqlite3.Connection, a: str, kind_a: str,
                   b: str, kind_b: str) -> None:
    """Record the symmetric equivalence of two flaw_ids: `a` (scheme `kind_a`)
    and `b` (scheme `kind_b`). Writes both directed edges so `resolve(a)` returns
    b typed as kind_b AND `resolve(b)` returns a typed as kind_a. This is what
    ingestion uses — a non-cve flaw with no cve anchors as a first-class peer.
    Idempotent."""
    from . import store as _store
    _store.add_flaw_alias(conn, a, kind_a, b, kind_b)


def resolve(conn: sqlite3.Connection, flaw_id: str) -> list[dict]:
    """All known aliases of a flaw_id (each {alias, kind})."""
    from . import store as _store
    return _store.resolve_crosswalk(conn, flaw_id)


def reverse_resolve(conn: sqlite3.Connection, alias: str) -> list[dict]:
    """All flaw_ids known to share this alias (each {flaw_id, kind})."""
    from . import store as _store
    return _store.reverse_crosswalk(conn, alias)