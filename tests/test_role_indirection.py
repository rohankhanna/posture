"""Alias-graph + role-indirection tests.

The spine is the alias↔alias graph (see spine.py): every flaw_id is a peer, cve
is NOT a primary key and NOT rebindable. These tests pin the crosswalk alias
mechanics (register/resolve/reverse_resolve, symmetric alias, crosswalk keeps
old joins resolving) and the remaining generic role resolution
(severity_coordinate / exploitability_signal). The old swappable-spine
(primary_key / rebind / vulnerability_join_key) tests are retired — the alias
graph replaces that mechanism.
"""
from posture import store, glossary as G, spine


def _conn():
    conn = store.connect(":memory:")
    G.ensure_seeded(conn)
    return conn


def test_register_and_resolve_returns_typed_aliases():
    conn = store.connect(":memory:")
    spine.register(conn, "CVE-2026-31589", "GHSA-aaaa", "ghsa")
    spine.register(conn, "CVE-2026-31589", "USN-999", "usn")
    conn.commit()
    aliases = spine.resolve(conn, "CVE-2026-31589")
    kinds = {a["kind"] for a in aliases}
    assert kinds == {"ghsa", "usn"}


def test_reverse_resolve_returns_flaw_id_key():
    conn = store.connect(":memory:")
    spine.register(conn, "CVE-2026-31589", "GHSA-aaaa", "ghsa")
    conn.commit()
    rev = spine.reverse_resolve(conn, "GHSA-aaaa")
    assert len(rev) == 1
    assert rev[0]["flaw_id"] == "CVE-2026-31589"


def test_register_alias_symmetric_both_directions():
    """The alias graph's correctness fix: register_alias writes both directed
    edges so resolve returns correctly-typed aliases in EACH direction."""
    conn = store.connect(":memory:")
    spine.register_alias(conn, "CVE-2026-99901", "cve", "GHSA-xxxx", "ghsa")
    conn.commit()
    fwd = spine.resolve(conn, "CVE-2026-99901")
    assert any(a["alias"] == "GHSA-xxxx" and a["kind"] == "ghsa" for a in fwd)
    # the symmetric other direction: resolve(ghsa) -> cve, typed cve
    back = spine.resolve(conn, "GHSA-xxxx")
    assert any(a["alias"] == "CVE-2026-99901" and a["kind"] == "cve" for a in back)


def test_crosswalk_preserves_old_joins():
    """The alias-graph contract: an old cve key still resolves to its alias
    through the crosswalk. (This used to be 'after rebind'; the rebind is gone
    but the crosswalk-still-resolves property is unchanged — it is the whole
    reason the alias graph replaces the swappable spine.)"""
    conn = _conn()
    spine.register(conn, "CVE-2026-99901", "X-2026-99901", "X")
    conn.commit()
    # forward: cve -> X alias
    aliases = spine.resolve(conn, "CVE-2026-99901")
    assert any(a["alias"] == "X-2026-99901" for a in aliases)
    # reverse: alias -> cve
    rev = spine.reverse_resolve(conn, "X-2026-99901")
    assert rev[0]["flaw_id"] == "CVE-2026-99901"


def test_role_resolution_for_non_spine_roles():
    """The generic role mechanism survives the spine retirement: roles other
    than the removed vulnerability_join_key still resolve to their seed terms."""
    conn = _conn()
    assert G.resolve_role(conn, "severity_coordinate").id == "cvss"
    assert G.resolve_role(conn, "exploitability_signal").id in {"epss", "kev", "ssvc"}


def test_cve_no_longer_carries_spine_role():
    """vulnerability_join_key is retired from ROLES and from the cve seed term;
    the spine is the alias graph, not a rebindable word."""
    conn = _conn()
    assert "vulnerability_join_key" not in G.ROLES
    cve = G.get(conn, "cve")
    assert "vulnerability_join_key" not in cve.roles