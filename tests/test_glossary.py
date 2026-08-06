"""Glossary tests — the vocabulary as data; roles; the trust gate."""
from posture import store, glossary as G


def _conn():
    conn = store.connect(":memory:")
    G.ensure_seeded(conn)
    return conn


def test_seed_present_and_cited():
    conn = _conn()
    ids = {t.id for t in G.all(conn)}
    # the spine + the redundant aliases + scoring + axes
    for needed in ("cve", "ghsa", "usn", "dsa", "rhsa", "apsb", "osv_id",
                   "cwe", "cvss", "epss", "kev", "csaf", "cyclonedx", "spdx"):
        assert needed in ids, needed
    # the six axes are seeded as kind=axis terms
    axes = [t for t in G.all(conn) if t.kind == "axis"]
    assert {a.id for a in axes} == {"vulnerability", "configuration", "exposure",
                                     "inventory", "threat", "trust"}
    # every term is cited (the map is foreign-authored; say so)
    assert all(t.citation for t in G.all(conn))


def test_known_axes_seeded_to_six_returns_axis_enum():
    from posture.axis import Axis
    conn = _conn()
    axes = G.known_axes(conn)
    assert len(axes) == 6
    assert all(isinstance(a, Axis) for a in axes)  # seed axes are enum values


def test_resolve_roles_map_to_seed_terms():
    conn = _conn()
    # the spine role (vulnerability_join_key) is retired; the generic role
    # mechanism still resolves the remaining roles to their seed terms.
    assert G.resolve_role(conn, "severity_coordinate").id == "cvss"
    assert G.resolve_role(conn, "exploitability_signal").id in {"epss", "kev", "ssvc"}
    # and vulnerability_join_key is no longer a role at all
    assert "vulnerability_join_key" not in G.ROLES
    assert G.resolve_role(conn, "vulnerability_join_key") is None


def test_known_kinds_excludes_axes_and_includes_schemes():
    conn = _conn()
    kinds = G.known_kinds(conn)
    assert "identifier_scheme" in kinds
    assert "axis" not in kinds  # axes are dimensions, not identifier kinds
    assert "coordinate_system" in kinds


def test_add_term_creates_candidate_not_known():
    conn = _conn()
    G.add_term(conn, G.Term(id="newx", label="New X", kind="identifier_scheme"))
    assert G.get(conn, "newx").status == "candidate"
    assert "newx" not in {t.id for t in G.all(conn, status="known")}


def test_promote_is_the_trust_gate_and_records_change():
    conn = _conn()
    G.add_term(conn, G.Term(id="newx", kind="identifier_scheme"))
    t = G.promote_term(conn, "newx", actor="tester", version="2026-08-01.2")
    assert t.status == "known"
    changes = store.term_changes(conn, "newx")
    actions = [c["action"] for c in changes]
    assert "add" in actions and "promote" in actions


def test_deprecate_with_successor_and_role_resolves_to_successor():
    conn = _conn()
    G.add_term(conn, G.Term(id="X", kind="identifier_scheme",
                            roles=["vulnerability_join_key"]))
    G.promote_term(conn, "X")
    G.deprecate_term(conn, "cve", successor="X")
    assert G.get(conn, "cve").status == "deprecated"
    # resolve_role follows a deprecated term to its known successor automatically
    # (the course-correction keeps the system working even before an explicit rebind)
    t = G.resolve_role(conn, "vulnerability_join_key")
    assert t.id == "X"
    # ...and an explicit rebind records the binding as auditable (defense in depth)
    G.rebind_role(conn, "vulnerability_join_key", "X")
    assert G.resolve_role(conn, "vulnerability_join_key").id == "X"


def test_promote_deprecated_rejected():
    conn = _conn()
    G.add_term(conn, G.Term(id="X", kind="identifier_scheme"))
    G.promote_term(conn, "X")
    G.deprecate_term(conn, "cve", successor="X")
    import pytest
    with pytest.raises(ValueError):
        G.promote_term(conn, "cve")


def test_rebind_requires_known_term():
    conn = _conn()
    G.add_term(conn, G.Term(id="X", kind="identifier_scheme"))  # candidate
    import pytest
    with pytest.raises(ValueError):
        G.rebind_role(conn, "vulnerability_join_key", "X")  # not known yet


def test_neighborhood_relates_by_kind_and_role():
    conn = _conn()
    # ghsa shares advisory_scheme role with usn/dsa/rhsa/apsb/osv_id
    near = {t.id for t in G.neighborhood(conn, "ghsa")}
    assert "usn" in near and "dsa" in near
    # cve is alone in its role (vulnerability_join_key) but shares kind
    near_cve = {t.id for t in G.neighborhood(conn, "cve")}
    assert "ghsa" in near_cve  # same kind=identifier_scheme