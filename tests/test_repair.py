"""Repair tests — reconcile raises proposals; apply is human-gated + no-wipe."""
from posture import store, glossary as G, repair as R, spine
from posture.policy import Policy, default_policy_path


def _conn():
    conn = store.connect(":memory:")
    G.ensure_seeded(conn)
    return conn


def _pol():
    return Policy.from_file(default_policy_path())


def test_deprecated_bound_term_raises_rebind_proposal():
    conn = _conn()
    G.add_term(conn, G.Term(id="X", kind="identifier_scheme",
                            roles=["vulnerability_join_key"]))
    G.promote_term(conn, "X")
    G.deprecate_term(conn, "cve", successor="X")
    props = R.reconcile(conn, _pol())
    kinds = [p.kind for p in props]
    assert "spine_rebind_needed" in kinds


def test_apply_rebinds_and_resolves_to_successor():
    conn = _conn()
    G.add_term(conn, G.Term(id="X", kind="identifier_scheme",
                            roles=["vulnerability_join_key"]))
    G.promote_term(conn, "X")
    G.deprecate_term(conn, "cve", successor="X")
    props = R.reconcile(conn, _pol())
    rebind = next(p for p in props if p.kind == "spine_rebind_needed")
    summary = R.apply(conn, rebind.id, actor="tester")
    assert "rebound" in summary["done"][0]
    # the spine now resolves to X
    assert spine.primary_key(_pol(), conn) == "X"
    # the proposal is marked applied; reconcile won't re-raise it
    again = R.reconcile(conn, _pol())
    assert all(p.id != rebind.id for p in again)


def test_orphan_distrusted_witness_raises_proposal():
    conn = _conn()
    # nvd is policy-authorized; distrust it -> orphan_distrusted
    from posture import provenance as _prov
    # record a verdict resting on nvd then distrust it
    _prov.distrust(conn, "nvd", "captured")
    conn.commit()
    props = R.reconcile(conn, _pol())
    assert any(p.kind == "orphan_distrusted" and "nvd" in p.detail for p in props)


def test_stale_policy_raises_proposal():
    conn = _conn()
    # craft a policy dated far in the past
    old = """
version: "2020-01-01.1"
supersedes: null
dated: 2020-01-01
rationale: ancient
witnesses:
  nvd: {axes: [vulnerability], weight: high, bias: false-alarm, order: 10, conditions: []}
spine: {role: vulnerability_join_key, primary_key: cve, crosswalk: [[cve, ghsa]]}
"""
    pol = Policy.from_yaml(old)
    props = R.reconcile(conn, pol, now_iso="2026-08-01T00:00:00+00:00")
    assert any(p.kind == "stale_policy" for p in props)


def test_apply_unknown_proposal_raises():
    import pytest
    conn = _conn()
    with pytest.raises(KeyError):
        R.apply(conn, "nope")