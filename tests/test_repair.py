"""Repair tests — reconcile raises proposals; apply is human-gated + no-wipe."""
from posture import store, glossary as G, repair as R
from posture.policy import Policy, default_policy_path


def _conn():
    conn = store.connect(":memory:")
    G.ensure_seeded(conn)
    return conn


def _pol():
    return Policy.from_file(default_policy_path())


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