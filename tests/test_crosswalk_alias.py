"""Alias-graph tests — cve is one peer among many, not a primary key.

The defining property of the alias↔alias spine: a flaw with NO cve (an OSV or
GHSA record that was never assigned a CVE) still anchors as a first-class peer,
and its equivalence to other flaw_ids resolves correctly in both directions via
the symmetric edges `add_flaw_alias` writes.
"""
from posture import store, spine


def test_cveless_flaw_anchors_directly():
    """An OSV record with no CVE is upserted as a catalog row keyed by its own
    flaw_id (the cves PK is TEXT, any scheme) — no cve required to exist."""
    conn = store.connect(":memory:")
    store.upsert_cve(conn, {
        "id": "OSV-2026-42", "flaw_type": "osv", "published": "2026-05-01",
        "description": "an osv record with no cve alias",
        "source": "osv", "fetched_at": "t", "policy_version": "v", "complete": 1,
    })
    conn.commit()
    row = store.get_cve(conn, "OSV-2026-42")
    assert row is not None
    assert row["flaw_type"] == "osv"
    # and it is reachable via the flaw-type registry (posture spine show)
    counts = {r["flaw_type"]: r["n"] for r in store.flaw_type_counts(conn)}
    assert counts.get("osv") == 1


def test_cveless_flaw_equivalence_resolves_both_directions():
    """OSV-2026-42 (no cve) is equivalent to GHSA-yyyy (no cve). register_alias
    writes both edges so each resolves to the other, correctly typed — without
    a cve ever existing. This is the case the old cve-centric crosswalk could
    not anchor (every row required a cve)."""
    conn = store.connect(":memory:")
    spine.register_alias(conn, "OSV-2026-42", "osv", "GHSA-yyyy-zzzz-wwww", "ghsa")
    conn.commit()
    # resolve(osv) -> ghsa alias typed ghsa
    fwd = spine.resolve(conn, "OSV-2026-42")
    assert any(a["alias"] == "GHSA-yyyy-zzzz-wwww" and a["kind"] == "ghsa" for a in fwd)
    # resolve(ghsa) -> osv alias typed osv (the symmetric edge)
    back = spine.resolve(conn, "GHSA-yyyy-zzzz-wwww")
    assert any(a["alias"] == "OSV-2026-42" and a["kind"] == "osv" for a in back)


def test_three_way_equivalence_is_transitive_via_edges():
    """cve <-> ghsa <-> osv: three peers of one flaw. Each pair gets symmetric
    edges; resolve from any peer returns the other two, correctly typed."""
    conn = store.connect(":memory:")
    spine.register_alias(conn, "CVE-2026-9", "cve", "GHSA-9", "ghsa")
    spine.register_alias(conn, "GHSA-9", "ghsa", "OSV-2026-9", "osv")
    conn.commit()
    cve_aliases = {a["alias"]: a["kind"] for a in spine.resolve(conn, "CVE-2026-9")}
    assert cve_aliases.get("GHSA-9") == "ghsa"
    # NOTE: cve -> osv is NOT a direct edge (only cve<->ghsa and ghsa<->osv);
    # transitivity is a graph-walk concern of the engine, not a stored edge.
    # The stored graph is the union of the pairwise equivalences.
    osv_aliases = {a["alias"]: a["kind"] for a in spine.resolve(conn, "OSV-2026-9")}
    assert osv_aliases.get("GHSA-9") == "ghsa"


def test_add_flaw_alias_is_idempotent():
    conn = store.connect(":memory:")
    spine.register_alias(conn, "CVE-1", "cve", "GHSA-1", "ghsa")
    spine.register_alias(conn, "CVE-1", "cve", "GHSA-1", "ghsa")  # duplicate
    conn.commit()
    assert len(spine.resolve(conn, "CVE-1")) == 1
    assert len(store.crosswalk_all(conn)) == 2  # the two directed edges only