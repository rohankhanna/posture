"""Spine tests — join-key crosswalk (the redundant spine)."""
from posture import store, spine


def test_crosswalk_add_and_resolve():
    conn = store.connect(":memory:")
    spine.register(conn, "CVE-2026-31589", "GHSA-aaaa", "ghsa")
    spine.register(conn, "CVE-2026-31589", "USN-999", "usn")
    conn.commit()
    aliases = spine.resolve(conn, "CVE-2026-31589")
    kinds = {a["kind"] for a in aliases}
    assert kinds == {"ghsa", "usn"}


def test_crosswalk_reverse_resolve():
    conn = store.connect(":memory:")
    spine.register(conn, "CVE-2026-31589", "GHSA-aaaa", "ghsa")
    conn.commit()
    rev = spine.reverse_resolve(conn, "GHSA-aaaa")
    assert len(rev) == 1
    assert rev[0]["defect_id"] == "CVE-2026-31589"


def test_crosswalk_idempotent():
    conn = store.connect(":memory:")
    spine.register(conn, "CVE-1", "GHSA-x", "ghsa")
    spine.register(conn, "CVE-1", "GHSA-x", "ghsa")  # duplicate -> ignored
    conn.commit()
    assert len(spine.resolve(conn, "CVE-1")) == 1


def test_register_alias_is_symmetric():
    """The alias graph: register_alias writes BOTH directed edges so resolve
    returns correctly-typed aliases in each direction — the correctness fix a
    single directed edge cannot give, and what lets a cve-less defect anchor."""
    conn = store.connect(":memory:")
    spine.register_alias(conn, "CVE-2026-31589", "cve", "GHSA-aaaa", "ghsa")
    conn.commit()
    # forward: resolve(cve) -> ghsa alias, typed as ghsa
    fwd = spine.resolve(conn, "CVE-2026-31589")
    assert any(a["alias"] == "GHSA-aaaa" and a["kind"] == "ghsa" for a in fwd)
    # the symmetric other direction: resolve(ghsa) -> cve alias, typed as cve
    # (a single directed edge would miss this — the whole point of add_defect_alias)
    back = spine.resolve(conn, "GHSA-aaaa")
    assert any(a["alias"] == "CVE-2026-31589" and a["kind"] == "cve" for a in back)