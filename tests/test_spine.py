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
    assert rev[0]["cve"] == "CVE-2026-31589"


def test_crosswalk_idempotent():
    conn = store.connect(":memory:")
    spine.register(conn, "CVE-1", "GHSA-x", "ghsa")
    spine.register(conn, "CVE-1", "GHSA-x", "ghsa")  # duplicate -> ignored
    conn.commit()
    assert len(spine.resolve(conn, "CVE-1")) == 1


def test_spine_primary_key_from_policy():
    from posture.policy import default_policy_path, Policy
    p = Policy.from_file(default_policy_path())
    assert spine.primary_key(p) == "cve"
    assert ("cve", "ghsa") in spine.crosswalk_kinds(p)