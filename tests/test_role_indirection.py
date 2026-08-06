"""Role-indirection tests — the spine is a JOB, not a word; rebinding is a
config edit, not a rewrite; the crosswalk keeps old joins resolving."""
from posture import store, glossary as G, spine
from posture.policy import Policy, default_policy_path


def _conn():
    conn = store.connect(":memory:")
    G.ensure_seeded(conn)
    return conn


def test_spine_primary_key_resolves_via_role_to_cve():
    conn = _conn()
    pol = Policy.from_file(default_policy_path())
    # with a store + seeded glossary, primary_key resolves the ROLE -> cve
    assert spine.primary_key(pol, conn) == "cve"


def test_spine_primary_key_no_store_falls_back_to_policy():
    pol = Policy.from_file(default_policy_path())
    # pure mode (no conn) falls back to the policy literal -> still cve
    assert spine.primary_key(pol) == "cve"


def test_rebind_role_swaps_spine_without_code_change():
    conn = _conn()
    pol = Policy.from_file(default_policy_path())
    G.add_term(conn, G.Term(id="X", kind="identifier_scheme",
                            roles=["vulnerability_join_key"]))
    G.promote_term(conn, "X")
    assert spine.primary_key(pol, conn) == "cve"
    spine.rebind(conn, "vulnerability_join_key", "X")
    assert spine.primary_key(pol, conn) == "X"
    # the role (the job) is unchanged; only the term filling it swapped
    assert spine.resolve_role(conn, "vulnerability_join_key").id == "X"


def test_crosswalk_preserves_old_joins_after_rebind():
    """The CVE-replacement contract: after rebinding the spine to X, an old cve
    key still resolves to its new alias through the crosswalk (no-wipe)."""
    conn = _conn()
    spine.register(conn, "CVE-2026-99901", "X-2026-99901", "X")
    conn.commit()
    # forward: old cve -> new X alias
    aliases = spine.resolve(conn, "CVE-2026-99901")
    assert any(a["alias"] == "X-2026-99901" for a in aliases)
    # reverse: new alias -> old cve
    rev = spine.reverse_resolve(conn, "X-2026-99901")
    assert rev[0]["cve"] == "CVE-2026-99901"


def test_course_correction_end_to_end():
    """The full 'CVEs are replaced' flow: new scheme appears -> candidate ->
    promoted -> cve deprecated -> role rebound -> old joins still resolve."""
    conn = _conn()
    pol = Policy.from_file(default_policy_path())
    # 1. new scheme X appears (candidate)
    G.add_term(conn, G.Term(id="X", label="New scheme", kind="identifier_scheme",
                            roles=["vulnerability_join_key"]))
    assert G.get(conn, "X").status == "candidate"
    # 2. human promotes X (trust gate)
    G.promote_term(conn, "X")
    # 3. human deprecates cve -> X and rebinds the role
    G.deprecate_term(conn, "cve", successor="X")
    spine.rebind(conn, "vulnerability_join_key", "X")
    # 4. the spine now resolves to X; nothing broke
    assert spine.primary_key(pol, conn) == "X"
    # 5. crosswalk keeps old joins resolving
    spine.register(conn, "CVE-2026-1", "X-2026-1", "X")
    conn.commit()
    assert spine.resolve(conn, "CVE-2026-1")[0]["alias"] == "X-2026-1"
    # 6. cve is deprecated but the change is recorded (auditable)
    changes = store.term_changes(conn, "cve")
    assert any(c["action"] == "deprecate" for c in changes)