"""Migration tests — the in-place schema migrations (v0 -> v1 -> v2).

v0: the cve-centric crosswalk (cve, alias, kind) + cves with no flaw_type.
v1: the alias graph crosswalk (flaw_id, alias, kind) + cves.flaw_type backfilled.
v2: de-cve the flaw-catalog layer's names — cves -> flaws, seen_cves -> seen_flaws
    (+ its cve_id column -> flaw_id). KEV keeps cve_id (genuinely cve-keyed).

The migrations must be (a) introspection-guarded + idempotent (safe to re-run on
an already-migrated db), (b) safe on a fresh db created with the current SCHEMA,
and (c) touch ONLY crosswalk/cves/flaws/seen_* — verdicts (territory) are
byte-untouched.
"""
import sqlite3

from posture import store


# The v0 crosswalk + cves shapes (pre-alias-graph). Verdicts match the current
# schema so the migration's "verdicts untouched" guarantee is testable.
_V0_SCHEMA = """
CREATE TABLE crosswalk (
    cve   TEXT,
    alias TEXT,
    kind  TEXT,
    PRIMARY KEY (cve, alias, kind)
);
CREATE INDEX ix_crosswalk_alias ON crosswalk(alias);

CREATE TABLE cves (
    id              TEXT PRIMARY KEY,
    published       TEXT,
    cvss            REAL,
    severity        TEXT,
    cvss_vector     TEXT,
    description     TEXT,
    fixed_raw       TEXT,
    refs            TEXT,
    cwe             TEXT,
    ref_tags        TEXT,
    enrich_state    TEXT,
    source          TEXT,
    fetched_at      TEXT,
    policy_version  TEXT,
    complete        INTEGER,
    distrusted      INTEGER DEFAULT 0,
    distrust_reason TEXT,
    discovered_at   TEXT
);

CREATE TABLE verdicts (
    device_id     TEXT,
    axis          TEXT,
    key           TEXT,
    status        TEXT,
    severity      TEXT,
    fixed_in      TEXT,
    detail        TEXT,
    witness       TEXT,
    policy_version TEXT,
    fetched_at    TEXT,
    complete      INTEGER,
    raw_ref       TEXT,
    computed_at   TEXT,
    distrusted    INTEGER DEFAULT 0,
    distrust_reason TEXT,
    PRIMARY KEY (device_id, axis, key, witness)
);
"""


def _make_v0_db(path):
    """Build a v0 db by hand (bypassing posture.connect, which would migrate)."""
    conn = sqlite3.connect(path)
    conn.executescript(_V0_SCHEMA)
    conn.execute("INSERT INTO crosswalk (cve, alias, kind) VALUES (?,?,?)",
                 ("CVE-2026-1", "GHSA-aaaa", "ghsa"))
    conn.execute("INSERT INTO cves (id, published, source, enrich_state, complete) "
                 "VALUES (?,?,?,?,?)",
                 ("CVE-2026-1", "2026-07-01", "mitre", "mitre", 1))
    conn.execute(
        """INSERT INTO verdicts
           (device_id, axis, key, status, witness, policy_version, fetched_at,
            complete, computed_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        ("host-TERRITORY", "vulnerability", "CVE-2026-1", "unpatched", "nvd",
         "v0", "t0", 1, "t0"),
    )
    conn.commit()
    conn.close()


# A v1 db: crosswalk already renamed (flaw_id), cves already has flaw_type, AND a
# seen_cves table with the cve_id column (the v1->v2 rename target). Used to test
# the v1->v2 step specifically (v0->v1 is a no-op on this shape).
_V1_SCHEMA = """
CREATE TABLE crosswalk (
    flaw_id TEXT,
    alias   TEXT,
    kind    TEXT,
    PRIMARY KEY (flaw_id, alias, kind)
);
CREATE INDEX ix_crosswalk_alias ON crosswalk(alias);

CREATE TABLE cves (
    id              TEXT PRIMARY KEY,
    flaw_type       TEXT,
    published       TEXT,
    cvss            REAL,
    severity        TEXT,
    cvss_vector     TEXT,
    description     TEXT,
    fixed_raw       TEXT,
    refs            TEXT,
    cwe             TEXT,
    ref_tags        TEXT,
    enrich_state    TEXT,
    source          TEXT,
    fetched_at      TEXT,
    policy_version  TEXT,
    complete        INTEGER,
    distrusted      INTEGER DEFAULT 0,
    distrust_reason TEXT,
    discovered_at   TEXT
);

CREATE TABLE seen_cves (
    cve_id     TEXT PRIMARY KEY,
    first_seen TEXT
);

CREATE TABLE verdicts (
    device_id     TEXT,
    axis          TEXT,
    key           TEXT,
    status        TEXT,
    severity      TEXT,
    fixed_in      TEXT,
    detail        TEXT,
    witness       TEXT,
    policy_version TEXT,
    fetched_at    TEXT,
    complete      INTEGER,
    raw_ref       TEXT,
    computed_at   TEXT,
    distrusted    INTEGER DEFAULT 0,
    distrust_reason TEXT,
    PRIMARY KEY (device_id, axis, key, witness)
);
"""


def _make_v1_db(path):
    """Build a v1 db by hand (already past v0->v1; user_version=1)."""
    conn = sqlite3.connect(path)
    conn.executescript(_V1_SCHEMA)
    conn.execute("INSERT INTO cves (id, flaw_type, published, source, "
                 "enrich_state, complete) VALUES (?,?,?,?,?,?)",
                 ("CVE-2026-1", "cve", "2026-07-01", "mitre", "mitre", 1))
    conn.execute("INSERT INTO cves (id, flaw_type, published, source, "
                 "enrich_state, complete) VALUES (?,?,?,?,?,?)",
                 ("GHSA-aaaa", "ghsa", "2026-07-02", "ghsa", "ghsa", 1))
    conn.execute("INSERT INTO seen_cves (cve_id, first_seen) VALUES (?,?)",
                 ("CVE-2026-1", "2026-08-01"))
    conn.execute("INSERT INTO seen_cves (cve_id, first_seen) VALUES (?,?)",
                 ("GHSA-aaaa", "2026-08-02"))
    conn.execute(
        """INSERT INTO verdicts
           (device_id, axis, key, status, witness, policy_version, fetched_at,
            complete, computed_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        ("host-TERRITORY", "vulnerability", "CVE-2026-1", "unpatched", "nvd",
         "v1", "t0", 1, "t0"),
    )
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()


# --- v0 -> v2 (runs both steps) ---------------------------------------------

def test_v0_db_migrates_to_flaws_and_alias_graph(tmp_path):
    db = tmp_path / "v0.db"
    _make_v0_db(str(db))

    # posture.connect runs the new SCHEMA (IF NOT EXISTS -> no-op on existing
    # tables; creates empty flaws/seen_flaws placeholders) then _migrate applies
    # v0->v1 then v1->v2, gated by PRAGMA user_version.
    conn = store.connect(str(db))

    # crosswalk renamed: cve -> flaw_id, old row preserved
    cols = {r[1] for r in conn.execute("PRAGMA table_info(crosswalk)")}
    assert "flaw_id" in cols and "cve" not in cols
    rows = conn.execute("SELECT flaw_id, alias, kind FROM crosswalk").fetchall()
    assert [tuple(r) for r in rows] == [("CVE-2026-1", "GHSA-aaaa", "ghsa")]

    # cves renamed to flaws; flaw_type added + backfilled 'cve' for the row
    assert not store._has_table(conn, "cves")
    fcols = {r[1] for r in conn.execute("PRAGMA table_info(flaws)")}
    assert "flaw_type" in fcols
    row = conn.execute("SELECT id, flaw_type, enrich_state FROM flaws").fetchone()
    assert row[0] == "CVE-2026-1" and row[1] == "cve" and row[2] == "mitre"

    # seen_flaws exists (fresh, empty — v0 had no seen_cves)
    assert store._has_table(conn, "seen_flaws")
    scol = {r[1] for r in conn.execute("PRAGMA table_info(seen_flaws)")}
    assert "flaw_id" in scol and "cve_id" not in scol

    # the migrations ran exactly once each + bumped user_version to 2
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    conn.close()


# --- v1 -> v2 (the table + column rename) ----------------------------------

def test_v1_db_renames_cves_to_flaws_and_seen_cves_cve_id_to_flaw_id(tmp_path):
    db = tmp_path / "v1.db"
    _make_v1_db(str(db))
    conn = store.connect(str(db))

    # cves -> flaws, data preserved (both the cve and the ghsa peer row)
    assert not store._has_table(conn, "cves")
    rows = conn.execute("SELECT id, flaw_type FROM flaws ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [("CVE-2026-1", "cve"), ("GHSA-aaaa", "ghsa")]

    # seen_cves -> seen_flaws, cve_id column -> flaw_id, sighting rows preserved
    assert not store._has_table(conn, "seen_cves")
    scol = {r[1] for r in conn.execute("PRAGMA table_info(seen_flaws)")}
    assert "flaw_id" in scol and "cve_id" not in scol
    seen = conn.execute("SELECT flaw_id, first_seen FROM seen_flaws ORDER BY flaw_id").fetchall()
    assert [tuple(r) for r in seen] == [("CVE-2026-1", "2026-08-01"),
                                       ("GHSA-aaaa", "2026-08-02")]

    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    conn.close()


def test_migration_leaves_verdicts_untouched(tmp_path):
    """Territory (verdicts) is byte-untouched by the migrations."""
    db = tmp_path / "v0.db"
    _make_v0_db(str(db))
    conn = store.connect(str(db))
    rows = conn.execute("SELECT * FROM verdicts").fetchall()
    assert len(rows) == 1
    v = dict(rows[0])
    assert v["device_id"] == "host-TERRITORY"
    assert v["key"] == "CVE-2026-1" and v["status"] == "unpatched"
    conn.close()


def test_migration_is_idempotent(tmp_path):
    """Re-opening an already-migrated db is a no-op (guards + user_version)."""
    db = tmp_path / "v0.db"
    _make_v0_db(str(db))
    store.connect(str(db)).close()
    conn = store.connect(str(db))
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    rows = conn.execute("SELECT flaw_id, alias, kind FROM crosswalk").fetchall()
    assert len(rows) == 1
    # a v1 db re-opened after migration is also a no-op
    db2 = tmp_path / "v1.db"
    _make_v1_db(str(db2))
    store.connect(str(db2)).close()
    conn2 = store.connect(str(db2))
    assert conn2.execute("PRAGMA user_version").fetchone()[0] == 2
    assert not store._has_table(conn2, "cves")
    conn2.close()


def test_fresh_db_is_already_at_v2():
    """A fresh db created with the current SCHEMA is at user_version 2 after
    connect, and the v0->v1 + v1->v2 steps were safe no-ops on it."""
    conn = store.connect(":memory:")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    # current shape: flaws (not cves), seen_flaws with flaw_id, crosswalk flaw_id
    assert store._has_table(conn, "flaws") and not store._has_table(conn, "cves")
    ccols = {r[1] for r in conn.execute("PRAGMA table_info(crosswalk)")}
    assert "flaw_id" in ccols and "cve" not in ccols
    scol = {r[1] for r in conn.execute("PRAGMA table_info(seen_flaws)")}
    assert "flaw_id" in scol
    conn.close()