"""Migration tests — the v0->v1 in-place schema migration.

v0: the cve-centric crosswalk (cve, alias, kind) + cves with no flaw_type.
v1: the alias graph crosswalk (flaw_id, alias, kind) + cves.flaw_type backfilled.

The migration must be (a) introspection-guarded + idempotent (safe to re-run on
an already-migrated db), (b) safe on a fresh db created with the current SCHEMA,
and (c) touch ONLY crosswalk/cves — verdicts (territory) are byte-untouched.
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


def test_v0_db_migrates_crosswalk_rename_and_flaw_type_backfill(tmp_path):
    db = tmp_path / "v0.db"
    _make_v0_db(str(db))

    # posture.connect runs the new SCHEMA (IF NOT EXISTS -> no-op on existing)
    # then _migrate applies the v0->v1 ALTERs, gated by PRAGMA user_version.
    conn = store.connect(str(db))

    # crosswalk renamed: cve -> flaw_id, old row preserved
    cols = {r[1] for r in conn.execute("PRAGMA table_info(crosswalk)")}
    assert "flaw_id" in cols and "cve" not in cols
    rows = conn.execute("SELECT flaw_id, alias, kind FROM crosswalk").fetchall()
    assert [tuple(r) for r in rows] == [("CVE-2026-1", "GHSA-aaaa", "ghsa")]

    # cves.flaw_type added + backfilled 'cve' for the pre-existing row
    ccols = {r[1] for r in conn.execute("PRAGMA table_info(cves)")}
    assert "flaw_type" in ccols
    row = conn.execute("SELECT id, flaw_type, enrich_state FROM cves").fetchone()
    assert row[0] == "CVE-2026-1" and row[1] == "cve" and row[2] == "mitre"

    # the migration ran exactly once + bumped user_version
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    conn.close()


def test_migration_leaves_verdicts_untouched(tmp_path):
    """Territory (verdicts) is byte-untouched by the v0->v1 migration."""
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
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    rows = conn.execute("SELECT flaw_id, alias, kind FROM crosswalk").fetchall()
    assert len(rows) == 1
    conn.close()


def test_fresh_db_is_already_at_v1():
    """A fresh db created with the current SCHEMA is at user_version 1 after
    connect, and the v0->v1 steps were safe no-ops on it."""
    conn = store.connect(":memory:")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    # crosswalk has flaw_id (current schema), cves has flaw_type — no cve column
    ccols = {r[1] for r in conn.execute("PRAGMA table_info(crosswalk)")}
    assert "flaw_id" in ccols and "cve" not in ccols
    conn.close()