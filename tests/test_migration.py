"""Migration tests — the in-place schema migrations (v0 -> v1 -> v2 -> v3 -> v4).

v0: the cve-centric crosswalk (cve, alias, kind) + cves with no flaw_type.
v1: the alias graph crosswalk (flaw_id, alias, kind) + cves.flaw_type backfilled.
v2: de-cve the flaw-catalog layer's names — cves -> flaws, seen_cves -> seen_flaws
    (+ its cve_id column -> flaw_id). KEV keeps cve_id (genuinely cve-keyed).
v3: discovery candidates become idempotent on url — dedup any accumulated dups
    (CI runs `posture discover` daily) + raise candidates_url_uq so add_candidate
    can upsert without bloating the exported spine. No-op on a fresh db.
v4: assessors are *observers* — the five id-carrying columns named `witness`
    (device_posture.deciding_witness, verdicts.witness, health_samples.witness,
    health_dossier.witness, distrust_marks.witness) rename to `observer`. The
    column DATA is preserved (only the name moves); the `state` table (stream
    cursor) is untouched. No-op on a fresh db (columns are already `observer`).

The migrations must be (a) introspection-guarded + idempotent (safe to re-run on
an already-migrated db), (b) safe on a fresh db created with the current SCHEMA,
and (c) touch ONLY crosswalk/cves/flaws/seen_*/candidates — PLUS the v4 column
renames, which change verdicts/device_posture/health/distrust column NAMES but
preserve their DATA (territory rows are never deleted).
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
    observer       TEXT,
    policy_version TEXT,
    fetched_at    TEXT,
    complete      INTEGER,
    raw_ref       TEXT,
    computed_at   TEXT,
    distrusted    INTEGER DEFAULT 0,
    distrust_reason TEXT,
    PRIMARY KEY (device_id, axis, key, observer)
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
           (device_id, axis, key, status, observer, policy_version, fetched_at,
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
    observer       TEXT,
    policy_version TEXT,
    fetched_at    TEXT,
    complete      INTEGER,
    raw_ref       TEXT,
    computed_at   TEXT,
    distrusted    INTEGER DEFAULT 0,
    distrust_reason TEXT,
    PRIMARY KEY (device_id, axis, key, observer)
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
           (device_id, axis, key, status, observer, policy_version, fetched_at,
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

    # the migrations ran exactly once each + bumped user_version to 3
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
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

    assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
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
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
    rows = conn.execute("SELECT flaw_id, alias, kind FROM crosswalk").fetchall()
    assert len(rows) == 1
    # a v1 db re-opened after migration is also a no-op
    db2 = tmp_path / "v1.db"
    _make_v1_db(str(db2))
    store.connect(str(db2)).close()
    conn2 = store.connect(str(db2))
    assert conn2.execute("PRAGMA user_version").fetchone()[0] == 4
    assert not store._has_table(conn2, "cves")
    conn2.close()


def test_fresh_db_is_already_at_v4():
    """A fresh db created with the current SCHEMA is at user_version 4 after
    connect; v0->v1 + v1->v2 + v3 are safe no-ops on it, v4 is a no-op (the
    id columns are already `observer`), and v3 raises the candidates unique
    index (a no-op dedup on an empty table)."""
    conn = store.connect(":memory:")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
    # current shape: flaws (not cves), seen_flaws with flaw_id, crosswalk flaw_id
    assert store._has_table(conn, "flaws") and not store._has_table(conn, "cves")
    ccols = {r[1] for r in conn.execute("PRAGMA table_info(crosswalk)")}
    assert "flaw_id" in ccols and "cve" not in ccols
    scol = {r[1] for r in conn.execute("PRAGMA table_info(seen_flaws)")}
    assert "flaw_id" in scol
    # v3: candidates has the url unique index on a fresh db (enables idempotent upsert)
    idx = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='candidates_url_uq'"
    ).fetchone()
    assert idx is not None
    conn.close()


# --- v3 -> v4 (the witness -> observer column rename) -----------------------

# The pre-rename (v3) shape of the five id-carrying columns. These columns were
# named `witness` before the observer rename; this fixture builds that LEGACY
# shape (mirroring the legacy `cve`/`cves`/`seen_cves` literals above) so the
# v3->v4 rename is exercised on real, not-already-renamed columns.
_V3_WITNESS_SCHEMA = """
CREATE TABLE device_posture (
    device_id        TEXT,
    axis             TEXT,
    status           TEXT,
    deciding_witness TEXT,
    bias             TEXT,
    gap              TEXT,
    policy_version   TEXT,
    computed_at      TEXT,
    PRIMARY KEY (device_id, axis)
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
CREATE TABLE health_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    witness     TEXT,
    device_id   TEXT,
    axis        TEXT,
    complete    INTEGER,
    latency_ms  INTEGER,
    reason      TEXT,
    fetched_at  TEXT
);
CREATE TABLE health_dossier (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    witness    TEXT,
    date       TEXT,
    axis       TEXT,
    claim      TEXT,
    citation   TEXT,
    direction  TEXT,
    added_at   TEXT
);
CREATE TABLE distrust_marks (
    witness   TEXT PRIMARY KEY,
    marked_at TEXT,
    reason    TEXT
);
CREATE TABLE state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def test_v3_db_renames_witness_columns_to_observer(tmp_path):
    db = tmp_path / "v3.db"
    raw = sqlite3.connect(str(db))
    raw.executescript(_V3_WITNESS_SCHEMA)
    raw.execute("INSERT INTO device_posture (device_id, axis, status, deciding_witness) "
                "VALUES (?,?,?,?)", ("host", "vulnerability", "caution", "nvd"))
    raw.execute("INSERT INTO verdicts (device_id, axis, key, status, witness, "
                "policy_version, fetched_at, complete, computed_at) VALUES (?,?,?,?,?,?,?,?,?)",
                ("host", "vulnerability", "CVE-2026-1", "unpatched", "nvd", "v4", "t0", 1, "t0"))
    raw.execute("INSERT INTO health_samples (witness, axis, complete, fetched_at) "
                "VALUES (?,?,?,?)", ("nvd", "vulnerability", 1, "t0"))
    raw.execute("INSERT INTO health_dossier (witness, axis, claim) VALUES (?,?,?)",
                ("nvd", "vulnerability", "ok"))
    raw.execute("INSERT INTO distrust_marks (witness, marked_at, reason) VALUES (?,?,?)",
                ("bad", "t0", "untrusted"))
    raw.execute("INSERT INTO state (key, value) VALUES (?,?)", ("stream_cursor", "abc123"))
    raw.execute("PRAGMA user_version = 3")
    raw.commit(); raw.close()

    conn = store.connect(str(db))              # runs v3->v4

    # every `witness` column is now `observer`
    dp = {r[1] for r in conn.execute("PRAGMA table_info(device_posture)")}
    assert "deciding_observer" in dp and "deciding_witness" not in dp
    vc = {r[1] for r in conn.execute("PRAGMA table_info(verdicts)")}
    assert "observer" in vc and "witness" not in vc
    hs = {r[1] for r in conn.execute("PRAGMA table_info(health_samples)")}
    assert "observer" in hs and "witness" not in hs
    hd = {r[1] for r in conn.execute("PRAGMA table_info(health_dossier)")}
    assert "observer" in hd and "witness" not in hd
    dm = {r[1] for r in conn.execute("PRAGMA table_info(distrust_marks)")}
    assert "observer" in dm and "witness" not in dm

    # data preserved across the rename — the id values did not move, only the name
    assert conn.execute("SELECT deciding_observer FROM device_posture").fetchone()[0] == "nvd"
    v = conn.execute("SELECT observer, key, status FROM verdicts").fetchone()
    assert tuple(v) == ("nvd", "CVE-2026-1", "unpatched")
    assert conn.execute("SELECT observer FROM distrust_marks").fetchone()[0] == "bad"

    # the stream cursor (state table) is untouched by the rename
    assert conn.execute("SELECT value FROM state WHERE key='stream_cursor'").fetchone()[0] == "abc123"

    assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
    conn.close()