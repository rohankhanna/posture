"""sqlite storage — verdicts (provenance-stamped), axis posture, versioned
policy, source-health samples/dossier, spine crosswalk, discovery candidates,
and distrust marks.

The load-bearing rule lives in `commit_device_verdicts`: a device's stored
verdicts for an axis are only replaced when the observer fetch was *provably
complete* (per-axis gate). An incomplete fetch preserves last-known-good
verdicts — fragile remote ends must never delete state by failing. This
mirrors Forebode's `db.commit_device_verdicts` (the run-#10 fleet wipe was an
empty/incomplete pull deleting ~14000 rows).
"""

from __future__ import annotations
import os
import sqlite3
from contextlib import contextmanager
from typing import Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS device_posture (
    device_id     TEXT,
    axis          TEXT,
    status        TEXT,
    deciding_observer TEXT,
    bias          TEXT,
    gap           TEXT,
    policy_version TEXT,
    computed_at   TEXT,
    PRIMARY KEY (device_id, axis)
);

CREATE TABLE IF NOT EXISTS verdicts (
    device_id     TEXT,
    axis          TEXT,
    key           TEXT,
    status        TEXT,
    severity      TEXT,
    fixed_in      TEXT,
    detail        TEXT,
    cvss          REAL,
    cvss_vector   TEXT,
    published     TEXT,
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

CREATE TABLE IF NOT EXISTS policy_versions (
    version    TEXT PRIMARY KEY,
    supersedes TEXT,
    dated      TEXT,
    rationale  TEXT,
    yaml       TEXT,
    installed_at TEXT
);

CREATE TABLE IF NOT EXISTS health_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    observer     TEXT,
    device_id   TEXT,
    axis        TEXT,
    complete    INTEGER,
    latency_ms  INTEGER,
    reason      TEXT,
    fetched_at  TEXT
);

CREATE TABLE IF NOT EXISTS health_dossier (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    observer    TEXT,
    date       TEXT,
    axis       TEXT,
    claim      TEXT,
    citation   TEXT,
    direction  TEXT,
    added_at   TEXT
);

-- The alias graph (alias↔alias). Every defect_id — cve, ghsa, osv, rustsec, pysec,
-- go, … — is a peer; cve is NOT a primary key. A row is ONE directed edge
-- (defect_id, alias, kind): "defect_id is also known as alias under scheme kind".
-- Ingestion uses add_defect_alias() to write BOTH directed edges of an equivalence
-- so resolve returns correctly-typed aliases in both directions. The spine
-- entity (the equivalence class) is a LOGICAL view over this graph, not a row.
CREATE TABLE IF NOT EXISTS crosswalk (
    defect_id TEXT,
    alias   TEXT,
    kind    TEXT,
    PRIMARY KEY (defect_id, alias, kind)
);
CREATE INDEX IF NOT EXISTS ix_crosswalk_alias ON crosswalk(alias);

CREATE TABLE IF NOT EXISTS candidates (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT,
    fmt        TEXT,
    axis       TEXT,
    status     TEXT DEFAULT 'review',   -- review | adopted | rejected
    note       TEXT,
    added_at   TEXT
);

CREATE TABLE IF NOT EXISTS distrust_marks (
    observer   TEXT PRIMARY KEY,
    marked_at TEXT,
    reason    TEXT
);

-- The glossary — the vocabulary as data, not code. Terms (CVE, CWE, KEV, the
-- axes, ...) are rows here. The six axes are the SEED; new terms grow the
-- system instead of breaking it. Trust changes (promote/deprecate/rebind) are
-- human-gated and recorded in term_changes (versioned, dated, cited).
CREATE TABLE IF NOT EXISTS glossary (
    id            TEXT PRIMARY KEY,   -- slug, e.g. "cve"
    label         TEXT,
    kind          TEXT,                -- identifier_scheme | coordinate_system | axis | ...
    roles         TEXT,                -- JSON list of functional roles (see glossary.ROLES)
    status        TEXT DEFAULT 'known',-- known | candidate | deprecated
    successor     TEXT,                -- term id, for deprecation course-correction
    citation      TEXT,                -- public-record pointer (the map is cited)
    discovered_at TEXT,
    promoted_at   TEXT,
    notes         TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_glossary_status ON glossary(status);
CREATE INDEX IF NOT EXISTS ix_glossary_kind ON glossary(kind);

-- New-term signals surfaced by the vocab monitor (auto-written; the machine
-- notices). Promoting a signal's term is the human trust gate.
CREATE TABLE IF NOT EXISTS term_signals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT,
    label       TEXT,
    context     TEXT,
    citation    TEXT,
    detected_at TEXT,
    status      TEXT DEFAULT 'open'    -- open | promoted | rejected
);

-- Audit log for every trust change (add | promote | deprecate | rebind).
-- A security tool that silently rewrote its own trust would itself be an
-- attack surface, so trust changes are recorded, never ambient.
CREATE TABLE IF NOT EXISTS term_changes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    action  TEXT,        -- add | promote | deprecate | rebind
    term_id TEXT,
    detail  TEXT,
    actor   TEXT,
    version TEXT,
    at      TEXT
);

-- Spine role -> term binding. The engine resolves ROLES (e.g.
-- vulnerability_join_key), not literal strings, so rebinding the spine (if CVEs
-- are ever replaced) is a config edit, not a code rewrite.
CREATE TABLE IF NOT EXISTS spine_bindings (
    role     TEXT PRIMARY KEY,
    term_id  TEXT,
    bound_at TEXT
);

-- Self-repair proposals. Auto-repairs (no-wipe, graceful-unknown, fallback)
-- run in the engine; trust-repairs (spine rebind) are human-approved here.
CREATE TABLE IF NOT EXISTS repair_proposals (
    id             TEXT PRIMARY KEY,
    kind           TEXT,              -- deprecated_term_referenced | spine_rebind_needed | source_drifted | stale_policy | orphan_distrusted
    detail         TEXT,
    proposed_action TEXT,             -- JSON
    evidence       TEXT,              -- JSON
    raised_at      TEXT,
    status         TEXT DEFAULT 'open'-- open | applied | dismissed
);

-- The defect catalog — the spine as a stream, not just a per-pull result. `id`
-- is a defect_id under any peer scheme (cve, ghsa, osv, rustsec, pysec, go, …);
-- `defect_type` records which. Rows arrive many ways: (a) MITRE stream skeletons
-- (enrich_state='mitre', the foreign-authored map point with no verdict), (b)
-- NVD-enriched CVE rows (enrich_state='nvd', CVSS + affected ranges), and (c)
-- self-enriched peer rows (enrich_state='osv'/'ghsa', carrying their own
-- severity + ranges on ingest). Provenance is stamped on EVERY row
-- (source/fetched_at/policy_version/complete) so a catalog row, like a verdict,
-- can be retroactively distrusted rather than deleted. The map is not the
-- territory: a skeleton says "MITRE published this; NVD has not yet enriched
-- it" — never "this device is vulnerable."
CREATE TABLE IF NOT EXISTS defects (
    id              TEXT PRIMARY KEY,
    defect_type       TEXT,             -- 'cve' | 'ghsa' | 'osv' | 'rustsec' | ... (the peer scheme)
    published       TEXT,
    cvss            REAL,
    severity        TEXT,
    cvss_vector     TEXT,
    description     TEXT,
    fixed_raw       TEXT,             -- JSON: raw fix/range info kept for traceability
    refs            TEXT,             -- JSON array of reference URLs
    cwe             TEXT,             -- JSON array of CWE ids (foothold/weakness-class signal)
    ref_tags        TEXT,             -- JSON array of reference tags (arming/patch-availability signal)
    enrich_state    TEXT,             -- 'mitre' (skeleton) | 'nvd' (enriched) | NULL (legacy)
    source          TEXT,             -- provenance: stratum that wrote this row ('mitre' | 'nvd')
    fetched_at      TEXT,             -- provenance: when this row was written
    policy_version  TEXT,             -- provenance: the trust policy that authorized it
    complete        INTEGER,          -- provenance: was the underlying fetch provably whole
    distrusted      INTEGER DEFAULT 0,
    distrust_reason TEXT,
    discovered_at   TEXT,             -- when the stream first sighted this defect
    prompt_hash     TEXT,             -- LLM-draft provenance: sha256 of the prompt sent (sha256:<hex>)
    raw_text_hash   TEXT              -- LLM-draft provenance: sha256 of the raw source text fed (sha256:<hex>)
);
CREATE INDEX IF NOT EXISTS ix_defects_enrich_state ON defects(enrich_state);
CREATE INDEX IF NOT EXISTS ix_defects_published ON defects(published);

-- First-sighting timestamps, driving the "new since last tick" signal. Kept
-- separate from the catalog so a re-upsert of a defects row (enrichment) never
-- clobbers when the stream first saw it. `defect_id` is any peer-scheme id (not
-- just cve) — every ingested defect is marked seen here.
CREATE TABLE IF NOT EXISTS seen_defects (
    defect_id    TEXT PRIMARY KEY,
    first_seen TEXT
);

-- CISA KEV overlay — the exploitability_signal. KEV entries carry only a cveID,
-- so this is a CVE-keyed OVERLAY (not a new defect_type): it adds "this CVE is
-- known-exploited, required-action X, due-date Y, ransomware-linked Z" to an
-- existing cve row without owning the defect_id. Idempotent full refresh (the
-- static JSON is ~1,660 entries, tiny) — INSERT OR REPLACE on cve_id.
CREATE TABLE IF NOT EXISTS kev (
    cve_id           TEXT PRIMARY KEY,
    date_added       TEXT,
    vendor_project   TEXT,
    product          TEXT,
    name             TEXT,
    short_description TEXT,
    required_action  TEXT,
    due_date         TEXT,
    ransomware_use   TEXT,
    cwes             TEXT,            -- JSON array
    catalog_version  TEXT,
    date_released    TEXT,
    fetched_at       TEXT
);

-- Apple advisory fix-version overlay — the apple_fixes map. Apple's own
-- security advisories are authoritative for iOS/iPadOS/macOS fix versions
-- (NVD's Apple coverage is thin: it records the CPE but often no version
-- range, so the NVD observer silently skips most Apple CVEs). This is a
-- (cve_id, product)-keyed OVERLAY (not a new defect_type): it records the
-- earliest Apple version that fixed each CVE for each product, plus the
-- advisory article id that states it, so a observer (or territory assess)
-- can read a durable fix map instead of replaying Apple's index + every
-- advisory per assess. CI-side ingestion builds it (live index + optional
-- Wayback historical recovery); per-product idempotent full refresh
-- (DELETE WHERE product + INSERT), so advisories aged off the index do not
-- leave stale rows.
CREATE TABLE IF NOT EXISTS apple_fixes (
    cve_id       TEXT NOT NULL,
    product      TEXT NOT NULL,   -- iphone_os | ipados | macos
    fixed_in     TEXT,            -- earliest Apple version that fixed this CVE
    advisory_id  TEXT,            -- the HTxxxx / numeric article that states it
    fetched_at   TEXT,
    PRIMARY KEY (cve_id, product)
);

-- Debian security-tracker fix overlay — the debian_fixes map. Debian's own
-- tracker (security-tracker.debian.org/tracker/data/json) is AUTHORITATIVE for
-- per-source-package / per-release CVE status — the status words
-- ``resolved`` (with a fixed dpkg version, or ``"0"`` = not affected) / ``open``
-- / ``undetermined`` that the OSV Debian mirror does NOT carry. Those status
-- words are what clear NVD's unknown-fix false positives on a Debian host, so
-- this is a (cve_id, release, package)-keyed OVERLAY (not a new defect_type)
-- built from a DIFFERENT feed than the OSV catalog rows: the fix-version fields
-- incidentally overlap with OSV's Debian ecosystem rows, but the status column
-- is the new signal (same justification as apple_fixes, which carries Apple
-- fix data no catalog row has). CI-side ingestion builds it from the one bulk
-- tracker pull; per-(release, package) idempotent full refresh
-- (DELETE WHERE release+package + INSERT), so CVEs aged off a release sheet do
-- not leave stale rows.
CREATE TABLE IF NOT EXISTS debian_fixes (
    cve_id       TEXT NOT NULL,
    release      TEXT NOT NULL,   -- codename: trixie, bookworm, ...
    package      TEXT NOT NULL,   -- source package: linux, ...
    status       TEXT,            -- resolved | open | undetermined (raw tracker status)
    fixed_in     TEXT,            -- dpkg version, "0" = not affected, or NULL (open/undetermined)
    fetched_at   TEXT,
    PRIMARY KEY (cve_id, release, package)
);

-- Ubuntu security-tracker fix overlay — the ubuntu_fixes map. Ubuntu's own
-- tracker (ubuntu.com/security/cves.json bulk CVE feed) is AUTHORITATIVE for
-- per-source-package / per-release CVE status — the status words
-- ``released`` (with a fixed version note) / ``needed`` / ``pending`` /
-- ``needs-triage`` / ``not-affected`` / ``DNE`` / ``ignored`` / ``deferred``
-- that the OSV Ubuntu mirror does NOT carry verbatim. Those status words are
-- what clear NVD's unknown-fix false positives on an Ubuntu host, so this is a
-- (cve_id, release, package)-keyed OVERLAY (not a new defect_type) built from
-- a DIFFERENT feed than the OSV catalog rows: the fix-version fields
-- incidentally overlap with OSV's Ubuntu ecosystem rows, but the raw status
-- column is the new signal (same justification as debian_fixes / apple_fixes).
-- CI-side ingestion builds it from the paginated bulk CVE JSON (?package=
-- filter, one pagination per package); per-(release, package) idempotent full
-- refresh (DELETE WHERE release+package + INSERT), so CVEs aged off a release
-- sheet do not leave stale rows.
CREATE TABLE IF NOT EXISTS ubuntu_fixes (
    cve_id       TEXT NOT NULL,
    release      TEXT NOT NULL,   -- codename: noble, jammy, focal, ...
    package      TEXT NOT NULL,   -- source package: linux, ...
    status       TEXT,            -- released | needed | pending | needs-triage | not-affected | DNE | ignored | deferred (raw tracker status)
    fixed_in     TEXT,            -- the per-release note/description (fixed version when released); NULL when empty
    fetched_at   TEXT,
    PRIMARY KEY (cve_id, release, package)
);

-- EPSS (Exploit Prediction Scoring System, FIRST.org) overlay — the
-- exploitability_likelihood map. EPSS scores EVERY published CVE daily with a
-- 0..1 probability of exploitation in the next 30 days + a percentile, free +
-- unauthenticated. This is a CVE-keyed OVERLAY (not a new defect_type): it
-- annotates an existing cve catalog row with a likelihood signal. It is
-- COMPLEMENTARY to ``kev`` (KEV = ~1,700 confirmed-exploited; EPSS = all CVEs
-- predicted-likelihood) and fills the gap NVD's 2026-04-15 risk-based-
-- enrichment retreat left (NVD now enriches EPSS only for KEV/federal/
-- EO14028-critical CVEs; the long tail lost its EPSS). CI-side ingestion pulls
-- the one daily CSV snapshot; idempotent full refresh (DELETE all + INSERT),
-- so scores aged out (a CVE dropped from the EPSS model) leave no stale rows.
CREATE TABLE IF NOT EXISTS epss (
    cve_id       TEXT PRIMARY KEY,
    epss         REAL,            -- 0..1 probability of exploitation in 30 days
    percentile   REAL,            -- 0..1 proportion scored at or below this score
    fetched_at   TEXT
);

-- Generic key/value state — the stream cursor lives here
-- (state key "stream:mitre_cursor" = the last-processed cvelistV5 tip SHA), as
-- do "stream:last_tick" / "stream:last_summary". A point-in-time sample, not a
-- catch-up queue: if the machine was asleep, the next tick after wake is fine
-- (the daily assess/refresh still owns the back-catalog).
CREATE TABLE IF NOT EXISTS state (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  TEXT
);
"""


def _now() -> str:
    # ISO-8601 UTC. (We avoid a local-now helper that breaks under some
    # harnesses; callers may pass a timestamp, and we stamp on commit.)
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _columns(conn, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _has_table(conn, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _migrate(conn: sqlite3.Connection) -> None:
    """In-place schema migration runner, gated by `PRAGMA user_version`.

    The schema is `CREATE TABLE IF NOT EXISTS` (idempotent for FRESH dbs), but
    that cannot rename a column or add one to an EXISTING db. This runner does
    the additive, introspection-guarded ALTERs that older dbs need, then bumps
    `user_version`. v0->v1 + v1->v2 reshape the catalog/crosswalk; v3 dedups
    candidates; v4 renames the five id columns witness->observer; v5 renames the
    catalog layer flaw->defect (tables + three columns); v6 adds per-row
    LLM-draft provenance columns (prompt_hash, raw_text_hash). Territory rows
    (verdicts / device_posture values) are never deleted — v4 changes their
    column NAMES but preserves their DATA. Each step is guarded so it is safe to
    re-run on an already-migrated db (and a no-op on a fresh db created with the
    current SCHEMA).
    """
    version = conn.execute("PRAGMA user_version").fetchone()[0]

    if version < 1:
        # v0 -> v1: the spine becomes the alias graph.
        #   (a) crosswalk: cve-centric (cve, alias, kind) -> (defect_id, alias, kind)
        #       so a non-cve defect with no cve can anchor as a first-class peer.
        #   (b) cves: add defect_type so peer rows record their scheme; backfill
        #       'cve' for pre-existing CVE rows.
        if "cve" in _columns(conn, "crosswalk") and "defect_id" not in _columns(conn, "crosswalk"):
            conn.execute("ALTER TABLE crosswalk RENAME COLUMN cve TO defect_id")
        # On a v0 db the catalog table is still `cves`; add defect_type + backfill.
        # On a fresh db (or one already at v2) the table is `defects` with defect_type
        # already present, so this step is a guarded no-op.
        if _has_table(conn, "cves") and "defect_type" not in _columns(conn, "cves"):
            conn.execute("ALTER TABLE cves ADD COLUMN defect_type TEXT")
            conn.execute("UPDATE cves SET defect_type='cve' WHERE defect_type IS NULL")
        conn.execute("PRAGMA user_version = 1")
        conn.commit()

    if version < 2:
        # v1 -> v2: de-cve the defect-catalog layer's names.
        #   (a) cves -> defects (the catalog holds defects of every peer scheme, not
        #       just cve; the table name lied).
        #   (b) seen_cves -> seen_defects + its cve_id column -> defect_id (it tracks
        #       first-sighting of ANY defect_id, not just cve).
        # connect() runs SCHEMA first, so on a v1 db `CREATE TABLE IF NOT EXISTS
        # defects` already made an EMPTY defects placeholder. Drop it, then rename the
        # data-bearing legacy table over it. Guarded by `_has_table('cves')` so a
        # v2 re-open (cves gone) and a fresh db (cves never existed) both skip.
        # Territory (verdicts / device_posture) is byte-untouched, as in v0->v1.
        if _has_table(conn, "cves"):
            conn.execute("DROP TABLE IF EXISTS defects")           # empty SCHEMA placeholder
            conn.execute("ALTER TABLE cves RENAME TO defects")
            # indices are reparented to the renamed table under their old names; drop
            # the old ix_cves_* and create ix_defects_* (the placeholder's ix_defects_*
            # were dropped with the placeholder table above).
            conn.execute("DROP INDEX IF EXISTS ix_cves_enrich_state")
            conn.execute("DROP INDEX IF EXISTS ix_cves_published")
            conn.execute("CREATE INDEX IF NOT EXISTS ix_defects_enrich_state ON defects(enrich_state)")
            conn.execute("CREATE INDEX IF NOT EXISTS ix_defects_published ON defects(published)")
        if _has_table(conn, "seen_cves"):
            conn.execute("DROP TABLE IF EXISTS seen_defects")      # empty placeholder
            conn.execute("ALTER TABLE seen_cves RENAME TO seen_defects")
        if _has_table(conn, "seen_defects") and "cve_id" in _columns(conn, "seen_defects") \
                and "defect_id" not in _columns(conn, "seen_defects"):
            conn.execute("ALTER TABLE seen_defects RENAME COLUMN cve_id TO defect_id")
        conn.execute("PRAGMA user_version = 2")
        conn.commit()

    if version < 3:
        # v2 -> v3: discovery candidates become idempotent on url.
        #   `posture discover` runs DAILY in CI (spine.yml) and re-surfaces the
        #   static AGGREGATORS every run; a bare INSERT accumulated duplicate
        #   rows that then bloated the exported spine (candidates ARE part of
        #   the signed spine export). Dedup any existing dups first — keep the
        #   lowest id (oldest), so a human's adopted/rejected status survives —
        #   then enforce url uniqueness so `add_candidate` can upsert.
        if _has_table(conn, "candidates"):
            conn.execute(
                "DELETE FROM candidates WHERE id NOT IN "
                "(SELECT MIN(id) FROM candidates GROUP BY url)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS candidates_url_uq ON candidates(url)"
            )
        conn.execute("PRAGMA user_version = 3")
        conn.commit()

    if version < 4:
        # v3 -> v4: assessors are *observers*, not "witnesses". Rename the five
        # columns that carry the observer id so the schema's words match the
        # code. SQLite >= 3.25 RENAME COLUMN (CI runs Python 3.11); RENAME
        # rewrites the stored CREATE TABLE including the PRIMARY KEY clauses on
        # `verdicts` and `distrust_marks`. Guarded + idempotent: a column already
        # renamed is skipped, so a fresh db (created with the current SCHEMA, where
        # these are already `observer`) and a re-open of a v4 db (version>=4, never
        # enters) both no-op. The `state` table (stream cursor) is untouched.
        renames = [
            ("device_posture", "deciding_witness", "deciding_observer"),
            ("verdicts", "witness", "observer"),
            ("health_samples", "witness", "observer"),
            ("health_dossier", "witness", "observer"),
            ("distrust_marks", "witness", "observer"),
        ]
        for table, old, new in renames:
            if _has_table(conn, table) and old in _columns(conn, table) \
                    and new not in _columns(conn, table):
                conn.execute(
                    f"ALTER TABLE {table} RENAME COLUMN {old} TO {new}"
                )
        conn.execute("PRAGMA user_version = 4")
        conn.commit()

    if version < 5:
        # v4 -> v5: the catalog layer's words move flaw -> defect (the word the
        # rest of the code already uses). On a real v4 db the legacy names still
        # live: table `flaws` (with column `flaw_type`), table `seen_flaws` (with
        # `flaw_id`), and crosswalk column `flaw_id` (renamed from `cve` by the
        # historical v0->v1 step). connect() ran the current SCHEMA first, so
        # empty `defects`/`seen_defects` placeholders already exist; drop them and
        # rename the data-bearing legacy tables over them (the v1->v2 pattern).
        # Then rename the three `flaw_*` columns. Guarded + idempotent: a fresh db
        # (created with the current SCHEMA, where these are already `defect*`)
        # and a re-open of a v5 db (version>=5, never enters) both no-op.
        # Territory (verdicts / device_posture) is byte-untouched, as always.
        if _has_table(conn, "flaws"):
            conn.execute("DROP TABLE IF EXISTS defects")          # empty SCHEMA placeholder
            conn.execute("ALTER TABLE flaws RENAME TO defects")
            # indices reparent to the renamed table under their old names; drop
            # the legacy ix_flaws_* and create ix_defects_* (the placeholder's
            # ix_defects_* were dropped with the placeholder table above).
            conn.execute("DROP INDEX IF EXISTS ix_flaws_enrich_state")
            conn.execute("DROP INDEX IF EXISTS ix_flaws_published")
            conn.execute("CREATE INDEX IF NOT EXISTS ix_defects_enrich_state ON defects(enrich_state)")
            conn.execute("CREATE INDEX IF NOT EXISTS ix_defects_published ON defects(published)")
        if _has_table(conn, "seen_flaws"):
            conn.execute("DROP TABLE IF EXISTS seen_defects")     # empty placeholder
            conn.execute("ALTER TABLE seen_flaws RENAME TO seen_defects")
        if _has_table(conn, "defects") and "flaw_type" in _columns(conn, "defects") \
                and "defect_type" not in _columns(conn, "defects"):
            conn.execute("ALTER TABLE defects RENAME COLUMN flaw_type TO defect_type")
        if _has_table(conn, "seen_defects") and "flaw_id" in _columns(conn, "seen_defects") \
                and "defect_id" not in _columns(conn, "seen_defects"):
            conn.execute("ALTER TABLE seen_defects RENAME COLUMN flaw_id TO defect_id")
        if _has_table(conn, "crosswalk") and "flaw_id" in _columns(conn, "crosswalk") \
                and "defect_id" not in _columns(conn, "crosswalk"):
            conn.execute("ALTER TABLE crosswalk RENAME COLUMN flaw_id TO defect_id")
        conn.execute("PRAGMA user_version = 5")
        conn.commit()

    if version < 6:
        # v5 -> v6: per-row LLM-draft provenance. An LLM-drafted row already
        # carries provider+model in source='llm:<model>'; the two new columns
        # add the prompt sent and the raw source text fed, each as a sha256
        # digest, so retroactive distrust of a provider (or of one prompt
        # template / one advisory text) is one sweep over exactly its rows
        # (node_680976461c89). NULL on every non-llm row and on llm rows whose
        # provider did not report provenance — additive, no data rewrite.
        # Guarded so a fresh db (columns already in SCHEMA) and a re-open of a
        # v6 db both no-op; territory (verdicts / device_posture) untouched.
        if "prompt_hash" not in _columns(conn, "defects"):
            conn.execute("ALTER TABLE defects ADD COLUMN prompt_hash TEXT")
        if "raw_text_hash" not in _columns(conn, "defects"):
            conn.execute("ALTER TABLE defects ADD COLUMN raw_text_hash TEXT")
        conn.execute("PRAGMA user_version = 6")
        conn.commit()

    if version < 7:
        # v6 -> v7: carry the real numeric CVSS score, CVSS vector string, and
        # publish date through the verdict (not just the severity string). The
        # defects catalog already had these columns; the verdicts table did not.
        # ALTER TABLE ADD COLUMN is idempotent-guarded (a fresh db created with
        # the current SCHEMA already has the columns; a re-open of a v7 db
        # never enters). All three default NULL so existing rows and observers
        # that don't populate them are unaffected.
        verdicts_cols = _columns(conn, "verdicts")
        for col, decl in [("cvss", "REAL"), ("cvss_vector", "TEXT"), ("published", "TEXT")]:
            if col not in verdicts_cols:
                conn.execute(f"ALTER TABLE verdicts ADD COLUMN {col} {decl}")
        conn.execute("PRAGMA user_version = 7")
        conn.commit()


def connect(path: str, readonly: bool = False) -> sqlite3.Connection:
    """Open (and migrate) the posture DB. Creates the file if missing.

    The schema is all `CREATE TABLE IF NOT EXISTS`, so executing it on every
    open is a cheap, idempotent migration for fresh dbs; `_migrate` then applies
    the additive ALTERs an existing (older) db needs, gated by
    `PRAGMA user_version`. `readonly` is kept for API symmetry with Forebode;
    read commands simply don't write. (A strict read-only URI mode would error
    on a fresh DB on first run; the schema's idempotency makes always-migrate
    the simpler, robust choice.)
    """
    if path != ":memory:":
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.commit()
    return conn


@contextmanager
def closing(conn: sqlite3.Connection):
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Verdicts + per-axis posture (completeness-gated commit)
# ---------------------------------------------------------------------------

def commit_device_verdicts(
    conn: sqlite3.Connection,
    device_id: str,
    axis: str,
    verdicts: list[dict],
    complete: bool,
    policy_version: str,
    ts: str,
) -> str:
    """The one deletion gate for a device/axis. Returns one of:

      "swapped"             — provably complete; verdicts atomically replaced.
      "preserved-incomplete" — fetch not provably complete; rows left untouched.
      "preserved-empty"      — complete but zero verdicts against an axis that
                               previously had rows (suspect false-absent).

    A clean axis is NEVER silently empty — "complete and zero" against an axis
    that had rows is suspicious (a observer may have lost its voice), so we
    preserve rather than wipe. This is the no-wipe + no-silent-clean rule
    combined. The engine additionally never calls this for an axis with no
    observer at all (those are UNKNOWN at the posture layer, not committed).
    """
    if not complete:
        return "preserved-incomplete"
    existing = conn.execute(
        "SELECT COUNT(*) c FROM verdicts WHERE device_id=? AND axis=?",
        (device_id, axis),
    ).fetchone()["c"]
    if not verdicts and existing > 0:
        return "preserved-empty"
    conn.execute(
        "DELETE FROM verdicts WHERE device_id=? AND axis=?",
        (device_id, axis),
    )
    conn.executemany(
        """INSERT OR REPLACE INTO verdicts
           (device_id, axis, key, status, severity, fixed_in, detail,
            cvss, cvss_vector, published,
            observer, policy_version, fetched_at, complete, raw_ref, computed_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [
            (
                device_id, v["axis"], v["key"], v["status"], v.get("severity"),
                v.get("fixed_in"), v.get("detail", ""),
                v.get("cvss"), v.get("cvss_vector"), v.get("published"),
                v["provenance"]["observer"], v["provenance"]["policy_version"],
                v["provenance"]["fetched_at"], int(v["provenance"]["complete"]),
                v["provenance"].get("raw_ref"), ts,
            )
            for v in verdicts
        ],
    )
    return "swapped"


def upsert_axis_posture(
    conn: sqlite3.Connection,
    device_id: str,
    axis: str,
    status: str,
    deciding_observer: str | None,
    bias: str | None,
    gap: str | None,
    policy_version: str,
    ts: str,
) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO device_posture
           (device_id, axis, status, deciding_observer, bias, gap,
            policy_version, computed_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (device_id, axis, status, deciding_observer, bias, gap, policy_version, ts),
    )


def verdicts_for_device_axis(conn, device_id: str, axis: str) -> list[dict]:
    rows = conn.execute(
        """SELECT * FROM verdicts WHERE device_id=? AND axis=?
           ORDER BY key, observer""",
        (device_id, axis),
    ).fetchall()
    return [dict(r) for r in rows]


def axis_posture(conn, device_id: str, axis: str) -> dict | None:
    r = conn.execute(
        "SELECT * FROM device_posture WHERE device_id=? AND axis=?",
        (device_id, axis),
    ).fetchone()
    return dict(r) if r else None


def all_axis_posture(conn, device_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM device_posture WHERE device_id=? ORDER BY axis",
        (device_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Policy versions
# ---------------------------------------------------------------------------

def install_policy_version(conn, version: str, supersedes: str | None,
                            dated: str, rationale: str, yaml_text: str) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO policy_versions
           (version, supersedes, dated, rationale, yaml, installed_at)
           VALUES (?,?,?,?,?,?)""",
        (version, supersedes, dated, rationale, yaml_text, _now()),
    )


def active_policy_version(conn) -> dict | None:
    r = conn.execute(
        "SELECT * FROM policy_versions ORDER BY installed_at DESC LIMIT 1"
    ).fetchone()
    return dict(r) if r else None


def policy_log(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT version, supersedes, dated, rationale, installed_at "
        "FROM policy_versions ORDER BY installed_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Source-health: operational samples + dated dossier
# ---------------------------------------------------------------------------

def record_health_sample(conn, observer: str, device_id: str, axis: str,
                          complete: bool, latency_ms: int, reason: str,
                          fetched_at: str) -> None:
    conn.execute(
        """INSERT INTO health_samples
           (observer, device_id, axis, complete, latency_ms, reason, fetched_at)
           VALUES (?,?,?,?,?,?,?)""",
        (observer, device_id, axis, int(complete), latency_ms, reason, fetched_at),
    )


def health_samples(conn, observer: str, limit: int = 50) -> list[dict]:
    rows = conn.execute(
        """SELECT * FROM health_samples WHERE observer=?
           ORDER BY id DESC LIMIT ?""",
        (observer, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def last_complete_sample(conn, observer: str) -> dict | None:
    r = conn.execute(
        """SELECT * FROM health_samples WHERE observer=? AND complete=1
           ORDER BY id DESC LIMIT 1""",
        (observer,),
    ).fetchone()
    return dict(r) if r else None


def add_dossier_entry(conn, observer: str, date: str, axis: str, claim: str,
                       citation: str, direction: str) -> None:
    conn.execute(
        """INSERT INTO health_dossier
           (observer, date, axis, claim, citation, direction, added_at)
           VALUES (?,?,?,?,?,?,?)""",
        (observer, date, axis, claim, citation, direction, _now()),
    )


def dossier(conn, observer: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM health_dossier WHERE observer=? ORDER BY date DESC, id DESC",
        (observer,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Spine alias graph (alias↔alias crosswalk)
# ---------------------------------------------------------------------------

def add_crosswalk(conn, defect_id: str, alias: str, kind: str) -> None:
    """Record ONE directed edge: defect_id is also known as `alias` under scheme
    `kind`. Idempotent. Most callers want the symmetric :func:`add_defect_alias`
    so resolve returns correctly-typed aliases in BOTH directions."""
    conn.execute(
        "INSERT OR IGNORE INTO crosswalk (defect_id, alias, kind) VALUES (?,?,?)",
        (defect_id, alias, kind),
    )


def add_defect_alias(conn, a: str, kind_a: str, b: str, kind_b: str) -> None:
    """Record the symmetric equivalence of two defect_ids: `a` (scheme `kind_a`)
    and `b` (scheme `kind_b`). Writes BOTH directed edges
    (a -> b@kind_b) + (b -> a@kind_a) so `resolve(a)` returns b typed as
    kind_b AND `resolve(b)` returns a typed as kind_a. This is the correctness
    fix a single directed edge cannot give, and the reason a non-cve defect with
    no cve can still anchor as a first-class peer. Idempotent."""
    add_crosswalk(conn, a, b, kind_b)
    add_crosswalk(conn, b, a, kind_a)


def resolve_crosswalk(conn, defect_id: str) -> list[dict]:
    """All known aliases of a defect_id (each {alias, kind})."""
    rows = conn.execute(
        "SELECT alias, kind FROM crosswalk WHERE defect_id=? ORDER BY kind, alias",
        (defect_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def crosswalk_all(conn) -> list[dict]:
    """All crosswalk rows, ordered by (defect_id, kind, alias) — the stable shape
    the spine export serializes and the round-trip test compares against."""
    rows = conn.execute(
        "SELECT defect_id, alias, kind FROM crosswalk ORDER BY defect_id, kind, alias"
    ).fetchall()
    return [dict(r) for r in rows]


def reverse_crosswalk(conn, alias: str) -> list[dict]:
    """All defect_ids known to share this alias (each {defect_id, kind})."""
    rows = conn.execute(
        "SELECT defect_id, kind FROM crosswalk WHERE alias=? ORDER BY kind, defect_id",
        (alias,),
    ).fetchall()
    return [dict(r) for r in rows]


def defect_type_counts(conn) -> list[dict]:
    """Distinct defect_type values in the catalog + their row counts — the
    peer registry `posture spine show` renders. Ordered by defect_type."""
    rows = conn.execute(
        "SELECT defect_type, COUNT(*) AS n FROM defects "
        "GROUP BY defect_type ORDER BY defect_type"
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Discovery candidates
# ---------------------------------------------------------------------------

def add_candidate(conn, url: str, fmt: str, axis: str, note: str = "") -> None:
    """Idempotent on url (the v3 migration enforces candidates_url_uq).
    Re-surfacing the same aggregator refreshes its fmt/axis/note from the
    latest definition but PRESERVES status + added_at — a human's
    adopted/rejected review decision is never wiped by a re-scan (which is
    why CI can run `posture discover` daily without spamming the table or
    resetting prior decisions)."""
    conn.execute(
        """INSERT INTO candidates (url, fmt, axis, status, note, added_at)
           VALUES (?,?,?,?,?,?)
           ON CONFLICT(url) DO UPDATE SET
               fmt=excluded.fmt, axis=excluded.axis, note=excluded.note""",
        (url, fmt, axis, "review", note, _now()),
    )


def candidates(conn, status: str | None = None) -> list[dict]:
    if status:
        rows = conn.execute(
            "SELECT * FROM candidates WHERE status=? ORDER BY id DESC", (status,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM candidates ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def set_candidate_status(conn, url: str, status: str) -> None:
    conn.execute("UPDATE candidates SET status=? WHERE url=?", (status, url))


# ---------------------------------------------------------------------------
# Provenance: audit + retroactive distrust (marks, never deletes)
# ---------------------------------------------------------------------------

def audit_observer(conn, observer: str) -> list[dict]:
    """All stored verdicts whose provenance rests on `observer`."""
    rows = conn.execute(
        """SELECT device_id, axis, key, status, observer, policy_version,
                  fetched_at, complete, distrusted, distrust_reason
           FROM verdicts WHERE observer=? ORDER BY device_id, axis, key""",
        (observer,),
    ).fetchall()
    return [dict(r) for r in rows]


def mark_distrust(conn, observer: str, reason: str) -> int:
    """Mark (not delete) every verdict resting on `observer` as distrusted.
    Returns the count of marked verdicts. Records are kept — you retain the
    fact that you no longer trust them, auditable and re-evaluable."""
    n = conn.execute(
        """UPDATE verdicts SET distrusted=1, distrust_reason=?
           WHERE observer=? AND (distrusted IS NULL OR distrusted=0)""",
        (reason, observer),
    ).rowcount
    conn.execute(
        """INSERT OR REPLACE INTO distrust_marks (observer, marked_at, reason)
           VALUES (?,?,?)""",
        (observer, _now(), reason),
    )
    return n


def distrust_marks(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM distrust_marks ORDER BY marked_at DESC").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Glossary — terms, signals, changes, spine bindings
# ---------------------------------------------------------------------------

def upsert_term(conn, t: dict) -> None:
    """Insert or replace a term row. `t` carries: id, label, kind, roles (list),
    status, successor, citation, discovered_at, promoted_at, notes."""
    import json as _json
    conn.execute(
        """INSERT OR REPLACE INTO glossary
           (id, label, kind, roles, status, successor, citation,
            discovered_at, promoted_at, notes)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (t["id"], t.get("label", ""), t.get("kind", ""),
         _json.dumps(t.get("roles") or [], sort_keys=True),
         t.get("status", "known"), t.get("successor"), t.get("citation", ""),
         t.get("discovered_at", ""), t.get("promoted_at"), t.get("notes", "")),
    )


def get_term(conn, term_id: str) -> dict | None:
    r = conn.execute("SELECT * FROM glossary WHERE id=?", (term_id,)).fetchone()
    if not r:
        return None
    import json as _json
    d = dict(r)
    d["roles"] = _json.loads(d.get("roles") or "[]")
    return d


def all_terms(conn, status: str | None = None) -> list[dict]:
    if status:
        rows = conn.execute("SELECT * FROM glossary WHERE status=? ORDER BY id",
                            (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM glossary ORDER BY id").fetchall()
    import json as _json
    out = []
    for r in rows:
        d = dict(r)
        d["roles"] = _json.loads(d.get("roles") or "[]")
        out.append(d)
    return out


def set_term_status(conn, term_id: str, status: str,
                    successor: str | None = None,
                    promoted_at: str | None = None) -> None:
    if successor is not None:
        conn.execute("UPDATE glossary SET status=?, successor=? WHERE id=?",
                      (status, successor, term_id))
    else:
        conn.execute("UPDATE glossary SET status=? WHERE id=?", (status, term_id))
    if promoted_at:
        conn.execute("UPDATE glossary SET promoted_at=? WHERE id=?",
                      (promoted_at, term_id))


def add_term_signal(conn, kind: str, label: str, context: str,
                    citation: str, detected_at: str) -> int:
    cur = conn.execute(
        """INSERT INTO term_signals (kind, label, context, citation, detected_at)
           VALUES (?,?,?,?,?)""",
        (kind, label, context, citation, detected_at),
    )
    return int(cur.lastrowid)


def term_signals(conn, status: str | None = None) -> list[dict]:
    if status:
        rows = conn.execute("SELECT * FROM term_signals WHERE status=? "
                            "ORDER BY id DESC", (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM term_signals ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def set_signal_status(conn, signal_id: int, status: str) -> None:
    conn.execute("UPDATE term_signals SET status=? WHERE id=?", (status, signal_id))


def record_term_change(conn, action: str, term_id: str, detail: str,
                       actor: str, version: str, at: str) -> None:
    conn.execute(
        """INSERT INTO term_changes (action, term_id, detail, actor, version, at)
           VALUES (?,?,?,?,?,?)""",
        (action, term_id, detail, actor, version, at),
    )


def term_changes(conn, term_id: str | None = None) -> list[dict]:
    if term_id:
        rows = conn.execute("SELECT * FROM term_changes WHERE term_id=? "
                            "ORDER BY id DESC", (term_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM term_changes ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def set_spine_binding(conn, role: str, term_id: str, at: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO spine_bindings (role, term_id, bound_at) VALUES (?,?,?)",
        (role, term_id, at),
    )


def get_spine_binding(conn, role: str) -> dict | None:
    r = conn.execute("SELECT * FROM spine_bindings WHERE role=?", (role,)).fetchone()
    return dict(r) if r else None


def all_spine_bindings(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM spine_bindings ORDER BY role").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Repair proposals
# ---------------------------------------------------------------------------

def upsert_repair_proposal(conn, p_id: str, kind: str, detail: str,
                           proposed_action: dict, evidence: dict,
                           raised_at: str, status: str = "open") -> None:
    import json as _json
    conn.execute(
        """INSERT OR REPLACE INTO repair_proposals
           (id, kind, detail, proposed_action, evidence, raised_at, status)
           VALUES (?,?,?,?,?,?,?)""",
        (p_id, kind, detail, _json.dumps(proposed_action, sort_keys=True),
         _json.dumps(evidence, sort_keys=True), raised_at, status),
    )


def repair_proposal(conn, p_id: str) -> dict | None:
    r = conn.execute("SELECT * FROM repair_proposals WHERE id=?", (p_id,)).fetchone()
    if not r:
        return None
    import json as _json
    d = dict(r)
    d["proposed_action"] = _json.loads(d.get("proposed_action") or "{}")
    d["evidence"] = _json.loads(d.get("evidence") or "{}")
    return d


def all_repair_proposals(conn, status: str | None = None) -> list[dict]:
    if status:
        rows = conn.execute("SELECT * FROM repair_proposals WHERE status=? "
                            "ORDER BY raised_at DESC", (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM repair_proposals "
                            "ORDER BY raised_at DESC").fetchall()
    import json as _json
    out = []
    for r in rows:
        d = dict(r)
        d["proposed_action"] = _json.loads(d.get("proposed_action") or "{}")
        d["evidence"] = _json.loads(d.get("evidence") or "{}")
        out.append(d)
    return out


def set_repair_proposal_status(conn, p_id: str, status: str) -> None:
    conn.execute("UPDATE repair_proposals SET status=? WHERE id=?", (status, p_id))


# ---------------------------------------------------------------------------
# Defect catalog — the spine as a stream (provenance-stamped, no-wipe)
# ---------------------------------------------------------------------------

def upsert_defect(conn, rec: dict) -> None:
    """Upsert one catalog row. Provenance is stamped on every write
    (source/fetched_at/policy_version/complete).

    The ON CONFLICT clause deliberately does NOT touch ``enrich_state``,
    ``distrusted``, ``distrust_reason``, or ``discovered_at`` — so an NVD
    enrichment re-upserting a MITRE skeleton cannot flip its stream state back,
    a re-skeleton cannot un-distrust a row, and first-sighting is permanent.
    (Mirrors the product CLI's catalog upsert preserving kev/epss; here the
    preserved fields are the stream/enrichment provenance.) Set those via
    :func:`set_enrich_state` / :func:`mark_defect_distrust` / :func:`mark_seen`.
    """
    import json as _json
    conn.execute(
        """INSERT INTO defects
             (id, defect_type, published, cvss, severity, cvss_vector, description,
              fixed_raw, refs, cwe, ref_tags, source, fetched_at,
              policy_version, complete)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             defect_type=excluded.defect_type, published=excluded.published,
             cvss=excluded.cvss, severity=excluded.severity,
             cvss_vector=excluded.cvss_vector, description=excluded.description,
             fixed_raw=excluded.fixed_raw, refs=excluded.refs, cwe=excluded.cwe,
             ref_tags=excluded.ref_tags, source=excluded.source,
             fetched_at=excluded.fetched_at,
             policy_version=excluded.policy_version, complete=excluded.complete""",
        (
            rec["id"],
            rec.get("defect_type", "cve"),
            rec.get("published"),
            rec.get("cvss"),
            rec.get("severity"),
            rec.get("cvss_vector"),
            rec.get("description", ""),
            _json.dumps(rec.get("fixed_raw"), default=str, sort_keys=True)
                if rec.get("fixed_raw") is not None else None,
            _json.dumps(rec.get("refs", [])),
            _json.dumps(rec.get("cwe", [])),
            _json.dumps(rec.get("ref_tags", [])),
            rec.get("source"),
            rec.get("fetched_at"),
            rec.get("policy_version"),
            int(rec.get("complete", 1)),
        ),
    )
    # first sighting of a brand-new id (no row existed -> INSERT happened)
    if conn.execute("SELECT discovered_at FROM defects WHERE id=?", (rec["id"],)).fetchone()["discovered_at"] is None:
        conn.execute("UPDATE defects SET discovered_at=? WHERE id=? AND discovered_at IS NULL",
                      (_now(), rec["id"]))


def set_enrich_state(conn, defect_id: str, state: str | None) -> None:
    """Set the stream/enrichment stratum of one defect: 'mitre' (skeleton, NVD not
    yet seen), 'nvd' (enriched), or NULL. Explicit only — upsert_defect won't flip
    it, so an NVD re-upsert can't accidentally erase the stream provenance."""
    conn.execute("UPDATE defects SET enrich_state=? WHERE id=?", (state, defect_id))


def pending_enrichment_ids(conn, limit: int | None = None) -> list[str]:
    """Defect ids the stream sighted via MITRE but NVD hasn't enriched yet — the
    per-tick retry pool for incremental NVD enrichment. Most-recent first."""
    sql = "SELECT id FROM defects WHERE enrich_state='mitre' ORDER BY published DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return [r[0] for r in conn.execute(sql)]


def _parse_defect_row(row) -> dict:
    """Parse one defects row's JSON columns (fixed_raw/refs/cwe/ref_tags) back to
    Python values. Shared by :func:`get_defect` and :func:`catalog_all` so the spine
    export/import and the CLI read through ONE parse path."""
    import json as _json
    d = dict(row)
    try:
        d["fixed_raw"] = _json.loads(d["fixed_raw"]) if d.get("fixed_raw") else None
    except (ValueError, TypeError):
        pass
    try:
        d["refs"] = _json.loads(d["refs"]) if d.get("refs") else []
    except (ValueError, TypeError):
        d["refs"] = []
    try:
        d["cwe"] = _json.loads(d["cwe"]) if d.get("cwe") else []
    except (ValueError, TypeError):
        d["cwe"] = []
    try:
        d["ref_tags"] = _json.loads(d["ref_tags"]) if d.get("ref_tags") else []
    except (ValueError, TypeError):
        d["ref_tags"] = []
    return d


def get_defect(conn, defect_id: str) -> dict | None:
    """One catalog row with fixed_raw/refs parsed back to Python values."""
    r = conn.execute("SELECT * FROM defects WHERE id=?", (defect_id,)).fetchone()
    if not r:
        return None
    return _parse_defect_row(r)


def catalog_list(conn, enrich_state: str | None = None, limit: int = 100,
                 offset: int = 0) -> list[dict]:
    """Catalog rows, most-recent first. ``enrich_state`` filters to 'mitre' or
    'nvd' skeletons/enriched rows when given."""
    if enrich_state:
        rows = conn.execute(
            "SELECT * FROM defects WHERE enrich_state=? ORDER BY published DESC "
            "LIMIT ? OFFSET ?", (enrich_state, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM defects ORDER BY published DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def catalog_all(conn, enrich_state: str | None = None) -> list[dict]:
    """All catalog rows, parsed, ordered by id — the stable full snapshot the
    spine export serializes and the round-trip test compares against. No
    ``LIMIT`` (caller owns memory; the spine is a point-in-time full snapshot,
    not a paginated browse). ``enrich_state`` filters to 'mitre'/'nvd' when
    given, mirroring :func:`catalog_list`."""
    if enrich_state:
        rows = conn.execute(
            "SELECT * FROM defects WHERE enrich_state=? ORDER BY id", (enrich_state,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM defects ORDER BY id").fetchall()
    return [_parse_defect_row(r) for r in rows]


def defects_for_cpe_head(conn, head: str) -> list[dict]:
    """NVD-enriched catalog rows whose affected CPE set includes ``head`` —
    the offline assess read path. A catalog-backed observer reads these
    instead of curling NVD: the defect axis decides from the imported spine
    with NO network (the release condition that retires the live-curl assess
    path).

    ``head`` is a lowercased ``part:vendor:product`` CPE head (the match key
    :func:`posture.sources.nvd_cve._cpe_head` produces). Only NVD-sourced rows
    carry CPE heads (``fixed_raw.cpe_heads``, built by
    :func:`posture.refresh._enriched_record`); OSV/GHSA rows are ecosystem/
    package-shaped, not CPE-shaped, so they are excluded by construction (their
    ``fixed_raw`` has no ``cpe_heads``). Distrusted rows are skipped — a
    retroactively-distrusted coordinate is not re-emitted as a verdict (the
    map is not the territory, and a distrusted map point stays distrusted).

    Returns parsed rows (fixed_raw/refs/cwe/ref_tags restored to Python
    values), ordered by id for determinism. No ``LIMIT``: the spine is a
    point-in-time snapshot, not a paginated browse (mirrors :func:`catalog_all`
    — the caller owns memory; assess fans out per device CPE head)."""
    out: list[dict] = []
    rows = conn.execute(
        "SELECT * FROM defects WHERE source='nvd' "
        "AND (distrusted IS NULL OR distrusted=0) ORDER BY id"
    ).fetchall()
    for r in rows:
        d = _parse_defect_row(r)
        fr = d.get("fixed_raw") or {}
        if head in (fr.get("cpe_heads") or []):
            out.append(d)
    return out


def mark_defect_distrust(conn, defect_id: str, reason: str) -> bool:
    """Retroactive distrust MARK on one catalog row (never a delete — you keep
    the fact that you no longer trust this row's provenance, auditable). Returns
    True if a row was newly marked."""
    cur = conn.execute(
        "UPDATE defects SET distrusted=1, distrust_reason=? "
        "WHERE id=? AND (distrusted IS NULL OR distrusted=0)",
        (reason, defect_id),
    )
    return cur.rowcount > 0


def audit_llm_provider(conn, model: str) -> list[dict]:
    """All catalog rows drafted by the LLM provider ``model`` (source =
    ``llm:<model>``), parsed — the audit view for retroactive distrust. Mirrors
    :func:`audit_observer` for verdicts: ask, later, what a provider ever told
    the spine and whether it still holds. Rows are kept (never deleted) so the
    distrust is auditable and re-evaluable."""
    rows = conn.execute(
        "SELECT * FROM defects WHERE source=? ORDER BY id",
        (f"llm:{model}",),
    ).fetchall()
    return [_parse_defect_row(r) for r in rows]


def mark_llm_provider_distrust(conn, model: str, reason: str) -> int:
    """Retroactive distrust MARK on EVERY catalog row the LLM provider ``model``
    drafted (source = ``llm:<model>``) — the one-sweep retraction provenance
    enables (node_680976461c89): a provider found biased or captured is
    retractable in a single UPDATE that marks exactly its rows, never a delete.
    Returns the count of newly-marked rows. Real-source precedence still holds:
    a row a real source has since enriched has source='nvd' (not 'llm:<model>'),
    so it is untouched — only rows still owned by the provider are marked."""
    cur = conn.execute(
        "UPDATE defects SET distrusted=1, distrust_reason=? "
        "WHERE source=? AND (distrusted IS NULL OR distrusted=0)",
        (reason, f"llm:{model}"),
    )
    return cur.rowcount


# ---------------------------------------------------------------------------
# seen_defects — first-sighting drives the "new since last tick" signal
# ---------------------------------------------------------------------------

def mark_seen(conn, defect_ids: list[str]) -> set[str]:
    """Record first-sighting for any defect not seen before; return the set that
    was *newly* seen in this call (first_seen just set = new since last tick)."""
    newly: set[str] = set()
    now = _now()
    for fid in defect_ids:
        cur = conn.execute(
            "INSERT INTO seen_defects(defect_id, first_seen) VALUES (?, ?) "
            "ON CONFLICT DO NOTHING", (fid, now),
        )
        if cur.rowcount:
            newly.add(fid)
    return newly


def seen_first_seen(conn, defect_id: str) -> str | None:
    row = conn.execute("SELECT first_seen FROM seen_defects WHERE defect_id=?",
                       (defect_id,)).fetchone()
    return row["first_seen"] if row else None


def seen_defects(conn) -> list[dict]:
    """All first-sighting rows, ordered by defect_id — the spine export serializes
    these so a client can restore the 'new since last tick' timeline."""
    rows = conn.execute("SELECT defect_id, first_seen FROM seen_defects ORDER BY defect_id").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# CISA KEV overlay — the exploitability_signal (CVE-keyed overlay, not a defect_type)
# ---------------------------------------------------------------------------

def upsert_kev(conn, row: dict) -> None:
    """Upsert one KEV overlay row keyed on cve_id (idempotent full refresh)."""
    import json as _json
    conn.execute(
        """INSERT OR REPLACE INTO kev
             (cve_id, date_added, vendor_project, product, name,
              short_description, required_action, due_date, ransomware_use,
              cwes, catalog_version, date_released, fetched_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            row["cve_id"], row.get("date_added"), row.get("vendor_project"),
            row.get("product"), row.get("name"), row.get("short_description"),
            row.get("required_action"), row.get("due_date"),
            row.get("ransomware_use"),
            _json.dumps(row.get("cwes", [])),
            row.get("catalog_version"), row.get("date_released"),
            row.get("fetched_at"),
        ),
    )


def kev_all(conn) -> list[dict]:
    """All KEV overlay rows, ordered by cve_id — the stable shape the spine
    export serializes and the round-trip test compares against."""
    rows = conn.execute("SELECT * FROM kev ORDER BY cve_id").fetchall()
    out = []
    import json as _json
    for r in rows:
        d = dict(r)
        try:
            d["cwes"] = _json.loads(d["cwes"]) if d.get("cwes") else []
        except (ValueError, TypeError):
            d["cwes"] = []
        out.append(d)
    return out


def kev_for_cve(conn, cve_id: str) -> dict | None:
    """One KEV overlay row for a cve_id (parsed), or None."""
    import json as _json
    r = conn.execute("SELECT * FROM kev WHERE cve_id=?", (cve_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    try:
        d["cwes"] = _json.loads(d["cwes"]) if d.get("cwes") else []
    except (ValueError, TypeError):
        d["cwes"] = []
    return d


# ---------------------------------------------------------------------------
# EPSS (FIRST.org) exploitability-likelihood overlay — the epss map
# (cve_id-keyed overlay, not a defect_type)
# ---------------------------------------------------------------------------

def replace_epss(conn, rows: list[dict], fetched_at: str) -> int:
    """Idempotent full refresh of the ``epss`` overlay: DELETE every row then
    INSERT the freshly-pulled daily snapshot ``rows`` (each
    ``{cve_id, epss, percentile}``). Returns the number inserted. EPSS is a
    complete daily snapshot of every scored CVE, so a wholesale replace (not
    INSERT OR REPLACE) means a CVE dropped from the model leaves no stale row.
    No-wipe on the caller side: a failed fetch must NOT call this (preserve
    last-known-good). Touches ONLY ``epss`` — never ``defects`` / ``verdicts`` /
    territory."""
    conn.execute("DELETE FROM epss")
    n = 0
    for r in rows:
        conn.execute(
            """INSERT OR REPLACE INTO epss
                 (cve_id, epss, percentile, fetched_at)
               VALUES (?,?,?,?)""",
            (r["cve_id"], r.get("epss"), r.get("percentile"), fetched_at),
        )
        n += 1
    return n


def epss_all(conn) -> list[dict]:
    """All epss overlay rows, ordered by cve_id — the stable shape the spine
    export serializes and the round-trip test compares against."""
    rows = conn.execute("SELECT * FROM epss ORDER BY cve_id").fetchall()
    return [dict(r) for r in rows]


def epss_for_cve(conn, cve_id: str) -> dict | None:
    """One epss overlay row for a cve_id, or None. The threat-axis read path:
    the likelihood score + percentile for a device's candidate CVE."""
    r = conn.execute("SELECT * FROM epss WHERE cve_id=?", (cve_id,)).fetchone()
    return dict(r) if r else None


# ---------------------------------------------------------------------------
# Apple advisory fix-version overlay — the apple_fixes map
# ((cve_id, product)-keyed overlay, not a defect_type)
# ---------------------------------------------------------------------------

def replace_apple_fixes(conn, product: str, rows: list[dict],
                        fetched_at: str) -> int:
    """Idempotent per-product full refresh of the ``apple_fixes`` overlay:
    DELETE every existing row for ``product`` then INSERT the freshly-built
    fix map ``rows`` (each ``{cve_id, fixed_in, advisory_id}``). Returns the
    number inserted. Deleting-then-inserting (rather than INSERT OR REPLACE)
    means advisories aged off Apple's rolling index do not leave stale rows —
    the overlay always reflects the current rebuild. No-wipe: touches ONLY
    ``apple_fixes`` — never ``defects`` / ``verdicts`` / territory."""
    conn.execute("DELETE FROM apple_fixes WHERE product=?", (product,))
    n = 0
    for r in rows:
        conn.execute(
            """INSERT OR REPLACE INTO apple_fixes
                 (cve_id, product, fixed_in, advisory_id, fetched_at)
               VALUES (?,?,?,?,?)""",
            (r["cve_id"], product, r.get("fixed_in"),
             r.get("advisory_id"), fetched_at),
        )
        n += 1
    return n


def apple_fixes_all(conn) -> list[dict]:
    """All apple_fixes overlay rows, ordered by (product, cve_id) — the stable
    shape the spine export serializes and the round-trip test compares against."""
    rows = conn.execute(
        "SELECT * FROM apple_fixes ORDER BY product, cve_id").fetchall()
    return [dict(r) for r in rows]


def apple_fixes_for_product(conn, product: str) -> list[dict]:
    """All apple_fixes overlay rows for one product, ordered by cve_id — the
    shape a observer reads at assess time (the durable fix map for a device's
    product)."""
    rows = conn.execute(
        "SELECT * FROM apple_fixes WHERE product=? ORDER BY cve_id",
        (product,)).fetchall()
    return [dict(r) for r in rows]


def apple_fixes_for(conn, cve_id: str, product: str) -> dict | None:
    """One apple_fixes overlay row for a (cve_id, product), or None. The
    observer's decide path: read the durable fix version + advisory id instead
    of replaying Apple's index per assess."""
    r = conn.execute(
        "SELECT * FROM apple_fixes WHERE cve_id=? AND product=?",
        (cve_id, product)).fetchone()
    return dict(r) if r else None


# ---------------------------------------------------------------------------
# Debian security-tracker fix overlay — the debian_fixes map
# ((cve_id, release, package)-keyed overlay, not a defect_type)
# ---------------------------------------------------------------------------

def replace_debian_fixes(conn, release: str, package: str, rows: list[dict],
                         fetched_at: str) -> int:
    """Idempotent per-(release, package) full refresh of the ``debian_fixes``
    overlay: DELETE every existing row for ``(release, package)`` then INSERT the
    freshly-built sheet ``rows`` (each ``{cve_id, status, fixed_in}``). Returns
    the number inserted. Deleting-then-inserting (rather than INSERT OR REPLACE)
    means CVEs aged off a release sheet do not leave stale rows — the overlay
    always reflects the current rebuild. No-wipe: touches ONLY ``debian_fixes``
    — never ``defects`` / ``verdicts`` / territory."""
    conn.execute(
        "DELETE FROM debian_fixes WHERE release=? AND package=?",
        (release, package))
    n = 0
    for r in rows:
        conn.execute(
            """INSERT OR REPLACE INTO debian_fixes
                 (cve_id, release, package, status, fixed_in, fetched_at)
               VALUES (?,?,?,?,?,?)""",
            (r["cve_id"], release, package, r.get("status"),
             r.get("fixed_in"), fetched_at),
        )
        n += 1
    return n


def debian_fixes_all(conn) -> list[dict]:
    """All debian_fixes overlay rows, ordered by (release, package, cve_id) — the
    stable shape the spine export serializes and the round-trip test compares
    against."""
    rows = conn.execute(
        "SELECT * FROM debian_fixes ORDER BY release, package, cve_id"
    ).fetchall()
    return [dict(r) for r in rows]


def debian_fixes_for_release_package(conn, release: str, package: str) -> list[dict]:
    """All debian_fixes overlay rows for one (release, package), ordered by cve_id
    — the shape a observer reads at assess time (the durable status sheet for a
    device's release + source package)."""
    rows = conn.execute(
        "SELECT * FROM debian_fixes WHERE release=? AND package=? ORDER BY cve_id",
        (release, package)).fetchall()
    return [dict(r) for r in rows]


def debian_fixes_for(conn, cve_id: str, release: str, package: str) -> dict | None:
    """One debian_fixes overlay row for a (cve_id, release, package), or None. The
    observer's decide path: read the durable status + fixed version instead of
    replaying the Debian bulk tracker per assess."""
    r = conn.execute(
        "SELECT * FROM debian_fixes WHERE cve_id=? AND release=? AND package=?",
        (cve_id, release, package)).fetchone()
    return dict(r) if r else None


# ---------------------------------------------------------------------------
# Ubuntu security-tracker fix overlay — the ubuntu_fixes map
# ((cve_id, release, package)-keyed overlay, not a defect_type)
# ---------------------------------------------------------------------------

def replace_ubuntu_fixes(conn, release: str, package: str, rows: list[dict],
                        fetched_at: str) -> int:
    """Idempotent per-(release, package) full refresh of the ``ubuntu_fixes``
    overlay: DELETE every existing row for ``(release, package)`` then INSERT the
    freshly-built sheet ``rows`` (each ``{cve_id, status, fixed_in}``). Returns
    the number inserted. Deleting-then-inserting (rather than INSERT OR REPLACE)
    means CVEs aged off a release sheet do not leave stale rows — the overlay
    always reflects the current rebuild. No-wipe: touches ONLY ``ubuntu_fixes``
    — never ``defects`` / ``verdicts`` / territory."""
    conn.execute(
        "DELETE FROM ubuntu_fixes WHERE release=? AND package=?",
        (release, package))
    n = 0
    for r in rows:
        conn.execute(
            """INSERT OR REPLACE INTO ubuntu_fixes
                 (cve_id, release, package, status, fixed_in, fetched_at)
               VALUES (?,?,?,?,?,?)""",
            (r["cve_id"], release, package, r.get("status"),
             r.get("fixed_in"), fetched_at),
        )
        n += 1
    return n


def ubuntu_fixes_all(conn) -> list[dict]:
    """All ubuntu_fixes overlay rows, ordered by (release, package, cve_id) — the
    stable shape the spine export serializes and the round-trip test compares
    against."""
    rows = conn.execute(
        "SELECT * FROM ubuntu_fixes ORDER BY release, package, cve_id"
    ).fetchall()
    return [dict(r) for r in rows]


def ubuntu_fixes_for_release_package(conn, release: str, package: str) -> list[dict]:
    """All ubuntu_fixes overlay rows for one (release, package), ordered by cve_id
    — the shape a observer reads at assess time (the durable status sheet for a
    device's release + source package)."""
    rows = conn.execute(
        "SELECT * FROM ubuntu_fixes WHERE release=? AND package=? ORDER BY cve_id",
        (release, package)).fetchall()
    return [dict(r) for r in rows]


def ubuntu_fixes_for(conn, cve_id: str, release: str, package: str) -> dict | None:
    """One ubuntu_fixes overlay row for a (cve_id, release, package), or None. The
    observer's decide path: read the durable status + fixed note instead of
    replaying the Ubuntu per-CVE tracker HTML per assess."""
    r = conn.execute(
        "SELECT * FROM ubuntu_fixes WHERE cve_id=? AND release=? AND package=?",
        (cve_id, release, package)).fetchone()
    return dict(r) if r else None


# ---------------------------------------------------------------------------
# Generic kv state — the stream cursor + tick summaries
# ---------------------------------------------------------------------------

def get_state(conn, key: str) -> str | None:
    row = conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_state(conn, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO state(key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
        "updated_at=excluded.updated_at", (key, value, _now()),
    )


# ---------------------------------------------------------------------------
# Incremental verdict upsert — the no-wipe per-key path (Phase 2 refresh)
# ---------------------------------------------------------------------------

def upsert_verdict(conn, v: dict, ts: str) -> None:
    """Per-key verdict upsert — the no-wipe counterpart to
    :func:`commit_device_verdicts`. INSERT ... ON CONFLICT(device_id, axis, key,
    observer) DO UPDATE: only the touched CVE's row is updated; every other
    verdict for the device/axis is left byte-identical. An incomplete fetch
    simply upserts fewer rows — it can never delete last-known-good verdicts the
    way a bulk DELETE-then-INSERT can.

    Used by the incremental refresh (per-CVE NVD enrichment -> re-decide -> one
    upsert). The full re-pull (rare reconciliation) still goes through
    ``commit_device_verdicts`` via ``assess``.
    """
    prov = v.get("provenance") or {}
    # accept a Provenance dataclass as well as a dict (the engine stamps one)
    if hasattr(prov, "to_dict"):
        prov = prov.to_dict()
    conn.execute(
        """INSERT INTO verdicts
             (device_id, axis, key, status, severity, fixed_in, detail,
              observer, policy_version, fetched_at, complete, raw_ref, computed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(device_id, axis, key, observer) DO UPDATE SET
             status=excluded.status, severity=excluded.severity,
             fixed_in=excluded.fixed_in, detail=excluded.detail,
             policy_version=excluded.policy_version, fetched_at=excluded.fetched_at,
             complete=excluded.complete, raw_ref=excluded.raw_ref,
             computed_at=excluded.computed_at""",
        (
            v["device_id"], v["axis"], v["key"], v["status"],
            v.get("severity"), v.get("fixed_in"), v.get("detail", ""),
            prov.get("observer") or v.get("observer", ""),
            prov.get("policy_version", ""),
            prov.get("fetched_at", ""),
            int(prov.get("complete", 1)),
            prov.get("raw_ref"),
            ts,
        ),
    )