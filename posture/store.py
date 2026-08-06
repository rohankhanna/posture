"""sqlite storage — verdicts (provenance-stamped), axis posture, versioned
policy, source-health samples/dossier, spine crosswalk, discovery candidates,
and distrust marks.

The load-bearing rule lives in `commit_device_verdicts`: a device's stored
verdicts for an axis are only replaced when the witness fetch was *provably
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
    deciding_witness TEXT,
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
    witness     TEXT,
    device_id   TEXT,
    axis        TEXT,
    complete    INTEGER,
    latency_ms  INTEGER,
    reason      TEXT,
    fetched_at  TEXT
);

CREATE TABLE IF NOT EXISTS health_dossier (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    witness    TEXT,
    date       TEXT,
    axis       TEXT,
    claim      TEXT,
    citation   TEXT,
    direction  TEXT,
    added_at   TEXT
);

-- The alias graph (alias↔alias). Every flaw_id — cve, ghsa, osv, rustsec, pysec,
-- go, … — is a peer; cve is NOT a primary key. A row is ONE directed edge
-- (flaw_id, alias, kind): "flaw_id is also known as alias under scheme kind".
-- Ingestion uses add_flaw_alias() to write BOTH directed edges of an equivalence
-- so resolve returns correctly-typed aliases in both directions. The spine
-- entity (the equivalence class) is a LOGICAL view over this graph, not a row.
CREATE TABLE IF NOT EXISTS crosswalk (
    flaw_id TEXT,
    alias   TEXT,
    kind    TEXT,
    PRIMARY KEY (flaw_id, alias, kind)
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
    witness   TEXT PRIMARY KEY,
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

-- The flaw catalog — the spine as a stream, not just a per-pull result. `id`
-- is a flaw_id under any peer scheme (cve, ghsa, osv, rustsec, pysec, go, …);
-- `flaw_type` records which. Rows arrive many ways: (a) MITRE stream skeletons
-- (enrich_state='mitre', the foreign-authored map point with no verdict), (b)
-- NVD-enriched CVE rows (enrich_state='nvd', CVSS + affected ranges), and (c)
-- self-enriched peer rows (enrich_state='osv'/'ghsa', carrying their own
-- severity + ranges on ingest). Provenance is stamped on EVERY row
-- (source/fetched_at/policy_version/complete) so a catalog row, like a verdict,
-- can be retroactively distrusted rather than deleted. The map is not the
-- territory: a skeleton says "MITRE published this; NVD has not yet enriched
-- it" — never "this device is vulnerable."
CREATE TABLE IF NOT EXISTS cves (
    id              TEXT PRIMARY KEY,
    flaw_type       TEXT,             -- 'cve' | 'ghsa' | 'osv' | 'rustsec' | ... (the peer scheme)
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
    discovered_at   TEXT              -- when the stream first sighted this CVE
);
CREATE INDEX IF NOT EXISTS ix_cves_enrich_state ON cves(enrich_state);
CREATE INDEX IF NOT EXISTS ix_cves_published ON cves(published);

-- First-sighting timestamps, driving the "new since last tick" signal. Kept
-- separate from the catalog so a re-upsert of a cves row (enrichment) never
-- clobbers when the stream first saw it.
CREATE TABLE IF NOT EXISTS seen_cves (
    cve_id     TEXT PRIMARY KEY,
    first_seen TEXT
);

-- CISA KEV overlay — the exploitability_signal. KEV entries carry only a cveID,
-- so this is a CVE-keyed OVERLAY (not a new flaw_type): it adds "this CVE is
-- known-exploited, required-action X, due-date Y, ransomware-linked Z" to an
-- existing cve row without owning the flaw_id. Idempotent full refresh (the
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


def _migrate(conn: sqlite3.Connection) -> None:
    """In-place schema migration runner, gated by `PRAGMA user_version`.

    The schema is `CREATE TABLE IF NOT EXISTS` (idempotent for FRESH dbs), but
    that cannot rename a column or add one to an EXISTING db. This runner does
    the additive, introspection-guarded ALTERs that older dbs need, then bumps
    `user_version`. It touches ONLY the crosswalk rename + the cves flaw_type
    add — never verdicts / device_posture / territory, which are byte-untouched.
    Each step is guarded so it is safe to re-run on an already-migrated db
    (and a no-op on a fresh db created with the current SCHEMA).
    """
    version = conn.execute("PRAGMA user_version").fetchone()[0]

    if version < 1:
        # v0 -> v1: the spine becomes the alias graph.
        #   (a) crosswalk: cve-centric (cve, alias, kind) -> (flaw_id, alias, kind)
        #       so a non-cve flaw with no cve can anchor as a first-class peer.
        #   (b) cves: add flaw_type so peer rows record their scheme; backfill
        #       'cve' for pre-existing CVE rows.
        if "cve" in _columns(conn, "crosswalk") and "flaw_id" not in _columns(conn, "crosswalk"):
            conn.execute("ALTER TABLE crosswalk RENAME COLUMN cve TO flaw_id")
        if "flaw_type" not in _columns(conn, "cves"):
            conn.execute("ALTER TABLE cves ADD COLUMN flaw_type TEXT")
        conn.execute("UPDATE cves SET flaw_type='cve' WHERE flaw_type IS NULL")
        conn.execute("PRAGMA user_version = 1")
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
    that had rows is suspicious (a witness may have lost its voice), so we
    preserve rather than wipe. This is the no-wipe + no-silent-clean rule
    combined. The engine additionally never calls this for an axis with no
    witness at all (those are UNKNOWN at the posture layer, not committed).
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
            witness, policy_version, fetched_at, complete, raw_ref, computed_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [
            (
                device_id, v["axis"], v["key"], v["status"], v.get("severity"),
                v.get("fixed_in"), v.get("detail", ""),
                v["provenance"]["witness"], v["provenance"]["policy_version"],
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
    deciding_witness: str | None,
    bias: str | None,
    gap: str | None,
    policy_version: str,
    ts: str,
) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO device_posture
           (device_id, axis, status, deciding_witness, bias, gap,
            policy_version, computed_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (device_id, axis, status, deciding_witness, bias, gap, policy_version, ts),
    )


def verdicts_for_device_axis(conn, device_id: str, axis: str) -> list[dict]:
    rows = conn.execute(
        """SELECT * FROM verdicts WHERE device_id=? AND axis=?
           ORDER BY key, witness""",
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

def record_health_sample(conn, witness: str, device_id: str, axis: str,
                          complete: bool, latency_ms: int, reason: str,
                          fetched_at: str) -> None:
    conn.execute(
        """INSERT INTO health_samples
           (witness, device_id, axis, complete, latency_ms, reason, fetched_at)
           VALUES (?,?,?,?,?,?,?)""",
        (witness, device_id, axis, int(complete), latency_ms, reason, fetched_at),
    )


def health_samples(conn, witness: str, limit: int = 50) -> list[dict]:
    rows = conn.execute(
        """SELECT * FROM health_samples WHERE witness=?
           ORDER BY id DESC LIMIT ?""",
        (witness, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def last_complete_sample(conn, witness: str) -> dict | None:
    r = conn.execute(
        """SELECT * FROM health_samples WHERE witness=? AND complete=1
           ORDER BY id DESC LIMIT 1""",
        (witness,),
    ).fetchone()
    return dict(r) if r else None


def add_dossier_entry(conn, witness: str, date: str, axis: str, claim: str,
                       citation: str, direction: str) -> None:
    conn.execute(
        """INSERT INTO health_dossier
           (witness, date, axis, claim, citation, direction, added_at)
           VALUES (?,?,?,?,?,?,?)""",
        (witness, date, axis, claim, citation, direction, _now()),
    )


def dossier(conn, witness: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM health_dossier WHERE witness=? ORDER BY date DESC, id DESC",
        (witness,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Spine alias graph (alias↔alias crosswalk)
# ---------------------------------------------------------------------------

def add_crosswalk(conn, flaw_id: str, alias: str, kind: str) -> None:
    """Record ONE directed edge: flaw_id is also known as `alias` under scheme
    `kind`. Idempotent. Most callers want the symmetric :func:`add_flaw_alias`
    so resolve returns correctly-typed aliases in BOTH directions."""
    conn.execute(
        "INSERT OR IGNORE INTO crosswalk (flaw_id, alias, kind) VALUES (?,?,?)",
        (flaw_id, alias, kind),
    )


def add_flaw_alias(conn, a: str, kind_a: str, b: str, kind_b: str) -> None:
    """Record the symmetric equivalence of two flaw_ids: `a` (scheme `kind_a`)
    and `b` (scheme `kind_b`). Writes BOTH directed edges
    (a -> b@kind_b) + (b -> a@kind_a) so `resolve(a)` returns b typed as
    kind_b AND `resolve(b)` returns a typed as kind_a. This is the correctness
    fix a single directed edge cannot give, and the reason a non-cve flaw with
    no cve can still anchor as a first-class peer. Idempotent."""
    add_crosswalk(conn, a, b, kind_b)
    add_crosswalk(conn, b, a, kind_a)


def resolve_crosswalk(conn, flaw_id: str) -> list[dict]:
    """All known aliases of a flaw_id (each {alias, kind})."""
    rows = conn.execute(
        "SELECT alias, kind FROM crosswalk WHERE flaw_id=? ORDER BY kind, alias",
        (flaw_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def crosswalk_all(conn) -> list[dict]:
    """All crosswalk rows, ordered by (flaw_id, kind, alias) — the stable shape
    the spine export serializes and the round-trip test compares against."""
    rows = conn.execute(
        "SELECT flaw_id, alias, kind FROM crosswalk ORDER BY flaw_id, kind, alias"
    ).fetchall()
    return [dict(r) for r in rows]


def reverse_crosswalk(conn, alias: str) -> list[dict]:
    """All flaw_ids known to share this alias (each {flaw_id, kind})."""
    rows = conn.execute(
        "SELECT flaw_id, kind FROM crosswalk WHERE alias=? ORDER BY kind, flaw_id",
        (alias,),
    ).fetchall()
    return [dict(r) for r in rows]


def flaw_type_counts(conn) -> list[dict]:
    """Distinct flaw_type values in the catalog + their row counts — the
    peer registry `posture spine show` renders. Ordered by flaw_type."""
    rows = conn.execute(
        "SELECT flaw_type, COUNT(*) AS n FROM cves "
        "GROUP BY flaw_type ORDER BY flaw_type"
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Discovery candidates
# ---------------------------------------------------------------------------

def add_candidate(conn, url: str, fmt: str, axis: str, note: str = "") -> None:
    conn.execute(
        """INSERT INTO candidates (url, fmt, axis, status, note, added_at)
           VALUES (?,?,?,?,?,?)""",
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

def audit_witness(conn, witness: str) -> list[dict]:
    """All stored verdicts whose provenance rests on `witness`."""
    rows = conn.execute(
        """SELECT device_id, axis, key, status, witness, policy_version,
                  fetched_at, complete, distrusted, distrust_reason
           FROM verdicts WHERE witness=? ORDER BY device_id, axis, key""",
        (witness,),
    ).fetchall()
    return [dict(r) for r in rows]


def mark_distrust(conn, witness: str, reason: str) -> int:
    """Mark (not delete) every verdict resting on `witness` as distrusted.
    Returns the count of marked verdicts. Records are kept — you retain the
    fact that you no longer trust them, auditable and re-evaluable."""
    n = conn.execute(
        """UPDATE verdicts SET distrusted=1, distrust_reason=?
           WHERE witness=? AND (distrusted IS NULL OR distrusted=0)""",
        (reason, witness),
    ).rowcount
    conn.execute(
        """INSERT OR REPLACE INTO distrust_marks (witness, marked_at, reason)
           VALUES (?,?,?)""",
        (witness, _now(), reason),
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
# CVE catalog — the spine as a stream (provenance-stamped, no-wipe)
# ---------------------------------------------------------------------------

def upsert_cve(conn, rec: dict) -> None:
    """Upsert one catalog row. Provenance is stamped on every write
    (source/fetched_at/policy_version/complete).

    The ON CONFLICT clause deliberately does NOT touch ``enrich_state``,
    ``distrusted``, ``distrust_reason``, or ``discovered_at`` — so an NVD
    enrichment re-upserting a MITRE skeleton cannot flip its stream state back,
    a re-skeleton cannot un-distrust a row, and first-sighting is permanent.
    (Mirrors Forebode's upsert_cve preserving kev/epss; here the preserved
    fields are the stream/enrichment provenance.) Set those explicitly via
    :func:`set_enrich_state` / :func:`mark_cve_distrust` / :func:`mark_seen`.
    """
    import json as _json
    conn.execute(
        """INSERT INTO cves
             (id, flaw_type, published, cvss, severity, cvss_vector, description,
              fixed_raw, refs, cwe, ref_tags, source, fetched_at,
              policy_version, complete)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             flaw_type=excluded.flaw_type, published=excluded.published,
             cvss=excluded.cvss, severity=excluded.severity,
             cvss_vector=excluded.cvss_vector, description=excluded.description,
             fixed_raw=excluded.fixed_raw, refs=excluded.refs, cwe=excluded.cwe,
             ref_tags=excluded.ref_tags, source=excluded.source,
             fetched_at=excluded.fetched_at,
             policy_version=excluded.policy_version, complete=excluded.complete""",
        (
            rec["id"],
            rec.get("flaw_type", "cve"),
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
    if conn.execute("SELECT discovered_at FROM cves WHERE id=?", (rec["id"],)).fetchone()["discovered_at"] is None:
        conn.execute("UPDATE cves SET discovered_at=? WHERE id=? AND discovered_at IS NULL",
                      (_now(), rec["id"]))


def set_enrich_state(conn, cve_id: str, state: str | None) -> None:
    """Set the stream/enrichment stratum of one CVE: 'mitre' (skeleton, NVD not
    yet seen), 'nvd' (enriched), or NULL. Explicit only — upsert_cve won't flip
    it, so an NVD re-upsert can't accidentally erase the stream provenance."""
    conn.execute("UPDATE cves SET enrich_state=? WHERE id=?", (state, cve_id))


def pending_mitre_ids(conn, limit: int | None = None) -> list[str]:
    """CVE ids the stream sighted via MITRE but NVD hasn't enriched yet — the
    per-tick retry pool for incremental NVD enrichment. Most-recent first."""
    sql = "SELECT id FROM cves WHERE enrich_state='mitre' ORDER BY published DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return [r[0] for r in conn.execute(sql)]


def _parse_cve_row(row) -> dict:
    """Parse one cves row's JSON columns (fixed_raw/refs/cwe/ref_tags) back to
    Python values. Shared by :func:`get_cve` and :func:`catalog_all` so the spine
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


def get_cve(conn, cve_id: str) -> dict | None:
    """One catalog row with fixed_raw/refs parsed back to Python values."""
    r = conn.execute("SELECT * FROM cves WHERE id=?", (cve_id,)).fetchone()
    if not r:
        return None
    return _parse_cve_row(r)


def catalog_list(conn, enrich_state: str | None = None, limit: int = 100,
                 offset: int = 0) -> list[dict]:
    """Catalog rows, most-recent first. ``enrich_state`` filters to 'mitre' or
    'nvd' skeletons/enriched rows when given."""
    if enrich_state:
        rows = conn.execute(
            "SELECT * FROM cves WHERE enrich_state=? ORDER BY published DESC "
            "LIMIT ? OFFSET ?", (enrich_state, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM cves ORDER BY published DESC LIMIT ? OFFSET ?",
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
            "SELECT * FROM cves WHERE enrich_state=? ORDER BY id", (enrich_state,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM cves ORDER BY id").fetchall()
    return [_parse_cve_row(r) for r in rows]


def mark_cve_distrust(conn, cve_id: str, reason: str) -> bool:
    """Retroactive distrust MARK on one catalog row (never a delete — you keep
    the fact that you no longer trust this row's provenance, auditable). Returns
    True if a row was newly marked."""
    cur = conn.execute(
        "UPDATE cves SET distrusted=1, distrust_reason=? "
        "WHERE id=? AND (distrusted IS NULL OR distrusted=0)",
        (reason, cve_id),
    )
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# seen_cves — first-sighting drives the "new since last tick" signal
# ---------------------------------------------------------------------------

def mark_seen(conn, cve_ids: list[str]) -> set[str]:
    """Record first-sighting for any CVE not seen before; return the set that
    was *newly* seen in this call (first_seen just set = new since last tick)."""
    newly: set[str] = set()
    now = _now()
    for cid in cve_ids:
        cur = conn.execute(
            "INSERT INTO seen_cves(cve_id, first_seen) VALUES (?, ?) "
            "ON CONFLICT DO NOTHING", (cid, now),
        )
        if cur.rowcount:
            newly.add(cid)
    return newly


def seen_first_seen(conn, cve_id: str) -> str | None:
    row = conn.execute("SELECT first_seen FROM seen_cves WHERE cve_id=?",
                       (cve_id,)).fetchone()
    return row["first_seen"] if row else None


def seen_cves(conn) -> list[dict]:
    """All first-sighting rows, ordered by cve_id — the spine export serializes
    these so a client can restore the 'new since last tick' timeline."""
    rows = conn.execute("SELECT cve_id, first_seen FROM seen_cves ORDER BY cve_id").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# CISA KEV overlay — the exploitability_signal (CVE-keyed overlay, not a flaw_type)
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
    witness) DO UPDATE: only the touched CVE's row is updated; every other
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
              witness, policy_version, fetched_at, complete, raw_ref, computed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(device_id, axis, key, witness) DO UPDATE SET
             status=excluded.status, severity=excluded.severity,
             fixed_in=excluded.fixed_in, detail=excluded.detail,
             policy_version=excluded.policy_version, fetched_at=excluded.fetched_at,
             complete=excluded.complete, raw_ref=excluded.raw_ref,
             computed_at=excluded.computed_at""",
        (
            v["device_id"], v["axis"], v["key"], v["status"],
            v.get("severity"), v.get("fixed_in"), v.get("detail", ""),
            prov.get("witness") or v.get("witness", ""),
            prov.get("policy_version", ""),
            prov.get("fetched_at", ""),
            int(prov.get("complete", 1)),
            prov.get("raw_ref"),
            ts,
        ),
    )