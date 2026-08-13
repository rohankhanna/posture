"""GitHub Advisory Database (GHSA) ingestion — a self-enriched OSV peer.

GitHub's Advisory Database (``github.com/github/advisory-database``) is a
human-reviewed catalog of security advisories for open-source packages. Each
advisory lives under ``advisories/github-reviewed/<YYYY>/<MM>/<id>/<id>.json``
and is published in the **OSV schema** (one schema for all vulnerability
databases), so this peer reuses :func:`posture.sources.osv_schema.osv_skeleton`
for record parsing — the same normalizer the OSV.dev hub peer will use.

GHSA is a **peer** of CVE (``defect_type='ghsa'``), not a CVE-keyed overlay like
KEV: a GHSA id owns its own catalog row. It is **self-enriched on ingest**
(``enrich_state='ghsa'``, NOT ``'mitre'`` pending NVD) — the record already
carries CVSS + affected ranges, so it lands complete and the incremental
refresh leaves it alone. Only cvelistV5 skeletons stay ``'mitre'`` for NVD
enrichment; GHSA rows skip that retry pool entirely.

A tick only-adds: it upserts catalog rows + symmetric alias-graph edges (the
CVE a GHSA aliases becomes a crosswalk edge), never touches ``verdicts``. **The
map is not the territory.** A GHSA row is a point on the foreign-authored map
(GitHub), never a fact about a machine; ingestion writes ZERO verdicts.

Real ingestion runs ONLY in CI — never from a local machine (the no-local-
feeding rule). Tests use local git fixtures (a bare upstream + a blobless work
clone, reused from ``tests.test_stream``) and never hit the network.
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .. import git_ingest as _gi
from .. import store as _store
from .osv_schema import osv_skeleton

GHSA_REPO = "https://github.com/github/advisory-database.git"

# State keys (in posture.db via store.get_state / set_state).
# GHSA_CURSOR_KEY: a repo-relative advisory path cursor for cap-resumed
#   backfill (mirrors stream.BACKFILL_CURSOR_KEY).
# GHSA_DONE_KEY: the self-disable flag set once the back-catalog is exhausted
#   (mirrors stream.BACKFILL_DONE_KEY); subsequent ticks take the incremental
#   diff path instead of re-enumerating history.
# GHSA_TIP_KEY: the last-processed tip SHA — the incremental diff cursor.
GHSA_CURSOR_KEY = "ghsa:tree_cursor"
GHSA_DONE_KEY = "ghsa:backfill_done"
GHSA_TIP_KEY = "ghsa:tip"

# The tree prefix where github-reviewed advisories live (unreviewed are excluded
# — only reviewed advisories carry the OSV schema + severity we ingest).
GHSA_PREFIX = "advisories/github-reviewed/"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ghsa_repo_path(cache_dir: str | os.PathLike | None = None) -> Path:
    """On-disk path of posture's advisory-database clone. Defaults to
    ``~/.local/share/posture/ghsa/advisory-database``; the ``POSTURE_GHSA_DIR``
    env var overrides the parent directory (so an existing clone can be reused
    without re-cloning). Creates the parent dir so a first-run clone has a home.
    Mirrors :func:`posture.mitre.mitre_repo_path` exactly."""
    base = Path(cache_dir) if cache_dir else \
        Path(os.environ.get(
            "POSTURE_GHSA_DIR",
            os.path.expanduser("~/.local/share/posture/ghsa")))
    base.mkdir(parents=True, exist_ok=True)
    return base / "advisory-database"


def _git(repo: Path, *args: str) -> str:
    """Run a git command in ``repo``; return stdout text. Raises on non-zero.
    Mirrors :func:`posture.stream._git` (kept local so a failure in one peer
    can't monkeypatch the other)."""
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({r.returncode}): {r.stderr.strip()}")
    return r.stdout


def _ensure_clone(repo: Path) -> None:
    """Clone advisory-database (blobless, no-checkout) if missing. The tick reads
    via ``git show <ref>:<path>`` / ``git archive`` / ``git diff`` — all operate
    on repo objects, so no working-tree checkout is needed. Mirrors
    :func:`posture.stream._ensure_clone`."""
    if (repo / ".git").exists():
        return
    repo.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--filter=blob:none", "--no-checkout",
         GHSA_REPO, str(repo)],
        check=True, capture_output=True,
    )


def _changed_paths(repo: Path, old: str, new: str, prefix: str) -> list[str]:
    """Paths under ``prefix`` that changed between two commits. Only ``.json``
    files are returned (the advisory-database repo also carries metadata files
    we don't care about). Generalizes :func:`posture.stream._changed_cve_paths`
    to any tree prefix."""
    out = _git(repo, "diff", "--name-only", old, new, "--", prefix).splitlines()
    return [p for p in (x.strip() for x in out) if p.endswith(".json")]


def _read_blob(repo: Path, ref: str, path: str) -> dict | None:
    """Read one advisory JSON blob from the repo at ``ref`` (on-demand via the
    blobless clone's promisor). Returns the parsed dict or None on read/parse
    failure (a single malformed record must not sink the tick). Mirrors
    :func:`posture.stream._read_blob`."""
    try:
        text = _git(repo, "show", f"{ref}:{path}")
    except RuntimeError:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _alias_kind(alias: str) -> str:
    """The scheme/kind label for an alias id, used as the ``kind`` on the
    crosswalk edge. A CVE alias -> ``'cve'``; any dash-prefixed scheme id
    (``GHSA-...``, ``PYSEC-...``, ``RUSTSEC-...``, ``GO-...``) -> the scheme
    prefix lowercased; otherwise ``'osv_id'`` (a bare ecosystem id with no
    recognizable scheme prefix)."""
    if alias.startswith("CVE-"):
        return "cve"
    if "-" in alias:
        prefix = alias.split("-", 1)[0]
        if prefix and prefix.replace("_", "").isalnum():
            return prefix.lower()
    return "osv_id"


def _upsert_one(conn, row: dict, aliases: list[str]) -> None:
    """Upsert one GHSA catalog row + register its alias-graph edges. The row is
    self-enriched (``enrich_state='ghsa'``); each alias becomes a symmetric
    crosswalk edge via :func:`posture.store.add_defect_alias` so resolve works in
    both directions. Marks the defect seen (drives the "new since tick" signal)."""
    _store.upsert_defect(conn, row)
    _store.set_enrich_state(conn, row["id"], "ghsa")
    for alias in aliases:
        _store.add_defect_alias(conn, row["id"], "ghsa", alias, _alias_kind(alias))
    _store.mark_seen(conn, [row["id"]])


def ghsa_ingest_tick(
    conn,
    repo_path: str | os.PathLike | None = None,
    cap: int = 1000,
    policy_version: str = "",
    now: str | None = None,
) -> dict:
    """One GHSA ingestion tick. Ingests the github-reviewed advisory back-catalog
    (cap-resumed across ticks) and then incrementally diffs new/changed
    advisories on subsequent ticks. Returns a stats dict.

    Idempotent + only-adds + no-wipe: it ``upsert_defect`` / ``set_enrich_state`` /
    ``add_defect_alias`` / ``mark_seen`` per advisory and never touches
    ``verdicts``. The cursor advances only after a sweep succeeds, so a tick
    killed mid-sweep retries the same range idempotently next time (re-upserts
    are harmless — ``upsert_defect`` is keyed on id and ``mark_seen`` is idempotent).

    Two phases:

      1. **Backfill** (first runs): enumerate ``advisories/github-reviewed/``
         past a path cursor via :func:`posture.git_ingest.git_backfill_slice`,
         upsert ``cap`` records per tick. Cap-resumed across ticks via
         ``GHSA_CURSOR_KEY``; once exhausted, set ``GHSA_DONE_KEY='1'`` and
         record the tip in ``GHSA_TIP_KEY``.
      2. **Incremental** (after done): ``git fetch``, diff
         ``old_tip..new_tip`` under the advisory prefix, parse + upsert each
         changed file. Advance ``GHSA_TIP_KEY`` after the sweep.

    Each record is parsed via :func:`posture.sources.osv_schema.osv_skeleton`
    with ``source='ghsa'`` / ``defect_type='ghsa'``; the row is self-enriched
    (``enrich_state='ghsa'``, NOT pending mitre).
    """
    repo = Path(repo_path) if repo_path else ghsa_repo_path()
    fetched_at = now or _now()
    stats = {"fetched_tip": None, "upserted": 0, "skipped": 0,
             "done": False, "incremental": False, "error": None}

    try:
        _ensure_clone(repo)
        _git(repo, "fetch", "origin", "--filter=blob:none")
        tip = _git(repo, "rev-parse", "FETCH_HEAD").strip()
    except Exception as exc:  # network / git failure — don't touch cursors
        stats["error"] = f"fetch failed: {exc}"
        return stats
    stats["fetched_tip"] = tip

    # Phase selection: once the back-catalog is exhausted, take the incremental
    # diff path (the backfill owns history; the diff owns go-live changes).
    if _store.get_state(conn, GHSA_DONE_KEY) == "1":
        old = _store.get_state(conn, GHSA_TIP_KEY)
        stats["incremental"] = True
        if not old:
            # Done flag set but no tip recorded (defensive): record the tip and
            # exit — the next tick takes the real incremental path.
            _store.set_state(conn, GHSA_TIP_KEY, tip)
            stats["done"] = True
            return stats
        try:
            paths = _changed_paths(repo, old, tip, GHSA_PREFIX)
        except RuntimeError as exc:
            # Force-push / history rewrite / cursor commit GC'd. Reset the tip
            # to the current HEAD and treat this tick as a no-op — never fail
            # into a path that could drop data.
            _store.set_state(conn, GHSA_TIP_KEY, tip)
            stats["error"] = f"diff failed (tip reset): {exc}"
            return stats
        for path in paths:
            rec = _read_blob(repo, tip, path)
            if not rec:
                stats["skipped"] += 1
                continue
            try:
                parsed = osv_skeleton(rec, "ghsa", "ghsa", policy_version, fetched_at)
            except Exception:
                # defense in depth: a malformed incremental advisory that slips
                # past osv_record's guards skips, never sinks the tick.
                stats["skipped"] += 1
                continue
            if not parsed:
                stats["skipped"] += 1
                continue
            row, aliases = parsed
            _upsert_one(conn, row, aliases)
            stats["upserted"] += 1
            conn.commit()  # release the write lock per record (mirrors stream/refresh)
        # Advance the tip only after the sweep. Records already upserted are
        # durable; if the process dies here the next tick re-diffs the same
        # range and re-upserts them idempotently.
        _store.set_state(conn, GHSA_TIP_KEY, tip)
        stats["done"] = True
        return stats

    # --- backfill path -------------------------------------------------------
    cursor = _store.get_state(conn, GHSA_CURSOR_KEY)

    def parse(text: str):
        try:
            rec = json.loads(text)
        except (ValueError, TypeError):
            return None
        return osv_skeleton(rec, "ghsa", "ghsa", policy_version, fetched_at)

    try:
        records, new_cursor, done = _gi.git_backfill_slice(
            repo, tip, GHSA_PREFIX, cursor, cap, parse,
        )
    except Exception as exc:
        stats["error"] = f"backfill slice failed: {exc}"
        return stats

    for parsed in records:
        if not parsed:
            stats["skipped"] += 1
            continue
        row, aliases = parsed
        _upsert_one(conn, row, aliases)
        stats["upserted"] += 1
        conn.commit()  # release the write lock per record (mirrors stream/refresh)

    if new_cursor:
        _store.set_state(conn, GHSA_CURSOR_KEY, new_cursor)
    if done:
        _store.set_state(conn, GHSA_DONE_KEY, "1")
        _store.set_state(conn, GHSA_TIP_KEY, tip)
        stats["done"] = True
    return stats