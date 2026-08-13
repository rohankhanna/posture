"""CVE stream — detect CVEs as MITRE publishes them (Phase 1, detection only).

Nobody offers a true *push* CVE feed for free. MITRE's cvelistV5 git repo
(``github.com/CVEProject/cvelistV5``) is the closest thing to a real-time
stream: CNAs publish CVE records to MITRE's CVE Services, and the repo updates
within minutes-to-hours. It is rate-limit-free and fully local once cloned.
posture keeps a blobless clone (see :func:`posture.mitre.mitre_repo_path`); this
module ``git fetch``es it on a short cadence (driven by a systemd user timer,
~10-17 min) and incrementally upserts newly-published/changed records as
*skeletons*.

A tick (Phase 1):

1. ``git fetch`` the clone, read the new tip SHA.
2. Diff ``cves/`` against the last-seen cursor SHA (``state`` key
   ``stream:mitre_cursor``) to get the changed CVE JSON files.
3. Parse each via :func:`posture.mitre.mitre_record` and upsert a *skeleton*
   catalog row (id/published/description/cvss_vector-if-present/refs, with
   ``fixed_raw={"source":"mitre","pending_nvd":True}`` and a reason string
   "MITRE-published; NVD not yet enriched"), mark it seen, and tag
   ``enrich_state='mitre'``.

Phase 1 **only adds** rows — it never touches ``verdicts``, so it can't wipe a
device's stored verdict set the way a failed broad-CPE re-pull can. NVD per-CVE
enrichment + incremental verdicts is Phase 2 (the incremental refresh; see
:mod:`posture.refresh`); the ``enrich_state='mitre'`` skeletons are the retry
pool the refresh promotes.

**The map is not the territory.** A skeleton row means "MITRE published this
CVE; NVD has not yet enriched it" — never "this device is vulnerable." A
freshly-seen CVE is a point on the foreign-authored MITRE map, not a fact about
a machine; no verdict is claimed until NVD ranges arrive.

Provenance is stamped on every skeleton (``source='mitre'``, ``fetched_at``,
``policy_version``, ``complete=True``) so a catalog row, like a verdict, can be
retroactively distrusted rather than deleted.
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import mitre as _mitre
from . import store as _store

CURSOR_KEY = "stream:mitre_cursor"
LAST_TICK_KEY = "stream:last_tick"
LAST_SUMMARY_KEY = "stream:last_summary"
# The back-fill path cursor (a repo-relative CVE JSON path) + done flag. The
# stream is forward-only ("from now on", O(1) bootstrap -> no history); this is
# the SEPARATE one-shot enumeration of the cvelistV5 back-catalog that populates
# CVE-peer history. Cap-resumed across ticks; self-disables when exhausted.
BACKFILL_CURSOR_KEY = "stream:backfill_cursor"
BACKFILL_DONE_KEY = "stream:backfill_done"
# A local ref that retains the cursor commit so git GC can't delete it
# (otherwise a later ``diff cursor..new`` fails). Points at the last-processed
# tip; updated after each successful tick. Best-effort — the state cursor is
# authoritative.
CURSOR_REF = "refs/posture/cursor"

# The skeleton reason — the honest stratum marker. NEVER "you are vulnerable."
SKELETON_REASON = "MITRE-published; NVD not yet enriched"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _git(repo: Path, *args: str) -> str:
    """Run a git command in ``repo``; return stdout text. Raises on non-zero."""
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({r.returncode}): {r.stderr.strip()}")
    return r.stdout


def _ensure_clone(repo: Path) -> None:
    """Clone cvelistV5 (blobless, no-checkout) if missing. The stream reads via
    ``git show <ref>:<path>`` and ``git diff`` — both operate on repo objects,
    so no working-tree checkout is needed."""
    if (repo / ".git").exists():
        return
    repo.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--filter=blob:none", "--no-checkout",
         _mitre.MITRE_REPO, str(repo)],
        check=True, capture_output=True,
    )


def _skeleton(rec: dict, policy_version: str, fetched_at: str) -> dict | None:
    """Build an ``upsert_defect``-shape skeleton from a parsed MITRE record.

    ``cvss``/``severity`` are None — MITRE doesn't give the numeric score in the
    NVD-attested form; the incremental refresh's ``nvd_query_cve`` fills them.
    The vector, if MITRE's CNA metrics carry one, is kept so a skeleton still
    shows its severity class tentatively. ``fixed_raw`` carries the stratum
    marker + the honest reason.
    """
    parsed = _mitre.mitre_record(rec)
    if not parsed.get("id"):
        return None
    return {
        "id": parsed["id"],
        "published": parsed.get("published"),
        "cvss": None,
        "severity": None,
        "cvss_vector": parsed.get("vector"),
        "description": parsed.get("description") or "",
        "fixed_raw": {"source": "mitre", "pending_nvd": True,
                      "reason": SKELETON_REASON},
        "refs": _mitre.mitre_refs(rec),
        "source": "mitre",
        "fetched_at": fetched_at,
        "policy_version": policy_version,
        "complete": True,
    }


def _changed_cve_paths(repo: Path, old: str, new: str) -> list[str]:
    """Paths under ``cves/`` that changed between two commits. Only CVE JSON
    files (``cves/<year>/<prefix>/<CVEID>.json``) are returned; cvelistV5 also
    commits metadata files outside ``cves/`` we don't care about."""
    out = _git(repo, "diff", "--name-only", old, new, "--", "cves/").splitlines()
    return [p for p in (x.strip() for x in out) if p.endswith(".json")]


def _read_blob(repo: Path, ref: str, path: str) -> dict | None:
    """Read one CVE JSON blob from the repo at ``ref`` (on-demand via the
    blobless clone's promisor). Returns the parsed dict or None on read/parse
    failure (a single malformed record must not sink the tick)."""
    try:
        text = _git(repo, "show", f"{ref}:{path}")
    except RuntimeError:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def stream_tick(
    conn,
    repo_path: str | os.PathLike | None = None,
    policy_version: str = "",
    now: str | None = None,
) -> dict:
    """One stream tick. Detects newly-published/changed CVEs since the last
    cursor and upserts skeleton rows. Returns a stats dict.

    Idempotent + no-wipe: it only ``upsert_defect`` / ``mark_seen`` /
    ``set_enrich_state`` per CVE and never touches ``verdicts``. The cursor
    advances only after the parse sweep succeeds, so a tick killed mid-sweep
    retries the same range next time (already-upserted skeletons are re-upserted
    harmlessly — ``upsert_defect`` is idempotent and ``mark_seen`` is keyed on id).

    Bootstrap is O(1): a first run (no cursor) records the current tip and
    produces nothing — the daily ``assess``/``refresh`` owns the back-catalog;
    the stream is "from now on", never a history enumeration.
    """
    repo = Path(repo_path) if repo_path else _mitre.mitre_repo_path()
    fetched_at = now or _now()
    stats = {"fetched_tip": None, "new": 0, "changed_files": 0,
             "skipped": 0, "bootstrapped": False, "error": None}

    try:
        _ensure_clone(repo)
        _git(repo, "fetch", "origin", "--filter=blob:none")
    except Exception as exc:  # network / git failure — don't touch the cursor
        stats["error"] = f"fetch failed: {exc}"
        return stats

    try:
        new = _git(repo, "rev-parse", "FETCH_HEAD").strip()
    except RuntimeError as exc:
        stats["error"] = f"rev-parse FETCH_HEAD failed: {exc}"
        return stats
    stats["fetched_tip"] = new

    old = _store.get_state(conn, CURSOR_KEY)
    if not old:
        # First run: record the cursor and produce nothing. The daily refresh
        # owns the back-catalog; the stream is "from now on" (O(1), no history
        # enumeration).
        _set_cursor(conn, repo, new, fetched_at)
        stats["bootstrapped"] = True
        return stats

    try:
        paths = _changed_cve_paths(repo, old, new)
    except RuntimeError as exc:
        # Force-push / history rewrite / cursor commit GC'd despite our ref.
        # Reset the cursor to the current tip and treat this tick as a no-op —
        # never fail into a path that could drop data.
        _set_cursor(conn, repo, new, fetched_at)
        stats["error"] = f"diff failed (cursor reset): {exc}"
        return stats

    stats["changed_files"] = len(paths)

    n_new = 0
    for path in paths:
        rec = _read_blob(repo, new, path)
        if not rec:
            stats["skipped"] += 1
            continue
        try:
            skel = _skeleton(rec, policy_version, fetched_at)
        except Exception:
            # defense in depth: a malformed record that slips past
            # mitre_record's guards (a non-dict field we did not anticipate)
            # skips, never sinks the tick — the single-bad-record invariant.
            stats["skipped"] += 1
            continue
        if not skel:
            stats["skipped"] += 1
            continue
        _store.upsert_defect(conn, skel)
        _store.set_enrich_state(conn, skel["id"], "mitre")
        # mark_seen returns the newly-seen set; a changed (re-published) CVE
        # already seen stays seen — only truly-new ids drive "new since tick".
        newly = _store.mark_seen(conn, [skel["id"]])
        if newly:
            n_new += 1
        conn.commit()  # release the write lock per CVE (mirrors refresh)
    stats["new"] = n_new

    # Advance the cursor only after the sweep. Skeletons already upserted are
    # durable; if the process dies here the next tick re-diffs the same range
    # and re-upserts them idempotently (no double-count: mark_seen is idempotent
    # and upsert_defect is keyed on id).
    _set_cursor(conn, repo, new, fetched_at)
    _store.set_state(conn, LAST_SUMMARY_KEY, json.dumps(stats, default=str))
    return stats


def _set_cursor(conn, repo: Path, sha: str, fetched_at: str) -> None:
    _store.set_state(conn, CURSOR_KEY, sha)
    _store.set_state(conn, LAST_TICK_KEY, fetched_at)
    try:
        _git(repo, "update-ref", CURSOR_REF, sha)
    except RuntimeError:
        pass  # ref update is best-effort retention; the state cursor is authoritative


# ---------------------------------------------------------------------------
# Back-fill — the one-shot CVE back-catalog enumeration
# ---------------------------------------------------------------------------

def backfill_tick(
    conn,
    repo_path: str | os.PathLike | None = None,
    cap: int = 1000,
    policy_version: str = "",
    now: str | None = None,
) -> dict:
    """One back-fill tick: enumerate the cvelistV5 ``cves/`` back-catalog past a
    path cursor and upsert skeletons (the same shape as ``stream_tick``) for
    ``cap`` records. Returns a stats dict.

    The stream is forward-only — it bootstraps O(1) and detects CVEs published
    *after* go-live, never the history. This tick is the SEPARATE one-shot
    enumeration of the historical catalog: cap-resumed across ticks (the cursor
    lives in ``posture.db``), it only-adds skeletons (no verdicts, no wipe), and
    it self-disables once exhausted (``BACKFILL_DONE_KEY``) so CI can call it
    every run cheaply after that.

    Skeletons carry the same provenance as the stream (``source='mitre'``,
    ``enrich_state='mitre'``, ``fixed_raw`` pending-nvd marker); the incremental
    refresh promotes them to NVD-enriched rows just like stream-sighted ones.
    """
    from . import git_ingest as _gi
    repo = Path(repo_path) if repo_path else _mitre.mitre_repo_path()
    fetched_at = now or _now()
    stats = {"fetched_tip": None, "upserted": 0, "skipped": 0,
             "done": False, "error": None}

    # self-disable: once the back-catalog is exhausted, never re-enumerate it
    # (the stream owns new CVEs from go-live; history doesn't change).
    if _store.get_state(conn, BACKFILL_DONE_KEY) == "1":
        stats["done"] = True
        return stats

    try:
        _ensure_clone(repo)
        _git(repo, "fetch", "origin", "--filter=blob:none")
        tip = _git(repo, "rev-parse", "FETCH_HEAD").strip()
    except Exception as exc:  # network / git failure — don't touch the cursor
        stats["error"] = f"fetch failed: {exc}"
        return stats
    stats["fetched_tip"] = tip

    cursor = _store.get_state(conn, BACKFILL_CURSOR_KEY)

    def parse(text: str):
        try:
            rec = json.loads(text)
        except (ValueError, TypeError):
            return None
        return _skeleton(rec, policy_version, fetched_at)

    try:
        records, new_cursor, done = _gi.git_backfill_slice(
            repo, tip, "cves/", cursor, cap, parse,
        )
    except Exception as exc:
        stats["error"] = f"backfill slice failed: {exc}"
        return stats

    for skel in records:
        if not skel:
            stats["skipped"] += 1
            continue
        _store.upsert_defect(conn, skel)
        _store.set_enrich_state(conn, skel["id"], "mitre")
        _store.mark_seen(conn, [skel["id"]])
        stats["upserted"] += 1
        conn.commit()  # release the write lock per CVE (mirrors stream/refresh)

    if new_cursor:
        _store.set_state(conn, BACKFILL_CURSOR_KEY, new_cursor)
    if done:
        _store.set_state(conn, BACKFILL_DONE_KEY, "1")
        stats["done"] = True
    return stats