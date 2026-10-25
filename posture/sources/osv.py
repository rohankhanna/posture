"""OSV.dev ingestion — the practical hub peer of CVE.

OSV (https://osv.dev) is *the* practical hub: one schema many peers emit.
RustSec, PyPA, Go, Red Hat, Debian, Ubuntu, Alpine, ... all emit OSV-schema
records, so ingesting OSV.dev's GCS export (storage.googleapis.com/
osv-vulnerabilities) pulls in a large fraction of the aggregator peer space in
one fetch. No rate limit, schema-standard — the highest-leverage CVE peer.

osv_ingest_tick is a two-phase cap-resumed ingestion:

* **Backfill** — enumerate ecosystems.txt, then per ecosystem download
  <ECO>/all.zip (a zip of OSV-schema JSON files, one record per file)
  straight to a temp file (records are then read from the zip on disk, one at
  a time — the zip itself never lands in memory, which matters once an
  ecosystem's zip grows past ~1GB compressed), and upsert one osv
  catalog row per record. Cap-resumed across ticks: the
  processed-ecosystem set lives in posture.db (state key
  osv:done_ecosystems); each tick processes up to cap records, marking
  an ecosystem done when its zip is exhausted within the cap and continuing to
  the next ecosystem in the same tick if cap remains.

* **Incremental** — once every ecosystem is backfilled, switch to per-ecosystem
  <ECO>/modified_id.csv diffs: rows whose modified timestamp is past the
  osv:modified_cursor state key are re-fetched as individual <ID>.json
  records and re-upserted. The cursor advances to the max modified seen.

OSV rows are **self-enriched on ingest** (they carry cvss + affected ranges), so
they land with enrich_state='osv' (NOT 'mitre' pending — only cvelistV5
skeletons stay 'mitre' for NVD enrichment). Each record's aliases are
registered as symmetric crosswalk edges against the OSV id via
:func:`posture.store.add_defect_alias` (the peer's own id is NOT in the alias
list — it is the defect_id of the row itself), so a cve-less OSV record still
anchors as a first-class peer.

Only-adds catalog rows + alias-graph edges; **never touches verdicts**. The
map is not the territory: an OSV row is a point on the foreign-authored OSV.dev
map, never a fact about a machine. Real ingestion runs ONLY in CI — never from a
local machine (the no-local-feeding rule). Tests monkeypatch curl_get against
a local fixture dir; no real network call is ever made from a test.

A note on binary safety: curl_get decodes its stdout as utf-8 with
replace errors, which is lossy for a binary zip. Under tests the monkeypatched
fetch returns the raw bytes directly; real CI ingestion needs a binary-safe
fetch path (a future refinement to _net — out of scope for this phase). The
stream-parse path here accepts both str and bytes bodies so the structure
is correct either way.
"""
from __future__ import annotations

import csv as _csv
import io
import json
import os as _os
import tempfile as _tempfile
import zipfile
from datetime import datetime, timezone

from . import _net
from .osv_schema import osv_skeleton


def _unlink(path: str) -> None:
    """Best-effort removal of a temp download (missing file is fine)."""
    try:
        _os.unlink(path)
    except OSError:
        pass

DEFAULT_BASE = "https://storage.googleapis.com/osv-vulnerabilities"

# State keys in posture.db.
#   OSV_DONE_ECOSYSTEMS_KEY — JSON list of ecosystems whose all.zip is fully
#     backfilled. Drives the backfill->incremental switch: once every ecosystem
#     in ecosystems.txt is in this set, the tick runs incremental instead.
#   OSV_MODIFIED_CURSOR_KEY — a timestamp (ISO-8601 string). Incremental fetches
#     each ecosystem's modified_id.csv and processes rows whose modified >
#     this cursor, advancing it to the max modified seen.
OSV_DONE_ECOSYSTEMS_KEY = "osv:done_ecosystems"
OSV_MODIFIED_CURSOR_KEY = "osv:modified_cursor"
# The backfill cursor: JSON {ecosystem, index} recording where in a zip's
# namelist the last cap-resumed tick stopped, so the next tick resumes there
# instead of re-processing from the start. Cleared when the ecosystem is done.
OSV_BACKFILL_CURSOR_KEY = "osv:backfill_cursor"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _alias_kind(alias: str) -> str:
    """Derive the crosswalk scheme kind for an alias id. CVE/GHSA are recognized
    explicitly; otherwise the prefix before the first dash (e.g. PYSEC, RUSTSEC,
    GO, DSA, USN) lowercased is the kind, falling back to osv_id when no dash
    prefix is present."""
    if alias.startswith("CVE-"):
        return "cve"
    if alias.startswith("GHSA-"):
        return "ghsa"
    idx = alias.find("-")
    if idx > 0:
        return alias[:idx].lower()
    return "osv_id"


def osv_ingest_tick(conn, cap: int = 1000, policy_version: str = "",
                   now: str | None = None, base_url: str | None = None) -> dict:
    """One OSV ingestion tick. Two-phase: backfill per-ecosystem, then incremental.

    Backfill: fetch ecosystems.txt, pick the next ecosystem NOT in the done
    set, fetch its all.zip, stream-parse via zipfile over the in-memory
    bytes (never extracted to disk), and upsert one osv row per record. Cap-
    resumed: processes up to cap records per tick across the current
    ecosystem; if the zip is exhausted within the cap, marks the ecosystem done
    and continues to the next ecosystem in the SAME tick only if cap remains.

    Incremental (once all ecosystems done): for each ecosystem, fetch
    modified_id.csv and re-fetch+upsert records whose modified is past
    the cursor. Advances the cursor to the max modified seen.

    Per record: store.upsert_defect, store.set_enrich_state(., ., "osv"),
    store.add_defect_alias for each alias (symmetric, so a cve-less OSV record
    anchors as a first-class peer), store.mark_seen, and conn.commit()
    (mirrors stream/refresh per-record commit).

    Idempotent + only-adds + no-wipe: writes only cves catalog rows +
    crosswalk alias edges + seen_defects; never touches verdicts (the
    map is not the territory). On ecosystems.txt fetch failure returns
    error and touches nothing (no catalog to walk). A single ecosystem's
    all.zip / modified_id.csv fetch failure is BEST-EFFORT: that ecosystem
    is skipped (left NOT done -> retried next tick) and the tick continues to the
    next ecosystem — one transient ecosystem outage must not sink the whole
    ingest tick (and the CI spine commit downstream). Only a TOTAL outage (every
    attempted ecosystem failed AND nothing was upserted) surfaces error.

    Returns a stats dict with keys: fetched_ecosystem (str|None), upserted
    (int), skipped (int), ecosystems_done (bool), incremental (bool),
    done (bool), error (str|None), failed_ecosystems (list[str] —
    ecosystems whose all.zip/csv fetch failed this tick, best-effort skipped).
    done=True only when all ecosystems are backfilled AND an incremental tick
    made no changes.
    """
    from .. import store as _store

    base = base_url or DEFAULT_BASE
    fetched_at = now or _now()
    stats: dict = {"fetched_ecosystem": None, "upserted": 0, "skipped": 0,
                   "ecosystems_done": False, "incremental": False,
                   "done": False, "error": None, "failed_ecosystems": []}

    # Fetch ecosystems.txt (plain text, NOT json — take the raw body, 3rd tuple
    # element, and splitlines()).
    _, code, body = _net.curl_get(f"{base}/ecosystems.txt", max_time=120)
    if code != 200 or not body:
        stats["error"] = f"ecosystems.txt fetch failed (http {code})"
        return stats
    ecosystems = [e.strip() for e in body.splitlines() if e.strip()]
    if not ecosystems:
        stats["error"] = "ecosystems.txt is empty"
        return stats

    # Load the processed-ecosystem set (JSON list in posture.db state).
    done_raw = _store.get_state(conn, OSV_DONE_ECOSYSTEMS_KEY)
    done_set = set(json.loads(done_raw) if done_raw else [])

    # All ecosystems backfilled -> switch to incremental.
    if set(ecosystems) <= done_set:
        return _incremental_tick(conn, ecosystems, base, cap, policy_version,
                                 fetched_at, stats, _store)

    # Backfill: process ecosystems not yet done, cap-resumed.
    return _backfill_tick(conn, ecosystems, done_set, base, cap, policy_version,
                          fetched_at, stats, _store)


def _backfill_tick(conn, ecosystems, done_set, base, cap, policy_version,
                   fetched_at, stats, _store) -> dict:
    """The backfill sweep: walk ecosystems not in done_set, fetch each one's
    all.zip, stream-parse, and upsert up to cap records total this tick.

    Cap-resumed across ticks via OSV_BACKFILL_CURSOR_KEY (a JSON
    {ecosystem, index} recording where in the zip's namelist the last tick
    stopped). Without this cursor, each tick would re-fetch the whole zip and
    re-process from the start — never making progress past cap records. The
    cursor is cleared when an ecosystem is marked done.
    """
    count = 0
    cursor_raw = _store.get_state(conn, OSV_BACKFILL_CURSOR_KEY)
    cursor = json.loads(cursor_raw) if cursor_raw else None
    # Validate the cursor: its ecosystem must still be in the list and not done.
    if cursor and (cursor.get("ecosystem") not in ecosystems
                   or cursor.get("ecosystem") in done_set):
        cursor = None
        _store.set_state(conn, OSV_BACKFILL_CURSOR_KEY, "")
        conn.commit()
    cursor_eco = cursor["ecosystem"] if cursor else None
    cursor_idx = cursor["index"] if cursor else 0
    done_grew = False   # did any ecosystem get marked done this tick?

    for eco in ecosystems:
        if eco in done_set:
            continue
        if count >= cap:
            break
        # If a saved cursor exists, skip ahead to that ecosystem (resume there).
        if cursor_eco is not None and eco != cursor_eco:
            continue
        stats["fetched_ecosystem"] = eco

        # Download the ecosystem's all.zip straight to a temp file on disk —
        # records are then read from the zip one at a time. Holding the body
        # in memory twice (curl bytes + BytesIO copy) crossed the VPS memory
        # cap once an ecosystem zip grew past ~1GB: the nightly build was
        # OOM-killed inside this step. Streaming to disk keeps memory flat
        # regardless of zip size.
        zip_path = None
        try:
            fd, zip_path = _tempfile.mkstemp(prefix="posture-osv-",
                                             suffix=".zip")
            _os.close(fd)
            zcode = _net.curl_download(f"{base}/{eco}/all.zip", zip_path,
                                       max_time=600)
        except Exception:
            zcode = 0
        if zcode != 200 or not zip_path or not _os.path.exists(zip_path):
            # Best-effort: a single ecosystem's all.zip fetch failure must NOT
            # sink the whole ingest tick (and the CI spine commit downstream).
            # Skip this ecosystem (it stays NOT in done_set -> retried next
            # tick) and continue. If a mid-zip cursor pointed here, clear it so a
            # persistently-failing cursor ecosystem doesn't block all progress
            # (the failed fetch has no mid-zip progress to preserve; re-running
            # from the start next tick is harmless — upserts are idempotent).
            if cursor_eco == eco:
                _store.set_state(conn, OSV_BACKFILL_CURSOR_KEY, "")
                conn.commit()
                cursor_eco = None
                cursor_idx = 0
            stats["failed_ecosystems"].append(eco)
            continue

        # Stream-parse the zip from disk (do NOT extract; zipfile reads each
        # member on demand). The temp file is removed as soon as this
        # ecosystem's slice is processed or skipped.
        try:
            zf = zipfile.ZipFile(zip_path)
        except Exception:
            # Same best-effort: a corrupt zip for one ecosystem skips it, not
            # the whole tick. Clear a mid-zip cursor here too.
            if cursor_eco == eco:
                _store.set_state(conn, OSV_BACKFILL_CURSOR_KEY, "")
                conn.commit()
                cursor_eco = None
                cursor_idx = 0
            _unlink(zip_path)
            stats["failed_ecosystems"].append(eco)
            continue
        names = [n for n in zf.namelist() if n.endswith(".json")]
        start = cursor_idx if cursor_eco == eco else 0

        eco_exhausted = True
        for idx in range(start, len(names)):
            if count >= cap:
                eco_exhausted = False  # didn't finish this ecosystem this tick
                _store.set_state(conn, OSV_BACKFILL_CURSOR_KEY,
                                 json.dumps({"ecosystem": eco, "index": idx}))
                conn.commit()
                break
            name = names[idx]
            try:
                rec = json.loads(zf.read(name).decode("utf-8", "replace"))
            except (ValueError, TypeError):
                stats["skipped"] += 1
                count += 1
                continue
            try:
                skel = osv_skeleton(rec, "osv", "osv", policy_version, fetched_at)
            except Exception:
                # defense in depth: a malformed record that slips past
                # osv_record's guards skips, never sinks the tick.
                stats["skipped"] += 1
                count += 1
                continue
            if not skel:
                stats["skipped"] += 1
                count += 1
                continue
            row, aliases = skel
            _store.upsert_defect(conn, row)
            _store.set_enrich_state(conn, row["id"], "osv")
            for alias in aliases:
                _store.add_defect_alias(conn, row["id"], "osv", alias,
                                      _alias_kind(alias))
            _store.mark_seen(conn, [row["id"]])
            conn.commit()  # release the write lock per record (mirrors stream/refresh)
            stats["upserted"] += 1
            count += 1

        zf.close()
        _unlink(zip_path)
        if eco_exhausted:
            done_set.add(eco)
            _store.set_state(conn, OSV_DONE_ECOSYSTEMS_KEY,
                             json.dumps(sorted(done_set)))
            _store.set_state(conn, OSV_BACKFILL_CURSOR_KEY, "")  # clear cursor
            conn.commit()
            done_grew = True
            # Resume subsequent ecosystems from the start of their zips.
            cursor_eco = None
            cursor_idx = 0

    stats["ecosystems_done"] = set(ecosystems) <= done_set
    # Best-effort completion: a per-ecosystem failure skipped + continued above.
    # Only surface error (exit 1) on a TOTAL outage — every attempted
    # ecosystem failed AND nothing was upserted AND none was newly marked done
    # (an exhausted-but-empty zip is real progress, not a failure). A partial
    # failure (some ecosystems succeeded) stays exit 0; the CLI reports the
    # failed ecosystems as a warning so a transient outage is visible but does
    # not sink the daily spine commit.
    if (stats["upserted"] == 0 and stats["failed_ecosystems"]
            and not done_grew):
        stats["error"] = (
            f"all.zip fetch/parse failed for every attempted ecosystem "
            f"({', '.join(stats['failed_ecosystems'])})")
    return stats


def _incremental_tick(conn, ecosystems, base, cap, policy_version, fetched_at,
                      stats, _store) -> dict:
    """The incremental sweep: for each ecosystem, fetch modified_id.csv and
    re-fetch+upsert records whose modified is past the cursor. Advances the
    cursor to the max modified seen. Processes up to cap records total."""
    stats["incremental"] = True
    stats["ecosystems_done"] = True
    cursor = _store.get_state(conn, OSV_MODIFIED_CURSOR_KEY) or ""
    count = 0
    max_modified = cursor
    for eco in ecosystems:
        if count >= cap:
            break
        stats["fetched_ecosystem"] = eco

        # Fetch the ecosystem's modified_id.csv (CSV with header, columns
        # include id and modified). A fetch failure for one ecosystem
        # doesn't sink the whole tick — skip and continue.
        _, ccode, cbody = _net.curl_get(f"{base}/{eco}/modified_id.csv",
                                        max_time=120)
        if ccode != 200 or not cbody:
            stats["failed_ecosystems"].append(eco)   # best-effort: skip + continue
            continue
        try:
            reader = _csv.DictReader(cbody.splitlines())
        except Exception:
            stats["failed_ecosystems"].append(eco)
            continue

        for row in reader:
            if count >= cap:
                break
            rid = (row.get("id") or "").strip()
            modified = (row.get("modified") or "").strip()
            if not rid or not modified or modified <= cursor:
                continue

            # Fetch the individual record JSON. curl_get parses json for us
            # (1st tuple element) when the body is valid JSON.
            pdata, rcode, _ = _net.curl_get(f"{base}/{eco}/{rid}.json",
                                           max_time=60)
            if rcode != 200 or not isinstance(pdata, dict):
                stats["skipped"] += 1
                count += 1
                continue
            try:
                skel = osv_skeleton(pdata, "osv", "osv", policy_version, fetched_at)
            except Exception:
                # defense in depth: a malformed incremental record skips, never
                # sinks the tick.
                stats["skipped"] += 1
                count += 1
                continue
            if not skel:
                stats["skipped"] += 1
                count += 1
                continue
            row_data, aliases = skel
            _store.upsert_defect(conn, row_data)
            _store.set_enrich_state(conn, row_data["id"], "osv")
            for alias in aliases:
                _store.add_defect_alias(conn, row_data["id"], "osv", alias,
                                      _alias_kind(alias))
            _store.mark_seen(conn, [row_data["id"]])
            conn.commit()  # release the write lock per record (mirrors stream/refresh)
            stats["upserted"] += 1
            count += 1
            if modified > max_modified:
                max_modified = modified

    if max_modified > cursor:
        _store.set_state(conn, OSV_MODIFIED_CURSOR_KEY, max_modified)
        conn.commit()

    # done only when an incremental tick made no changes (steady state).
    if stats["upserted"] == 0 and stats["skipped"] == 0:
        stats["done"] = True
    return stats