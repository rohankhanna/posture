"""Spine export/import — the signed-directory interface between CI and clients.

This is the missing piece that makes "feed and enrich in CI, consume locally"
real. posture's catalog lives in SQLite; that's a working state, not a durable,
auditable, signed artifact. The spine export serializes the **map** half of the
map/territory split to sharded JSONL plus a self-auditing manifest, which CI then
cosign-signs and commits. A client clones the signed repo, verifies the
signature, and imports the JSONL back into its own SQLite DB to run ``assess``
locally over its private devices (the territory half — never exported).

**Data-only.** The spine is the MAP: ``flaws``, ``crosswalk``, ``candidates``,
``distrust_marks``, ``seen_flaws``. It NEVER serializes ``verdicts`` /
``device_posture`` / ``health_*`` / ``glossary`` / ``repair_proposals`` — those
are territory (device-specific) or engine-internal. No device data ever leaves CI.

Layout under ``--out DIR`` (default ``.``)::

    DIR/spine/manifest.json          # cosign signs THIS -> state.sig
    DIR/spine/flaws/2026-07.jsonl    # sharded by published month (100MB-file
    DIR/spine/flaws/unknown.jsonl    #   limit; rows with no date -> 'unknown')
    DIR/spine/crosswalk.jsonl
    DIR/spine/candidates.jsonl
    DIR/spine/distrust_marks.jsonl
    DIR/spine/seen_flaws.jsonl

The manifest carries a per-file ``sha256`` + ``count`` for every shard, so
tamper-evidence lives in the signature over the manifest, NOT in git history.
That is what frees history to be gc'd/squashed without losing trust: a client
verifies ``state.sig`` against ``manifest.json``, and ``manifest.json`` pins
every shard. (See docs/sources.md item 9 — "repo = signed directory;
signing frees history to be gc'd".)

The map is not the territory. A spine row is a point on the foreign-authored
NVD/MITRE/vendor map, not a fact about a machine; the client's verdicts are
the territory and stay local.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from pathlib import Path

from . import store as _store

MANIFEST_VERSION = "1"
SPINE_DIR = "spine"
# The MAP tables — the spine. Territory/engine-internal tables are deliberately
# absent: verdicts, device_posture, health_*, glossary, term_signals,
# spine_bindings, repair_proposals, policy_versions, state.
FLAT_TABLES = ("crosswalk", "candidates", "distrust_marks", "seen_flaws", "kev",
               "apple_fixes")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _flaw_shard_key(row: dict) -> str:
    """YYYY-MM bucket from a flaws row's ``published`` (e.g. '2026-07-31' ->
    '2026-07'). Rows with no parseable date land in 'unknown' so nothing is
    dropped — the spine is a complete snapshot."""
    pub = row.get("published") or ""
    return pub[:7] if len(pub) >= 7 else "unknown"


def _write_jsonl(path: Path, rows: list[dict]) -> tuple[str, int]:
    """Write rows as one JSON object per line; return (sha256, count). The sha256
    is over the exact bytes written, so a client re-reading the file can detect
    any tampering via the manifest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = "".join(json.dumps(r, sort_keys=True, default=str) + "\n" for r in rows)
    path.write_text(data)
    return hashlib.sha256(data.encode("utf-8")).hexdigest(), len(rows)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

def export_spine(conn, out_dir: os.PathLike | str = ".",
                 policy_version: str = "",
                 source_version: dict | None = None,
                 now: str | None = None) -> dict:
    """Serialize the catalog tables to ``<out_dir>/spine/*.jsonl`` + manifest.

    Opens the DB read-only in spirit (the caller passes a readonly connection;
    export never writes to the DB). Returns the manifest dict. ``source_version``
    records the stream cursor (cvelist tip + last tick) so a client can tell
    which upstream state the snapshot reflects.
    """
    root = Path(out_dir) / SPINE_DIR
    root.mkdir(parents=True, exist_ok=True)
    generated_at = now or _now()
    src = source_version or {}
    if "cvelist_tip" not in src:
        src["cvelist_tip"] = _store.get_state(conn, "stream:mitre_cursor")
    if "stream_last_tick" not in src:
        src["stream_last_tick"] = _store.get_state(conn, "stream:last_tick")

    files: list[dict] = []
    counts: dict[str, int] = {}

    # --- flaws: sharded by published month ---
    flaws = _store.catalog_all(conn)
    counts["flaws"] = len(flaws)
    buckets: dict[str, list[dict]] = {}
    for row in flaws:
        buckets.setdefault(_flaw_shard_key(row), []).append(row)
    for shard, rows in sorted(buckets.items()):
        sha, n = _write_jsonl(root / "flaws" / f"{shard}.jsonl", rows)
        files.append({"path": f"flaws/{shard}.jsonl", "sha256": sha, "count": n})

    # --- flat tables ---
    loaders = {
        "crosswalk": _store.crosswalk_all,
        "candidates": _store.candidates,
        "distrust_marks": _store.distrust_marks,
        "seen_flaws": _store.seen_flaws,
        "kev": _store.kev_all,
        "apple_fixes": _store.apple_fixes_all,
    }
    for name in FLAT_TABLES:
        rows = loaders[name](conn)
        counts[name] = len(rows)
        sha, n = _write_jsonl(root / f"{name}.jsonl", rows)
        files.append({"path": f"{name}.jsonl", "sha256": sha, "count": n})

    # --- self-clean: drop any *.jsonl shard under root that this export did NOT
    #     write. Makes export idempotent w.r.t. format renames (a prior run's
    #     spine/cves/*.jsonl or seen_cves.jsonl is removed instead of lingering
    #     beside the new spine/flaws/*.jsonl). manifest.json is regenerated below.
    #     Materialize the rglob FIRST: it is a generator, and unlinking/rmtree-ing
    #     shards mid-iteration removes a directory rglob still intends to descend
    #     into -> FileNotFoundError on the old shard dir (e.g. 'spine/cves').
    written = {entry["path"] for entry in files}
    import shutil as _shutil
    for path in list(root.rglob("*.jsonl")):
        rel = path.relative_to(root).as_posix()
        if rel not in written:
            path.unlink()
            # remove the shard dir if it is now empty (e.g. the old cves/ dir)
            d = path.parent
            if d != root and d.exists() and not any(d.iterdir()):
                _shutil.rmtree(d)

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "generated_at": generated_at,
        "policy_version": policy_version,
        "source_version": src,
        "counts": counts,
        "files": files,
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n"
    )
    return manifest


# ---------------------------------------------------------------------------
# verify (manifest-internal consistency — NOT the cosign signature)
# ---------------------------------------------------------------------------

def verify_spine(from_dir: os.PathLike | str = ".") -> dict:
    """Recompute every shard sha256 and assert it matches ``manifest.json``.
    This checks the manifest's internal consistency (the snapshot is intact on
    disk); it does NOT verify the cosign signature (that's ``cosign
    verify-blob``). Clients run this after ``cosign verify-blob`` and before
    :func:`import_spine`. Raises ``ValueError`` on any mismatch/missing file.
    Returns the manifest on success.
    """
    root = Path(from_dir) / SPINE_DIR
    manifest = json.loads((root / "manifest.json").read_text())
    for entry in manifest["files"]:
        path = root / entry["path"]
        if not path.exists():
            raise ValueError(f"spine shard missing: {entry['path']}")
        if _sha256_file(path) != entry["sha256"]:
            raise ValueError(f"spine shard tampered (sha256 mismatch): {entry['path']}")
        # cross-check count cheaply (line count == declared count)
        n = sum(1 for line in path.read_text().splitlines() if line.strip())
        if n != entry["count"]:
            raise ValueError(
                f"spine shard row-count mismatch: {entry['path']} "
                f"({n} != {entry['count']})"
            )
    return manifest


# ---------------------------------------------------------------------------
# import (client consumption path; idempotent)
# ---------------------------------------------------------------------------

def import_spine(conn, from_dir: os.PathLike | str = ".",
                 verify_manifest: bool = True) -> dict:
    """Load ``<from_dir>/spine/*.jsonl`` into the SQLite DB (the client
    consumption path; also enables the round-trip test). Idempotent: flaws use
    INSERT OR REPLACE (the client's catalog mirrors the signed spine — the
    client does not enrich independently), the flat tables use INSERT OR
    REPLACE/IGNORE on their primary keys. If ``verify_manifest``, recompute
    every shard sha256 and assert it matches ``manifest.json`` first (raise on
    mismatch). Never touches ``verdicts`` / territory. Returns a stats dict.
    """
    root = Path(from_dir) / SPINE_DIR
    if verify_manifest:
        verify_spine(from_dir)
    manifest = json.loads((root / "manifest.json").read_text())

    stats = {k: 0 for k in ("flaws", "crosswalk", "candidates",
                           "distrust_marks", "seen_flaws", "kev",
                           "apple_fixes")}

    # --- flaws: full INSERT OR REPLACE (all columns, including enrich_state,
    #     distrusted, distrust_reason, discovered_at — a faithful mirror of
    #     the signed map; upsert_flaw would drop those) ---
    for shard_path in sorted((root / "flaws").glob("*.jsonl")):
        for row in _read_jsonl(shard_path):
            conn.execute(
                """INSERT OR REPLACE INTO flaws
                     (id, flaw_type, published, cvss, severity, cvss_vector,
                      description, fixed_raw, refs, cwe, ref_tags, enrich_state,
                      source, fetched_at, policy_version, complete, distrusted,
                      distrust_reason, discovered_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row["id"], row.get("flaw_type"), row.get("published"),
                    row.get("cvss"),
                    row.get("severity"), row.get("cvss_vector"),
                    row.get("description", ""),
                    json.dumps(row.get("fixed_raw"), default=str, sort_keys=True)
                        if row.get("fixed_raw") is not None else None,
                    json.dumps(row.get("refs") or []),
                    json.dumps(row.get("cwe") or []),
                    json.dumps(row.get("ref_tags") or []),
                    row.get("enrich_state"), row.get("source"),
                    row.get("fetched_at"), row.get("policy_version"),
                    int(row.get("complete") or 0),
                    int(row.get("distrusted") or 0),
                    row.get("distrust_reason"), row.get("discovered_at"),
                ),
            )
            stats["flaws"] += 1

    # --- crosswalk: INSERT OR IGNORE (PK flaw_id,alias,kind — idempotent) ---
    for row in _read_jsonl(root / "crosswalk.jsonl"):
        conn.execute(
            "INSERT OR IGNORE INTO crosswalk (flaw_id, alias, kind) VALUES (?,?,?)",
            (row["flaw_id"], row["alias"], row["kind"]),
        )
        stats["crosswalk"] += 1

    # --- candidates: INSERT OR REPLACE (id PK) ---
    for row in _read_jsonl(root / "candidates.jsonl"):
        conn.execute(
            """INSERT OR REPLACE INTO candidates
                 (id, url, fmt, axis, status, note, added_at)
               VALUES (?,?,?,?,?,?,?)""",
            (row["id"], row.get("url"), row.get("fmt"), row.get("axis"),
             row.get("status", "review"), row.get("note"), row.get("added_at")),
        )
        stats["candidates"] += 1

    # --- distrust_marks: INSERT OR REPLACE (witness PK) ---
    for row in _read_jsonl(root / "distrust_marks.jsonl"):
        conn.execute(
            "INSERT OR REPLACE INTO distrust_marks (witness, marked_at, reason) "
            "VALUES (?,?,?)",
            (row["witness"], row.get("marked_at"), row.get("reason")),
        )
        stats["distrust_marks"] += 1

    # --- seen_flaws: INSERT OR REPLACE (flaw_id PK) ---
    for row in _read_jsonl(root / "seen_flaws.jsonl"):
        conn.execute(
            "INSERT OR REPLACE INTO seen_flaws (flaw_id, first_seen) VALUES (?,?)",
            (row["flaw_id"], row.get("first_seen")),
        )
        stats["seen_flaws"] += 1

    # --- kev: INSERT OR REPLACE (cve_id PK) — the exploitability_signal overlay
    for row in _read_jsonl(root / "kev.jsonl"):
        conn.execute(
            """INSERT OR REPLACE INTO kev
                 (cve_id, date_added, vendor_project, product, name,
                  short_description, required_action, due_date, ransomware_use,
                  cwes, catalog_version, date_released, fetched_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (row["cve_id"], row.get("date_added"), row.get("vendor_project"),
             row.get("product"), row.get("name"), row.get("short_description"),
             row.get("required_action"), row.get("due_date"),
             row.get("ransomware_use"),
             json.dumps(row.get("cwes") or []),
             row.get("catalog_version"), row.get("date_released"),
             row.get("fetched_at")),
        )
        stats["kev"] += 1

    # --- apple_fixes: INSERT OR REPLACE (cve_id, product PK) — the Apple
    #     fix-version overlay. Per-product idempotent refresh on the ingest side
    #     (DELETE WHERE product + INSERT); on import we INSERT OR REPLACE so a
    #     re-import replaces, never duplicates.
    for row in _read_jsonl(root / "apple_fixes.jsonl"):
        conn.execute(
            """INSERT OR REPLACE INTO apple_fixes
                 (cve_id, product, fixed_in, advisory_id, fetched_at)
               VALUES (?,?,?,?,?)""",
            (row["cve_id"], row.get("product"), row.get("fixed_in"),
             row.get("advisory_id"), row.get("fetched_at")),
        )
        stats["apple_fixes"] += 1

    conn.commit()
    # surface any drift between manifest counts and what we loaded — but only
    # when the manifest was verified (unverified imports skip the manifest
    # entirely, so its counts aren't a trustworthy baseline).
    if verify_manifest:
        for k in stats:
            if manifest["counts"].get(k) != stats[k]:
                raise ValueError(
                    f"spine import count drift for {k}: loaded {stats[k]} "
                    f"!= manifest {manifest['counts'].get(k)}"
                )
    return stats