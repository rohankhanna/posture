"""Spine export/import — the signed-directory interface between CI and clients.

This is the missing piece that makes "feed and enrich in CI, consume locally"
real. posture's catalog lives in SQLite; that's a working state, not a durable,
auditable, signed artifact. The spine export serializes the **map** half of the
map/territory split to sharded JSONL plus a self-auditing manifest, which CI then
cosign-signs and commits. A client clones the signed repo, verifies the
signature, and imports the JSONL back into its own SQLite DB to run assess
locally over its private devices (the territory half — never exported).

**Data-only.** The spine is the MAP: defects, crosswalk, candidates,
distrust_marks, seen_defects. It NEVER serializes verdicts /
device_posture / health_* / glossary / repair_proposals — those
are territory (device-specific) or engine-internal. No device data ever leaves CI.

**Streaming.** Export walks every table with a server-side cursor and writes
each shard incrementally, hashing bytes as they land: peak memory stays one
row plus per-part bookkeeping no matter how large the catalog grows. (The
catalog outgrew the VPS unit's memory cap when the export assembled the whole
catalog in RAM — the daily build was OOM-killed; this is the durable fix.)
The manifest pins every shard by sha256 + count exactly as before, so
:func:`verify_spine` / :func:`import_spine` and downstream consumers are
unaffected.

Layout under --out DIR (default .)::

    DIR/spine/manifest.json          # cosign signs THIS -> state.sig
    DIR/spine/defects/2026-07.jsonl         # sharded by published month; oversized
    DIR/spine/defects/2026-07-000001.jsonl  # months split into numbered parts
    DIR/spine/defects/unknown.jsonl         # rows with no date -> 'unknown')
    DIR/spine/crosswalk.jsonl
    DIR/spine/candidates.jsonl
    DIR/spine/distrust_marks.jsonl
    DIR/spine/seen_defects.jsonl

The manifest carries a per-file sha256 + count for every shard, so
tamper-evidence lives in the signature over the manifest, NOT in git history.
That is what frees history to be gc'd/squashed without losing trust: a client
verifies state.sig against manifest.json, and manifest.json pins
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
import shutil
from pathlib import Path

from . import store as _store

MANIFEST_VERSION = "1"
SPINE_DIR = "spine"
MAX_DEFECT_SHARD_BYTES = 48 * 1024 * 1024
# Staging/previous directory names used by :func:`publish_spine`. Both are
# hidden siblings of the served spine directory, so a web server that serves
# the parent directory does not advertise them.
STAGING_DIR_NAME = ".spine-staging"
PREVIOUS_DIR_NAME = ".spine-previous"
# The MAP tables — the spine. Territory/engine-internal tables are deliberately
# absent: verdicts, device_posture, health_*, glossary, term_signals,
# spine_bindings, repair_proposals, policy_versions, state.
FLAT_TABLES = ("crosswalk", "candidates", "distrust_marks", "seen_defects", "kev",
               "apple_fixes", "debian_fixes", "ubuntu_fixes", "epss")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _defect_shard_key(row: dict) -> str:
    """YYYY-MM bucket from a defects row's published (e.g. '2026-07-31' ->
    '2026-07'). Rows with no parseable date land in 'unknown' so nothing is
    dropped — the spine is a complete snapshot. This is the reference rule that
    :data:`posture.store._DEFECT_SHARD_KEY_SQL` mirrors in SQL so the export
    streams rows already ordered by bucket."""
    pub = row.get("published") or ""
    return pub[:7] if len(pub) >= 7 else "unknown"


def _serialize_line(row: dict) -> bytes:
    """One row as its exact on-disk bytes (UTF-8 JSON line) — the same bytes the
    sha256 covers, so the digest always matches what was written, on any
    locale."""
    return (json.dumps(row, sort_keys=True, default=str) + "\n").encode("utf-8")


def _write_jsonl(path: Path, rows) -> tuple[str, int]:
    """Stream rows as one JSON object per line; return (sha256, count). The
    sha256 is computed incrementally over the exact bytes written, so a client
    re-reading the file can detect any tampering via the manifest — and the
    whole shard never exists in memory (the flat overlays run to tens of MB)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    count = 0
    with open(path, "wb") as handle:
        for row in rows:
            line = _serialize_line(row)
            handle.write(line)
            digest.update(line)
            count += 1
    return digest.hexdigest(), count


class _MonthSharder:
    """Streaming per-month shard writer for defects.

    Consumes (shard_key, row) pairs ordered by shard key (see
    :func:`posture.store.catalog_iter_shard_keys`) and writes each month's rows
    to YYYY-MM.jsonl, splitting oversized months into numbered
    YYYY-MM-NNNNNN.jsonl parts no larger than max_bytes (a single row
    is always kept intact; the ceiling leaves headroom below the repository
    host's hard file-size limit and its lower warning threshold). Because the
    final filename depends on the part count — unknown until the bucket
    closes — parts stream to hidden .part-NNNNNN files and are renamed
    into place when the bucket finishes. Memory stays at one serialized row
    plus per-part bookkeeping, no matter how large the month grows."""

    def __init__(self, defects_dir: Path, max_bytes: int) -> None:
        self._dir = defects_dir
        self._max = max_bytes
        self._dir.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []
        self.total = 0
        self._bucket: str | None = None
        self._parts: list[tuple[Path, str, int]] = []
        self._handle = None
        self._digest = None
        self._tmp: Path | None = None
        self._count = 0
        self._bytes = 0

    def _open_part(self) -> None:
        self._tmp = self._dir / f".{self._bucket}.jsonl.part-{len(self._parts) + 1:06d}"
        self._handle = open(self._tmp, "wb")
        self._digest = hashlib.sha256()
        self._count = 0
        self._bytes = 0

    def _close_part(self) -> None:
        self._handle.close()
        self._parts.append((self._tmp, self._digest.hexdigest(), self._count))
        self._handle = None

    def _finish_bucket(self) -> None:
        if self._handle is not None:
            self._close_part()
        if not self._parts:
            return
        single = len(self._parts) == 1
        for index, (tmp, sha, count) in enumerate(self._parts, start=1):
            filename = (f"{self._bucket}.jsonl" if single
                        else f"{self._bucket}-{index:06d}.jsonl")
            # atomically replace the same-named shard from a previous run
            os.replace(tmp, self._dir / filename)
            self.entries.append({"path": f"defects/{filename}", "sha256": sha,
                                 "count": count})
        self._parts = []

    def write(self, shard_key: str, row: dict) -> None:
        if shard_key != self._bucket:
            self._finish_bucket()
            self._bucket = shard_key
        line = _serialize_line(row)
        if self._handle is None:
            self._open_part()
        elif self._count and self._bytes + len(line) > self._max:
            self._close_part()
            self._open_part()
        self._handle.write(line)
        self._digest.update(line)
        self._count += 1
        self._bytes += len(line)
        self.total += 1

    def finish(self) -> list[dict]:
        self._finish_bucket()
        return self.entries


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_jsonl(path: Path):
    """Yield parsed JSON objects one line at a time (empty file yields
    nothing) — the import path streams shards instead of holding whole files
    in memory."""
    if not path.exists():
        return
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

def export_spine(conn, out_dir: os.PathLike | str = ".",
                 policy_version: str = "",
                 source_version: dict | None = None,
                 now: str | None = None) -> dict:
    """Serialize the catalog tables to <out_dir>/spine/*.jsonl + manifest.

    Opens the DB read-only in spirit (the caller passes a readonly connection;
    export never writes to the DB). Returns the manifest dict. source_version
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

    # --- defects: streamed shard-by-shard, rows already ordered by published
    #     month (server-side cursor; the whole catalog never lands in RAM) ---
    defects_dir = root / "defects"
    if defects_dir.exists():
        # drop provisional parts from any crashed prior run — the self-clean
        # below only matches final *.jsonl names
        for stale in defects_dir.glob("*.jsonl.part-*"):
            stale.unlink()
    sharder = _MonthSharder(defects_dir, MAX_DEFECT_SHARD_BYTES)
    for shard_key, row in _store.catalog_iter_shard_keys(conn):
        sharder.write(shard_key, row)
    files.extend(sharder.finish())
    counts["defects"] = sharder.total

    # --- flat tables (streamed one row at a time) ---
    loaders = {
        "crosswalk": _store.crosswalk_iter,
        "candidates": _store.candidates_iter,
        "distrust_marks": _store.distrust_marks_iter,
        "seen_defects": _store.seen_defects_iter,
        "kev": _store.kev_iter,
        "apple_fixes": _store.apple_fixes_iter,
        "debian_fixes": _store.debian_fixes_iter,
        "ubuntu_fixes": _store.ubuntu_fixes_iter,
        "epss": _store.epss_iter,
    }
    for name in FLAT_TABLES:
        sha, n = _write_jsonl(root / f"{name}.jsonl", loaders[name](conn))
        counts[name] = n
        files.append({"path": f"{name}.jsonl", "sha256": sha, "count": n})

    # --- self-clean: drop any *.jsonl shard under root that this export did NOT
    #     write. Makes export idempotent w.r.t. format renames (a prior run's
    #     spine/flaws/*.jsonl or seen_flaws.jsonl is removed instead of lingering
    #     beside the new spine/defects/*.jsonl). manifest.json is regenerated below.
    #     Materialize the rglob FIRST: it is a generator, and unlinking/rmtree-ing
    #     shards mid-iteration removes a directory rglob still intends to descend
    #     into -> FileNotFoundError on the old shard dir (e.g. 'spine/flaws').
    written = {entry["path"] for entry in files}
    for path in list(root.rglob("*.jsonl")):
        rel = path.relative_to(root).as_posix()
        if rel not in written:
            path.unlink()
            # remove the shard dir if it is now empty (e.g. the old cves/ dir)
            d = path.parent
            if d != root and d.exists() and not any(d.iterdir()):
                shutil.rmtree(d)

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
# publish (export -> verify -> atomic swap of the served spine directory)
# ---------------------------------------------------------------------------

def publish_spine(conn, out_dir: os.PathLike | str = ".",
                  policy_version: str = "",
                  source_version: dict | None = None,
                  now: str | None = None,
                  sign_key: os.PathLike | str | None = None) -> dict:
    """Export the spine, verify it, and publish it in one atomic step.

    The deployment line serves the spine directory directly to clients, so the
    directory must never be observed half-written. :func:`export_spine` writes
    shards first and the manifest last, and it self-cleans shards the current
    run did not write — an interrupted export therefore leaves the previously
    published map in a broken state (the old manifest can reference shards the
    self-clean already deleted, or a shard can be half-overwritten under an old
    digest).

    This function removes that window:

    1. the export lands in a staging directory beside the served directory;
    2. the staged map is verified (manifest digest + row count for every
       shard; the optional manifest signature is produced here too, so the
       published map carries its signature);
    3. only a verified map replaces the served directory, and it does so with
       a single rename.

    Any failure before the swap leaves the previously published map exactly as
    it was and removes the staging directory. The served map is therefore
    always either the last verified snapshot or the new one — never a
    mixture.

    Returns the published manifest (the same dict :func:`export_spine`
    returns). Raises on any failure; the caller decides how loudly to fail.
    """
    root = Path(out_dir)
    staging = root / STAGING_DIR_NAME
    previous = root / PREVIOUS_DIR_NAME
    published = root / SPINE_DIR

    if staging.exists():
        shutil.rmtree(staging)
    try:
        manifest = export_spine(conn, out_dir=staging,
                                policy_version=policy_version,
                                source_version=source_version, now=now)
        if sign_key:
            sign_manifest(staging, sign_key)
        verify_spine(staging)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    # --- the swap: two renames on the same filesystem, no copy -------------
    if previous.exists():
        shutil.rmtree(previous)
    if published.exists():
        os.replace(published, previous)
    try:
        os.replace(staging / SPINE_DIR, published)
    except BaseException:
        # the new map never landed — put the previous one back
        if previous.exists() and not published.exists():
            os.replace(previous, published)
        shutil.rmtree(staging, ignore_errors=True)
        raise
    shutil.rmtree(previous, ignore_errors=True)
    shutil.rmtree(staging, ignore_errors=True)
    return manifest


# ---------------------------------------------------------------------------
# verify (manifest-internal consistency — NOT the cosign signature)
# ---------------------------------------------------------------------------

def verify_spine(from_dir: os.PathLike | str = ".") -> dict:
    """Recompute every shard sha256 and assert it matches manifest.json.
    This checks the manifest's internal consistency (the snapshot is intact on
    disk); it does NOT verify the cosign signature (that's cosign
    verify-blob). Clients run this after cosign verify-blob and before
    :func:`import_spine`. Raises ValueError on any mismatch/missing file.
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
        with open(path, encoding="utf-8") as handle:
            n = sum(1 for line in handle if line.strip())
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
    """Load <from_dir>/spine/*.jsonl into the SQLite DB (the client
    consumption path; also enables the round-trip test). Idempotent: defects use
    INSERT OR REPLACE (the client's catalog mirrors the signed spine — the
    client does not enrich independently), the flat tables use INSERT OR
    REPLACE/IGNORE on their primary keys. If verify_manifest, recompute
    every shard sha256 and assert it matches manifest.json first (raise on
    mismatch). Never touches verdicts / territory. Returns a stats dict.
    """
    root = Path(from_dir) / SPINE_DIR
    if verify_manifest:
        verify_spine(from_dir)
    manifest = json.loads((root / "manifest.json").read_text())

    stats = {k: 0 for k in ("defects", "crosswalk", "candidates",
                           "distrust_marks", "seen_defects", "kev",
                           "apple_fixes", "debian_fixes", "ubuntu_fixes",
                           "epss")}

    # --- defects: full INSERT OR REPLACE (all columns, including enrich_state,
    #     distrusted, distrust_reason, discovered_at, prompt_hash, raw_text_hash
    #     — a faithful mirror of the signed map; upsert_defect would drop those) ---
    for shard_path in sorted((root / "defects").glob("*.jsonl")):
        for row in _read_jsonl(shard_path):
            conn.execute(
                """INSERT OR REPLACE INTO defects
                     (id, defect_type, published, cvss, severity, cvss_vector,
                      description, fixed_raw, refs, cwe, ref_tags, enrich_state,
                      source, fetched_at, policy_version, complete, distrusted,
                      distrust_reason, discovered_at, prompt_hash, raw_text_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row["id"], row.get("defect_type"), row.get("published"),
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
                    row.get("prompt_hash"), row.get("raw_text_hash"),
                ),
            )
            stats["defects"] += 1

    # --- crosswalk: INSERT OR IGNORE (PK defect_id,alias,kind — idempotent) ---
    for row in _read_jsonl(root / "crosswalk.jsonl"):
        conn.execute(
            "INSERT OR IGNORE INTO crosswalk (defect_id, alias, kind) VALUES (?,?,?)",
            (row["defect_id"], row["alias"], row["kind"]),
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

    # --- distrust_marks: INSERT OR REPLACE (observer PK) ---
    for row in _read_jsonl(root / "distrust_marks.jsonl"):
        conn.execute(
            "INSERT OR REPLACE INTO distrust_marks (observer, marked_at, reason) "
            "VALUES (?,?,?)",
            (row["observer"], row.get("marked_at"), row.get("reason")),
        )
        stats["distrust_marks"] += 1

    # --- seen_defects: INSERT OR REPLACE (defect_id PK) ---
    for row in _read_jsonl(root / "seen_defects.jsonl"):
        conn.execute(
            "INSERT OR REPLACE INTO seen_defects (defect_id, first_seen) VALUES (?,?)",
            (row["defect_id"], row.get("first_seen")),
        )
        stats["seen_defects"] += 1

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

    # --- debian_fixes: INSERT OR REPLACE (cve_id, release, package PK) — the
    #     Debian security-tracker status overlay. Per-(release, package)
    #     idempotent refresh on the ingest side (DELETE WHERE release+package +
    #     INSERT); on import we INSERT OR REPLACE so a re-import replaces, never
    #     duplicates.
    for row in _read_jsonl(root / "debian_fixes.jsonl"):
        conn.execute(
            """INSERT OR REPLACE INTO debian_fixes
                 (cve_id, release, package, status, fixed_in, fetched_at)
               VALUES (?,?,?,?,?,?)""",
            (row["cve_id"], row.get("release"), row.get("package"),
             row.get("status"), row.get("fixed_in"), row.get("fetched_at")),
        )
        stats["debian_fixes"] += 1

    # --- ubuntu_fixes: INSERT OR REPLACE (cve_id, release, package PK) — the
    #     Ubuntu security-tracker status overlay. Per-(release, package)
    #     idempotent refresh on the ingest side (DELETE WHERE release+package +
    #     INSERT); on import we INSERT OR REPLACE so a re-import replaces, never
    #     duplicates.
    for row in _read_jsonl(root / "ubuntu_fixes.jsonl"):
        conn.execute(
            """INSERT OR REPLACE INTO ubuntu_fixes
                 (cve_id, release, package, status, fixed_in, fetched_at)
               VALUES (?,?,?,?,?,?)""",
            (row["cve_id"], row.get("release"), row.get("package"),
             row.get("status"), row.get("fixed_in"), row.get("fetched_at")),
        )
        stats["ubuntu_fixes"] += 1

    # --- epss: INSERT OR REPLACE (cve_id PK) — the FIRST.org exploitability-
    #     likelihood overlay (complementary to kev; fills the NVD-degradation
    #     gap). Idempotent full refresh on the ingest side (DELETE all + INSERT);
    #     on import we INSERT OR REPLACE so a re-import replaces, never
    #     duplicates.
    for row in _read_jsonl(root / "epss.jsonl"):
        conn.execute(
            """INSERT OR REPLACE INTO epss
                 (cve_id, epss, percentile, fetched_at)
               VALUES (?,?,?,?)""",
            (row["cve_id"], row.get("epss"), row.get("percentile"),
             row.get("fetched_at")),
        )
        stats["epss"] += 1

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


# ---------------------------------------------------------------------------
# manifest signing (ed25519 over manifest.json -> state.sig)
# ---------------------------------------------------------------------------

def generate_signing_keypair(private_key_path: os.PathLike | str,
                             public_key_path: os.PathLike | str) -> None:
    """Generate a fresh ed25519 keypair and write it to two PEM files.

    The private key file is the spine's signing identity; guard it like a
    credential (chmod 600 on the VPS, never commit it). The public key file
    is distributed to clients so they can verify the spine signature.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(private_key_path).write_bytes(priv_pem)
    Path(public_key_path).write_bytes(pub_pem)
    try:
        Path(private_key_path).chmod(0o600)
    except OSError:
        pass  # chmod may not be meaningful on all platforms


def sign_manifest(out_dir: os.PathLike | str,
                  private_key_path: os.PathLike | str) -> str:
    """Sign <out_dir>/spine/manifest.json with an ed25519 private key
    and write the hex-encoded signature to <out_dir>/spine/state.sig.

    Returns the hex-encoded signature. The signature is over the exact bytes
    of manifest.json on disk, so a client re-reading the file can detect
    tampering via :func:`verify_manifest_signature`.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    root = Path(out_dir) / SPINE_DIR
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        raise ValueError(f"manifest not found: {manifest_path}")
    priv_pem = Path(private_key_path).read_bytes()
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    if not isinstance(priv, ed25519.Ed25519PrivateKey):
        raise ValueError("private key is not ed25519")
    manifest_bytes = manifest_path.read_bytes()
    signature = priv.sign(manifest_bytes)
    sig_hex = signature.hex()
    (root / "state.sig").write_text(sig_hex + "\n")
    return sig_hex


def verify_manifest_signature(out_dir: os.PathLike | str,
                              public_key_path: os.PathLike | str) -> None:
    """Verify the ed25519 signature in <out_dir>/spine/state.sig against
    <out_dir>/spine/manifest.json using the supplied public key.

    Raises ValueError if the signature file is missing, the key is not
    ed25519, or the signature does not verify. This is the cryptographic trust
    anchor: a client runs this BEFORE :func:`verify_spine` (sha256 internal
    consistency) and :func:`import_spine`.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    root = Path(out_dir) / SPINE_DIR
    sig_path = root / "state.sig"
    manifest_path = root / "manifest.json"
    if not sig_path.exists():
        raise ValueError("spine signature missing: state.sig not found")
    if not manifest_path.exists():
        raise ValueError("spine manifest missing: manifest.json not found")
    pub_pem = Path(public_key_path).read_bytes()
    pub = serialization.load_pem_public_key(pub_pem)
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        raise ValueError("public key is not ed25519")
    sig_hex = sig_path.read_text().strip()
    try:
        signature = bytes.fromhex(sig_hex)
    except ValueError:
        raise ValueError("state.sig is not valid hex")
    manifest_bytes = manifest_path.read_bytes()
    try:
        pub.verify(signature, manifest_bytes)
    except Exception:
        raise ValueError("spine signature verification FAILED — manifest may "
                         "be tampered or signed by a different key")
