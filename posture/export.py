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

**Size-capped shards.** Every shard the export writes is capped well below the
repository host's hard per-file limit, which refuses a push containing a file
above it. A defect month that outgrows the cap becomes numbered parts
(2026-07-000001.jsonl, ...), and the flat overlay tables are capped the
same way (crosswalk-000001.jsonl, ...). The export also fails closed if
any written shard ever reaches the hard limit, so an un-publishable map is
never published.

Layout under --out DIR (default .)::

    DIR/spine/manifest.json          # cosign signs THIS -> state.sig
    DIR/spine/defects/2026-07.jsonl         # sharded by published month; oversized
    DIR/spine/defects/2026-07-000001.jsonl  # months split into numbered parts
    DIR/spine/defects/unknown.jsonl         # rows with no date -> 'unknown')
    DIR/spine/crosswalk.jsonl
    DIR/spine/crosswalk-000001.jsonl   # a flat table that outgrew the size cap
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
# The published map's own layout, inside the served directory. The manifest
# names every shard and its digest; the defect shards live in their own
# directory, one file per published month. These names are the ones the
# deployment runbook documents and the deployment-line gate checks, so the
# operator's verification steps name the paths the code actually writes.
MANIFEST_NAME = "manifest.json"
DEFECTS_DIR = "defects"
# Per-shard size caps. The repository host rejects a push that contains a file
# above its hard per-file limit, so every shard the export writes is capped
# well below it. The defect shards are capped per published month; the flat
# overlay tables are capped per table (a table that outgrows the cap becomes
# numbered parts, exactly like an oversized month).
MAX_DEFECT_SHARD_BYTES = 48 * 1024 * 1024
MAX_FLAT_SHARD_BYTES = 48 * 1024 * 1024
# The host's hard per-file limit (GitHub refuses a push containing a file above
# 100MB). The caps above stay well under it; the export fails closed if a
# written shard ever reaches it, so an un-pushable map is never published.
HARD_FILE_SIZE_LIMIT_BYTES = 100 * 1024 * 1024
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

# The overlay tables of the map: the peer overlays a host may require its
# published map to carry. The vendor fix-status overlays (Ubuntu, Debian,
# Apple) are the ones that clear NVD's unknown-fix false positives on a
# fully-updated host, and the known-exploited set says which defects are
# being exploited. A map can be intact, consistent with its own manifest,
# correctly signed and fresh while one of these tables is empty: the
# overlay rows are missing, and the map is quietly wrong about which
# packages are patched.
OVERLAY_TABLES = ("kev", "apple_fixes", "debian_fixes", "ubuntu_fixes")

# The overlay tables whose rows are keyed by a release (a distribution
# codename) and a source package. Their coverage is a per-release question,
# not a per-table one: a table that still holds rows for three of the four
# releases the host requires is a map that is quietly narrow, and the
# vendor fix-status rows of the missing release are the ones that clear
# NVD's unknown-fix false positives on that release. The published manifest
# therefore states, per release, how many rows the map carries and when the
# most recent of them was fetched.
RELEASE_KEYED_OVERLAY_TABLES = ("ubuntu_fixes", "debian_fixes")


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


def _clean_stale_parts(directory: Path) -> None:
    """Remove the hidden .<name>.jsonl.part-NNNNNN staging files a crashed
    run left behind. The parts are renamed into place when a shard finishes, so
    a leftover part file is always garbage from an interrupted run (and would
    otherwise sit in the published directory forever)."""
    if not directory.exists():
        return
    for path in directory.iterdir():
        if path.name.startswith(".") and ".part-" in path.name:
            path.unlink()


class _ShardWriter:
    """Streaming writer for one logical shard, split into size-capped parts.

    Rows are written as one JSON object per line; the sha256 is computed
    incrementally over the exact bytes written, so a client re-reading the file
    can detect any tampering via the manifest. When the next row would push the
    current part past max_bytes, a new part starts (a single row is never
    split — it is always kept intact). Because the final file name depends on
    the part count, which is only known when the shard finishes, parts stream
    to hidden .<prefix>.jsonl.part-NNNNNN files and are renamed into place
    at the end. Memory stays at one serialized row plus per-part bookkeeping,
    no matter how large the table grows.

    A shard that fits in one part keeps the plain name (<prefix>.jsonl); a
    shard that outgrows the cap becomes numbered parts
    (<prefix>-000001.jsonl, <prefix>-000002.jsonl, ...)."""

    def __init__(self, directory: Path, prefix: str, max_bytes: int,
                 rel_prefix: str = "") -> None:
        self._dir = directory
        self._prefix = prefix
        self._max = max_bytes
        self._rel = rel_prefix
        self._dir.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []
        self.total = 0
        self._parts: list[tuple[Path, str, int]] = []
        self._handle = None
        self._digest = None
        self._tmp: Path | None = None
        self._count = 0
        self._bytes = 0

    def _open_part(self) -> None:
        self._tmp = self._dir / f".{self._prefix}.jsonl.part-{len(self._parts) + 1:06d}"
        self._handle = open(self._tmp, "wb")
        self._digest = hashlib.sha256()
        self._count = 0
        self._bytes = 0

    def _close_part(self) -> None:
        self._handle.close()
        self._parts.append((self._tmp, self._digest.hexdigest(), self._count))
        self._handle = None

    def write(self, row: dict) -> None:
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
        if self._handle is not None:
            self._close_part()
        single = len(self._parts) == 1
        for index, (tmp, sha, count) in enumerate(self._parts, start=1):
            filename = (f"{self._prefix}.jsonl" if single
                        else f"{self._prefix}-{index:06d}.jsonl")
            # atomically replace the same-named shard from a previous run
            os.replace(tmp, self._dir / filename)
            self.entries.append({"path": f"{self._rel}{filename}", "sha256": sha,
                                 "count": count})
        self._parts = []
        return self.entries


class _MonthSharder:
    """Streaming per-month shard writer for defects.

    Consumes (shard_key, row) pairs ordered by shard key (see
    :func:`posture.store.catalog_iter_shard_keys`) and writes each month's rows
    to YYYY-MM.jsonl, splitting oversized months into numbered
    YYYY-MM-NNNNNN.jsonl parts no larger than max_bytes (a single row
    is always kept intact; the ceiling leaves headroom below the repository
    host's hard file-size limit and its lower warning threshold). Memory stays
    at one serialized row plus per-part bookkeeping, no matter how large the
    month grows."""

    def __init__(self, defects_dir: Path, max_bytes: int) -> None:
        self._dir = defects_dir
        self._max = max_bytes
        self._dir.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []
        self.total = 0
        self._bucket: str | None = None
        self._writer: _ShardWriter | None = None

    def _finish_bucket(self) -> None:
        if self._writer is not None:
            self.entries.extend(self._writer.finish())
            self._writer = None

    def write(self, shard_key: str, row: dict) -> None:
        if shard_key != self._bucket:
            self._finish_bucket()
            self._bucket = shard_key
            self._writer = _ShardWriter(self._dir, shard_key, self._max,
                                        rel_prefix="defects/")
        self._writer.write(row)
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


def assert_shard_sizes_within_limit(root: Path, files: list[dict],
                                    limit: int | None = None) -> None:
    """Fail closed when a written shard exceeds the host's hard per-file limit.

    The repository host rejects a push that contains a file above its limit, so
    an oversize shard is a map that cannot be published. The check is on the
    bytes actually on disk (not on the byte counters used for the cap), and it
    runs before the manifest is written: a failed export therefore leaves no
    manifest claiming the oversize shards.
    """
    limit = HARD_FILE_SIZE_LIMIT_BYTES if limit is None else limit
    for entry in files:
        path = root / entry["path"]
        size = path.stat().st_size
        if size > limit:
            raise ValueError(
                f"spine shard exceeds the {limit}-byte hard file limit: "
                f"{entry['path']} ({size} bytes)"
            )


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

def _tally_release_coverage(coverage: dict, row: dict) -> None:
    """Fold one release-keyed overlay row into the per-release coverage.

    The coverage states three things per release: how many rows the map
    carries for it, which source packages contributed them, and when the
    most recent of them was fetched. The fetch time is what tells a live
    release from a retained one: the per-(release, package) refresh deletes
    the rows it is about to replace, so a release whose tracker feed
    returned nothing ends up with no rows at all, while a release the
    nightly job stopped ingesting keeps its last-known-good rows and goes
    quietly stale.
    """
    release = str(row.get("release") or "").strip()
    if not release:
        return
    entry = coverage.setdefault(release, {
        "rows": 0, "newest_fetched_at": None, "packages": {}})
    entry["rows"] += 1
    package = str(row.get("package") or "").strip()
    if package:
        packages = entry["packages"]
        packages[package] = packages.get(package, 0) + 1
    fetched_at = str(row.get("fetched_at") or "").strip()
    if fetched_at and fetched_at > (entry["newest_fetched_at"] or ""):
        entry["newest_fetched_at"] = fetched_at


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
    defects_dir = root / DEFECTS_DIR
    # drop provisional parts from any crashed prior run — the self-clean
    # below only matches final *.jsonl names
    _clean_stale_parts(defects_dir)
    _clean_stale_parts(root)
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
    release_coverage: dict[str, dict] = {
        name: {} for name in RELEASE_KEYED_OVERLAY_TABLES}
    for name in FLAT_TABLES:
        # Same size cap as the defect shards: a flat table that outgrows the
        # cap becomes numbered parts instead of one unbounded file, so no
        # single published file can cross the host's hard per-file limit.
        writer = _ShardWriter(root, name, MAX_FLAT_SHARD_BYTES)
        for row in loaders[name](conn):
            writer.write(row)
            if name in release_coverage:
                _tally_release_coverage(release_coverage[name], row)
        files.extend(writer.finish())
        counts[name] = writer.total

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

    # Fail closed on an oversize shard: the host refuses a push that contains
    # a file above its hard per-file limit, so an oversize shard is a map that
    # cannot be published. The check reads the bytes actually on disk.
    assert_shard_sizes_within_limit(root, files)

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "generated_at": generated_at,
        "policy_version": policy_version,
        "source_version": src,
        "counts": counts,
        "files": files,
        "release_coverage": release_coverage,
    }
    (root / MANIFEST_NAME).write_text(
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

def read_manifest(from_dir: os.PathLike | str = ".") -> dict:
    """The manifest of a published map directory.

    The manifest is the map's own statement about itself: which shards it
    holds, what each shard's digest and row count are, and when the map
    was built (generated_at). Reading it is cheap; verifying it is
    :func:`verify_spine`'s job.
    """
    root = Path(from_dir) / SPINE_DIR
    return json.loads((root / MANIFEST_NAME).read_text())


def verify_spine(from_dir: os.PathLike | str = ".") -> dict:
    """Recompute every shard sha256 and assert it matches manifest.json.
    This checks the manifest's internal consistency (the snapshot is intact on
    disk); it does NOT verify the cosign signature (that's cosign
    verify-blob). Clients run this after cosign verify-blob and before
    :func:`import_spine`. Raises ValueError on any mismatch/missing file.
    Returns the manifest on success.
    """
    root = Path(from_dir) / SPINE_DIR
    manifest = read_manifest(from_dir)
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
# verify (freshness — how old is the map the host is serving?)
# ---------------------------------------------------------------------------


def _parse_generated_at(manifest: dict) -> _dt.datetime:
    """The build timestamp a manifest carries, as an aware datetime.

    Raises ValueError when the manifest carries no timestamp or one
    this version cannot read: a map whose age cannot be established is
    not a map that can be shown to be fresh.
    """
    raw = manifest.get("generated_at")
    if not raw or not isinstance(raw, str):
        raise ValueError(
            "the manifest carries no generated_at timestamp, so the age of "
            "the map cannot be established")
    text = raw.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        stamp = _dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(
            f"the manifest's generated_at ({raw}) is not a readable "
            f"timestamp, so the age of the map cannot be established"
        ) from exc
    if stamp.tzinfo is None:
        # A timestamp without an offset is read as UTC: every writer in
        # this repository stamps the manifest in UTC.
        stamp = stamp.replace(tzinfo=_dt.UTC)
    return stamp


def manifest_age_days(manifest: dict,
                      now: _dt.datetime | None = None) -> float:
    """The age of a manifest, in days, from its generated_at stamp.

    A negative age means the manifest was stamped in the future (a
    builder whose clock runs ahead); the map is not stale, and the caller
    sees the skew in the number it reports.
    """
    stamp = _parse_generated_at(manifest)
    reference = now or _dt.datetime.now(_dt.UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=_dt.UTC)
    return (reference - stamp).total_seconds() / 86400.0


def verify_manifest_freshness(manifest: dict, max_age_days: float,
                               now: _dt.datetime | None = None) -> float:
    """Check that a map is no older than max_age_days.

    The publish path is atomic, so a daily build that has been failing for
    days leaves the previously published map serving, intact and
    internally consistent. Every check on the map's contents still passes,
    and the only thing that shows the build has stopped is the map's own
    build timestamp. This check reads that timestamp and fails loudly when
    the map is older than the host allows.

    Returns the map's age in days. Raises ValueError when the map is
    older than the allowed age, when its age cannot be established, or
    when the allowed age is not a positive number of days.
    """
    if max_age_days is None or max_age_days <= 0:
        raise ValueError(
            "the maximum map age must be a positive number of days")
    age = manifest_age_days(manifest, now=now)
    if age > max_age_days:
        raise ValueError(
            f"the map was generated at {manifest.get('generated_at')} and is "
            f"{age:.1f} day(s) old, which is older than the {max_age_days:g} "
            f"day(s) allowed (the daily build has not published a newer map; "
            f"the last good map is still serving)")
    return age


# ---------------------------------------------------------------------------
# verify (overlay coverage — does the map still carry the overlay rows?)
# ---------------------------------------------------------------------------


def verify_overlay_coverage(
        manifest: dict,
        required_overlays: list[str] | tuple[str, ...] | None = None,
) -> dict[str, int]:
    """Check that a published map still carries the overlay rows it must.

    A map is published atomically, so a build that produced a map without
    the vendor fix-status overlays leaves the previously published map
    serving: intact, consistent with its own manifest, correctly signed and
    fresh. Every check on that map passes, and the only thing that shows
    the overlay rows are gone is the map's own row counts. The overlay rows
    are what clear NVD's unknown-fix false positives on a fully-updated
    host, so their absence is a map that reports patched packages as
    unpatched, not a map that is merely incomplete.

    required_overlays names the overlay tables the host requires. Each
    one must be an overlay table the map can carry (:data:`OVERLAY_TABLES`),
    and each must hold at least one row. Returns the row count of every
    required overlay. Raises ValueError when a required overlay is not
    a known overlay table, when the map's manifest carries no row counts at
    all, or when a required overlay is absent from the map or empty.
    """
    if not required_overlays:
        return {}
    counts = manifest.get("counts")
    if not isinstance(counts, dict):
        raise ValueError(
            "the published map's manifest carries no row counts, so its "
            "overlay coverage cannot be established")
    coverage: dict[str, int] = {}
    missing: list[str] = []
    for name in required_overlays:
        if name not in OVERLAY_TABLES:
            raise ValueError(
                f"{name} is not an overlay table the published map can carry "
                f"(the overlay tables are: {', '.join(OVERLAY_TABLES)})")
        count = counts.get(name)
        if count is None:
            missing.append(f"{name} (the map carries no {name} table at all)")
            continue
        try:
            count = int(count)
        except (TypeError, ValueError):
            raise ValueError(
                f"the published map's manifest states an unreadable row "
                f"count for the {name} overlay ({count!r})") from None
        if count <= 0:
            missing.append(f"{name} (the map's {name} overlay is empty)")
            continue
        coverage[name] = count
    if missing:
        raise ValueError(
            "the published map does not carry the overlay rows the host "
            "requires: " + "; ".join(missing) + " (the vendor fix-status "
            "overlays are what clear NVD's unknown-fix false positives on a "
            "fully-updated host, so a map without them reports patched "
            "packages as unpatched)")
    return coverage


# ---------------------------------------------------------------------------
# verify (per-release overlay coverage — does the map still carry every
# release the host requires?)
# ---------------------------------------------------------------------------


def _parse_timestamp(value: str) -> _dt.datetime | None:
    """An ISO-8601 timestamp as an aware datetime, or None when unreadable."""
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


def verify_overlay_release_coverage(
        manifest: dict,
        requirements: list[tuple[str, str, int]] | None = None,
        max_age_days: float | None = None,
        now: str | None = None,
) -> dict[str, dict]:
    """Check that a published map still carries every required overlay release.

    The overlay coverage check (:func:`verify_overlay_coverage`) asks whether
    an overlay table holds rows at all. That is a per-table question, and a
    per-table answer hides a per-release failure: the nightly job's
    per-(release, package) refresh deletes the rows it is about to replace,
    so a release whose tracker feed returned nothing ends up with no rows
    at all, while the table as a whole still holds the other releases' rows
    and the presence check still passes. The map is then quietly narrow: the
    missing release reports patched packages as unpatched, which is exactly
    the false positive the vendor fix-status overlay exists to clear.

    requirements is a list of (table, release, min_rows) triples: the
    map must carry at least min_rows rows for that release of that
    release-keyed overlay table. max_age_days additionally requires every
    required release to have been fetched within that many days, which
    catches the other silent direction — a release the nightly job stopped
    ingesting keeps its last-known-good rows, so only their age shows that
    they stopped being refreshed.

    Returns the per-release coverage that was checked. Raises
    ValueError when a requirement names a table that is not a
    release-keyed overlay table, when the manifest carries no per-release
    coverage at all (a map published before the manifest recorded it), when
    a required release is absent or below its floor, or when a required
    release is older than the freshness allowance.
    """
    requirements = list(requirements or [])
    if not requirements and max_age_days is None:
        return {}
    for table, release, min_rows in requirements:
        if table not in RELEASE_KEYED_OVERLAY_TABLES:
            raise ValueError(
                f"{table} is not a release-keyed overlay table "
                f"(the release-keyed overlay tables are: "
                f"{', '.join(RELEASE_KEYED_OVERLAY_TABLES)})")
        if not str(release).strip():
            raise ValueError(
                f"the {table} overlay coverage requirement names no release")
        if int(min_rows) < 1:
            raise ValueError(
                f"the {table} overlay coverage requirement for release "
                f"{release} asks for {min_rows} row(s); the minimum is one")
    coverage = manifest.get("release_coverage")
    if not isinstance(coverage, dict):
        raise ValueError(
            "the published map's manifest carries no per-release overlay "
            "coverage, so the releases the host requires cannot be "
            "established (the map was published before the manifest "
            "recorded it)")
    now_dt = _parse_timestamp(now) if now else _dt.datetime.now(_dt.timezone.utc)
    checked: dict[str, dict] = {}
    missing: list[str] = []
    for table, release, min_rows in requirements:
        release = str(release).strip()
        per_table = coverage.get(table)
        if not isinstance(per_table, dict):
            missing.append(
                f"{table} (the map's manifest records no per-release "
                f"coverage for it)")
            continue
        entry = per_table.get(release)
        if not isinstance(entry, dict):
            missing.append(
                f"{table} release {release} (the map carries no rows for "
                f"that release at all)")
            continue
        rows = int(entry.get("rows") or 0)
        if rows < int(min_rows):
            missing.append(
                f"{table} release {release} (the map carries {rows} row(s), "
                f"fewer than the {int(min_rows)} the host requires)")
            continue
        if max_age_days is not None:
            newest = _parse_timestamp(entry.get("newest_fetched_at") or "")
            if newest is None:
                missing.append(
                    f"{table} release {release} (the map records no fetch "
                    f"time for it, so its freshness cannot be established)")
                continue
            age_days = (now_dt - newest).total_seconds() / 86400.0
            if age_days > max_age_days:
                missing.append(
                    f"{table} release {release} (its newest row was fetched "
                    f"{age_days:.1f} day(s) ago, older than the "
                    f"{max_age_days:g} day(s) the host allows, so the "
                    f"release's fix-status rows stopped being refreshed)")
                continue
        checked.setdefault(table, {})[release] = {
            "rows": rows,
            "newest_fetched_at": entry.get("newest_fetched_at"),
        }
    if missing:
        raise ValueError(
            "the published map does not carry the per-release overlay "
            "coverage the host requires: " + "; ".join(missing) +
            " (the vendor fix-status overlays are what clear NVD's "
            "unknown-fix false positives on a fully-updated host, so a map "
            "without them reports patched packages as unpatched)")
    return checked


def verify_overlay_package_coverage(
        manifest: dict,
        requirements: list[tuple[str, str, str, int]] | None = None,
) -> dict[str, dict]:
    """Check that a published map still carries every required overlay package.

    The per-release coverage check (:func:`verify_overlay_release_coverage`)
    asks whether a release still holds rows. That is a per-release
    question, and a per-release answer hides a per-package failure: the
    nightly job ingests each distro-tracker overlay per release and per
    source package (posture ingest ubuntu --release noble --package
    linux), and the per-(release, package) refresh deletes the rows it
    is about to replace, so a source package whose tracker feed returned
    nothing ends up with no rows at all while the release as a whole
    still holds the other packages' rows and the per-release floor still
    passes. The map is then quietly narrow in a different direction: the
    missing package's fix-status rows are gone, so a patched package of
    that source on that release is reported as unpatched, which is
    exactly the false positive the vendor fix-status overlay exists to
    clear.

    requirements is a list of (table, release, package, min_rows)
    quadruples: the map must carry at least min_rows rows for that
    package of that release of that release-keyed overlay table. The
    manifest already records, per release, which source packages
    contributed rows and how many (the packages map inside the
    release_coverage entry), so the check reads that record and
    reports a package that is missing or below its floor rather than
    serving it as a quietly narrow overlay.

    Freshness is not checked at the package level. A release's recorded
    fetch time is the newest across every package it carries, so a
    package whose rows went stale while a sibling package stayed fresh
    would pass a package-level freshness check by borrowing the sibling's
    timestamp — a misleading signal. The freshness of the overlay rows is
    bound at the per-release level by
    :func:`verify_overlay_release_coverage`, which is the right
    granularity for it.

    Returns the per-package coverage that was checked. Raises
    ValueError when a requirement names a table that is not a
    release-keyed overlay table, when the manifest carries no per-release
    coverage at all, when a required release is absent, or when a
    required package is absent or below its floor.
    """
    requirements = list(requirements or [])
    if not requirements:
        return {}
    for table, release, package, min_rows in requirements:
        if table not in RELEASE_KEYED_OVERLAY_TABLES:
            raise ValueError(
                f"{table} is not a release-keyed overlay table "
                f"(the release-keyed overlay tables are: "
                f"{', '.join(RELEASE_KEYED_OVERLAY_TABLES)})")
        if not str(release).strip():
            raise ValueError(
                f"the {table} overlay package coverage requirement names "
                f"no release")
        if not str(package).strip():
            raise ValueError(
                f"the {table} overlay package coverage requirement for "
                f"release {release} names no package")
        if int(min_rows) < 1:
            raise ValueError(
                f"the {table} overlay package coverage requirement for "
                f"release {release} package {package} asks for {min_rows} "
                f"row(s); the minimum is one")
    coverage = manifest.get("release_coverage")
    if not isinstance(coverage, dict):
        raise ValueError(
            "the published map's manifest carries no per-release overlay "
            "coverage, so the packages the host requires cannot be "
            "established (the map was published before the manifest "
            "recorded it)")
    checked: dict[str, dict] = {}
    missing: list[str] = []
    for table, release, package, min_rows in requirements:
        release = str(release).strip()
        package = str(package).strip()
        per_table = coverage.get(table)
        if not isinstance(per_table, dict):
            missing.append(
                f"{table} (the map's manifest records no per-release "
                f"coverage for it)")
            continue
        entry = per_table.get(release)
        if not isinstance(entry, dict):
            missing.append(
                f"{table} release {release} (the map carries no rows for "
                f"that release at all, so its packages cannot be checked)")
            continue
        packages = entry.get("packages")
        if not isinstance(packages, dict):
            missing.append(
                f"{table} release {release} (the map records no per-package "
                f"counts for it)")
            continue
        rows = int(packages.get(package) or 0)
        if rows < int(min_rows):
            missing.append(
                f"{table} release {release} package {package} "
                f"(the map carries {rows} row(s) for that package, "
                f"fewer than the {int(min_rows)} the host requires)")
            continue
        checked.setdefault(table, {}).setdefault(release, {})[package] = rows
    if missing:
        raise ValueError(
            "the published map does not carry the per-package overlay "
            "coverage the host requires: " + "; ".join(missing) +
            " (the vendor fix-status overlays are what clear NVD's "
            "unknown-fix false positives on a fully-updated host, so a map "
            "without a package's rows reports patched packages of that "
            "source as unpatched)")
    return checked


# ---------------------------------------------------------------------------
# import (client consumption path; idempotent)
# ---------------------------------------------------------------------------

def _read_jsonl_shards(root: Path, name: str):
    """Yield the parsed rows of every part of one flat table."""
    for path in _table_shards(root, name):
        yield from _read_jsonl(path)


def _table_shards(root: Path, name: str) -> list[Path]:
    """Every part of one flat table, in write order.

    A table that fits in one part is the single file <name>.jsonl; a table
    that outgrew the size cap is the numbered parts <name>-000001.jsonl,
    <name>-000002.jsonl, ... The parts win when both are present: the
    unsplit file is the stale shape from an earlier export.
    """
    parts = sorted(root.glob(f"{name}-*.jsonl"))
    if parts:
        return parts
    single = root / f"{name}.jsonl"
    return [single] if single.exists() else []


def import_spine(conn, from_dir: os.PathLike | str = ".",
                 verify_manifest: bool = True) -> dict:
    """Load <from_dir>/spine/*.jsonl into the SQLite DB (the client
    consumption path; also enables the round-trip test). A flat table that was
    exported as numbered parts (because it outgrew the shard size cap) is read
    back from every part. Idempotent: defects use
    INSERT OR REPLACE (the client's catalog mirrors the signed spine — the
    client does not enrich independently), the flat tables use INSERT OR
    REPLACE/IGNORE on their primary keys. If verify_manifest, recompute
    every shard sha256 and assert it matches manifest.json first (raise on
    mismatch). Never touches verdicts / territory. Returns a stats dict.
    """
    root = Path(from_dir) / SPINE_DIR
    if verify_manifest:
        verify_spine(from_dir)
    manifest = json.loads((root / MANIFEST_NAME).read_text())

    stats = {k: 0 for k in ("defects", "crosswalk", "candidates",
                           "distrust_marks", "seen_defects", "kev",
                           "apple_fixes", "debian_fixes", "ubuntu_fixes",
                           "epss")}

    # --- defects: full INSERT OR REPLACE (all columns, including enrich_state,
    #     distrusted, distrust_reason, discovered_at, prompt_hash, raw_text_hash
    #     — a faithful mirror of the signed map; upsert_defect would drop those) ---
    for shard_path in sorted((root / DEFECTS_DIR).glob("*.jsonl")):
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
    for row in _read_jsonl_shards(root, "crosswalk"):
        conn.execute(
            "INSERT OR IGNORE INTO crosswalk (defect_id, alias, kind) VALUES (?,?,?)",
            (row["defect_id"], row["alias"], row["kind"]),
        )
        stats["crosswalk"] += 1

    # --- candidates: INSERT OR REPLACE (id PK) ---
    for row in _read_jsonl_shards(root, "candidates"):
        conn.execute(
            """INSERT OR REPLACE INTO candidates
                 (id, url, fmt, axis, status, note, added_at)
               VALUES (?,?,?,?,?,?,?)""",
            (row["id"], row.get("url"), row.get("fmt"), row.get("axis"),
             row.get("status", "review"), row.get("note"), row.get("added_at")),
        )
        stats["candidates"] += 1

    # --- distrust_marks: INSERT OR REPLACE (observer PK) ---
    for row in _read_jsonl_shards(root, "distrust_marks"):
        conn.execute(
            "INSERT OR REPLACE INTO distrust_marks (observer, marked_at, reason) "
            "VALUES (?,?,?)",
            (row["observer"], row.get("marked_at"), row.get("reason")),
        )
        stats["distrust_marks"] += 1

    # --- seen_defects: INSERT OR REPLACE (defect_id PK) ---
    for row in _read_jsonl_shards(root, "seen_defects"):
        conn.execute(
            "INSERT OR REPLACE INTO seen_defects (defect_id, first_seen) VALUES (?,?)",
            (row["defect_id"], row.get("first_seen")),
        )
        stats["seen_defects"] += 1

    # --- kev: INSERT OR REPLACE (cve_id PK) — the exploitability_signal overlay
    for row in _read_jsonl_shards(root, "kev"):
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
    for row in _read_jsonl_shards(root, "apple_fixes"):
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
    for row in _read_jsonl_shards(root, "debian_fixes"):
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
    for row in _read_jsonl_shards(root, "ubuntu_fixes"):
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
    for row in _read_jsonl_shards(root, "epss"):
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
    manifest_path = root / MANIFEST_NAME
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
    manifest_path = root / MANIFEST_NAME
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
