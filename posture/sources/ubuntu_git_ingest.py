"""Ubuntu CVE-tracker git-repo ingestion — the durable git-source alternative
to the paginated bulk-CVE-JSON ubuntu_ingest path.

The HTTP path (:mod:`posture.sources.ubuntu_ingest`) fetches Ubuntu's bulk CVE
JSON endpoint (ubuntu.com/security/cves.json) with ?package=<pkg>
pagination.  That endpoint is rate-fragile and caps PAGE_SIZE=20, forcing
~1180 paginated HTTP requests for two kernel packages (~110 minutes even when
healthy at 1.5-6.4 s/page).  When the API degrades (intermittent 503/504, 4-11 s
200s) the ingest grinds until systemd kills the whole unit.

This module is the durable replacement: the **ubuntu-cve-tracker** git
repository (git://git.launchpad.net/ubuntu-cve-tracker) is the canonical
plain-text store the JSON API is built from.  One git clone (or
git pull on a subsequent tick) fetches every CVE's full status sheet in a
single round-trip, with no pagination and no rate-limiting.  The plain-text CVE
files are parsed into the same (cve_id, release, package, status, fixed_in)
overlay rows that ubuntu_ingest_tick produces, so the ubuntu_fixes
overlay schema and the spine manifest stay byte-compatible.

Why a git source is strictly better here (the audit): the JSON API is a derived
view of the same data; the git repo IS the source of truth.  One git pull
replaces thousands of paginated HTTP round-trips, is idempotent by construction
(git tracks state), and degrades gracefully (a failed pull leaves the previous
checkout, so the tick parses what it has rather than writing nothing).  The
HTTP path is kept as a fallback for environments where the git protocol is
blocked.

Plain-text CVE file format (the parser): each file in active/ (and
optionally retired/) is named CVE-YYYY-NNNNN and carries:

  * a header section with metadata fields (Candidate:, PublicDate:,
    Description:, Priority:, …);
  * one or more package sections, each introduced by a Patches_<package>:
    header, followed by status lines of the form::

        <release>_<package>: <status> [(<note>)]

    where <release> is a release codename (noble, jammy, focal,
    …) or upstream, <status> is one of released, needed,
    needs-triage, not-affected, DNE, ignored, deferred,
    pending, and (<note>) is an optional parenthetical that carries the
    fixed version for released (e.g. released (5.15.0-25.25)) or a
    reason for ignored / not-affected.

The parser extracts {cve_id: {(release, package): (status, fixed_in)}} from
every file, filters to the requested releases × packages cross-product,
and writes each (release, package) slice as a per-(release, package) full
refresh to the ubuntu_fixes overlay via
:func:`posture.store.replace_ubuntu_fixes` — the same store function the HTTP
path uses, so the overlay schema is identical.

Scope is EXPLICIT and has NO default: a caller must pass releases +
packages (the editorial choice of which release × package sheets belong on
the PUBLIC spine is deferred to the operator).  All-or-nothing per tick: if the
tracker directory cannot be read, the tick returns error and writes nothing
(no-wipe at tick granularity — the overlay keeps its last-known-good).

Real ingestion runs ONLY in CI — never from a local machine (the no-local-
feeding rule).  Tests monkeypatch :func:`clone_or_pull_tracker` to point at a
bundled fixture directory; NVD_API_KEY is never touched.
"""
from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# The canonical ubuntu-cve-tracker git repository.  The git:// protocol is
# used because it is the fastest unauthenticated transport for a read-only
# clone; https:// is the fallback when git:// is firewalled.
UCT_GIT_URL = "git://git.launchpad.net/ubuntu-cve-tracker"
UCT_GIT_URL_HTTPS = "https://git.launchpad.net/ubuntu-cve-tracker"
DEFAULT_TRACKER_DIR = "/opt/posture/ubuntu-cve-tracker"
TIMEOUT = 600  # a full clone can be large; a pull is fast

# Only files whose name is a CVE id are parsed.  The tracker directory also
# contains triage scripts, supported-package lists, and other non-CVE files.
_CVE_FILENAME = re.compile(r"^CVE-\d{4}-\d+$", re.I)

# A Patches_ header introduces a package section.
#   Patches_linux:
#   Patches_linux-nvidia-6.17:
_PATCHES_HEADER = re.compile(r"^Patches_(.+):\s*$")

# A status line inside a package section:
#   noble_linux: released (5.15.0-25.25)
#   jammy_linux: needed
#   focal_linux: DNE
#   upstream_linux: needs-triage
#   esm-infra/bionic_linux: needs-triage   (ESM variant — skipped, not a plain codename)
# The release is everything before the LAST underscore+package suffix.
# We match <prefix>_<package>: <status> [optional (note)].
_STATUS_LINE = re.compile(
    r"^(?P<release>[a-z][a-z0-9./-]*?)_(?P<package>[A-Za-z0-9.+-]+):\s*"
    r"(?P<status>[A-Za-z-]+)\s*(?:\((?P<note>[^)]*)\))?\s*$",
)

# The Candidate: line carries the CVE id (may differ from the filename in rare
# cases; we trust the Candidate field).
_CANDIDATE = re.compile(r"^Candidate:\s*(CVE-\d{4}-\d+)\s*$", re.I)

# Known Ubuntu release codenames (for filtering ESM/proxy variants like
# "esm-infra/bionic" or "trusty/esm" which are NOT plain release codenames).
# A plain codename contains only lowercase letters and digits (no slash).
_IS_PLAIN_CODENAME = re.compile(r"^[a-z][a-z0-9]*$")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def clone_or_pull_tracker(
    dest_dir: str | None = None,
    repo_url: str | None = None,
    timeout: int = TIMEOUT,
) -> tuple[str | None, str]:
    """Clone or pull the ubuntu-cve-tracker git repository.

    Returns (dest_dir_or_None, reason).  If dest_dir already contains a
    git checkout, a git pull is performed; otherwise a fresh git clone
    is attempted (git:// first, https:// fallback).  None means the
    clone/pull failed — the caller treats it as a no-op (no-wipe).

    This function is the live network seam.  Tests monkeypatch it to point at
    a bundled fixture directory instead of doing a real clone.
    """
    dest = dest_dir or DEFAULT_TRACKER_DIR
    url = repo_url or UCT_GIT_URL

    if os.path.isdir(os.path.join(dest, ".git")):
        try:
            subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=dest, timeout=timeout,
                capture_output=True, check=True,
            )
            return dest, "pulled"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None, "git pull failed"

    parent = os.path.dirname(dest) or "."
    os.makedirs(parent, exist_ok=True)
    for try_url in (url, UCT_GIT_URL_HTTPS if url == UCT_GIT_URL else url):
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", try_url, dest],
                timeout=timeout,
                capture_output=True, check=True,
            )
            return dest, "cloned"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
    return None, "git clone failed"


def parse_cve_file(
    content: str,
) -> dict[tuple[str, str], tuple[str, str | None]]:
    """Parse one ubuntu-cve-tracker plain-text CVE file.

    Returns {(release, package): (status, fixed_in)} for every package
    section in the file.  fixed_in is the parenthetical note (the fixed
    version for released, a reason for ignored/not-affected), or
    None when no parenthetical is present.

    Lines before the first Patches_ header are metadata (Candidate,
    Description, Priority, …) and are skipped.  Within a package section,
    indented lines (patch metadata like break-fix:) are skipped; only
    status lines matching <release>_<package>: <status> [(<note>)] are
    extracted.  ESM/proxy release variants (esm-infra/bionic, trusty/esm)
    are skipped — they contain a slash and are not plain release codenames.
    The upstream pseudo-release is also skipped (it is not an Ubuntu
    release codename).
    """
    out: dict[tuple[str, str], tuple[str, str | None]] = {}
    current_package: str | None = None

    for line in content.splitlines():
        # A Patches_ header starts a new package section.
        m = _PATCHES_HEADER.match(line)
        if m:
            current_package = m.group(1).strip()
            continue

        if current_package is None:
            continue  # still in the metadata header

        # Indented lines are patch metadata (break-fix:, etc.) — skip them.
        if line.startswith(" ") or line.startswith("\t"):
            continue

        # A blank line might separate sections; do not reset current_package
        # because some files have blank lines within a section.
        if not line.strip():
            continue

        # Try to match a status line for the current package.
        m = _STATUS_LINE.match(line)
        if not m:
            continue

        release = m.group("release")
        pkg = m.group("package")
        status = m.group("status")
        note = m.group("note")

        # The package suffix on the status line must match the section's
        # package name.  This prevents cross-talk when a line from a different
        # package section is misidentified.
        if pkg != current_package:
            continue

        # Skip non-plain-codename releases: upstream, ESM variants
        # (esm-infra/bionic, trusty/esm), fips variants, etc.
        if release == "upstream":
            continue
        if not _IS_PLAIN_CODENAME.match(release):
            continue

        fixed_in = note.strip() if note else None
        if fixed_in is not None and not fixed_in:
            fixed_in = None
        out[(release, pkg)] = (status, fixed_in)

    return out


def _scan_tracker_dir(
    tracker_dir: str,
    releases: list[str],
    packages: list[str],
) -> dict[str, dict[str, dict[str, tuple[str, str | None]]]]:
    """Scan the tracker directory for CVE files and extract per-package,
    per-release status rows.

    Returns {package: {release: {cve_id: (status, fixed_in)}}} filtered to
    the requested releases × packages cross-product.  Files that are
    not CVEs (scripts, supported-package lists, …) are skipped by filename.
    """
    rel_set = {r.lower() for r in releases}
    pkg_set = {p for p in packages}

    result: dict[str, dict[str, dict[str, tuple[str, str | None]]]] = {
        p: {r: {} for r in releases} for p in packages
    }

    active_dir = Path(tracker_dir) / "active"
    if not active_dir.is_dir():
        # Some checkouts may have a flat layout; try the directory itself.
        active_dir = Path(tracker_dir)

    for entry in sorted(active_dir.iterdir()):
        if not entry.is_file():
            continue
        if not _CVE_FILENAME.match(entry.name):
            continue

        content = entry.read_text(errors="replace")
        parsed = parse_cve_file(content)
        if not parsed:
            continue

        # Extract the CVE id from the Candidate: line (authoritative).
        cve_id: str | None = None
        for line in content.splitlines():
            cm = _CANDIDATE.match(line)
            if cm:
                cve_id = cm.group(1)
                break
        if not cve_id:
            # Fall back to the filename if no Candidate line is present.
            cve_id = entry.name

        for (release, pkg), (status, fixed_in) in parsed.items():
            if pkg not in pkg_set:
                continue
            if release.lower() not in rel_set:
                continue
            result[pkg][release][cve_id] = (status, fixed_in)

    return result


def ubuntu_git_ingest_tick(
    conn,
    releases: list[str] | None = None,
    packages: list[str] | None = None,
    tracker_dir: str | None = None,
    now: str | None = None,
    fetch: bool = True,
) -> dict:
    """One Ubuntu-fix ingestion tick from the ubuntu-cve-tracker git repo.

    If fetch is True (default), :func:`clone_or_pull_tracker` is called
    first to refresh the local checkout.  If the fetch fails but a previous
    checkout exists, the tick proceeds with the stale checkout (graceful
    degradation — a failed pull is not a reason to skip the ingest; the
    previous state is still usable).  If no checkout exists and the fetch
    fails, the tick returns error and writes nothing (no-wipe).

    After the fetch, every CVE file in the tracker's active/ directory is
    parsed, filtered to the releases × packages cross-product, and each
    (release, package) slice is written as a per-(release, package) full
    refresh to the ubuntu_fixes overlay via
    :func:`posture.store.replace_ubuntu_fixes` — the same store function the
    HTTP path uses.

    Scope is the full cross-product of releases × packages; both must
    be non-empty (there is NO default scope — the public-spine editorial choice
    is the operator's, deferred).  An empty scope returns error and touches
    nothing.

    Stats keys: releases (list), packages (list), sheets (int —
    release × package pairs written), rows (int — total overlay rows
    inserted), fetched (bool), source (str — "git"), error
    (str|None).
    """
    from .. import store as _store

    fetched_at = now or _now()
    releases = [r for r in (releases or []) if r]
    packages = [p for p in (packages or []) if p]
    stats = {"releases": releases, "packages": packages, "sheets": 0,
             "rows": 0, "fetched": False, "source": "git", "error": None}

    if not releases or not packages:
        stats["error"] = ("no scope: pass --release and --package "
                          "(no default public-spine scope is wired)")
        return stats

    dest = tracker_dir or DEFAULT_TRACKER_DIR

    if fetch:
        resolved, reason = clone_or_pull_tracker(dest_dir=dest)
        if resolved is not None:
            dest = resolved
            stats["fetched"] = True
        elif not os.path.isdir(dest):
            # No previous checkout and the fetch failed: no-wipe.
            stats["error"] = f"tracker fetch failed and no checkout: {reason}"
            return stats
        # else: fetch failed but a previous checkout exists — proceed with it
        # (graceful degradation; the stale checkout is still parseable).
    elif not os.path.isdir(dest):
        stats["error"] = f"tracker directory not found: {dest}"
        return stats

    # Scan + parse the tracker directory.
    try:
        pkg_data = _scan_tracker_dir(dest, releases, packages)
    except OSError as exc:
        stats["error"] = f"tracker scan failed: {exc}"
        return stats

    # Write each (release, package) slice as a full refresh.
    for pkg in packages:
        for release in releases:
            sheet = pkg_data[pkg][release]
            rows = [{"cve_id": cid, "status": st, "fixed_in": fi}
                    for cid, (st, fi) in sheet.items()]
            n = _store.replace_ubuntu_fixes(conn, release, pkg, rows, fetched_at)
            stats["sheets"] += 1
            stats["rows"] += n
    return stats
