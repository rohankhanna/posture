"""Ubuntu security-tracker fix-status ingestion — the ubuntu_fixes spine overlay.

The Ubuntu vendor observer (ubuntu_tracker) replays Ubuntu's per-CVE HTML
pages (ubuntu.com/security/<CVE>) per assess() (posture observers are
pure fan-out, no shared DB across runs). That is correct for per-device
decision but expensive + rate-fragile when the status sheet is wanted durable
in the signed spine. This module is the CI-side ingestion counterpart: a
free-function ubuntu_ingest_tick that fetches Ubuntu's BULK CVE JSON feed
once per package (?package=<pkg> paginated), slices it per (release,
package), and writes each slice as a per-(release, package) full refresh to the
ubuntu_fixes overlay (the map, not the territory). A observer — or a future
territory assess — can then read the durable status sheet via
store.ubuntu_fixes_for_release_package instead of replaying the per-CVE
HTML pull per run.

Why this overlay is NOT repeat work (the audit): posture ingest osv pulls
the Ubuntu ecosystem's all.zip and stores Ubuntu fix ranges in the
defects catalog's fixed_raw.ranges. But OSV's Ubuntu mirror carries only
affected + fixed entries — it DROPS Ubuntu's status words
(released/needed/needs-triage/not-affected/DNE/ignored/
deferred). Those status words are exactly what clear NVD's unknown-fix
false positives on an Ubuntu host, and they live ONLY in Ubuntu's own
authoritative tracker. So this overlay is a DIFFERENT feed (ubuntu.com's bulk
CVE JSON, not osv.dev) bringing a NEW signal — same justification as
debian_fixes (Debian status words no catalog row carries) and
apple_fixes. The fix-version fields incidentally overlap with the OSV
catalog; the raw status column + the per-release description note are
the new value.

Bulk, not per-CVE: the observer scrapes one HTML page per candidate CVE (no
bulk endpoint the observer uses). Ingestion instead uses Ubuntu's bulk CVE JSON
(ubuntu.com/security/cves.json), which carries every CVE's per-package /
per-release status + note in one paginated document, filtered to one source
package per fetch via ?package=<pkg>. One pagination per package; the per-
(release, package) slice is cut in-memory exactly as the debian overlay cuts
its bulk JSON. This mirrors the debian_fixes / apple_fixes overlay
pattern (an idempotent, no-wipe catalog overlay) but is (cve_id, release,
package)-keyed and per-(release, package) full-refresh (DELETE WHERE
release+package + INSERT) so CVEs aged off a release sheet leave no stale rows.
ubuntu_ingest_tick is a free function over a passed-in conn
((conn, ...) -> stats): it writes ONLY the ubuntu_fixes overlay —
never defects / verdicts / territory.

Scope is EXPLICIT and has NO default: a caller must pass releases +
packages (the editorial choice of which release x package sheets belong on
the PUBLIC spine is deferred to the operator — there is no CI default wired in
spine.yml yet). The tick fetches EVERY package's full CVE set first; if ANY
package fetch fails, it returns error and writes nothing (no-wipe at the
tick granularity — the overlay keeps its last-known-good; never a partial
DELETE without the re-INSERT), mirroring the debian tick's one-bulk-fetch
all-or-nothing shape.

Real ingestion runs ONLY in CI — never from a local machine (the no-local-
feeding rule). Tests monkeypatch ubuntu_tracker.curl_get (the binding the
tick routes every read through) against a bundled JSON fixture;
NVD_API_KEY is never touched.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from urllib.parse import quote

from . import ubuntu_tracker as _ut

# NOTE on curl routing: every network read here goes through _ut.curl_get
# (attribute access on the ubuntu_tracker module, resolved at call time) — the
# SAME binding the observer's _fetch_live uses. Tests then monkeypatch one
# name (posture.sources.ubuntu_tracker.curl_get) to fake the bulk JSON
# pull, exactly as the debian-ingest tests patch debian_tracker.curl_get.

# Ubuntu's bulk CVE JSON feed (paginated; ?package= narrows to one source
# package per fetch). The endpoint returns JSON, so curl_get's parsed slot (1)
# carries the data. PAGE_SIZE is the page limit requested; the API may
# return fewer rows than asked, and the pager advances by the count actually
# returned so an API clamp never loops or skips.
UBUNTU_CVE_URL = "https://ubuntu.com/security/cves.json"
PAGE_SIZE = 20
TIMEOUT = 300  # one package's CVE set can be a few thousand rows over a few pages

# Fail-fast circuit breaker. Ubuntu's CVE endpoint is rate-fragile and serves
# roughly 1180 paginated requests for two kernel packages (PAGE_SIZE=20, the
# API refuses larger pages). When the upstream degrades -- intermittent
# 503/504 or multi-second 200s -- the tick used to grind through every page
# until the systemd unit's TimeoutStartSec killed the whole daily spine build,
# taking the export step down with it. These thresholds abort the tick fast so
# vps_spine.sh's `|| ... last-known-good retained, spine continues` fires and
# the spine still refreshes from the other sources with the ubuntu overlay
# held at last-known-good. The tick stays all-or-nothing (a mid-tick abort
# writes nothing; the overlay is never partially wiped).
#
# The breaker tracks three degradation signals:
#   - consecutive_fail / total_fail: non-200 pages (503/504/timeout).
#   - consecutive_slow / total_slow: successful pages slower than
#     SLOW_PAGE_SECONDS (a healthy feed is sub-second to ~2s; sustained >5s
#     200s mean the upstream is throttling and the tick will not finish in
#     budget).
#   - wall-clock budget (TICK_MAX_SECONDS): a backstop that aborts the tick
#     regardless of the specific failure pattern, so an intermittent mix of
#     slow 200s and 503s that evades the consecutive counters is still caught.
#
# KEY FIX: consecutive_slow is NOT reset on a page failure. A failure is
# itself a sign of degradation, not a "healthy page" that should reset the
# slow counter. Only a fast successful page (<= SLOW_PAGE_SECONDS) resets
# consecutive_slow. This prevents the intermittent pattern where bursts of
# consecutive 503s (under MAX_CONSECUTIVE_FAIL) are separated by single slow
# 200s that reset consecutive_fail while the 503s reset consecutive_slow,
# leaving every counter below its threshold while the tick grinds for hours.
MAX_CONSECUTIVE_FAIL = 8  # consecutive failed pages (non-200 / non-dict) -> abort
MAX_TOTAL_FAIL = 80  # cumulative failed pages across the whole tick -> abort
SLOW_PAGE_SECONDS = 5.0  # a successful page slower than this is a "slow" hit
MAX_CONSECUTIVE_SLOW = 12  # consecutive slow+failed pages -> abort
MAX_TOTAL_SLOW = 80  # cumulative slow pages across the whole tick -> abort
TICK_MAX_SECONDS = 7200  # wall-clock budget (2h); healthy run is ~110min


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _fetch_page(package: str, offset: int, limit: int) -> tuple[dict | None, str]:
    """One paginated Ubuntu bulk CVE pull (JSON), filtered to package.
    Returns (data_or_None, reason). None means absent/failed — the caller
    treats it as a no-op (no-wipe). Delegates to the observer's curl binding so
    the read path is identical across observer + ingestion. Retries up to
    three times on a transient non-dict 200 (rate-limit blip)."""
    url = (f"{UBUNTU_CVE_URL}?package={quote(package)}"
           f"&limit={limit}&offset={offset}")
    # Force IPv4: ubuntu.com's cves.json endpoint times out over IPv6 from
    # some VPS networks (HTTP 504 / gateway timeout), while IPv4 responds
    # reliably.  The -4 flag keeps every other source on its default path.
    for attempt in range(3):
        data, code, _body = _ut.curl_get(
            url,
            headers=["User-Agent: posture/1.0", "Accept-Encoding: gzip, deflate"],
            max_time=TIMEOUT,
            extra=["-4"],
        )
        if code == 200 and isinstance(data, dict):
            return data, "live"
        if attempt < 2:
            time.sleep(2)
    return None, f"ubuntu cves fetch absent (http {code or 'timeout'})"


def _fetch_package(package: str, page_size: int = PAGE_SIZE) -> tuple[list | None, str]:
    """Paginate the ?package=<package> feed until total_results is
    reached, accumulating every CVE object. Returns (cves_or_None, reason).
    None means a page fetch failed — the caller treats it as a no-op (no-wipe).

    The pager advances offset by the number of CVEs each page actually
    returned (not the requested page_size), so an API that clamps the page
    size still converges; an empty page (no rows but offset < total) breaks the
    loop to avoid a stall, treating the partial pull as a success of what was
    fetched (the next tick re-attempts)."""
    cves: list = []
    offset = 0
    while True:
        data, reason = _fetch_page(package, offset, page_size)
        if data is None:
            return None, reason
        page = data.get("cves") or []
        cves.extend(page)
        total = data.get("total_results") or 0
        offset += len(page)
        if not page or offset >= total:
            break
    return cves, "live"


def extract_release(cves: list, release: str,
                    package: str) -> dict[str, tuple[str, str | None]]:
    """Extract {cve_id: (status, fixed_in)} for release (codename, e.g.
    'noble') of package (source package, e.g. 'linux') from the bulk Ubuntu
    CVE JSON cves list.

    Each CVE object carries a packages array; the entry whose name
    matches package holds a statuses array of per-release objects
    (release_codename + status + description note). A CVE with no
    matching package / no status for the release is skipped (not tracked for
    this release). Returns only CVEs that have a status for the release. The
    raw tracker status word + the per-release description note are returned
    VERBATIM (the NEW signal the OSV mirror lacks); an empty note becomes
    None (released-with-no-version, needed, needs-triage, DNE, ...).
    """
    out: dict[str, tuple[str, str | None]] = {}
    rel = release.strip().lower()
    pkg = package.strip()
    for cve in cves:
        cid = cve.get("id")
        if not cid:
            continue
        for pkgobj in cve.get("packages") or []:
            if (pkgobj.get("name") or "").strip() != pkg:
                continue  # a different source package on the same CVE page
            for st in pkgobj.get("statuses") or []:
                rc = (st.get("release_codename") or "").strip().lower()
                if rc != rel:
                    continue
                status = st.get("status")
                if not status:
                    continue  # no usable status for this release
                note = st.get("description") or None
                if note is not None and not note.strip():
                    note = None
                out[cid] = (status, note)
                break  # this package's row for the release
            break  # found the target package; do not scan siblings
    return out


def ubuntu_ingest_tick(conn, releases: list[str] | None = None,
                      packages: list[str] | None = None,
                      page_size: int = PAGE_SIZE,
                      now: str | None = None) -> dict:
    """One Ubuntu-fix ingestion tick: fetch the bulk CVE JSON once per package
    (paginated, ?package= filtered), slice it per (release, package)
    via :func:`extract_release`, and write each slice as a per-(release,
    package) full refresh to the ubuntu_fixes overlay. Returns a stats dict.

    Scope is the full cross-product of releases x packages; both must be
    non-empty (there is NO default scope — the public-spine editorial choice is
    the operator's, deferred). An empty scope returns error and touches
    nothing.

    All-or-nothing per tick (mirrors the debian tick's one-bulk-fetch shape):
    EVERY package's full CVE set is fetched first; if ANY package fetch fails,
    the tick returns error and writes nothing (no-wipe at tick granularity —
    the overlay keeps its last-known-good; never a partial DELETE without the
    re-INSERT). On success, each (release, package) sheet is an idempotent full
    refresh (store.replace_ubuntu_fixes = DELETE WHERE release+package +
    INSERT), so a re-run replaces, never appends, and CVEs aged off a release
    sheet leave no stale rows. Writes ONLY the ubuntu_fixes overlay — never
    defects / verdicts / territory.

    Stats keys: releases (list), packages (list), sheets (int —
    release x package pairs written), rows (int — total overlay rows
    inserted), fetched (bool), error (str|None).
    """
    from .. import store as _store

    fetched_at = now or _now()
    releases = [r for r in (releases or []) if r]
    packages = [p for p in (packages or []) if p]
    stats = {"releases": releases, "packages": packages, "sheets": 0,
             "rows": 0, "fetched": False, "error": None}

    if not releases or not packages:
        stats["error"] = ("no scope: pass --release and --package "
                          "(no default public-spine scope is wired)")
        return stats

    # fetch + extract per page so the full CVE set is never held in memory
    # at once (the API serves large objects; accumulating all 19k+ CVEs for
    # the linux package exceeds a 2G VPS).  Resilient: a transient page
    # failure (504) skips that page and continues; the first page must
    # succeed or the tick aborts (no-wipe for a total outage). A fail-fast
    # circuit breaker (MAX_CONSECUTIVE_FAIL / MAX_TOTAL_FAIL / slow-page
    # watermark / wall-clock budget) aborts the tick on sustained upstream
    # degradation so the daily spine is not held hostage to one flaky source.
    consecutive_fail = 0
    total_fail = 0
    consecutive_slow = 0
    total_slow = 0
    tick_start = time.monotonic()
    pkg_data: dict[str, dict[str, dict[str, tuple[str, str | None]]]] = {}
    for pkg in packages:
        per_release: dict[str, dict[str, tuple[str, str | None]]] = {
            r: {} for r in releases}
        offset = 0
        skipped = 0
        total = 0
        while True:
            t0 = time.monotonic()
            data, reason = _fetch_page(pkg, offset, page_size)
            elapsed = time.monotonic() - t0
            if data is None:
                skipped += 1
                consecutive_fail += 1
                total_fail += 1
                # KEY FIX: a failure is itself a degradation event. Increment
                # the slow+failed counters on failure too, so an intermittent
                # pattern (bursts of 503s separated by slow 200s) accumulates
                # consecutive_slow across both failures and slow successes.
                # Only a fast success (<= SLOW_PAGE_SECONDS) resets it.
                consecutive_slow += 1
                total_slow += 1
                print(f"ingest ubuntu: skipping page offset={offset} for {pkg}: {reason}", flush=True)
                if offset == 0:
                    stats["error"] = f"first page failed for {pkg}: {reason}"
                    return stats
                if consecutive_fail >= MAX_CONSECUTIVE_FAIL:
                    stats["error"] = (f"upstream degraded: {consecutive_fail} consecutive "
                                      f"failed pages for {pkg} ({reason}); aborting tick, "
                                      f"last-known-good retained")
                    return stats
                if total_fail >= MAX_TOTAL_FAIL:
                    stats["error"] = (f"upstream degraded: {total_fail} total failed pages "
                                      f"across tick ({reason}); aborting, last-known-good retained")
                    return stats
                # The slow-page and budget checks belong here too, not only on
                # the success branch.  Without them, an intermittent pattern
                # (bursts of 503s separated by a single slow 200) accumulates
                # consecutive_slow during the failure pages but the threshold
                # is not evaluated until the next slow success, so the breaker
                # fires up to one burst later than it should.  A sequence of
                # slow-failing pages (each with 3x retry at 300s timeout) can
                # also exceed the wall-clock budget without the backstop
                # firing if the budget check is only on the success branch.
                if consecutive_slow >= MAX_CONSECUTIVE_SLOW:
                    stats["error"] = (f"upstream degraded: {consecutive_slow} consecutive slow+failed pages "
                                      f"for {pkg} (last failure: {reason}); "
                                      f"aborting tick, last-known-good retained")
                    return stats
                if total_slow >= MAX_TOTAL_SLOW:
                    stats["error"] = (f"upstream degraded: {total_slow} total slow+failed pages "
                                      f"across tick; aborting, last-known-good retained")
                    return stats
                if time.monotonic() - tick_start > TICK_MAX_SECONDS:
                    stats["error"] = (f"upstream degraded: tick exceeded {TICK_MAX_SECONDS}s "
                                      f"wall-clock budget; aborting, last-known-good retained")
                    return stats
                offset += page_size
                if total and offset >= total:
                    break
                continue
            # success: classify speed for the slow-page breaker. A healthy
            # ubuntu.com feed is sub-second to ~2s; sustained >5s pages mean
            # the upstream is degraded and the tick will not finish in budget.
            if elapsed > SLOW_PAGE_SECONDS:
                consecutive_slow += 1
                total_slow += 1
            else:
                consecutive_slow = 0
            consecutive_fail = 0
            if consecutive_slow >= MAX_CONSECUTIVE_SLOW:
                stats["error"] = (f"upstream degraded: {consecutive_slow} consecutive slow+failed pages "
                                  f"(>{SLOW_PAGE_SECONDS:.0f}s each, last {elapsed:.1f}s) for {pkg}; "
                                  f"aborting tick, last-known-good retained")
                return stats
            if total_slow >= MAX_TOTAL_SLOW:
                stats["error"] = (f"upstream degraded: {total_slow} total slow pages "
                                  f"across tick (>{SLOW_PAGE_SECONDS:.0f}s each); aborting, "
                                  f"last-known-good retained")
                return stats
            # wall-clock budget backstop: abort if the tick has run too long,
            # regardless of the specific failure pattern.
            if time.monotonic() - tick_start > TICK_MAX_SECONDS:
                stats["error"] = (f"upstream degraded: tick exceeded {TICK_MAX_SECONDS}s "
                                  f"wall-clock budget; aborting, last-known-good retained")
                return stats
            page = data.get("cves") or []
            for release in releases:
                per_release[release].update(
                    extract_release(page, release, pkg))
            total = data.get("total_results") or 0
            offset += len(page)
            if not page or offset >= total:
                break
        if skipped > 0:
            print(f"ingest ubuntu: {skipped} page(s) skipped for {pkg}; partial data written", flush=True)
        pkg_data[pkg] = per_release
    stats["fetched"] = True

    for pkg in packages:
        for release in releases:
            sheet = pkg_data[pkg][release]
            rows = [{"cve_id": cid, "status": st, "fixed_in": fi}
                    for cid, (st, fi) in sheet.items()]
            n = _store.replace_ubuntu_fixes(conn, release, pkg, rows, fetched_at)
            stats["sheets"] += 1
            stats["rows"] += n
    return stats