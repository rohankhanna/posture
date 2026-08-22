"""Ubuntu security-tracker fix-status ingestion — the ubuntu_fixes spine overlay.

The Ubuntu vendor observer (``ubuntu_tracker``) replays Ubuntu's per-CVE HTML
pages (``ubuntu.com/security/<CVE>``) per ``assess()`` (posture observers are
pure fan-out, no shared DB across runs). That is correct for per-device
decision but expensive + rate-fragile when the status sheet is wanted durable
in the signed spine. This module is the CI-side ingestion counterpart: a
free-function ``ubuntu_ingest_tick`` that fetches Ubuntu's BULK CVE JSON feed
once per package (``?package=<pkg>`` paginated), slices it per (release,
package), and writes each slice as a per-(release, package) full refresh to the
``ubuntu_fixes`` overlay (the map, not the territory). A observer — or a future
territory assess — can then read the durable status sheet via
``store.ubuntu_fixes_for_release_package`` instead of replaying the per-CVE
HTML pull per run.

Why this overlay is NOT repeat work (the audit): ``posture ingest osv`` pulls
the ``Ubuntu`` ecosystem's ``all.zip`` and stores Ubuntu fix ranges in the
``defects`` catalog's ``fixed_raw.ranges``. But OSV's Ubuntu mirror carries only
``affected`` + ``fixed`` entries — it DROPS Ubuntu's status words
(``released``/``needed``/``needs-triage``/``not-affected``/``DNE``/``ignored``/
``deferred``). Those status words are exactly what clear NVD's unknown-fix
false positives on an Ubuntu host, and they live ONLY in Ubuntu's own
authoritative tracker. So this overlay is a DIFFERENT feed (ubuntu.com's bulk
CVE JSON, not osv.dev) bringing a NEW signal — same justification as
``debian_fixes`` (Debian status words no catalog row carries) and
``apple_fixes``. The fix-version fields incidentally overlap with the OSV
catalog; the raw ``status`` column + the per-release ``description`` note are
the new value.

Bulk, not per-CVE: the observer scrapes one HTML page per candidate CVE (no
bulk endpoint the observer uses). Ingestion instead uses Ubuntu's bulk CVE JSON
(``ubuntu.com/security/cves.json``), which carries every CVE's per-package /
per-release status + note in one paginated document, filtered to one source
package per fetch via ``?package=<pkg>``. One pagination per package; the per-
(release, package) slice is cut in-memory exactly as the debian overlay cuts
its bulk JSON. This mirrors the ``debian_fixes`` / ``apple_fixes`` overlay
pattern (an idempotent, no-wipe catalog overlay) but is (cve_id, release,
package)-keyed and per-(release, package) full-refresh (DELETE WHERE
release+package + INSERT) so CVEs aged off a release sheet leave no stale rows.
``ubuntu_ingest_tick`` is a free function over a passed-in ``conn``
(``(conn, ...) -> stats``): it writes ONLY the ``ubuntu_fixes`` overlay —
never ``defects`` / ``verdicts`` / territory.

Scope is EXPLICIT and has NO default: a caller must pass ``releases`` +
``packages`` (the editorial choice of which release x package sheets belong on
the PUBLIC spine is deferred to the operator — there is no CI default wired in
spine.yml yet). The tick fetches EVERY package's full CVE set first; if ANY
package fetch fails, it returns ``error`` and writes nothing (no-wipe at the
tick granularity — the overlay keeps its last-known-good; never a partial
DELETE without the re-INSERT), mirroring the debian tick's one-bulk-fetch
all-or-nothing shape.

Real ingestion runs ONLY in CI — never from a local machine (the no-local-
feeding rule). Tests monkeypatch ``ubuntu_tracker.curl_get`` (the binding the
tick routes every read through) against a bundled JSON fixture;
NVD_API_KEY is never touched.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import quote

from . import ubuntu_tracker as _ut

# NOTE on curl routing: every network read here goes through ``_ut.curl_get``
# (attribute access on the ubuntu_tracker module, resolved at call time) — the
# SAME binding the observer's ``_fetch_live`` uses. Tests then monkeypatch one
# name (``posture.sources.ubuntu_tracker.curl_get``) to fake the bulk JSON
# pull, exactly as the debian-ingest tests patch ``debian_tracker.curl_get``.

# Ubuntu's bulk CVE JSON feed (paginated; ``?package=`` narrows to one source
# package per fetch). The endpoint returns JSON, so curl_get's parsed slot (1)
# carries the data. ``PAGE_SIZE`` is the page limit requested; the API may
# return fewer rows than asked, and the pager advances by the count actually
# returned so an API clamp never loops or skips.
UBUNTU_CVE_URL = "https://ubuntu.com/security/cves.json"
PAGE_SIZE = 500
TIMEOUT = 300  # one package's CVE set can be a few thousand rows over a few pages


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _fetch_page(package: str, offset: int, limit: int) -> tuple[dict | None, str]:
    """One paginated Ubuntu bulk CVE pull (JSON), filtered to ``package``.
    Returns ``(data_or_None, reason)``. None means absent/failed — the caller
    treats it as a no-op (no-wipe). Delegates to the observer's curl binding so
    the read path is identical across observer + ingestion."""
    url = (f"{UBUNTU_CVE_URL}?package={quote(package)}"
           f"&limit={limit}&offset={offset}")
    data, code, _body = _ut.curl_get(
        url,
        headers=["User-Agent: posture/1.0", "Accept-Encoding: gzip, deflate"],
        max_time=TIMEOUT,
    )
    if code == 200 and isinstance(data, dict):
        return data, "live"
    return None, f"ubuntu cves fetch absent (http {code or 'timeout'})"


def _fetch_package(package: str, page_size: int = PAGE_SIZE) -> tuple[list | None, str]:
    """Paginate the ``?package=<package>`` feed until ``total_results`` is
    reached, accumulating every CVE object. Returns ``(cves_or_None, reason)``.
    None means a page fetch failed — the caller treats it as a no-op (no-wipe).

    The pager advances ``offset`` by the number of CVEs each page actually
    returned (not the requested ``page_size``), so an API that clamps the page
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
    """Extract ``{cve_id: (status, fixed_in)}`` for ``release`` (codename, e.g.
    'noble') of ``package`` (source package, e.g. 'linux') from the bulk Ubuntu
    CVE JSON ``cves`` list.

    Each CVE object carries a ``packages`` array; the entry whose ``name``
    matches ``package`` holds a ``statuses`` array of per-release objects
    (``release_codename`` + ``status`` + ``description`` note). A CVE with no
    matching package / no status for the release is skipped (not tracked for
    this release). Returns only CVEs that have a status for the release. The
    raw tracker status word + the per-release ``description`` note are returned
    VERBATIM (the NEW signal the OSV mirror lacks); an empty note becomes
    ``None`` (released-with-no-version, needed, needs-triage, DNE, ...).
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
    (paginated, ``?package=`` filtered), slice it per ``(release, package)``
    via :func:`extract_release`, and write each slice as a per-(release,
    package) full refresh to the ``ubuntu_fixes`` overlay. Returns a stats dict.

    Scope is the full cross-product of ``releases`` x ``packages``; both must be
    non-empty (there is NO default scope — the public-spine editorial choice is
    the operator's, deferred). An empty scope returns ``error`` and touches
    nothing.

    All-or-nothing per tick (mirrors the debian tick's one-bulk-fetch shape):
    EVERY package's full CVE set is fetched first; if ANY package fetch fails,
    the tick returns ``error`` and writes nothing (no-wipe at tick granularity —
    the overlay keeps its last-known-good; never a partial DELETE without the
    re-INSERT). On success, each (release, package) sheet is an idempotent full
    refresh (``store.replace_ubuntu_fixes`` = DELETE WHERE release+package +
    INSERT), so a re-run replaces, never appends, and CVEs aged off a release
    sheet leave no stale rows. Writes ONLY the ``ubuntu_fixes`` overlay — never
    ``defects`` / ``verdicts`` / territory.

    Stats keys: ``releases`` (list), ``packages`` (list), ``sheets`` (int —
    release x package pairs written), ``rows`` (int — total overlay rows
    inserted), ``fetched`` (bool), ``error`` (str|None).
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

    # fetch every package's full CVE set first; a single package outage fails
    # the whole tick (no-wipe: write nothing, preserve last-known-good).
    pkg_data: dict[str, list] = {}
    for pkg in packages:
        cves, reason = _fetch_package(pkg, page_size=page_size)
        if cves is None:
            stats["error"] = reason
            return stats
        pkg_data[pkg] = cves
    stats["fetched"] = True

    for pkg in packages:
        for release in releases:
            sheet = extract_release(pkg_data[pkg], release, pkg)
            rows = [{"cve_id": cid, "status": st, "fixed_in": fi}
                    for cid, (st, fi) in sheet.items()]
            n = _store.replace_ubuntu_fixes(conn, release, pkg, rows, fetched_at)
            stats["sheets"] += 1
            stats["rows"] += n
    return stats