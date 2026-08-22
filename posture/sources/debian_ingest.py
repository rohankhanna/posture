"""Debian security-tracker fix-version ingestion — the debian_fixes spine overlay.

The Debian vendor observer (``debian_tracker``) replays Debian's bulk
``/tracker/data/json`` per ``assess()`` (posture observers are pure fan-out, no
shared DB across runs). That is correct for per-device decision but expensive +
rate-fragile when the status sheet is wanted durable in the signed spine. This
module is the CI-side ingestion counterpart: a free-function
``debian_ingest_tick`` that fetches the ONE bulk tracker document, slices it per
(release, package) via the observer's own ``bulk_extract``, and writes each
slice as a per-(release, package) full refresh to the ``debian_fixes`` overlay
(the map, not the territory). A observer — or a future territory assess — can
then read the durable status sheet via ``store.debian_fixes_for_release_package``
instead of replaying the 80MB+ bulk pull per run.

Why this overlay is NOT repeat work (the audit): ``posture ingest osv`` already
pulls the ``Debian`` ecosystem's ``all.zip`` and stores Debian fix ranges in the
``defects`` catalog's ``fixed_raw.ranges``. But OSV's Debian mirror carries only
``affected`` + ``fixed`` entries — it DROPS Debian's status words
(``resolved``/``open``/``undetermined``, and ``"0"`` = not-affected). Those
status words are exactly what clears NVD's unknown-fix false positives on a
Debian host, and they live ONLY in Debian's own authoritative tracker. So this
overlay is a DIFFERENT feed (debian.org, not osv.dev) bringing a NEW signal —
same justification as ``apple_fixes`` (Apple fix data no catalog row carries).
The fix-version fields incidentally overlap with the OSV catalog; the ``status``
column is the new value.

This mirrors the apple_fixes overlay pattern (an idempotent, no-wipe catalog
overlay) but is (cve_id, release, package)-keyed and per-(release, package)
full-refresh (DELETE WHERE release+package + INSERT) so CVEs aged off a release
sheet leave no stale rows. ``debian_ingest_tick`` is a free function over a
passed-in ``conn`` (``(conn, ...) -> stats``): it writes ONLY the
``debian_fixes`` overlay — never ``defects`` / ``verdicts`` / territory.

Scope is EXPLICIT and has NO default: a caller must pass ``releases`` +
``packages`` (the editorial choice of which release×package sheets belong on the
PUBLIC spine is deferred to the operator — there is no CI default wired in
spine.yml yet). The tick iterates the full cross-product, one ``bulk_extract``
slice per (release, package).

Real ingestion runs ONLY in CI — never from a local machine (the no-local-
feeding rule). Tests monkeypatch ``debian_tracker.curl_get`` (the binding the
tick routes every read through) against the bundled JSON fixture;
NVD_API_KEY is never touched.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import debian_tracker as _dt

# NOTE on curl routing: every network read here goes through ``_dt.curl_get``
# (attribute access on the debian_tracker module, resolved at call time) — the
# SAME binding the observer's ``_fetch_live`` uses. Tests then monkeypatch one
# name (``posture.sources.debian_tracker.curl_get``) to fake the bulk pull,
# exactly as the observer tests already do.


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _fetch_bulk() -> tuple[dict | None, str]:
    """Live Debian bulk tracker pull (JSON). Returns ``(data_or_None, reason)``.
    None means absent/failed — the caller treats it as a no-op (no-wipe: write
    nothing, preserve last-known-good). Delegates to the observer's curl binding
    so the read path is identical across observer + ingestion."""
    data, code, _body = _dt.curl_get(
        _dt.TRACKER_URL,
        headers=["User-Agent: posture/1.0", "Accept-Encoding: gzip, deflate"],
        max_time=_dt.TIMEOUT,
    )
    if code == 200 and data is not None:
        return data, "live"
    return None, f"bulk tracker fetch absent (http {code or 'timeout'})"


def debian_ingest_tick(conn, releases: list[str] | None = None,
                       packages: list[str] | None = None,
                       now: str | None = None) -> dict:
    """One Debian-fix ingestion tick: fetch the bulk tracker JSON once, slice it
    per ``(release, package)`` via :func:`debian_tracker.bulk_extract`, and write
    each slice as a per-(release, package) full refresh to the ``debian_fixes``
    overlay. Returns a stats dict.

    Scope is the full cross-product of ``releases`` x ``packages``; both must be
    non-empty (there is NO default scope — the public-spine editorial choice is
    the operator's, deferred). An empty scope returns ``error`` and touches
    nothing.

    Idempotent full refresh per (release, package) (``store.replace_debian_fixes``
    = DELETE WHERE release+package + INSERT), so a re-run replaces, never
    appends, and CVEs aged off a release sheet leave no stale rows. No-wipe on
    fetch failure: a failed/absent bulk pull returns ``error`` and writes nothing
    (the overlay keeps its last-known-good; never a partial DELETE without the
    re-INSERT). Writes ONLY the ``debian_fixes`` overlay — never ``defects`` /
    ``verdicts`` / territory.

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

    data, reason = _fetch_bulk()
    if data is None:
        stats["error"] = reason
        return stats
    stats["fetched"] = True

    for release in releases:
        for pkg in packages:
            # bulk_extract returns {cve_id: (status, fixed_in)} for this one
            # (release, package) slice — the authoritative status words the OSV
            # mirror lacks.
            sheet = _dt.bulk_extract(data, release, [pkg])
            rows = [{"cve_id": cid, "status": st, "fixed_in": fi}
                    for cid, (st, fi) in sheet.items()]
            n = _store.replace_debian_fixes(conn, release, pkg, rows, fetched_at)
            stats["sheets"] += 1
            stats["rows"] += n
    return stats