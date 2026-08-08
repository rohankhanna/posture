"""Apple advisory fix-version ingestion — the apple_fixes spine overlay.

The Apple vendor witness (``apple_advisory``) replays Apple's live security-
releases index + every per-release advisory page per ``assess()`` (posture
witnesses are pure fan-out, no shared DB across runs). That is correct for
per-device decision but expensive + rate-fragile when the catalog is wanted
durable in the signed spine. This module is the CI-side ingestion counterpart:
a free-function ``apple_ingest_tick`` that builds the same earliest-fix-
version-wins ``cve -> fixed_in`` map (live index, plus optional Wayback-
historical recovery of pre-index CVEs) and writes it once per product to the
``apple_fixes`` overlay (the map, not the territory). A witness — or a future
territory assess — can then read the durable fix map via ``store.apple_fixes_for``
instead of replaying Apple per run.

This mirrors the KEV overlay pattern (an idempotent, no-wipe catalog overlay)
but is (cve_id, product)-keyed rather than cve-keyed, and per-product full-
refresh (DELETE WHERE product + INSERT) so advisories aged off Apple's rolling
index leave no stale rows. ``apple_ingest_tick`` is a free function over a
passed-in ``conn`` (``(conn, ...) -> stats``): it writes ONLY the ``apple_fixes``
overlay — never ``flaws`` / ``verdicts`` / territory.

Real ingestion runs ONLY in CI — never from a local machine (the no-local-
feeding rule). Tests monkeypatch ``curl_get`` (here + ``apple_advisory.curl_get``)
against bundled HTML fixtures; NVD_API_KEY is never touched.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from . import apple_advisory as _aa

# CI ingests every Apple product the witness recognizes. iphone_os + ipados
# share one joint advisory row ("iOS X and iPadOS X"), so both resolve from the
# same index walk; macOS is its own.
PRODUCTS = tuple(_aa.PRODUCTS)              # ("iphone_os", "ipados", "macos")

# NOTE on curl routing: every network read here goes through ``_aa.curl_get``
# (attribute access on the apple_advisory module, resolved at call time) — the
# SAME binding the witness + the historical-recovery paths use. Tests then
# monkeypatch one name (``posture.sources.apple_advisory.curl_get``) to fake the
# index, the advisories, AND the Wayback CDX/snapshots, exactly as the iteration-1
# backfill tests already do.


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _curl(url, max_time=_aa.TIMEOUT):
    """Thin wrapper over the apple_advisory curl binding: returns ``(body, ok)``
    for an HTML page (Apple + Wayback serve HTML, not JSON). Best-effort."""
    _data, code, body = _aa.curl_get(
        url, headers=[f"User-Agent: {_aa._UA}"], max_time=max_time)
    if code == 200 and body:
        return body, True
    return "", False


def _fetch_index_html() -> tuple[str, bool]:
    """Live Apple security-releases index (HTML). Best-effort: returns
    ``("", False)`` on any non-200/empty/failure (the tick then no-ops for this
    product; never a hard fail that breaks CI)."""
    return _curl(_aa.INDEX_URL)


def _fetch_advisory_html(url: str) -> str | None:
    """Live Apple advisory page (HTML) keyed by URL. Best-effort: ``None`` on
    any non-200/empty/failure (the map build skips that advisory)."""
    body, ok = _curl(url)
    return body if ok else None


def _fetch_wayback_snapshot(url: str) -> str | None:
    """Live Wayback snapshot page (HTML). Best-effort: ``None`` on failure.
    Delegates to the witness's ``_wayback_fetch`` so the snapshot read path is
    identical across witness + ingestion."""
    return _aa._wayback_fetch(url)


def apple_ingest_tick(conn, product: str = "iphone_os", history: bool = False,
                      now: str | None = None) -> dict:
    """One Apple-fix ingestion tick for ``product``: build the earliest-fix-
    version-wins ``cve -> fixed_in`` map from Apple's live index (+ optional
    Wayback-historical recovery of pre-index CVEs) and write it as a per-product
    full refresh to the ``apple_fixes`` overlay. Returns a stats dict.

    Idempotent full refresh per product (``store.replace_apple_fixes`` =
    DELETE WHERE product + INSERT), so a re-run replaces, never appends, and
    advisories aged off the rolling index leave no stale rows. No-wipe: writes
    ONLY the ``apple_fixes`` overlay — never ``flaws`` / ``verdicts`` / territory.

    ``history=True`` augments the index map with pre-index advisories discovered
    via the Wayback Machine's archived yearly snapshots of Apple's cumulative
    "Apple security updates" index (HT1222 + HT201222) — the iteration-1
    historical-recovery path. ``history=False`` (default) builds from the live
    index only. A failed/absent index fetch returns ``error`` and touches
    nothing (best-effort; never breaks CI).

    The advisory id provenance (which advisory states each recorded fix) is
    collected via the ``adv_of`` out-param the map builders now expose, so the
    overlay's ``advisory_id`` column is faithful to the donor's ``apple_fixes``.
    """
    from .. import store as _store

    fetched_at = now or _now()
    stats = {"product": product, "history": history, "rows": 0,
             "index_cves": 0, "history_cves_added": 0,
             "history_cves_earlier": 0, "error": None}

    if product not in _aa.PRODUCTS:
        stats["error"] = f"unknown product {product!r} (not in {list(PRODUCTS)})"
        return stats

    index_html, ok = _fetch_index_html()
    if not ok or not index_html:
        stats["error"] = "apple advisory index fetch failed/absent"
        return stats

    # The index pass builds the map + collects per-CVE advisory provenance.
    # build_fix_map's advisory getter has the (version, url, adv_id) signature
    # the witness uses; adapt the single-arg live fetcher to it.
    adv_of: dict[str, str] = {}
    fixed = _aa.build_fix_map(
        index_html, lambda _v, url, _a: _fetch_advisory_html(url), product,
        adv_of=adv_of)
    stats["index_cves"] = len(fixed)

    # Optional historical recovery (Wayback yearly snapshots of HT1222/HT201222).
    # Advisories the index already covered (by advisory id) are skipped so
    # backfill never re-fetches them; cross-product advisories are skipped by
    # ``backfill_fix_map``. Earliest-fix-version-wins merges the eras.
    if history:
        covered = {adv_id for _v, _u, adv_id in _aa.parse_index(index_html, product)}
        urls = _aa.discover_historical_urls(fetch_snapshot=_fetch_wayback_snapshot)
        if urls:
            merged, hstats = _aa.backfill_fix_map(
                urls, _fetch_advisory_html, product, base=fixed,
                covered_adv_ids=covered, delay=_aa._BACKFILL_DELAY, adv_of=adv_of)
            fixed = merged
            stats["history_cves_added"] = hstats["cves_added"]
            stats["history_cves_earlier"] = hstats["cves_earlier"]

    rows = [{"cve_id": cid, "fixed_in": ver, "advisory_id": adv_of.get(cid, "")}
            for cid, ver in fixed.items()]
    stats["rows"] = _store.replace_apple_fixes(conn, product, rows, fetched_at)
    return stats