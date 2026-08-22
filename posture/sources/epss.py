"""EPSS (Exploit Prediction Scoring System) ingestion — the epss spine overlay.

FIRST.org's EPSS scores EVERY published CVE daily with a 0..1 probability of
exploitation in the wild in the next 30 days, plus a percentile, free +
unauthenticated (bulk gzipped CSV). This module is the CI-side ingestion
counterpart: a free-function ``epss_ingest_tick`` that pulls the one daily CSV
snapshot, parses it, and writes it as an idempotent full refresh to the ``epss``
overlay (the map, not the territory).

Why this overlay is NOT repeat work (the audit): NVD used to carry EPSS per CVE
but moved to risk-based enrichment 2026-04-15 — only KEV/federal/EO14028-
critical CVEs get CPE/CVSS/EPSS now; the long tail lost its EPSS. So EPSS is no
longer reliably in the ``defects`` catalog, and pulling FIRST's daily CSV
directly FILLS THE GAP NVD's retreat created. EPSS is also COMPLEMENTARY to the
``kev`` overlay, not a duplicate: KEV = ~1,700 confirmed-exploited (CISA);
EPSS = all CVEs with a predicted-likelihood score. A new exploitability signal,
not a re-fetch of an existing one.

This mirrors the ``kev`` overlay pattern (an idempotent, no-wipe CVE-keyed
catalog overlay) but is a wholesale full refresh (DELETE all + INSERT) since
EPSS is a complete daily snapshot of every scored CVE — a CVE dropped from the
model must leave no stale row. ``epss_ingest_tick`` is a free function over a
passed-in ``conn`` (``(conn, ...) -> stats``): it writes ONLY the ``epss``
overlay — never ``defects`` / ``verdicts`` / territory.

The file is gzipped and the canonical URL redirects, so the fetch uses the
binary-safe ``curl_get_bytes`` with ``-L`` (follow redirects) + gzip-decompress
in Python (the OSV all.zip binary-fetch pattern). The URL is overridable; a
wrong/stale host fails LOUDLY (``error`` + no-op, no-wipe) — safe to wire.

Cadence: EPSS scores update once DAILY, so a CI step should ingest on a DAILY
cadence (not hourly) to avoid rewriting the ~270k-row shard needlessly. The
``spine.yml`` step is NOT wired here — the operator chooses the cadence.

Real ingestion runs ONLY in CI — never from a local machine (the no-local-
feeding rule). Tests monkeypatch ``curl_get_bytes`` (the binding the tick routes
through) against a bundled gzipped-CSV fixture; NVD_API_KEY never touched.
"""
from __future__ import annotations

import csv
import gzip
import io
from datetime import datetime, timezone

from . import _net

# The canonical FIRST/Empirical-Security bulk EPSS CSV (gzipped). The URL
# redirects to the current day's file, so `-L` is required. Override via the
# ``url`` param if FIRST moves the host. A wrong host fails loudly (no-wipe).
EPSS_URL = "https://epss.cyentific.com/epss_scores-current.csv.gz"
TIMEOUT = 300  # the snapshot is ~270k rows / a few MB gzipped

# curl routing: every network read goes through ``_net.curl_get_bytes`` (the
# binary-safe binding, so the gzip bytes are not corrupted by a lossy utf-8
# decode). Tests monkeypatch ``posture.sources.epss.curl_get_bytes``.


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# Indirection so tests patch ONE name (``posture.sources.epss.curl_get_bytes``)
# rather than the shared ``_net`` binding other ingest modules also use.
def curl_get_bytes(url, headers=None, max_time=TIMEOUT, extra=None):
    return _net.curl_get_bytes(url, headers=headers, max_time=max_time, extra=extra)


def _fetch_csv(url: str) -> tuple[str | None, str]:
    """Live EPSS bulk pull (gzipped CSV). Returns ``(csv_text_or_None, reason)``.
    None means absent/failed — the caller treats it as a no-op (no-wipe)."""
    body, code = curl_get_bytes(url, max_time=TIMEOUT, extra=["-L"])
    if code != 200 or not body:
        return None, f"epss fetch absent (http {code or 'timeout'})"
    try:
        raw = gzip.decompress(body)
    except (OSError, EOFError) as exc:
        return None, f"epss gzip decode failed ({type(exc).__name__})"
    return raw.decode("utf-8", "replace"), "live"


def _parse_csv(text: str) -> list[dict]:
    """Parse the EPSS CSV into ``[{cve_id, epss, percentile}]``. The file's
    first line is a ``#``-prefixed comment header (``#cve,epss,percentile,...``)
    or a bare ``cve,epss,percentile`` header; data rows follow. A malformed /
    non-numeric row is skipped, never raises (one bad row must not sink the
    snapshot). Returns only rows with a parseable cve + two floats."""
    rows: list[dict] = []
    reader = csv.reader(io.StringIO(text))
    seen_header = False
    for fields in reader:
        if not fields:
            continue
        first = fields[0].lstrip("#").strip().lower()
        if not seen_header:
            # the header row (with or without a leading '#'); data starts after
            if first == "cve":
                seen_header = True
            continue
        if len(fields) < 3:
            continue
        cve_id = fields[0].strip()
        if not cve_id or cve_id.startswith("#"):
            continue
        try:
            epss = float(fields[1])
            percentile = float(fields[2])
        except (ValueError, TypeError):
            continue
        rows.append({"cve_id": cve_id, "epss": epss, "percentile": percentile})
    return rows


def epss_ingest_tick(conn, url: str | None = None, now: str | None = None) -> dict:
    """One EPSS ingestion tick: fetch the daily gzipped CSV snapshot, parse it,
    and write it as an idempotent full refresh to the ``epss`` overlay. Returns
    a stats dict.

    Idempotent full refresh (``store.replace_epss`` = DELETE all + INSERT), so a
    re-run replaces, never appends, and a CVE dropped from the EPSS model leaves
    no stale row. No-wipe: a failed/absent fetch returns ``error`` and touches
    nothing (the overlay keeps its last-known-good). Writes ONLY the ``epss``
    overlay — never ``defects`` / ``verdicts`` / territory.

    ``url`` overrides ``EPSS_URL`` (e.g. if FIRST moves the host). EPSS updates
    once daily; a CI step should run this on a DAILY cadence to avoid rewriting
    the ~270k-row shard needlessly each hour.

    Stats keys: ``rows`` (int — overlay rows inserted), ``fetched`` (bool),
    ``error`` (str|None).
    """
    from .. import store as _store

    fetched_at = now or _now()
    stats = {"rows": 0, "fetched": False, "error": None}

    text, reason = _fetch_csv(url or EPSS_URL)
    if text is None:
        stats["error"] = reason
        return stats
    stats["fetched"] = True

    rows = _parse_csv(text)
    if not rows:
        # a 200 with a parseable-but-empty body (model file not posted yet?) —
        # treat as a soft no-op (no-wipe), not a hard error.
        stats["error"] = "epss snapshot parsed to zero rows"
        return stats
    stats["rows"] = _store.replace_epss(conn, rows, fetched_at)
    return stats