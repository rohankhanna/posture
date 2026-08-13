"""Discovery — the horizon-scan meta-stage.

The domain expands: new identifier schemes, new scoring systems, new sources
appear (OSV, EPSS, SSVC, national AI-vuln-DBs, CSAF providers, the AI-supply-
chain sub-domain that didn't exist three years ago). You can't hardcode every
future source. Instead, this stage periodically checks a registry of known
aggregators for NEW schemes/feeds and SURFACES them for human review. It
never auto-adopts — the boundary is the whole point: the machine notices, the
human decides to trust.

Also the home of the bet on standard formats: anything speaking STIX 2.x,
CSAF, OSV-schema, or CycloneDX can be ingested by a generic adapter (see
sources/base.py), so a new source that adopts a standard costs ~zero to add.
"""

from __future__ import annotations
import sqlite3
from dataclasses import dataclass


# Registry of aggregators to periodically check for new sources / standard
# feeds. This is intentionally a static starter list — extend it as the field
# grows. Each entry: where to look, what standard format it tends to emit
# (so a generic adapter can absorb it), and which axis it would speak to.
AGGREGATORS: list[dict] = [
    {"name": "FIRST.org", "url": "https://www.first.org/epss/",
     "fmt": "csv", "axis": "vulnerability",
     "note": "EPSS predictions + CVSS SIG; watch for new scoring schemes"},
    {"name": "CISA KEV / CSW", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
     "fmt": "json", "axis": "threat", "note": "known-exploited catalog + CSAF advisories"},
    {"name": "ENISA", "url": "https://www.enisa.europa.eu/",
     "fmt": "csaf", "axis": "vulnerability",
     "note": "EU efforts; non-US cross-check of the NVD-centric picture"},
    {"name": "MITRE CWE/CAPEC/ATT&CK/D3FEND", "url": "https://attack.mitre.org/",
     "fmt": "stix", "axis": "vulnerability", "note": "the attack-pattern / defense family"},
    {"name": "OWASP", "url": "https://owasp.org/",
     "fmt": "text", "axis": "configuration",
     "note": "Top 10 / API Top 10 / LLM Top 10 (a brand-new axis frontier)"},
    {"name": "Cloud Security Alliance", "url": "https://cloudsecurityalliance.org/",
     "fmt": "text", "axis": "configuration", "note": "cloud posture / CSPM guidance"},
    {"name": "OSV schema providers", "url": "https://oss-vdb.io/",
     "fmt": "osv", "axis": "vulnerability",
     "note": "ecosystem package advisories; standard schema -> generic adapter"},
    {"name": "CSAF providers", "url": "https://oasis-open.github.io/csaf-documentation/",
     "fmt": "csaf", "axis": "vulnerability",
     "note": "CSAF is the advisory standard replacing plain text"},
    {"name": "CycloneDX / SPDX SBOM", "url": "https://cyclonedx.org/",
     "fmt": "cyclonedx", "axis": "inventory",
     "note": "SBOM standards -> measured inventory (the floor under everything)"},
]


@dataclass
class Candidate:
    name: str
    url: str
    fmt: str
    axis: str
    note: str
    status: str = "review"


def horizon_scan(conn: sqlite3.Connection | None = None) -> list[Candidate]:
    """Return the candidate sources to surface for human review — the DELTA
    against what's already recorded, not the whole registry.

    Offline by default (this is what CI runs daily via spine.yml): an
    aggregator is surfaced only if its url is not already in the candidates
    table (any status — so a human's adopted/rejected decision stops it
    resurfacing). No network, no LLM. When the static AGGREGATORS list is
    extended as the field grows, the next scan surfaces just the new entries.

    Pass conn=None for the raw registry (introspection / tests). The live
    `--fetch` path is `horizon_scan_live` (opt-in, never the CI default): a
    local machine does not feed or enrich — the daily cadence lives in CI."""
    base = [Candidate(**a) for a in AGGREGATORS]
    if conn is None:
        return base
    from . import store as _store
    known = {row["url"] for row in _store.candidates(conn)}
    return [c for c in base if c.url not in known]


def fetch_aggregator(url: str) -> str:
    """Fetch one aggregator page (the opt-in `--fetch` path). Returns the raw
    body or '' on failure. Reuses the shared curl helper (header-only auth,
    max-time) — no new network surface, no new dependency."""
    from .sources import _net
    _json, _code, body = _net.curl_get(url, max_time=60)
    return body or ""


def horizon_scan_live(conn: sqlite3.Connection) -> list[Candidate]:
    """Opt-in live horizon scan (the `posture discover --fetch` manual path,
    NEVER the CI default — feeding/enrichment runs in CI, not from a local
    machine). For each aggregator not already recorded, fetch its page and
    surface the aggregator itself as a single review candidate. A human still
    promotes or rejects."""
    surfaced: list[Candidate] = []
    for c in horizon_scan(conn):               # start from the offline delta
        fetch_aggregator(c.url)                # live: confirm reachability
        surfaced.append(c)
    return surfaced


def register_candidate(conn: sqlite3.Connection, c: Candidate) -> None:
    from . import store as _store
    _store.add_candidate(conn, c.url, c.fmt, c.axis, c.note)


def candidates(conn: sqlite3.Connection, status: str | None = None) -> list[dict]:
    from . import store as _store
    return _store.candidates(conn, status=status)


def set_candidate_status(conn: sqlite3.Connection, url: str, status: str) -> None:
    if status not in {"review", "adopted", "rejected"}:
        raise ValueError(f"bad candidate status {status!r}")
    from . import store as _store
    _store.set_candidate_status(conn, url, status)


# Map of standard format -> adapter hint (sources/base.StandardFormatObserver
# consumes these). Betting on standards adoption is the hedge against domain
# expansion: a new source that speaks a standard costs ~zero to ingest.
STANDARD_FORMATS = {
    "stix": "STIX 2.x (threat intel / ATT&CK)",
    "csaf": "CSAF (vendor security advisories)",
    "osv": "OSV-schema (ecosystem package advisories)",
    "cyclonedx": "CycloneDX (SBOM)",
    "spdx": "SPDX (SBOM)",
}