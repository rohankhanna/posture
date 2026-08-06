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


def horizon_scan() -> list[Candidate]:
    """Return the starter set of candidate sources to consider adopting.
    In a full impl this would diff against already-registered witnesses and
    fetch each aggregator for genuinely-new feeds; here it returns the static
    registry so the surface-for-review contract is concrete and testable."""
    return [Candidate(**a) for a in AGGREGATORS]


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


# Map of standard format -> adapter hint (sources/base.StandardFormatWitness
# consumes these). Betting on standards adoption is the hedge against domain
# expansion: a new source that speaks a standard costs ~zero to ingest.
STANDARD_FORMATS = {
    "stix": "STIX 2.x (threat intel / ATT&CK)",
    "csaf": "CSAF (vendor security advisories)",
    "osv": "OSV-schema (ecosystem package advisories)",
    "cyclonedx": "CycloneDX (SBOM)",
    "spdx": "SPDX (SBOM)",
}