# Sources & limits reference

The exact constraints the posture-spine CI ingestion and the signed git data
repo must be designed against. This is reference data gathered 2026-08-05
(retrieval date for every fact below); it is the canonical record of the source
constraints, and carries the *design decisions* that depend on these numbers.

posture's spine is **all defects** (every defect that is a peer of cves, across
every defect_type). cve is one peer, not a primary key. See
[README.md](../README.md) for the engine overview.

Vocabulary: **defect** = the universal spine entity; **defect_type** = the naming
scheme (`cve` / `ghsa` / `osv` / `rustsec` / `sap-note` / `fg-ir` / …);
**defect_id** = a specific id under a type (`CVE-2026-99901`, `GHSA-…`,
`OSV-…`). The spine entity = the equivalence class of defect_ids that denote
one defect. `defect_type` is a glossary role; `cve` is the term bound to it
today — but there is **no swapping and no rebinding**: all defect_types are
peers simultaneously.

---

## GitHub limits (the binding constraints)

### Repository
| Limit | Value |
|---|---|
| Single file — hard max | 100 MiB (push blocked); warn at 50 MiB |
| Repo size — recommended | 10 GB (ideal < 1 GB); no hard auto-block, GitHub emails Support above |
| Max push (pack) | 2 GB hard |
| Pushes / min / repo | 6 (recommended) |
| Git read ops (fetch/clone) / sec / repo | 15 (recommended) |
| Max files in one diff | 300 |

### Actions — compute, storage, concurrency
| Limit | Value |
|---|---|
| Free minutes | 2,000 min/mo (Linux 1×; Windows 2×, macOS 10×) |
| Public repos + self-hosted runners | **not billed** for minutes |
| Actions/artifact storage — Free | 500 MB (Pro 1 GB, Team 2 GB, Enterprise 50 GB) |
| Cache storage / repo | 10 GB free (configurable to 10 TB) |
| Cache retention | 7 days since last access |
| Artifact/log retention | default 90 days (public capped 90; private up to 400) |
| Job time — GitHub-hosted | 6 hours (self-hosted 5 days) |
| Matrix | 256 jobs / workflow run |
| Concurrent jobs — Free | 20 (Pro 40, Team 60, Enterprise 500) |

### Scheduled workflows
| Behavior | Value |
|---|---|
| Cron | POSIX 5-field, UTC (IANA tz optional); `@daily` not supported |
| Minimum interval | 5 minutes |
| High-load | **may be delayed or dropped**, worst at top-of-hour → use off-zero cron (`7 * * * *`) + idempotent/resumable ingestion |
| Auto-disable (public repo) | after 60 days of no activity → ingestion's own periodic push is the keepalive |

### Secrets & signing
| Item | Value |
|---|---|
| Secret size | 48 KB max; 100 repo secrets; masked in logs; **not available to fork-PR runs** |
| OIDC for keyless cloud signing | available (`permissions: id-token: write`) |
| **Commit signing** | GPG / SSH (Git 2.34+) — signs **commits**; "verified" badge is persistent post key-rotation |
| **Artifact signing** | cosign/sigstore keyless (OIDC) — signs **blobs/artifacts**, NOT commits |
| → design | GPG-signed commits (history layer) + optional sigstore-signed `state.sig` snapshot (attestation layer). Both. |

### Self-hosted runners
- **Officially discouraged on PUBLIC repos** — fork PRs can execute code on the runner ("pwn requests").
- → `posture-digest` must be a **private** repo carrying the self-hosted runner, triggered from the public `posture` repo via `workflow_run` / `repository_dispatch`; fork PRs never touch it.
- Ephemeral runners recommended; outbound HTTPS only (no inbound ports).

### API rate limits (REST + GraphQL)
| Actor | Limit |
|---|---|
| Authenticated (PAT/OAuth/App) | 5,000 req/hr (15,000 GHEC) |
| `GITHUB_TOKEN` in Actions | 1,000 req/hr per repo |
| Unauthenticated | 60 req/hr |
| Secondary — concurrent | 100 (REST + GraphQL combined) |
| Secondary — content-generating | **500/hr** (bites before 5,000 for write-heavy work) |
| → design | commit via **`git push` batches** (6/min, 2 GB/push), NOT per-record REST API |

---

## Sources

### The defect-record / aggregator peers

**NVD CVE API 2.0** — `services.nvd.nist.gov/rest/json/cves/2.0`
- Rate: **50 req / 30 s WITH apiKey** (**header `apiKey:`, not query string**), 5/30 s without; 6 s sleep between requests recommended; 120-day date-range max; `resultsPerPage` max 2,000.
- **2026-04-15: NVD moved to risk-based enrichment** — only KEV / federal / EO 14028 critical-software CVEs get CPE/CVSS/EPSS; everything else listed but NOT enriched; pre-March-2026 backlog "Not Scheduled".
- → NVD is **no longer the enrichment source for most defects**. Use cvelistV5 + OSV + GHSA as peers; NVD = threat-prioritized overlay (KEV/critical only). Partially obsoletes the old NVD-enrichment design.

**MITRE cvelistV5** — `github.com/CVEProject/cvelistV5` (git)
- ~1.7 GB clone, refreshed ~7 min, the **only** bulk path (legacy CSV/HTML/XML/CVRF retired 2024-06-30). `delta.json` + `deltaLog.json` for diffs; per-midnight baseline zip + hourly delta zips under Releases.
- CVE Services API `cveawg.mitre.org/api` — rate limits **not published** (AWS ELB enforced); records published hourly.
- → **primary defect-record source** (the CNA's own record, which NVD no longer enriches).

**OSV.dev** — `api.osv.dev`
- **No published rate limit** (GCP DoS protection can still throttle); 32 MiB HTTP/1.1 response cap (use HTTP/2).
- GCS export `gs://osv-vulnerabilities`: `all.zip` + per-ecosystem `all.zip` + `modified_id.csv` for incremental (continuously updated; GCS ~5,000 req/s/bucket).
- → **the practical hub**: RustSec, PyPA, Ubuntu, Go, Red Hat, Debian, Alpine, Android, … all emit OSV schema. One rate-friendly, schema-standard channel ingests a large fraction of the peer space. The generic OSV-schema adapter is the highest-leverage implementation.

**GitHub Advisory Database (GHSA)**
- GraphQL `securityAdvisories` + REST `/advisories`, shared **5,000/hr authenticated** (1,000/hr `GITHUB_TOKEN` in Actions, 60/hr unauth), 100 concurrent.
- Also a **git clone** `github.com/github/advisory-database` (CC-BY 4.0, OSV schema, `github_reviewed` flag) — clone beats the API for bulk.
- ID: `GHSA-xxxx-xxxx-xxxx-xxxx` (`[23456789cfghjmpqrvwx]`); carries optional `cve_id`.

**CISA KEV + CSAF**
- KEV: static CSV/JSON (`cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`), no rate limit, business-day updates, ~1,660 entries; `cisagov/kev-data` git mirror.
- CSAF: `cisagov/CSAF` repo (CSAF v2.0 IT/OT advisories).

### Distro / vendor peers

| Source | Access | Rate limit | ID scheme | Public? |
|---|---|---|---|---|
| **Debian** | bulk JSON `security-tracker.debian.org/tracker/data/json` (~82 MB, CDN 1h, conditional) or **git clone `salsa.debian.org/security-tracker-team/security-tracker.git`** for heavy use | none (etiquette: poll ≤ hourly) | CVE / DSA-NNNN-N / DLA-NNNN-N | PUBLIC |
| **Ubuntu** | **OSV tarball `security-metadata.canonical.com/osv/` or GitHub `canonical/ubuntu-security-notices`** — NOT the live API (flaky: only `limit≤10, offset=0` reliable; `cves.json` 429s as of April 2026) | none documented | USN-NNNN-N (+rev) / UBUNTU-CVE-`<cve>` | PUBLIC |
| **Apple** | **HTML scrape only, no API.** Cleanest JSON = community **SOFA feed** `sofa.macadmins.io/v2/{macos,ios,…}_data_feed.json` (6h, <1000 req/h) — a middleman observer needing its own dossier | none (robots Request-rate 5/s for Inquira UA only) | legacy `HT######` / current 6-digit numeric; CVE- standard | PUBLIC |
| **Red Hat** | **unauth JSON API** `access.redhat.com/hydra/rest/securitydata` (`/cve.json`, `/csaf.json`, …) + static tree `security.access.redhat.com/data/` (CSAF v2 + VEX + OSV `all.json` + `changes.csv` for incremental). CC-BY-4.0 | none documented | RHSA/RHBA/RHEA-YYYY:NNNN (one shared per-year pool) | PUBLIC (model source) |
| **IBM** | `GET ibm.com/support/pages/securityapp/api/site/datalist` (JSON) + per-bulletin HTML `/support/pages/node/{NID}` | none documented | node id (nid) + CVE | PUBLIC |
| **Fortinet** | HTML `fortiguard.com/psirt` + RSS `filestore.fortinet.com/fortiguard/rss/ir.xml` | none documented | FG-IR-YY-NNN | PUBLIC |
| **Palo Alto** | **JSON API** `security.paloaltonetworks.com/json` (+ per-advisory `/json/{id}`, RSS, CSV) — cleanest vendor surface | none documented | PAN-SA-YYYY-NNNN | PUBLIC |
| **Juniper** | listing/RSS public (`support.juniper.net/security/`, Mist RSS); **some full-text needs Support Portal login** | none documented | JSA###### | PARTIAL |
| **Cisco** | **RSS/CSAF zero-cred** `sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml` + `csaf_20.xml`; openVuln API needs free reg + OAuth2 | none documented | cisco-sa-`<product>`-`<random>` | PUBLIC (RSS/CSAF) |
| **VMware** | advisory text public (`support.broadcom.com/.../SecurityAdvisories/VMSA-YYYY-NNNN`); patch binaries need free Broadcom account | none documented | VMSA-YYYY-NNNN (.rev) | PUBLIC (text) |
| **SAP** | **none — portal-gated (S-user / support contract); no public surface** | n/a | SAP Note # (numeric) | **HARD-BLOCKED → loud UNKNOWN with a dossier** |

### Ecosystem DBs (all PUBLIC, no rate limits, OSV schema)
| Source | Access | ID | Repo size |
|---|---|---|---|
| **RustSec** | git clone `rustsec/advisory-db` (canonical) + OSV API | RUSTSEC-YYYY-NNNN | ~36 MB |
| **Go vuln DB** | HTTP API `vuln.go.dev` (OSV schema) + bulk `vulndb.zip`; `golang/vulndb` is pipeline-only | GO-YYYY-NNNN | ~50 MB (no severity labels, deliberate) |
| **PyPA** | git clone `pypa/advisory-database` (canonical) + OSV API | PYSEC-YYYY-NNNN | ~18 MB |

### Commercial scanners
| Source | Web browse | API | Status |
|---|---|---|---|
| **Snyk** | `security.snyk.io` PUBLIC | `api.snyk.io` — **Enterprise token** (1,620 req/min tiered) | web PUBLIC, API COMMERCIAL-ONLY |
| **Tenable Nessus** | plugin dir + RSS PUBLIC | cloud/sc APIs — licensed keys | web PUBLIC, API COMMERCIAL-ONLY |
| **Qualys** | 14-day pipeline page only (partial) | KB APIs — subscription | web PARTIAL, API COMMERCIAL-ONLY |

---

## PUBLIC vs GATED (for a no-cred public CI job)

**PUBLIC (CI-reachable):** Debian, Ubuntu (tarball/mirror), Apple (SOFA/scrape), Red Hat, IBM, Fortinet, Palo Alto, Cisco (RSS/CSAF), VMware (text), RustSec, Go, PyPA, CISA KEV/CSAF, GHSA (git clone), MITRE cvelistV5, OSV, NVD.

**HARD-BLOCKED → loud UNKNOWN with a dossier:** SAP (portal-gated). **Partial:** Juniper (some full text), Cisco API (free reg), VMware (patches). **Commercial-only APIs:** Snyk / Tenable / Qualys (web browse public, APIs paid).

These gaps are **declared, not hidden** — posture's honesty rule: a defect_type posture can't reach is a loud `UNKNOWN` with a dossier, never a silent "clean".

---

## Design implications (the full picture)

1. **Spine enrichment = cvelistV5 (CNA records) + OSV + GHSA as peers**; NVD = overlay for KEV/critical only (NVD stopped enriching most CVEs 2026-04-15).
2. **OSV is the practical hub** — many peers emit OSV schema; no rate limit; GCS incremental export. The generic OSV-schema adapter is the highest-leverage implementation.
3. **Per-source access paths:** Red Hat (CSAF + `changes.csv`), Debian (Salsa git), Ubuntu (OSV tarball / GitHub mirror, NOT flaky live API), Apple (SOFA or scrape), IBM (datalist JSON), Fortinet (RSS), Palo Alto (JSON API), Cisco (RSS/CSAF), CISA (KEV CSV + CSAF repo), GHSA (git clone), NVD (header apiKey, KEV/critical only), MITRE cvelistV5 (git, primary record source).
4. **Hard-blocked → loud UNKNOWN with a dossier:** SAP, Snyk/Tenable/Qualys APIs. Declared coverage gaps, not hidden.
5. **`posture-digest` = private repo + self-hosted runner**; public `posture` repo triggers it via `workflow_run`/`repository_dispatch`; fork PRs never on the runner. (Self-hosted runners are officially discouraged on public repos.)
6. **Signing = GPG-signed commits (history) + optional sigstore-signed `state.sig` (snapshot attestation).** Both.
7. **Cadence = off-zero cron + idempotent/resumable** (a dropped run is recovered by the next); ingestion's own periodic push is the keepalive against 60-day auto-disable.
8. **Bulk writes via `git push` batches** (6/min, 2 GB/push), NOT per-record REST API (the 500 content-gen/hr secondary limit bites first).
9. **Repo = signed directory** (content stays at the source URL, not committed), sharded by defect_type/time for the 100 MB file limit; signing frees history to be gc'd (tamper-evidence lives in the signature, not the history).

10. **Implemented (first cut, 2026-08-06).** The in-repo `.github/workflows/spine.yml` runs the daily off-zero-cron ingestion (`posture stream` + `posture refresh --no-devices` + DB-only course-correction + `posture spine export`) on ephemeral GitHub-hosted runners, commits the sharded `spine/*.jsonl` + `manifest.json`, and cosign-signs `manifest.json` keyless via GitHub OIDC (`spine/state.sig`). `refresh --no-devices` is the map/territory contract — catalog enrichment only, zero verdicts, no device data in CI. The cvelistV5 clone + `posture.db` persist in the Actions cache (else the stream cursor resets and stream would re-bootstrap every run, producing nothing). First cut is **one repo** (created private first, flipped public after a clean-history audit); the `posture-digest` private + self-hosted split (item 5) is deferred until a hosted runner can't carry the load. A **credentialed lane** is scaffolded as a dormant second job that pushes gated-vendor output (SAP/Snyk/Tenable/Qualys/Cisco/VMware, to be wired as credentials are obtained) to a separate *private* `rohankhanna/posture-cred` repo — never into the public repo's history, so the public flip can't leak non-redistributable content. An open question is resolved: the operator holds no gated creds yet but will apply; NVD is public-lane, not credentialed. GPG-signed commits (item 6 history layer) deferred — the sigstore `state.sig` snapshot attestation (the non-negotiable layer) ships first.

---

*Retrieval date: 2026-08-05. Sources: docs.github.com (repository-limits, actions/reference/limits, events-that-trigger-workflows, encrypted-secrets, openid-connect, self-hosted-runners, commit-signature-verification, rest rate-limits); nvd.nist.gov/developers; github.com/CVEProject/cvelistV5; google.github.io/osv.dev; docs.github.com/graphql (security-advisories); cisa.gov; security-tracker.debian.org; ubuntu.com/security; support.apple.com; access.redhat.com; ibm.com/support/pages; fortiguard.com; security.paloaltonetworks.com; support.juniper.net; sec.cloudapps.cisco.com; support.broadcom.com; github.com/rustsec/advisory-db; vuln.go.dev; github.com/pypa/advisory-database; security.snyk.io; tenable.com/plugins; qualys.com.*