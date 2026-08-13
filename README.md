<p align="center">
  <a href="https://github.com/rohankhanna/posture/actions/workflows/spine.yml"><img src="https://github.com/rohankhanna/posture/actions/workflows/spine.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT">
  <img src="https://img.shields.io/badge/status-experimental-orange.svg" alt="experimental">
</p>

# posture

**A local Python tool that combines public vulnerability data with evidence you
supply to show the known security problems on a device — and clearly marks what it
could not assess.**

Most vulnerability scanners answer one question: *which known CVEs (Common
Vulnerabilities and Exposures) match this machine?* posture answers a wider one:
*what is this device's security posture
across the things that actually matter — misconfiguration, network exposure, what's
installed, what's being exploited, whether what's installed can be trusted, and
known flaws — and where am I blind?* A dimension with no evidence is a loud
`UNKNOWN`, never a silent "clean."

posture is **device-agnostic**: it does not scan your machine itself. You *represent*
a device as a small YAML file and point posture at evidence you gather (an SBOM, a
config snapshot, a socket capture, signatures), and posture assesses that
description locally. The public flaw data it draws on (CVEs, advisories, the CISA KEV
list — CISA is the Cybersecurity and Infrastructure Security Agency; KEV is Known
Exploited Vulnerabilities) is a shared, signed **catalog** that a CI workflow builds
and publishes and that you clone and verify.

## Who it is for

- **Security engineers** who want a broader, provenance-aware picture of a host's
  posture than a CVE-only scanner gives — and who want missing evidence surfaced
  rather than papered over.
- **Fleet / portfolio tooling** that needs to keep device-specific assessment
  private (the *territory*) while consuming one shared signed catalog of public
  flaw data (the *map*).
- **Downstream tools**, which can use posture as a Python library (the catalog
  ingest + assessment engine).

> **Map and territory.** The public catalog is the *map* — CVE records, advisories,
> KEV entries drawn by outside authorities (NIST, MITRE, CISA, and vendors — NIST
> is the U.S. National Institute of Standards and Technology; MITRE maintains the
> CVE list). Your
> device, with its real installed versions and configuration, is the *territory*.
> posture assesses the territory using the map, and never pretends the map is the
> territory: a clean result means "the map places nothing here," not "this device
> is invulnerable." Unmapped territory — unreported bugs, software with no CPE
> (Common Platform Enumeration), firmware NVD (National Vulnerability Database)
> never scored — has no coordinates and is reported as `UNKNOWN`, not
> as safe.

## Highlights

- **Assess six dimensions of a host, not just CVEs.** Known flaws (vulnerability),
  misconfiguration (configuration), network reachability (exposure), what's
  installed (inventory), what's being exploited in the wild (threat), and whether
  installed artifacts are trusted (trust).
- **Combine public data with local evidence you supply.** NVD, MITRE, OSV (Open
  Source Vulnerabilities), the GitHub Advisory Database, CISA KEV, and vendor
  advisories (Ubuntu, Debian, Apple) feed the vulnerability and threat dimensions;
  an SBOM (Software Bill of Materials), a config snapshot, a socket capture, and
  signatures that *you* produce feed the rest.
- **Missing evidence is `UNKNOWN`, not "clean."** A dimension with no witness is
  loud, never silently safe — so a zero never lulls you into a claim of
  invulnerability.
- **Every verdict is provenance-stamped** with its source and time, so you can
  audit which verdicts rest on a given source and, if that source later proves
  unreliable, mark its verdicts distrusted after the fact without deleting history.

## Status

posture is **experimental** (version 0.1.0). It is source-installable only (not on
PyPI). The CI ingestion pipeline works and signs a catalog; the local assessment
engine works against bundled fixtures and a live NVD pull. There is **no
API-stability guarantee** yet — programmatic interfaces may change. Do not rely on
it for production decisions without auditing the verdicts yourself.

posture currently ships with **six default axes** (more stable than the adapters that
feed them, but not immutable — see [Core concepts](#core-concepts)). A
**credentialed lane** for gated commercial sources (SAP/Snyk/Tenable/Qualys/Cisco/
VMware) is scaffolded in CI but dormant — no credentialed witnesses are wired and no
credentialed-only records exist yet.

## Installation

```bash
git clone https://github.com/rohankhanna/posture.git
cd posture
python -m pip install -e .
```

Requires **Python ≥ 3.11**. Runtime dependencies (PyYAML, packaging, cryptography)
are installed automatically.

`git` and `curl` are required **only** for network ingestion and live NVD assessment
— not for the offline demo. They are ordinary system tools, not Python packages
(posture shells out to `curl` for NVD because Python's `requests` hangs on NVD's
CDN).

> The repository is currently **private** while it is being prepared for public
> release. The clone URL above will work once it goes public.

## Quick start

```bash
posture demo
```

`posture demo` runs an **offline** assessment against a small sample device
(`posture/fixtures/sample_device.yaml`) and the bundled fixture data — no network,
no credentials, no evidence for you to gather. It is a tour of the output shape, not
a real assessment: the sample device supplies only an NVD software matcher, so four
of the six dimensions have no evidence and come back loud `UNKNOWN`.

```
posture 0.1.0  ·  device demo-host  ·  policy 2026-08-06.3  ·  2026-08-13T14:41:26+00:00
overall: incomplete (axis(es) unknown)
========================================================================
! [configuration] UNKNOWN  (0 verdicts, complete=True, commit=swapped)
     Misconfiguration (open SSH, default creds, world-readable keys).
   GAP: no witness produced any signal (axis blank — not 'clean')
! [exposure] UNKNOWN  (0 verdicts, complete=True, commit=swapped)
     Network reachability (is this service on the open internet).
   GAP: no witness produced any signal (axis blank — not 'clean')
! [inventory] UNKNOWN  (0 verdicts, complete=True, commit=swapped)
     What is installed (the SBOM — the measured floor under everything).
   GAP: no witness produced any signal (axis blank — not 'clean')
! [threat] UNKNOWN  (0 verdicts, complete=True, commit=swapped)
     What is being exploited in the wild (KEV / IOC).
   GAP: no witness produced any signal (axis blank — not 'clean')
! [trust] UNKNOWN  (0 verdicts, complete=True, commit=swapped)
     Can you trust what is installed (provenance / signatures / SLSA).
   GAP: no witness produced any signal (axis blank — not 'clean')
! [vulnerability] UNPATCHED  (4 verdicts, complete=True, commit=swapped)
     Known flaws (CVEs + advisories).
     decided by nvd (bias=false-alarm)
       - CVE-2026-99901 unpatched [CRITICAL] fixed_in=6.18.5
       - CVE-2026-99902 patched [HIGH] fixed_in=6.17
       - CVE-2026-99903 unpatched [HIGH] fixed_in=6.18
       - CVE-2026-99904 not_affected [MEDIUM]
========================================================================
  This product uses the NVD API but is not endorsed or certified by the NVD.
```

Only `vulnerability` has verdicts (one critical unpatched, one high patched, one high
unpatched, one not-affected) — decided by the `nvd` witness. The other five are loud
`UNKNOWN` because the demo device supplied no evidence for them: `UNKNOWN` means "no
witness produced a signal," **not** "clean." The `decided by nvd` line is
**provenance** — which source produced each verdict. The footer is the mandatory NVD
attribution notice.

The `overall: incomplete` headline is the core honesty rule: as long as any
dimension is `UNKNOWN`, the posture is *incomplete*, not "clean" — a zero on one
dimension does not let you ignore the others.

## Your first real assessment

Real assessment means gathering evidence for the dimensions you care about and
describing the device in a YAML file. To see a populated multi-dimension result
offline, save this as `full_device.yaml` — it points at the bundled fixture
samples posture ships for each evidence type (a CIS config, a socket capture, an
SBOM, a KEV list), so it runs with no network:

```yaml
# full_device.yaml
id: full-demo
name: "Full evidence demo host"
os: linux
os_version: "6.18"
patch_level: "6.18"
matchers:
  - { type: nvd_cpe, cpe: "cpe:2.3:o:linux:linux_kernel", version: "6.18" }
config:
  path: sample_config.json        # CIS checker input  -> configuration
exposure_path: sample.json        # socket capture      -> exposure
sbom_path: sample.json            # CycloneDX SBOM      -> inventory
kev_path: sample.json             # CISA KEV candidates -> threat
```

```bash
posture assess full_device.yaml
```

```
posture 0.1.0  ·  device full-demo  ·  policy 2026-08-06.3  ·  2026-08-13T14:44:40+00:00
overall: incomplete (axis(es) unknown)
========================================================================
! [configuration] FAIL  (20 verdicts, complete=True, commit=swapped)
     Misconfiguration (open SSH, default creds, world-readable keys).
     decided by cis_checker (bias=false-safe)
       - CIS-6.2.1 fail [high]
       - CIS-1.1.2 fail [medium]
       - CIS-4.1.3 fail [medium]
       - CIS-5.4.1 fail [medium]
       - CIS-6.1.2 fail [high]
       ... +15 more
! [exposure] EXPOSED  (3 verdicts, complete=True, commit=swapped)
     Network reachability (is this service on the open internet).
     decided by local_exposure (bias=false-safe)
       - tcp/22 exposed [HIGH]
       - tcp/5432 closed
       - tcp/8080 closed
  [inventory] PRESENT  (3 verdicts, complete=True, commit=swapped)
     What is installed (the SBOM — the measured floor under everything).
     decided by cyclonedx_sbom (bias=neutral)
       - openssl@3.0.2 present
       - nginx@1.25.3 present
       - busybox@1.36 present
! [threat] UNKNOWN  (0 verdicts, complete=True, commit=swapped)
     What is being exploited in the wild (KEV / IOC).
   GAP: no witness produced any signal (axis blank — not 'clean')
! [trust] UNKNOWN  (0 verdicts, complete=True, commit=swapped)
     Can you trust what is installed (provenance / signatures / SLSA).
   GAP: no witness produced any signal (axis blank — not 'clean')
! [vulnerability] UNPATCHED  (4 verdicts, complete=True, commit=swapped)
     Known flaws (CVEs + advisories).
     decided by nvd (bias=false-alarm)
       - CVE-2026-99901 unpatched [CRITICAL] fixed_in=6.18.5
       - CVE-2026-99902 patched [HIGH] fixed_in=6.17
       - CVE-2026-99903 unpatched [HIGH] fixed_in=6.18
       - CVE-2026-99904 not_affected [MEDIUM]
========================================================================
  This product uses the NVD API but is not endorsed or certified by the NVD.
```

Now `configuration`, `exposure`, and `inventory` are populated (by `cis_checker`,
`local_exposure`, `cyclonedx_sbom`). `threat` and `trust` remain `UNKNOWN` — the KEV
fixture's CVEs did not match the device's, and no signature artifacts were supplied.
That is the honest result: posture reports what each witness could decide and loudly
flags the dimensions it could not.

To assess against **real NVD data** instead of the bundled fixture, add `--live`:

```bash
posture assess <device.yaml> --live
```

> **Three ways the NVD vulnerability witness gets its data — and what each sends.**
> 1. **Bundled fixture (the default, offline).** `posture assess` and `posture demo`
>    read `posture/fixtures/nvd_sample.json` — a small synthetic sample, *not* real
>    NVD. Nothing leaves your machine.
> 2. **`--live` (network).** The NVD witness queries the NVD API directly and sends
>    the device's **CPE** (the software identifier from your matcher) as NVD's
>    `virtualMatchString` parameter. This is the only path that sends device data to
>    a third party.
> 3. **Imported signed catalog (offline).** `posture spine import` loads the catalog
>    CI builds from real NVD — but today only the **Apple fix-version overlay** from
>    that catalog flows into a live `assess`. The NVD vulnerability witness has **no
>    catalog path yet**: without `--live` it reads the bundled fixture, not the
>    catalog. Wiring more of the catalog into local assessment is ongoing work.
>
> An **`NVD_API_KEY`** is optional but recommended for `--live` — it raises the rate
> limit from 5 to 50 requests / 30 s. Never store the key in the repository; see
> [Configuration](#configuration).

## Understanding the result

Each dimension (the output above) reports a status, a verdict count, and its
provenance:

- **Statuses.** Vulnerability uses `unpatched` / `patched` / `not_affected` /
  `unknown`. The other dimensions use their own (`fail`/`pass`, `exposed`/`closed`,
  `present`/`absent`, `targeted`/`clear`, `untrusted`/`trusted`) — all defaulting to
  `unknown` when no evidence is supplied.
- **`overall: incomplete (axis(es) unknown)`** — the headline. As long as any
  dimension is `UNKNOWN`, posture is *incomplete*, not "clean."
- **`decided by <witness>`** — **provenance**: which source produced each verdict.
  Every verdict is stamped with its source and time and stored, which is what makes
  trust **monitorable over time**: you can later ask "which of my verdicts rest on
  source X?" (`posture audit <witness>`) and, if that source proves unreliable, mark
  its verdicts **distrusted after the fact** (`posture distrust <witness>`). The
  verdicts are *marked*, not deleted — the history of what you once believed is
  preserved so you can see exactly what a now-distrusted source was claiming.
  **Retroactive distrust** means: you never have to pretend you always knew a source
  was bad; you record that you stopped trusting it on a given date, and everything
  that rested on it is visibly flagged from that point on.

## Core concepts

### Security dimensions (axes)

posture reasons about **axes** — the categories of posture signal a real security
pillar tracks. posture currently ships with **six default axes** (the seed set). They
are more stable than the adapters that feed them (when a source is captured,
defunded, or superseded, you swap the adapter; the axis and its verdict logic stay),
but they are not immutable: axes are vocabulary held as data in a **glossary**, so a
new dimension can be promoted without an engine change. The six seed axes:

| Axis | What it asks | Example statuses |
|---|---|---|
| `vulnerability` | What's broken? (CVEs + advisories) | unpatched / patched / not_affected |
| `configuration` | What's misconfigured? | fail / pass |
| `exposure` | What's network-reachable? | exposed / closed |
| `inventory` | What's installed? (the SBOM) | present / absent |
| `threat` | What's being exploited in the wild? | targeted / clear |
| `trust` | Can you trust what's installed? (signatures) | untrusted / trusted |

(`posture axes` lists these with their keys and full status sets.)

### Sources and witnesses

A **witness** is a source or local check that supplies evidence for an axis. posture
is source-agnostic: every witness implements one uniform contract, so adding a
source is one module, not an engine change. The registered witnesses:

| Witness | Axis | Input it consumes | Network? |
|---|---|---|---|
| `nvd` | vulnerability | device CPE matcher; CVE/CVSS (Common Vulnerability Scoring System) data | yes (`--live`) |
| `ubuntu_tracker` | vulnerability | Ubuntu release + packages + CVE candidates | yes (Ubuntu tracker) |
| `debian_tracker` | vulnerability | Debian release + packages + CVE candidates | yes (Debian tracker) |
| `apple_advisory` | vulnerability | Apple product + OS version + CVE candidates | yes (Apple advisories) |
| `cyclonedx_sbom` | inventory | a supplied CycloneDX SBOM file | no (local) |
| `cis_checker` | configuration | a supplied config snapshot | no (local) |
| `local_exposure` | exposure | a supplied socket capture | no (local) |
| `kev` | threat | supplied CVE candidates checked against CISA KEV | no (local) |
| `sigverify` | trust | supplied artifacts + supplied keys | no (local) |

(`posture witnesses` lists these with their bias, weight, and policy order.)

### Device evidence reference

posture is an **assessment engine**, not an auto-collector: it does not inventory
your machine. You (or a tool you run) produce the evidence and reference it from the
device YAML. Bare/relative paths in the fields below also resolve under
`posture/fixtures/` for offline testing.

| Device YAML field | Type | Axis populated | Produced by |
|---|---|---|---|
| `matchers[].{type: nvd_cpe, cpe, version}` | CPE matcher | vulnerability | you (from installed software) |
| `config` / `cis_checks` | config snapshot | configuration | a config collector / CIS scan |
| `exposure` / `exposure_path` | socket capture (e.g. `ss -tulpn`) | exposure | a socket capture tool |
| `sbom` / `sbom_path` | CycloneDX SBOM | inventory | an SBOM generator (`cyclonedx`, `syft`) |
| `kev` / `kev_path` | CVE candidates vs CISA KEV | threat | a prior NVD pass / your OS package list |
| `artifacts` / `artifacts_path` | artifacts + keys | trust | your signing/verification material |
| `cve_candidates` | CVE id list | vulnerability (vendor witnesses) | a prior NVD pass / OS pkg list |
| `ubuntu_release`, `ubuntu_packages` | Ubuntu release + packages | vulnerability | you |
| `debian_release`, `debian_packages` | Debian release + packages | vulnerability | you |
| `apple_product`, `os_version` | Apple product + OS version | vulnerability | you |

### Public map and private territory

The public catalog (CVEs, advisories, KEV) is the **map** — drawn by outside
authorities. Your device is the **territory**. posture keeps them separate: CI builds
and signs the map; you assess your territory locally. A verdict says "the catalog
places this flaw on this device's map," never "this device has this flaw" as an
absolute. (See
[Honesty and trust model](#honesty-and-trust-model).)

## Configuration

**Environment variables**

| Variable | Purpose |
|---|---|
| `NVD_API_KEY` | Raises the NVD rate limit 5 → 50 req/30 s. **Optional but recommended.** Sent **header-only**, never in the query string (query-string `apiKey` triggers NVD's 404-masquerade). Keep it out of the repo. |
| `POSTURE_CVELIST_DIR` | Parent directory of the MITRE cvelistV5 clone. The clone is created as `$POSTURE_CVELIST_DIR/cvelistV5`. Default: `~/.local/share/posture/cvelist` (→ `…/cvelistV5`). Set to reuse an existing clone. |
| `POSTURE_GHSA_DIR` | Parent directory of the GitHub advisory-database clone, created as `$POSTURE_GHSA_DIR/advisory-database`. Default: `~/.local/share/posture/ghsa` (→ `…/advisory-database`). |

**Default paths**

| Path | Default |
|---|---|
| posture DB | `~/.local/share/posture/posture.db` |
| cvelistV5 clone | `~/.local/share/posture/cvelist/cvelistV5` |
| advisory-database clone | `~/.local/share/posture/ghsa/advisory-database` |

**Trust policy.** Trust in sources is a **versioned, dated YAML file**, not code:
`posture/policy/policy.yaml`. `posture policy show` prints the active policy;
`posture policy validate <file>` checks a candidate. Each witness has a policy
`order` — lower runs last and wins (e.g. vendor witnesses `order: 5` override NVD
`order: 10` on the same CVE).

## Honesty and trust model

- **`UNKNOWN` is never "clean."** A dimension with no witness is loud; a clean
  result only means "the map places nothing here," not "invulnerable." Unmapped
  territory (unreported bugs, software with no CPE, firmware NVD never scored) has
  no coordinates and is reported as `UNKNOWN`.
- **Provenance on every verdict.** Each verdict records which witness produced it
  and when. Because that is stored, you can audit which verdicts rest on a given
  source and **distrust that source retroactively** — marking its verdicts, not
  deleting them — so the history of what you once believed is preserved (see
  [Understanding the result](#understanding-the-result)).
- **Ingestion never erases verdicts.** A failed or incomplete pull only *adds*
  catalog rows and alias edges; it cannot replace a device's stored state.
- **`--live` is the only path that sends device data to a third party.** It sends
  the device's CPE to NVD as `virtualMatchString`. Offline/catalog assessment sends
  nothing. The NVD API key (if used) is sent **header-only**, never in the query
  string, and is never committed.
- **NVD attribution** is emitted in every NVD-sourced output and in this README's
  footer — the map is foreign-authored, so it is attributed:

  > This product uses the NVD API but is not endorsed or certified by the NVD.

## Consuming the signed catalog

CI publishes a **cosign-signed manifest** for the exported catalog
(`spine/manifest.json`), not a signed git repository. Consuming it is a two-step
process, and each step answers a different question:

**1. Verify the manifest signature externally.** posture does **not** verify the
cosign signature itself — this is your **trust anchor**, so it is yours to perform.
It answers: *did this catalog come from this project's CI, and not from someone who
pushed to the repo or tampered with the commit?*

```bash
cosign verify-blob \
  --certificate spine/state.crt \
  --signature spine/state.sig \
  --certificate-identity "https://github.com/rohankhanna/posture/.github/workflows/spine.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  spine/manifest.json
```

Pin `--certificate-identity` to this project's workflow ref and
`--certificate-oidc-issuer` to GitHub Actions' token endpoint — this establishes
*whose* identity is allowed to sign, not merely that some valid certificate signed.
Confirm the identity string against a checked-in certificate before relying on it.

**Why this step is necessary:** without it, `git pull` gives you bytes that anyone
with write access (or anyone who compromised a commit) could have replaced. The
cosign keyless signature is bound to this specific GitHub workflow via OIDC, so a
valid signature proves the manifest was produced by *this* CI job, not by a pushed
commit. This is the layer that survives a git history rewrite — the signature is
over the content, not the commit.

**2. Import the catalog.** This answers a different question: *since CI signed the
manifest, have the catalog's shard files been corrupted or tampered with on disk or
in transit?* `posture spine import` recomputes every shard's sha256 and asserts it
matches the now-verified manifest before loading anything:

```bash
posture spine import --from .          # verifies shard hashes vs manifest
posture assess <device.yaml>           # assess your private fleet, locally
```

**Why this step is necessary:** step 1 proves the manifest is authentic, but the
manifest is just a list of shard hashes. Step 2 checks that the shard files you
actually have match that signed list — catching corruption or substitution of the
data files themselves. `posture spine import --no-verify` skips this check; do not
use it for a catalog you did not verify yourself.

**What the imported catalog actually drives today:** importing populates the local
catalog tables (flaws, crosswalks, candidates, distrust marks, KEV, Apple fixes).
Of these, only the **Apple fix-version overlay** currently flows into a live
`posture assess` verdict (it is injected as a device input for `apple_advisory`).
The rest is browsable library data (`posture catalog list`, `posture crosswalk show`)
and the source pool the vulnerability witnesses draw from — but the **threat (KEV)
witness still requires you to supply `kev`/`kev_path` in the device YAML**, and
configuration/exposure/inventory/trust are driven entirely by evidence you supply.
Wiring more of the catalog into local assessment is ongoing work.

The CI workflow itself uses cosign **keyless** signing via GitHub OIDC (no key
material to manage). GPG-signed git *commits* (the history layer) are deferred — the
sigstore manifest signature (the non-negotiable layer) ships first.

## Data sources and ingestion

**How the product is actually used.** There are two audiences for ingestion, and
they should not be conflated:

- **Most users do not run ingestion at all.** CI builds and signs the catalog every
  6 hours and commits it to `spine/`. You `git pull`, verify the signature, import,
  and run `posture assess` locally over your private fleet. The commands below are
  not part of your day-to-day flow.
- **Operators self-hosting their own catalog** (air-gapped site, a different
  vendor mix, or contributing a new source) run the ingestion commands themselves
  to build a local `posture.db` independent of the published spine. This is also the
  path for development and for the local MITRE stream timer below.

posture's signed catalog is fed by several public, rate-friendly peers. Every ingestion path
**only adds** catalog rows and alias edges and **never touches verdicts**. The full
source-coverage reference (rate limits, access paths, vendor peer table, public vs
gated) lives in [`docs/sources.md`](docs/sources.md).

| Command | What it does |
|---|---|
| `posture stream` | One MITRE cvelistV5 stream tick: `git fetch` + diff since a cursor, upsert skeleton rows (NVD not yet enriched). Cursor bootstraps O(1); a force-push no-ops, never fails into a wipe. |
| `posture backfill --cap N` | cvelistV5 back-catalog (history the forward-only stream can't take); cap-resumed; self-disables once exhausted. |
| `posture ingest ghsa --cap N` | GitHub Advisory Database (CC-BY 4.0, OSV schema): blobless clone, cap-resumed backfill + incremental. CVE aliases become symmetric crosswalk edges. |
| `posture ingest osv --cap N` | osv.dev hub — the highest-leverage peer (RustSec, PyPA, Go, Red Hat, Debian, Ubuntu, Alpine…). Per-ecosystem backfill + incremental. A CVE-less OSV record still anchors as first-class. |
| `posture ingest kev` | CISA KEV overlay (annotates existing CVE rows; not a new flaw type). Idempotent full refresh, ~1,660 entries. |
| `posture ingest apple [--product …] [--history]` | Apple advisory fix-version overlay, CVE+product-keyed, per-product full refresh. `--history` recovers pre-index CVEs from Wayback (more fetches). |
| `posture refresh [--devices <yaml> \| --no-devices]` | Incremental NVD enrichment + per-CVE re-decide; upserts verdicts one key at a time, never a bulk swap. |

### CI ingestion (the recommended publication path)

`.github/workflows/spine.yml` runs on ephemeral GitHub-hosted runners every 6 h
(off-zero cron, with a skip-if-running guard so a busy run is skipped, not queued):
`stream` → `backfill` → `ingest ghsa/osv/kev/apple` → `refresh --no-devices` →
DB-only course-correction (`posture monitor run`, `posture repair reconcile`,
`posture discover`) → `spine export` → cosign-sign `manifest.json` → commit `spine/`.

**`--no-devices` is the contract:** CI runs catalog enrichment only — no fleet, no
verdicts, no device data. The committed `spine/` is data-only.

A **credentialed lane** is scaffolded as a dormant second CI job for future
gated-vendor sources (SAP/Snyk/Tenable/Qualys/Cisco/VMware, to be wired as
credentials are obtained). It is dormant — no credentialed witnesses are wired and
no credentialed-only records exist yet. When wired, it would push to a separate
*private* repo, never into this repo's history.

### Optional local MITRE stream

For an operator who wants to run the MITRE stream locally, a systemd user timer
fires `posture stream` at a 10–17 min cadence:

```bash
mkdir -p ~/.config/posture ~/.config/systemd/user
# Create the EnvironmentFile the unit REQUIRES (no `-` prefix, so a missing file
# breaks the unit). It can be empty; put optional settings there, e.g.
#   NVD_API_KEY=...
# chmod 600; never commit it.
touch ~/.config/posture/env && chmod 600 ~/.config/posture/env
cp systemd/posture-stream.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now posture-stream.timer
```

**Local vs remote, and why this exists.** The local stream builds *your own*
`posture.db` catalog independently of the published signed spine. Running both at
once means maintaining a local catalog parallel to the signed one — generally pick
one path. The explicit `stream`/`backfill`/`ingest` commands exist for operator
self-hosting (air-gapped sites, a different vendor mix) and for development; CI is
the recommended path for everyone else. The cvelistV5 clone defaults to
`~/.local/share/posture/cvelist/cvelistV5`; set `POSTURE_CVELIST_DIR` to reuse an
existing clone without re-cloning.

## Vendor-specific assessment

NVD over-reports on backport distros (it doesn't know your distro's patch
backports) and silently skips most Apple CVEs. Three **vendor witnesses** close
those gaps, each overriding NVD **on the same CVE key by policy order** (their
`order: 5` < NVD's `10`, so they run last and win):

- **`ubuntu_tracker`** — Ubuntu security tracker, authoritative per release + kernel
  flavor.
- **`debian_tracker`** — Debian security tracker bulk JSON; assumes the device runs
  the latest release.
- **`apple_advisory`** — Apple security advisories (iOS/iPadOS/macOS); builds
  `cve → fixed_in`, earliest version wins.

Because witnesses run in a pure fan-out (they cannot see each other's verdicts),
each vendor witness takes its candidate CVEs as a **device input** rather than from
the NVD pass:

```yaml
id: ubuntu-host
os: linux
patch_level: "6.18"
matchers:
  - { type: nvd_cpe, cpe: "cpe:2.3:o:canonical:ubuntu_linux", version: "6.18" }
cve_candidates: ["CVE-2026-99901", "CVE-2026-99903"]   # from a prior NVD pass / OS pkg list
ubuntu_release: noble
ubuntu_packages: ["linux-nvidia-6.17"]
# debian host: debian_release: trixie, debian_packages: [linux]
# apple host:  apple_product: iphone_os, os_version: "26.5.2"
```

A device of the wrong distro gets an honest no-op from each vendor witness (zero
verdicts) — NVD's verdicts stand and the `UNKNOWN`-not-clean rule is unaffected.

## CLI reference

Every subcommand takes `--help` for full options. Common options include
`--db <path>` (default `~/.local/share/posture/posture.db`) and `--policy <file>`.

**Most users**

| Command | Purpose |
|---|---|
| `posture demo` | offline assessment from the bundled sample device (NVD-only) |
| `posture assess <device.yaml> [--live]` | assess a device (`--live` pulls real NVD, sending the CPE to NVD) |
| `posture axes` | list the axes, their keys, and statuses |
| `posture witnesses` | registered witnesses + bias/weight/order/health |
| `posture policy {show\|log\|validate}` | trust policy: print, history, or check a candidate |
| `posture health [--add-dossier …]` | source-health (operational + dossier + drift) |
| `posture distrust <witness>` | mark a witness's verdicts distrusted (retroactive) |
| `posture audit <witness>` | which verdicts rest on this witness? |
| `posture spine {show\|export\|import}` | the flaw catalog; `import` takes `--from` and `--no-verify` |
| `posture catalog {show <id>\|list\|pending}` | browse the flaw catalog |
| `posture crosswalk {add\|show}` | the identifier alias graph |

**Catalog operators** (self-hosting / development)

| Command | Purpose |
|---|---|
| `posture stream` | MITRE cvelistV5 stream tick (skeletons, only-adds) |
| `posture backfill --cap N` | cvelistV5 back-catalog (self-disables when done) |
| `posture ingest {kev\|osv\|ghsa\|apple}` | aggregator peers + overlays (`apple`: `--product`, `--history`) |
| `posture refresh [--no-devices\|--devices <yaml>] [--cap N]` | incremental NVD enrichment + re-decide |

**Governance & development**

| Command | Purpose |
|---|---|
| `posture discover [--fetch]` | horizon scan: surface new aggregator candidates |
| `posture glossary {list\|roles\|show\|add\|promote\|deprecate}` | the vocabulary as data (axes, flaw types, roles) |
| `posture monitor {run\|queue}` | vocabulary monitor |
| `posture repair {list\|apply <id>\|reconcile}` | trust-repair proposals (`apply` takes a proposal id) |

## Library API

The current programmatic API (no stability guarantee at 0.1.0):

```python
from posture.stream import stream_tick
from posture.refresh import refresh_tick

stream_tick(conn, repo_path=..., policy_version=...)          # one MITRE stream tick
refresh_tick(conn, devices, policy_version=..., cap=..., live=True)  # NVD enrich + re-decide
```

## Development and tests

`pyproject.toml` does not yet declare a development extra, so install the test
runner separately:

```bash
python -m pip install pytest
python -m pytest
```

## Contributing

Bug reports and well-scoped fixes are welcome via issues and pull requests on
`main`. A conventional contribution: clone, `pip install -e .`, `pip install pytest`,
run `python -m pytest`, and open a PR with a clear description. Please also read
[SECURITY.md](SECURITY.md) before reporting or working on security-sensitive issues.

**Adding a data source** is the highest-leverage contribution. Implement the uniform
`Witness` contract (see `posture/sources/base.py` and the existing witnesses), emit
the source's required attribution line wherever its data surfaces, and add the
source to the trust policy with an appropriate `order`. Source-health dossiers and
policy-version bumps are also high-value.

## Acknowledgements

posture builds one honest map from many authors' maps. It gratefully uses the public
data and feeds of:

- **MITRE CVE** — `CVE Project / cvelistV5`.
- **NIST NVD** — CVE API 2.0. *This product uses the NVD API but is not endorsed or
  certified by the NVD.*
- **OSV.dev** / `osv-vulnerabilities` — the practical aggregator across ecosystems
  (RustSec, PyPA, Go, Red Hat, Debian, Ubuntu, Alpine, …).
- **GitHub Advisory Database** — CC-BY 4.0, OSV schema.
- **CISA** — Known Exploited Vulnerabilities catalog.

Each is a *witness* to an axis, not an oracle; the honesty rules above apply to all
of them.

## License

MIT — see [LICENSE](LICENSE).