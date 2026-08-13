<p align="center">
  <a href="https://github.com/rohankhanna/posture/actions/workflows/spine.yml"><img src="https://github.com/rohankhanna/posture/actions/workflows/spine.yml/badge.svg" alt="spine CI"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT">
  <img src="https://img.shields.io/badge/status--experimental-orange.svg" alt="experimental">
</p>

# posture

## What posture does

`posture` is a **local security-posture assessment tool**. It reads evidence about
a device — installed software, configuration, open ports, a supplied SBOM,
supplied signatures — and combines it with public security data (CVEs, vendor
advisories, the CISA KEV list) to assess that device across **six dimensions**,
not just known vulnerabilities: misconfiguration, network exposure, inventory,
active threats, and whether installed artifacts are trusted, as well as
vulnerabilities themselves.

It runs locally; your device-specific data never leaves your machine. The public
flaw data it consumes is a shared, signed **catalog** that a CI workflow builds
and publishes, and that you clone and verify. A dimension with no evidence is
reported as a loud **`UNKNOWN`**, never a silent “clean.”

## Who it is for

- **Security engineers** who want a broader, provenance-aware picture of a host's
  posture than a CVE-only scanner gives — and who want missing evidence surfaced
  rather than papered over.
- **Fleet / portfolio tooling** that needs to keep device-specific assessment
  private (the *territory*) while consuming one shared signed catalog of public
  flaw data (the *map*).
- **Downstream tools**, which can use posture as a Python library (the catalog
  ingest + assessment engine).

> **Map and territory.** Public catalog data is the *map* — CVE records,
> advisories, KEV entries drawn by outside authorities. Your device, with its
> real installed versions and configuration, is the *territory*. posture assesses
> the territory using the map, and never pretends the map is the territory: a
> clean result means “the map places nothing here,” not “this device is
> invulnerable.”

## Highlights

- **Assess six dimensions of a host**, not just CVEs: vulnerability,
  configuration, exposure, inventory, active threats, and artifact trust.
- **Combine public data with local evidence.** NVD, MITRE, OSV, GitHub Advisory
  DB, CISA KEV, and vendor advisories (Ubuntu, Debian, Apple) feed the
  vulnerability and threat axes; an SBOM, a config snapshot, a socket capture,
  and signatures that *you* supply feed the rest.
- **Keep device data local.** All device-specific assessment runs on your
  machine; the CI-published catalog is data-only and carries no device data.
- **Missing evidence is `UNKNOWN`, not “clean.”** An axis with no witness is
  loud, never silently safe.
- **Every verdict is provenance-stamped** with its source and time, so results
  can be audited and a source can be **retroactively distrusted** later.
- **Run an offline demo** with no credentials and no network.

## Status

posture is **experimental** (version 0.1.0). It is source-installable only (not
on PyPI). The CI ingestion pipeline works and signs a catalog; the local
assessment engine works against a bundled fixture and a live NVD pull. There is
**no API-stability guarantee** yet — programmatic interfaces may change. Do not
rely on it for production decisions without auditing the verdicts yourself.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Assessing a device](#assessing-a-device)
- [Understanding the result](#understanding-the-result)
- [Core concepts](#core-concepts)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Honesty and trust model](#honesty-and-trust-model)
- [Consuming the signed catalog](#consuming-the-signed-catalog)
- [Data sources and ingestion](#data-sources-and-ingestion)
- [Vendor-specific assessment](#vendor-specific-assessment)
- [CLI reference](#cli-reference)
- [Library API](#library-api)
- [Development and tests](#development-and-tests)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Installation

```bash
git clone https://github.com/rohankhanna/posture.git
cd posture
python -m pip install -e .
```

Requires **Python ≥ 3.11**. Runtime dependencies (PyYAML, packaging,
cryptography) are installed automatically.

`git` and `curl` are required **only** for network ingestion and live NVD
assessment — not for the offline demo. They are ordinary system tools, not
Python packages (posture shells out to `curl` for NVD because `requests` hangs on
NVD's CDN).

> The repository is currently **private** while it is being prepared for public
> release. The clone URL above will work once it goes public.

## Quick start

No network, no credentials — tour the full six-axis assessment from the bundled
fixture:

```bash
posture demo
```

```
overall: incomplete (axis(es) unknown)
! [vulnerability] UNPATCHED  (4 verdicts)
     Known flaws (CVEs + advisories).
     decided by nvd (bias=false-alarm)
       - CVE-2026-99901 unpatched [CRITICAL] fixed_in=6.18.5
       - CVE-2026-99902 patched   [HIGH]     fixed_in=6.17
       - CVE-2026-99903 unpatched [HIGH]     fixed_in=6.18
       - CVE-2026-99904 not_affected [MEDIUM]
! [configuration] UNKNOWN   (0 verdicts)   GAP: axis blank — not 'clean'
! [exposure]      UNKNOWN   (0 verdicts)   GAP: axis blank — not 'clean'
! [inventory]     UNKNOWN   (0 verdicts)   GAP: axis blank — not 'clean'
! [threat]        UNKNOWN   (0 verdicts)   GAP: axis blank — not 'clean'
! [trust]         UNKNOWN   (0 verdicts)   GAP: axis blank — not 'clean'
  This product uses the NVD API but is not endorsed or certified by the NVD.
```

The `vulnerability` axis has verdicts (two unpatched CVEs, one patched, one
not-affected). The other five are loud `UNKNOWN` because the demo device supplied
no evidence for them — `UNKNOWN` means “no witness produced a signal,” **not**
“clean.” The `decided by nvd` line is provenance: which source produced each
verdict. The footer is the mandatory NVD attribution.

## Assessing a device

A device is a small YAML file describing what to assess. A checked-in example
ships with the repo:

```bash
posture assess posture/fixtures/sample_device.yaml
```

That runs offline against the bundled fixture (same output as `demo` above). To
assess against real NVD data instead, add `--live`:

```bash
posture assess posture/fixtures/sample_device.yaml --live
```

`--live` pulls from NVD over the network. An **`NVD_API_KEY`** is optional but
strongly recommended — with a key the rate limit is 50 requests / 30 s instead
of 5. Never store the key in the repository; see [Configuration](#configuration).

The sample device's shape:

```yaml
id: demo-host
name: "Demo Linux host"
os: linux
os_version: "6.18"
patch_level: "6.18"
matchers:
  - { type: nvd_cpe, cpe: "cpe:2.3:o:linux:linux_kernel", version: "6.18" }
```

## Understanding the result

Each axis reports a status. For vulnerabilities: `unpatched`, `patched`,
`not_affected`, or `unknown`. The other axes use their own statuses (`fail`/
`pass`, `exposed`/`closed`, `present`/`absent`, `targeted`/`clear`,
`untrusted`/`trusted`) — all defaulting to `unknown` when no evidence is
supplied.

- **`overall: incomplete (axis(es) unknown)`** — the headline. As long as any
  axis is `UNKNOWN`, the posture is *incomplete*, not “clean.” This is the core
  honesty rule: a zero on one axis does not let you ignore the others.
- **Provenance** — every verdict records which witness produced it and when
  (`decided by nvd`). Because provenance is stored, you can later ask “which of
  my verdicts rest on source X?” (`posture audit <witness>`) and mark that
  source's verdicts distrusted after the fact (`posture distrust <witness>`) —
  **retroactive distrust**, without deleting history.

## Core concepts

### The six security axes

posture reasons about six stable **axes**. Sources change; axes don't.

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

A **witness** is a source or local check that supplies evidence for an axis.
posture is source-agnostic: every witness implements one uniform contract, so
adding a source is one module, not an engine change. The registered witnesses:

| Witness | Axis | Notes |
|---|---|---|
| `nvd` | vulnerability | CVE/CVSS data; over-reports on backport distros |
| `ubuntu_tracker` | vulnerability | authoritative per Ubuntu release + kernel flavor |
| `debian_tracker` | vulnerability | Debian security tracker; assumes latest release |
| `apple_advisory` | vulnerability | Apple advisories; closes NVD's thin Apple coverage |
| `cyclonedx_sbom` | inventory | reads a supplied CycloneDX SBOM (local only) |
| `cis_checker` | configuration | bundled CIS-style benchmark against a config snapshot |
| `local_exposure` | exposure | reads a supplied socket capture (e.g. `ss -tulpn`) |
| `kev` | threat | overlays CISA KEV against supplied CVE candidates |
| `sigverify` | trust | verifies supplied signatures against supplied keys |

(`posture witnesses` lists these with their bias, weight, and policy order.)

### Public map and private territory

The public catalog (CVEs, advisories, KEV) is the **map** — drawn by outside
authorities. Your device is the **territory**. posture keeps them separate: CI
builds and signs the map; you assess your territory locally. A verdict says “the
map places this flaw on your device,” never “your device has this flaw” as an
absolute. (See [Honesty and trust model](#honesty-and-trust-model).)

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

**Trust policy.** Trust in sources is a **versioned, dated YAML file**, not
code: `posture/policy/policy.yaml`. `posture policy show` prints the active
policy; `posture policy validate <file>` checks a candidate. Each witness has a
policy `order` — lower runs last and wins (e.g. vendor witnesses `order: 5`
override NVD `order: 10` on the same CVE).

## How it works

### The flaw catalog (“spine”)

The shared catalog is called the **spine**: one table of flaw records where
every row carries provenance (`source`, `fetched_at`, `policy_version`,
`flaw_type`). A CVE is one kind of flaw among several — not the primary key — so
the spine widens as new sources are wired rather than deepening a single CVE/NVD
tunnel.

### Identifier crosswalks

The same flaw is often known by different ids across databases (a CVE, a GHSA,
an OSV, a USN, a DSA). posture stores these as an **alias graph** — an
equivalence class of ids that denote one flaw — rather than forcing everything
onto a CVE key. A CVE-less record still anchors as a first-class entry.

### Source adapters (“skeleton/flesh”)

The engine (the **skeleton**) is source-agnostic; each source is a replaceable
adapter (the **flesh**) behind the uniform witness contract. Adding a source is
one module; the core never changes.

### Trust policy and provenance

Every verdict is stamped with which witness produced it and when. That provenance
is what makes trust **monitorable over time**: you can audit which verdicts rest
on a given source and distrust that source retroactively (the verdicts are
marked, not deleted). Source *health* (operational reliability, a dated
governance/funding dossier, drift detection) is tracked alongside, so
degradation paths can be decided before a crisis rather than during one.

## Honesty and trust model

- **`UNKNOWN` is never “clean.”** An axis with no witness is loud; a clean result
  only means “the map places nothing here,” not “invulnerable.”
- **No-wipe.** An incomplete fetch never replaces stored verdicts — ingestion
  only *adds* catalog rows and alias edges. A failed pull can't erase a device's
  state.
- **Provenance on every verdict**, enabling retroactive distrust.
- **NVD via `curl`, header-only `apiKey`** — never the query string.
- **NVD attribution** is emitted in every NVD-sourced output:

  > This product uses the NVD API but is not endorsed or certified by the NVD.

## Consuming the signed catalog

CI publishes a **cosign-signed manifest** for the exported catalog (`spine/
manifest.json`), not a signed git repository. Verification is a two-step
process:

**1. Verify the manifest signature externally** (posture does **not** verify the
cosign signature itself — this is the trust anchor, so it is yours to perform):

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
*whose* identity is allowed to sign, not merely that some valid certificate
signed. Confirm the identity string against a checked-in certificate before
relying on it.

**2. Import the catalog**, which checks every shard's sha256 against the
now-verified manifest:

```bash
posture spine import --from .          # verifies shard hashes vs manifest
posture assess <device.yaml> --live    # assess your private fleet, locally
```

(`posture spine import --no-verify` skips the manifest hash check — do not use
this for a catalog you did not verify yourself.)

The CI workflow itself uses cosign **keyless** signing via GitHub OIDC (no key
material to manage). Note: GPG-signed git *commits* are deferred — the sigstore
manifest signature is the layer that ships first.

## Data sources and ingestion

posture's spine is fed by several public, rate-friendly peers. Every ingestion
path **only adds** catalog rows and alias edges and **never touches verdicts**.

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
(off-zero cron, with a skip-if-running guard so a busy run is skipped, not
queued): `stream` → `backfill` → `ingest ghsa/osv/kev/apple` →
`refresh --no-devices` → DB-only course-correction → `spine export` →
cosign-sign `manifest.json` → commit `spine/`.

**`--no-devices` is the contract:** CI runs catalog enrichment only — no fleet,
no verdicts, no device data. The committed `spine/` is data-only.

A **credentialed lane** is scaffolded as a dormant second CI job for future
gated-vendor sources (SAP/Snyk/Tenable/Qualys/Cisco/VMware, to be wired as
credentials are obtained). It is **not yet functional** — no credentialed
witnesses are wired, and its export is empty until they are. When wired, it would
push to a separate *private* repo, never into this repo's history.

### Optional local MITRE stream

For an operator who wants to run the MITRE stream locally (not the full
ingestion/enrichment pipeline — CI is the recommended path for that), a systemd
user timer fires `posture stream` at a non-deterministic 10–17 min cadence:

```bash
mkdir -p ~/.config/posture ~/.config/systemd/user
# ~/.config/posture/env is the unit's EnvironmentFile (required by the unit).
# Put optional settings there, e.g.  NVD_API_KEY=...   (chmod 600; never commit it)
cp systemd/posture-stream.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now posture-stream.timer
```

The cvelistV5 clone defaults to `~/.local/share/posture/cvelist/cvelistV5`; set
`POSTURE_CVELIST_DIR` to reuse an existing clone without re-cloning.

## Vendor-specific assessment

NVD over-reports on backport distros (it doesn't know your distro's patch
backports) and silently skips most Apple CVEs. Three **vendor witnesses** close
those gaps, each overriding NVD **on the same CVE key by policy order** (their
`order: 5` < NVD's `10`, so they run last and win):

- **`ubuntu_tracker`** — Ubuntu security tracker, authoritative per release +
  kernel flavor.
- **`debian_tracker`** — Debian security tracker bulk JSON; assumes the device
  runs the latest release.
- **`apple_advisory`** — Apple security advisories (iOS/iPadOS/macOS); builds
  `cve → fixed_in`, earliest version wins.

Because witnesses run in a pure fan-out (they cannot see each other's verdicts),
each vendor witness takes its candidate CVEs as a **device input** rather than
from the NVD pass:

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

| Command | Purpose |
|---|---|
| `posture demo` | offline 6-axis assessment from the bundled fixture |
| `posture assess <device.yaml> [--live]` | assess a device (`--live` pulls real NVD) |
| `posture axes` | list the six axes, their keys, and statuses |
| `posture witnesses` | registered witnesses + bias/weight/order/health |
| `posture policy {show\|log\|validate}` | trust policy: print, history, or check a candidate |
| `posture health [--add-dossier …]` | source-health (operational + dossier + drift) |
| `posture distrust <witness>` | mark a witness's verdicts distrusted (retroactive) |
| `posture audit <witness>` | which verdicts rest on this witness? |
| `posture spine {show\|export\|import}` | the flaw catalog; `import` takes `--from` and `--no-verify` |
| `posture catalog {show <id>\|list\|pending}` | browse the flaw catalog |
| `posture crosswalk {add\|show}` | the identifier alias graph |
| `posture stream` | MITRE cvelistV5 stream tick (skeletons, only-adds) |
| `posture backfill --cap N` | cvelistV5 back-catalog (self-disables when done) |
| `posture ingest {kev\|osv\|ghsa\|apple}` | aggregator peers + overlays (`apple`: `--product`, `--history`) |
| `posture refresh [--no-devices\|--devices <yaml>] [--cap N]` | incremental NVD enrichment + re-decide |
| `posture discover [--fetch]` | horizon scan: surface new aggregator candidates |
| `posture glossary {list\|roles\|show\|add\|promote\|deprecate}` | the vocabulary as data |
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
`main`. A conventional contribution: clone, `pip install -e .`, `pip install
pytest`, run `python -m pytest`, and open a PR with a clear description.

**Adding a data source** is the highest-leverage contribution. Implement the
uniform `Witness` contract (see `posture/sources/base.py` and the existing
witnesses), emit the source's required attribution line wherever its data
surfaces, and add the source to the trust policy with an appropriate `order`.
Source-health dossiers and policy-version bumps are also high-value.

## Acknowledgements

posture builds one honest map from many authors' maps. It gratefully uses the
public data and feeds of:

- **MITRE CVE** — `CVE Project / cvelistV5`.
- **NIST NVD** — CVE API 2.0. *This product uses the NVD API but is not endorsed
  or certified by the NVD.*
- **OSV.dev** / `osv-vulnerabilities` — the practical aggregator across
  ecosystems (RustSec, PyPA, Go, Red Hat, Debian, Ubuntu, Alpine, …).
- **GitHub Advisory Database** — CC-BY 4.0, OSV schema.
- **CISA** — Known Exploited Vulnerabilities catalog.

Each is a *witness* to an axis, not an oracle; the honesty rules above apply to
all of them.

## License

MIT — see [LICENSE](LICENSE).