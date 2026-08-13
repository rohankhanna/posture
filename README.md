<p align="center">
  <a href="https://github.com/rohankhanna/posture/actions/workflows/spine.yml"><img src="https://github.com/rohankhanna/posture/actions/workflows/spine.yml/badge.svg" alt="spine CI"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="v0.1.0">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT">
  <img src="https://img.shields.io/badge/status--experimental-orange.svg" alt="experimental">
</p>

# posture

> A source-agnostic, axis-based **posture pillar** with monitored trust.

`posture` is the **spine** of a larger forecaster we imagine as a **weatherman** —
a map over the world's flaw-space, not just a CVE tracker. The spine requires good
posture; hence the name. It is a sibling to [Forebode](../forebode), not a
replacement: a reusable foundation Forebode (and other portfolio tools) can migrate
onto. *(“posture” is a working title.)*

The fundamental design:

> *The spine is all flaws — every flaw that is a peer of CVEs, across every
> flaw_type, simultaneously; CVE is one peer among many, not a primary key. The
> body is the six axes; the resilience is the skeleton/flesh split; and the trust
> in the spine itself has to be monitored as a living thing, because it already
> nearly broke once.*

For the source-coverage and rate/size limits the spine is designed against, see
[`docs/sources.md`](docs/sources.md).

---

## Highlights

- **Spine = an alias↔alias graph, not a key.** The spine entity is the
  *equivalence class* of flaw_ids that denote one flaw (`cve ↔ ghsa ↔ osv ↔ usn ↔
  dsa`), not a single join key. CVE is one peer among many, not a primary key and
  not rebindable — a CVE-numbering freeze (MITRE's 2024 near-lapse) doesn't strand
  the system.
- **Six stable axes.** `vulnerability / configuration / exposure / inventory /
  threat / trust`. Sources churn *within* an axis; axes are stable. The system
  reasons about axes; a source is one *witness* to an axis.
- **Skeleton/flesh split.** The engine is source-agnostic; every source is a
  module behind one uniform `Witness` contract. Adding a source = one module; the
  5-step core never changes. Trust is a **versioned, dated policy file**, not
  code.
- **Trust monitored as a living thing.** A source-health subsystem watches the
  witnesses (operational health + a dated funding/governance/capture dossier +
  drift hooks), with pre-declared degradation/fallback decided *before* a crisis,
  and provenance-stamped verdicts that allow **retroactive distrust**.
- **Multi-peer ingestion.** MITRE cvelistV5 + OSV + GHSA + CISA KEV + NVD feed the
  spine as peers. Every ingestion path **only adds** catalog rows and alias edges
  and **never touches verdicts** — an incomplete fetch can't wipe a device's
  state.
- **Signed CI spine.** A public repo + workflow feed and enrich the catalog (the
  *map*) with cosign-keyless signatures; your machine only *consumes* — clone,
  verify, and `posture assess` locally over your private fleet (the *territory*).
- **Honesty rules.** An axis with no witness is a loud `UNKNOWN`, never a silent
  “clean”. The map is not the territory.

---

## Installation

```bash
cd ~/Desktop/posture
pip install -e .
```

Requires **Python ≥ 3.11**. Runtime deps: `PyYAML`, `packaging`, `cryptography`.
Ingestion additionally expects `git` and `curl` on `PATH` (used as external
subprocesses — `requests` hangs on NVD's CDN; the CVE clone path needs `git`).

---

## Quick start

Everything below works offline against the bundled fixture, so you can tour the
full six-axis posture before any network or fleet:

```bash
posture demo              # offline: full 6-axis posture from the bundled fixture
posture axes              # the six axes
posture witnesses         # registered witnesses + health state
posture policy show       # the active versioned trust policy
posture health            # source-health (operational + dossier + drift)
posture spine show        # flaw-type registry + crosswalk edge counts (the alias graph)
```

Source-health is editable, so you can record a dossier and distrust a witness
retroactively:

```bash
posture health --add-dossier nvd --date 2026-08-01 --axis vulnerability \
  --claim "NVD backlog growing" --citation https://nvd.nist.gov --direction funding
posture distrust nvd --reason "audit test"   # retroactive distrust
posture audit nvd                            # which verdicts rest on this witness?
```

A real CVE pull (needs network + `NVD_API_KEY`):

```bash
posture assess host --live --db ~/.local/share/posture/posture.db
```

---

## How it works — the four ideas

### 1. The spine is an alias graph, not a key

The spine entity is the *equivalence class* of flaw_ids that denote the same
flaw — a many-to-many alias graph, not a single join key. CVE is **one peer
among many**, not a primary key and not rebindable. A CVE-less flaw (an OSV or
GHSA record with no CVE) still anchors as a first-class peer. So a
CVE-numbering freeze doesn't strand the system, and the spine widens as peers
are wired rather than deepening the CVE/NVD tunnel.

### 2. The body is six stable axes

| Axis | Question it answers | Witness |
|---|---|---|
| `vulnerability` | what's broken? | CVE spine (NVD, MITRE, OSV, GHSA…) |
| `configuration` | what's misconfigured? | CIS benchmark |
| `exposure` | what's reachable? | local socket surface |
| `inventory` | what's installed? | CycloneDX SBOM |
| `threat` | what's being attacked? | CISA KEV overlay |
| `trust` | can you trust what's installed? | signature verification |

Sources churn *within* an axis; axes are stable. The system reasons about axes; a
source is one *witness* to an axis.

### 3. Skeleton/flesh split

The engine is source-agnostic; every source is a module behind one uniform
`Witness` contract. Adding a source = one module; the 5-step core never changes.
Trust is a **versioned, dated policy file**, not code.

### 4. Trust in the spine is monitored as a living thing

A source-health subsystem watches the witnesses (operational health measured
from fetch results + a dated funding/governance/capture dossier + drift hooks),
with pre-declared degradation/fallback decided *before* a crisis, and
provenance-stamped verdicts that allow **retroactive distrust**.

---

## Vendor witnesses (real flesh on the body)

NVD is no longer the spine — it is one *peer* (and increasingly an overlay: NVD
stopped enriching most CVEs on 2026-04-15, so cvelistV5 + OSV + GHSA carry the
peer space and NVD is threat-prioritized for KEV/critical). But where NVD *is*
consumed it still over-reports on backport distros and silently skips
thin-coverage CVEs (Apple). Three real **vendor witnesses** close those gaps,
each overriding NVD **on the same CVE key by policy order** (their `order: 5` <
NVD's `10`, so the engine runs them last and they win) — no code change, one YAML
number each:

- **`ubuntu_tracker`** — Ubuntu security tracker, authoritative per release +
  kernel flavor. Fixed `<ver>` → patched if running kernel ≥ ver else unpatched;
  Not affected → patched; Vulnerable → unpatched.
- **`debian_tracker`** — Debian security tracker bulk JSON. `resolved` (with
  version or `"0"` = not affected) → patched; `open` → unpatched;
  `undetermined`/absent → no verdict. Assumes the device runs the latest release.
- **`apple_advisory`** — Apple security advisories (iOS/iPadOS/macOS). Builds
  `cve → fixed_in` (earliest version wins); `device_version ≥ fixed_in` →
  patched, else unpatched; not in Apple's feed → no verdict (NVD stands — its
  Apple coverage is thin and silently skips most).

Because posture's witnesses run in a pure fan-out (`assess(device, policy)` —
they cannot see each other's verdicts), each vendor witness takes its candidate
CVE set as a **device input** rather than from the NVD pass:

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
verdicts) — NVD's verdicts stand and the loud-degradation rule is unaffected; it
is never broken by them.

## Beyond the spine — the other axes

The five non-vulnerability axes were honest stubs (loud `UNKNOWN`) until wired.
All five are now real witnesses — no axis is left at a stub:

- **`cyclonedx_sbom`** (inventory) — reads a CycloneDX SBOM the device supplies
  (`device["sbom"]` inline, or `device["sbom_path"]` to a local JSON file) and
  emits one `present` Verdict per component, keyed `<name>@<version>`. The SBOM
  is the measured floor under everything; an axis with packages is never “clear”.
  No network — local only.
- **`cis_checker`** (configuration) — runs a bundled CIS-style benchmark (demo
  scope) against a device config snapshot (`device["config"]`, optionally scoped
  via `device["cis_checks"]`), emitting `fail`/`pass` per check id. A missing
  setting is a `fail`; no config supplied is an honest no-op.
- **`local_exposure`** (exposure) — reads a local socket capture the device
  supplies (`device["exposure"]` / `device["exposure_path"]`, e.g. `ss -tulpn`
  output) and emits `exposed`/`closed` per socket, keyed `proto/port`. A loopback
  bind is `closed`; a wildcard, non-loopback, or missing bind is `exposed`
  (false-safe). No network — local only.
- **`kev`** (threat) — overlays the device's `cve_candidates` against a CISA KEV
  cve-id set the device supplies (`device["kev"]` / `device["kev_path"]`; a client
  gets the set from the imported spine's `kev.jsonl`) and emits
  `targeted`/`clear` per CVE. No KEV overlay supplied is an honest no-op (NOT
  all-clear); an explicitly-empty set is all-clear.
- **`sigverify`** (trust) — verifies a supplied signature against a supplied
  public key per artifact (`device["artifacts"]` / `device["artifacts_path"]`)
  via `cryptography` (ed25519 default, rsa-pss also supported) and emits
  `trusted`/`untrusted` keyed on the artifact id. An unverifiable artifact is
  `untrusted` and flagged loudly — never silently skipped.

```yaml
id: server
config: { sshd_permit_root_login: "no", tmp_nosuid: "yes", password_min_len: 14 }
cis_checks: ["CIS-6.2.1", "CIS-5.4.1"]
sbom:
  bomFormat: CycloneDX
  specVersion: "1.4"
  components: [{name: openssl, version: "3.0.2"}, {name: nginx, version: "1.25.3"}]
exposure:
  - {proto: tcp, port: 22, bind: "0.0.0.0", service: ssh}
  - {proto: tcp, port: 5432, bind: "127.0.0.1", service: postgres}
cve_candidates: ["CVE-2026-1001", "CVE-2026-1002"]
kev: ["CVE-2026-1001"]
```

Each witness turns its axis from loud `UNKNOWN` into a real status when the
device supplies input, and is an honest no-op otherwise — the loud-degradation
rule holds for every axis.

---

## Ingestion & the signed CI spine

posture earns its product name through its ingestion engine. The spine is **all
flaws**, fed by several public, rate-friendly peers (no credentialed lane needed
for these). Every ingestion path **only adds** catalog rows + alias-graph edges
and **never touches verdicts** — an incomplete fetch can't wipe a device's stored
state. One honest map, many authors:

| Command | What it does |
|---|---|
| `posture stream` | One MITRE cvelistV5 stream tick: `git fetch` + diff since a cursor, upsert **skeleton** rows (`enrich_state='mitre'`, NVD not yet enriched). Cursor bootstraps O(1); a force-push no-ops, never fails into a wipe. |
| `posture backfill --cap N` | cvelistV5 back-catalog (the history the forward-only stream can't take), cap-resumed across ticks; **self-disables** once exhausted. |
| `posture ingest ghsa --cap N` | GitHub Advisory Database (CC-BY 4.0, OSV schema): blobless clone, cap-resumed backfill + incremental diff. Self-enriched on ingest (`enrich_state='ghsa'`); CVE aliases become symmetric crosswalk edges. |
| `posture ingest osv --cap N` | osv.dev hub — the highest-leverage peer (RustSec, PyPA, Go, Red Hat, Debian, Ubuntu, Alpine… all emit OSV schema). Per-ecosystem `all.zip` backfill + `modified_id.csv` incremental. Self-enriched; a CVE-less OSV record still anchors as a first-class peer. |
| `posture ingest kev` | CISA KEV **overlay** (not a new flaw_type — entries carry only a `cveID`): idempotent full refresh of the ~1,660-entry catalog annotates existing cve rows. |
| `posture ingest apple` | Apple advisory fix-version overlay, CVE+product-keyed, per-product full refresh (optional `--history` Wayback recovery). |
| `posture refresh --devices <yaml>` | Incremental NVD enrichment (curl, **header-only** `apiKey`) + per-CVE re-decide; upserts verdicts one key at a time — never a bulk swap. Last-known-good verdicts are never deleted. |
| `posture refresh --no-devices` | CI mode: catalog-only enrichment, **zero verdicts**. |

The catalog (`flaws` table, `id` is a TEXT PK accepting any flaw_id) carries
**provenance on every row** (`source`/`fetched_at`/`policy_version`/`complete` +
`flaw_type`), so a catalog row, like a verdict, can be retroactively
**distrusted** (`posture catalog` + `mark_flaw_distrust`) — marked, never
deleted. Each foreign source emits its required attribution line wherever its
data surfaces. **The map is not the territory:** a skeleton says "MITRE
published this; NVD has not enriched it" — never "this device is vulnerable."

### Feeding without a local machine

The systemd timer below is the **local** ingestion path. There is also a **CI**
path that exists for one reason: **no feeding or enrichment should ever run from a
local machine.** A public GitHub repo + workflow feed and enrich the catalog
(the *map*); your machine only *consumes* — clone the signed repo, verify the
signature, run `posture assess` locally over your private fleet (the
*territory*). The map/territory split, made concrete across a git bus instead of
an HTTP API.

**Topology.** `.github/workflows/spine.yml` runs on ephemeral GitHub-hosted
runners: `posture stream` → `posture backfill` → `posture ingest ghsa`/`osv`/
`kev`/`apple` → `posture refresh --no-devices` (NVD catalog enrichment, **zero
verdicts**) → DB-only course-correction → `posture spine export` (sharded JSONL
+ `manifest.json`) → `cosign sign-blob` keyless via GitHub OIDC
(`spine/state.sig` + `spine/state.crt`) → commit + push `spine/`. The cvelistV5
+ advisory-database blobless clones and `posture.db` persist across runs in the
Actions cache. Signing is non-negotiable — without it a shallow clone just
trusts whatever GitHub serves, the single-org dependency posture was built to
escape.

**`--no-devices` is the contract:** CI runs catalog enrichment only — no fleet,
no verdicts, no vendor trackers. No device data ever leaves your machine; the
committed `spine/` is data-only.

**Credentialed lane.** A second, dormant job pushes gated-vendor output
(SAP/Snyk/Tenable/Qualys/Cisco/VMware — wired as you obtain credentials) to a
*separate private* repo `posture-cred`, never into this repo's history — so the
eventual public flip can't leak non-redistributable content.

**Consume on a client:**

```bash
git clone https://github.com/rohankhanna/posture.git && cd posture
cosign verify-blob --certificate spine/state.crt --signature spine/state.sig \
                   spine/manifest.json     # verifies against Fulcio's public roots
posture spine import --db ~/.local/share/posture/posture.db --from .
posture assess <device.yaml> --live        # territory: your private fleet, local
```

**Sign + publish from a checkout** (what CI automates):

```bash
posture spine export --db ~/.local/share/posture/posture.db --out .
cosign sign-blob --output-signature spine/state.sig --output-certificate spine/state.crt \
                 spine/manifest.json
```

### Local ingestion

A non-deterministic **systemd user timer** (`systemd/posture-stream.{service,timer}`)
fires the stream tick 10–17 min after the previous tick *finished*
(`OnUnitInactiveSec=10min` + `RandomizedDelaySec=7min`, drifting, never
wall-clock pinned), with a DNS-readiness gate on `github.com`:

```bash
cp systemd/posture-stream.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now posture-stream.timer
```

The cvelistV5 clone lives at `~/.local/share/posture/cvelist/cvelistV5` by
default; set `POSTURE_CVELIST_DIR` to reuse an existing clone (e.g. Forebode's)
without re-cloning.

---

## Configuration

**Environment variables**

| Variable | Purpose |
|---|---|
| `NVD_API_KEY` | NVD rate limit 5 → 50 req/30 s. Sent **header-only**, never in the query string (query-string `apiKey` triggers NVD's 404-masquerade). Optional but recommended. |
| `POSTURE_CVELIST_DIR` | Parent of the cvelistV5 clone (default `~/.local/share/posture/cvelist/cvelistV5`). Set to reuse an existing clone. |
| `POSTURE_GHSA_DIR` | Parent of the advisory-database clone (default `~/.local/share/posture/ghsa/advisory-database`). |

**Default paths**

| Path | Default |
|---|---|
| posture DB | `~/.local/share/posture/posture.db` |
| cvelistV5 clone | `~/.local/share/posture/cvelist/cvelistV5` |
| advisory-database clone | `~/.local/share/posture/ghsa/advisory-database` |

The trust policy is a **versioned, dated YAML file** — not code. `posture policy
show` prints the active policy; `posture policy validate <file>` checks a
candidate. The bundled policy ships in `posture/policy/policy.yaml`.

**Library API** (stable, for downstream shells like Forebode):
`posture.stream.stream_tick(conn, repo_path=..., policy_version=...)`,
`posture.refresh.refresh_tick(conn, devices, policy_version=..., cap=..., live=...)`.

---

## Honesty rules

posture inherits Forebode's **“the map is not the territory”** discipline:

- An axis with no witness is `UNKNOWN` and loud — **never** silent/clean.
- **No-wipe:** an incomplete fetch never replaces stored verdicts.
- NVD fetch uses `curl` with a **header-only** `apiKey` (never the query string).
- NVD attribution is emitted in any NVD-sourced output.
- A catalog row or verdict carries provenance and can be **retroactively
  distrusted** — marked, never deleted.

> This product uses the NVD API but is not endorsed or certified by the NVD.

---

## CLI reference

| Group | Command | Purpose |
|---|---|---|
| **Assessment** | `posture demo` | offline 6-axis posture from the bundled fixture |
| | `posture assess <device.yaml> [--live]` | assess a device (full re-pull with `--live`) |
| | `posture axes` | list the six axes |
| | `posture witnesses` | registered witnesses + health state |
| | `posture policy show \| validate` | trust policy |
| | `posture health [--add-dossier …]` | source-health (operational + dossier + drift) |
| | `posture distrust <witness>` | mark a witness's verdicts distrusted (retroactive) |
| | `posture audit <witness>` | which verdicts rest on this witness? |
| **Spine** | `posture spine show \| export \| import` | flaw-type registry + crosswalk; signed-directory I/O |
| | `posture catalog list \| pending \| show <id>` | browse the flaw catalog |
| | `posture crosswalk add \| show` | spine alias graph |
| **Ingestion** | `posture stream` | MITRE cvelistV5 stream tick (skeletons) |
| | `posture backfill --cap N` | cvelistV5 back-catalog (self-disables when done) |
| | `posture ingest kev \| osv \| ghsa \| apple` | aggregator peers + overlays |
| | `posture refresh [--no-devices \| --devices <yaml>]` | incremental NVD enrichment + re-decide |
| **Self-correction** | `posture discover [--fetch]` | horizon scan: surface new aggregator candidates (delta) |
| | `posture glossary …` | the vocabulary as data |
| | `posture monitor run \| queue` | vocabulary monitor |
| | `posture repair list \| apply \| reconcile` | self-repair proposals |

`posture --help` lists every subcommand; each subcommand has `--help` of its own.

---

## Documentation

- [`docs/sources.md`](docs/sources.md) — source-coverage reference and the
  GitHub/NVD/OSV rate & size limits the spine is designed against.
- `posture health` / `posture audit` — the source-health and provenance surface
  that makes trust in the spine inspectable.

---

## Tests

```bash
python -m pytest
```

---

## Contributing

posture is early and experimental. Bug reports and well-scoped fixes are
welcome via issues and pull requests on the `main` branch. Source-health
dossiers, new `Witness` modules behind the existing contract, and policy-version
bumps are the highest-leverage contributions.

When adding a source, implement the uniform `Witness` contract (see
`posture/sources/base.py` and the existing witnesses) and emit the source's
required attribution line wherever its data surfaces.

---

## Acknowledgements

The spine is one honest map built from many authors' maps. posture gratefully
uses the public data and feeds of:

- **MITRE CVE** — `CVE Project / cvelistV5` (CVE sponsorship records).
- **NIST NVD** — CVE API 2.0. *This product uses the NVD API but is not endorsed
  or certified by the NVD.*
- **OSV.dev** / `osv-vulnerabilities` GCS hub — the practical aggregator across
  ecosystems (RustSec, PyPA, Go, Red Hat, Debian, Ubuntu, Alpine, …).
- **GitHub Advisory Database** — CC-BY 4.0, OSV schema.
- **CISA** — Known Exploited Vulnerabilities catalog + CSAF.

Each is a *witness* to an axis, not an oracle; the honesty rules above apply to
all of them.

---

## License

MIT — see [LICENSE](LICENSE).