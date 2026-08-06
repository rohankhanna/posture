# posture (working title)

A source-agnostic, axis-based **posture pillar** with monitored trust. The
fundamental design:

> *The spine is all flaws — every flaw that is a peer of cves, across every
> flaw_type, simultaneously; cve is one peer among many, not a primary key.
> The body is the six axes; the resilience is the skeleton/flesh split; and
> the trust in the spine itself has to be monitored as a living thing,
> because it already nearly broke once.*

posture is the **spine** of a bigger superapp we imagine as a **weatherman**
— a forecaster over the world's flaw-space, not just a CVE tracker. The
spine requires good posture; hence the name. (See
[`docs/sources.md`](docs/sources.md) for the source-coverage + limits
reference the spine is designed against.)

It is a sibling to [Forebode](../forebode), not a replacement for it — a
reusable foundation Forebode (and other portfolio tools) can migrate onto.

## The four ideas

1. **Spine = an alias↔alias graph, not a key.** The spine entity is the
   *equivalence class* of flaw_ids that denote the same flaw — a many-to-many
   alias graph (`cve ↔ ghsa ↔ osv ↔ usn ↔ dsa`), not a single join key. CVE is
   **one peer among many**, not a primary key and not rebindable. A cve-less
   flaw (an OSV or GHSA record with no CVE) still anchors as a first-class peer.
   So a CVE-numbering freeze (MITRE's 2024 near-lapse) doesn't strand the system,
   and the spine widens as peers are wired rather than deepening the CVE/NVD
   tunnel.
2. **Body = six stable axes.** `vulnerability / configuration / exposure /
   inventory / threat / trust`. Sources churn *within* an axis; axes are
   stable. The system reasons about axes; a source is one *witness* to an axis.
3. **Skeleton/flesh split.** The engine is source-agnostic; every source is a
   module behind one uniform `Witness` contract. Adding a source = one module;
   the 5-step core never changes. Trust is a **versioned, dated policy file**,
   not code.
4. **Trust in the spine is monitored as a living thing.** A source-health
   subsystem watches the witnesses (operational health measured from fetch
   results + a dated funding/governance/capture dossier + drift hooks), with
   pre-declared degradation/fallback decided *before* a crisis, and
   provenance-stamped verdicts that allow **retroactive distrust**.

## Vendor witnesses (real flesh on the body)

NVD is no longer the spine — it is one *peer* (and increasingly an overlay, see
*Ingestion* below: NVD stopped enriching most CVEs 2026-04-15, so cvelistV5 +
OSV + GHSA carry the peer space and NVD is threat-prioritized for KEV/critical).
But where NVD *is* consumed it still over-reports on backport distros and
silently skips thin-coverage CVEs (Apple). Three real **vendor witnesses**
close those gaps, each overriding NVD **on the same CVE key by policy order**
(their `order: 5` < NVD's `10`, so the engine runs them last and they win) — no
code change, one YAML number each:

- **`ubuntu_tracker`** — Ubuntu security tracker (`ubuntu.com/security/<CVE>`),
  authoritative per release + kernel flavor. Fixed `<ver>` → patched if running
  kernel ≥ ver else unpatched; Not affected → patched; Vulnerable → unpatched.
- **`debian_tracker`** — Debian security tracker bulk JSON
  (`security-tracker.debian.org/tracker/data/json`). `resolved` (with version
  or `"0"`=not affected) → patched; `open` → unpatched; `undetermined`/absent →
  no verdict. Assumes the device runs the latest release (status mapping, not
  installed-vs-fixed compare).
- **`apple_advisory`** — Apple security advisories (iOS/iPadOS/macOS). Builds
  `cve → fixed_in` (earliest version wins) from the advisory index + pages;
  `device_version ≥ fixed_in` → patched, else unpatched; not in Apple's feed →
  no verdict (NVD stands — NVD's iOS coverage is thin and silently skips most).

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
# apple host: apple_product: iphone_os, os_version: "26.5.2"
```

A device with no vendor input gets an honest no-op from each vendor witness
(zero verdicts) — NVD's verdicts stand and the loud-degradation rule is
unaffected; a host of the wrong distro is never broken by them.

## Beyond the spine — the other axes

The five non-vulnerability axes were honest stubs (loud `UNKNOWN`) until
wired. Two are now real witnesses; the rest remain stubbed:

- **`cyclonedx_sbom`** (inventory) — reads a CycloneDX SBOM the device supplies
  (`device["sbom"]` inline, or `device["sbom_path"]` to a local JSON file) and
  emits one `present` Verdict per component, keyed `<name>@<version>`. The SBOM
  is the measured floor under everything; an axis with packages is never
  "clear". No network — local only.
- **`cis_checker`** (configuration) — runs a bundled CIS-style benchmark
  (demo scope) against a device config snapshot (`device["config"]`,
  optionally scoped via `device["cis_checks"]`), emitting `fail`/`pass` per
  check id. A missing setting is a `fail` (a missing control is not a pass);
  no config supplied is an honest no-op (axis stays `UNKNOWN`).

```yaml
id: server
config: { sshd_permit_root_login: "no", tmp_nosuid: "yes", password_min_len: 14 }
cis_checks: ["CIS-6.2.1", "CIS-5.4.1"]
sbom:
  bomFormat: CycloneDX
  specVersion: "1.4"
  components: [{name: openssl, version: "3.0.2"}, {name: nginx, version: "1.25.3"}]
```

`exposure`, `threat`, and `trust` are still stubs (`UNKNOWN` and loud) — wiring
them is the remaining work on the "wire real witnesses for the 5 stubbed axes"
thread.

## Ingestion (a multi-peer aggregator, cve one peer among many)

posture earns the product name "forebode" — high signal / low noise / low LLM —
through its ingestion engine. The spine is **all flaws**, fed by several
public, rate-friendly peers (no credentialed lane needed for these). Every
ingestion path **only adds** catalog rows + alias-graph edges and **never
touches verdicts** — an incomplete fetch can't wipe a device's stored state.
One honest map, many authors:

1. **`posture stream` (MITRE detect — skeletons only).** A ~10-17 min tick
   `git fetch`es MITRE's cvelistV5 clone, diffs changed CVE JSON since a stream
   cursor, and upserts **skeleton** catalog rows (`flaw_type='cve'`,
   `enrich_state='mitre'`, `pending_nvd=True`, reason "MITRE-published; NVD not
   yet enriched"). The cursor bootstraps O(1) (first run records the tip and
   produces nothing; history is the back-fill's job, not the stream's). A
   force-push/history-rewrite resets the cursor and no-ops — it never fails
   into a wipe path.

2. **`posture backfill` (cvelistV5 back-catalog — the history the forward-only
   stream can't take).** Cap-resumed across ticks, it enumerates the `cves/`
   back-catalog past a path cursor and upserts the same skeletons. It
   **self-disables** once exhausted (a state flag), so daily CI calls it
   cheaply as a no-op thereafter. Skeletons land `enrich_state='mitre'` and
   join the refresh's pending pool.

3. **`posture ingest ghsa` (GitHub Advisory Database — a self-enriched OSV
   peer).** A blobless clone of `github/advisory-database` (CC-BY 4.0, OSV
   schema); cap-resumed backfill of `advisories/github-reviewed/` then
   incremental diff. Each GHSA id owns its own row (`flaw_type='ghsa'`,
   `enrich_state='ghsa'` — **self-enriched on ingest**, NOT pending mitre, so
   refresh leaves it alone); its CVE aliases become symmetric crosswalk edges.

4. **`posture ingest osv` (osv.dev — the highest-leverage peer).** The OSV GCS
   hub is the practical aggregator: RustSec, PyPA, Go, Red Hat, Debian,
   Ubuntu, Alpine, … all emit OSV schema, so one adapter ingests a large
   fraction of the peer space. Per-ecosystem `all.zip` backfill (cap-resumed),
   then `modified_id.csv` incremental. OSV rows are self-enriched
   (`flaw_type='osv'`, `enrich_state='osv'`); each alias becomes a crosswalk
   edge. A cve-less OSV record still anchors as a first-class peer.

5. **`posture ingest kev` (CISA Known Exploited Vulnerabilities — the
   `exploitability_signal` overlay).** A CVE-keyed **overlay** (not a new
   flaw_type — KEV entries carry only a `cveID`): an idempotent full refresh of
   the static ~1,660-entry catalog annotates existing cve rows ("known-
   exploited; required action X; due date Y; ransomware-linked Z") without
   owning the flaw_id.

6. **`posture refresh` (wipe-proof incremental NVD enrichment).** Takes the
   pending MITRE skeletons, enriches each per-CVE from NVD via **curl** with a
   **header-only** `apiKey` (NEVER the query string — that was Forebode's
   run-#10 fleet-wipe root cause), promotes the row to `enrich_state='nvd'`,
   then re-decides per device CPE and upserts **one** verdict row per CVE
   through `store.upsert_verdict` (per-key `ON CONFLICT DO UPDATE`). It never
   calls the bulk `commit_device_verdicts` swap — an incomplete NVD fetch
   simply upserts fewer rows; last-known-good verdicts are never deleted. The
   full re-pull is demoted to the rare `posture assess` reconciliation. With
   `--no-devices` it is catalog-only enrichment (zero verdicts) — the CI mode.

The catalog (`cves` table, `id` is a TEXT PK accepting any flaw_id) carries
**provenance on every row** (`source`/`fetched_at`/`policy_version`/`complete`
+ `flaw_type`), so a catalog row, like a verdict, can be retroactively
**distrusted** (`posture catalog` + `mark_cve_distrust`) — marked, never
deleted. Each foreign source emits its required attribution line wherever its
data surfaces (NVD ToU; MITRE CVE sponsorship; CISA KEV; GitHub CC-BY 4.0;
OSV.dev). **The map is not the territory:** a skeleton says "MITRE published
this; NVD has not enriched it" — never "this device is vulnerable."

```bash
posture stream                          # one MITRE stream tick (skeletons only)
posture backfill --cap 5000             # cvelistV5 back-catalog (self-disables when done)
posture ingest ghsa --cap 5000          # GitHub Advisory Database peer (OSV schema)
posture ingest osv --cap 5000           # osv.dev hub peer (many ecosystems)
posture ingest kev                      # CISA KEV overlay (exploitability_signal)
posture refresh --devices ~/.config/posture/devices.yaml   # incremental NVD + re-decide
posture refresh --no-devices --cap 200   # CI: catalog-only, zero verdicts
posture catalog list [--state mitre|nvd|ghsa|osv]  # browse the catalog
posture catalog pending                  # skeletons awaiting NVD enrichment
posture catalog show CVE-2026-XXXX       # one row (parsed) + attribution
posture spine show                      # flaw-type registry + crosswalk edge counts
posture assess <device.yaml> --live      # full re-pull (rare reconciliation)
```

A non-deterministic **systemd user timer** (`systemd/posture-stream.{service,timer}`)
fires the stream tick 10-17 min after the previous tick *finished*
(`OnUnitInactiveSec=10min` + `RandomizedDelaySec=7min`, drifting, never
wall-clock pinned), with a DNS-readiness gate on `github.com`. Install:

```bash
cp systemd/posture-stream.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now posture-stream.timer
```

The cvelistV5 clone lives at `~/.local/share/posture/cvelist/cvelistV5` by
default; set `POSTURE_CVELIST_DIR` to reuse an existing clone (e.g. the
Forebode one) without re-cloning. Library API (stable, for the Forebode shell):
`posture.stream.stream_tick(conn, repo_path=..., policy_version=...)`,
`posture.refresh.refresh_tick(conn, devices, policy_version=..., cap=..., live=...)`.

## CI spine — feeding without a local machine

The systemd timer above is the **local** ingestion path. There is also a
**CI** path that exists for one reason: **no feeding or enrichment should ever
run from a local machine.** A public GitHub repo + a workflow feed and enrich
the catalog (the spine — the *map*); your machine only *consumes* — clone the
signed repo, verify the signature, run `posture assess` locally over your
private fleet (the *territory*). The map/territory split, made concrete across a
git bus instead of an HTTP API.

**Topology:** one public repo. `.github/workflows/spine.yml` runs daily on
ephemeral GitHub-hosted runners: `posture stream` (MITRE detect) →
`posture backfill` (cvelistV5 back-catalog; self-disables when done) →
`posture ingest ghsa` / `osv` / `kev` (the aggregator peers) →
`posture refresh --no-devices` (NVD catalog enrichment, **zero verdicts**) →
DB-only course-correction → `posture spine export` (sharded JSONL +
`manifest.json`) → `cosign sign-blob` keyless via GitHub OIDC
(`spine/state.sig` + `spine/state.crt`) → commit+push `spine/`. The cvelistV5 +
advisory-database blobless clones + `posture.db` persist across runs in the
Actions cache. Signing is non-negotiable — without it a shallow clone just
trusts whatever GitHub serves, the single-org dependency posture was built to
escape. (`docs/sources.md` has the rate/size limits this is designed against;
the self-hosted / `posture-digest` private split is deferred until a hosted
runner can't carry the load.)

**`--no-devices` is the contract:** CI runs `posture refresh --no-devices` —
catalog enrichment only, no fleet, no verdicts, no vendor trackers. No device
data ever leaves your machine; the committed `spine/` is data-only.

**Credentialed lane:** a second, dormant job pushes gated-vendor output
(SAP/Snyk/Tenable/Qualys/Cisco/VMware — to be wired as you obtain credentials)
to a *separate private* repo `posture-spine-cred`, never into this repo's
history — so the eventual public flip can't leak non-redistributable content.

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

## Honesty rules (inherited from Forebode's "the map is not the territory")

- An axis with no witness is `UNKNOWN` and loud — **never** silent/clean.
- No-wipe: an incomplete fetch never replaces stored verdicts.
- NVD attribution is emitted in any NVD-sourced output.
- NVD fetch uses `curl` with a **header-only** `apiKey` (never the query string).

## Quick start

```bash
cd ~/Desktop/posture
pip install -e .
posture demo              # offline: full 6-axis posture from the bundled fixture
posture axes              # list the six axes
posture policy show       # the active versioned trust policy
posture witnesses         # registered witnesses + which axes
posture health            # source-health (operational + dossier + drift)
posture health --add-dossier nvd --date 2026-08-01 --axis vulnerability \
  --claim "NVD backlog growing" --citation https://nvd.nist.gov --direction funding
posture distrust nvd --reason "audit test"   # retroactive distrust
posture audit nvd
posture crosswalk add CVE-2026-31589 GHSA-xxxx ghsa
posture crosswalk show CVE-2026-31589
posture discover          # horizon scan: candidate sources for review
posture spine show        # flaw-type registry + crosswalk edge counts (the alias graph)
```

Move the catalog (the spine) to/from sharded JSONL — the signed-directory
interface (see *CI spine* below):

```bash
posture spine export --db ~/.local/share/posture/posture.db --out .   # -> spine/*.jsonl + manifest.json
posture spine import --db ./rt.db --from .                            # <- load a signed spine locally
```

A real CVE-spine pull (network + `NVD_API_KEY`):

```bash
posture assess host --live --db ~/.local/share/posture/posture.db
```

## Tests

```bash
python -m pytest
```