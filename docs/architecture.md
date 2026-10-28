# Architecture

posture is a local security posture assessment engine. It combines a signed
public catalog of defect data (the map) with evidence you supply for a device
(the territory) to produce provenance-stamped verdicts across six security
dimensions. Missing evidence is a loud `UNKNOWN`, never a silent "clean."

This document is the version-controlled architecture source of truth. It
defines the system boundary, the engine/shell split, the two communication
interfaces, and the invariants that hold across them.

## System boundary

posture is **device-agnostic**. It does not scan your machine. You represent a
device as a YAML file and point posture at evidence you gather (an SBOM, a
configuration snapshot, a socket capture, signatures). posture assesses that
description locally against a signed catalog of public defect data.

The public catalog (CVEs, advisories, KEV entries) is the **map** — drawn by
outside authorities (NIST, MITRE, CISA, vendors). Your device is the
**territory**. posture keeps them separate and never pretends the map is the
territory: a clean result means "the map places nothing here," not "this device
is invulnerable."

## Engine and shell

posture is the **engine** and **defect spine**. It owns:

- The defect catalog (SQLite store of all known defects across all defect
  types — CVE, GHSA, OSV, vendor advisories — joined by an alias graph).
- The assessment engine (six-axis fan-out, per-axis aggregation, loud
  degradation, provenance-stamped commit).
- The ingestion pipeline (MITRE stream, NVD enrichment, OSV/GHSA/KEV/Apple
  ingestion, LLM draft enrichment — all catalog-only, never touching verdicts).
- The signed spine export/import (JSONL shards + cosign-signed manifest).
- The versioned trust policy (observer authority order, bias, weight).
- The glossary (axes, defect types, roles — vocabulary held as data).

A **shell** (today, Forebode/weatherman) is the user-facing product layer. It
imports posture as a library for assessment and clones the signed spine for
catalog data. The shell presents results to the user but must not duplicate
CVE intelligence — all defect matching, enrichment, and verdict logic lives in
the engine, not the shell.

### No duplicate intelligence

The shell must not carry its own CVE matching, NVD enrichment, or defect
catalog. If the shell needs defect data, it pulls the signed spine and imports
it via `posture.spine.import_spine`. If the shell needs to assess a device, it
calls `posture.engine.assess` with its own registry and policy. The shell's
role is presentation and device-specific workflow, not intelligence.

This rule exists because posture was built to kill dual-system drift: two
engines running in parallel inevitably diverge, and the divergence is
invisible until it produces a wrong verdict. One engine, one catalog, one
source of truth.

## Two communication channels

The engine and shell communicate through two channels, and only these two:

### Channel 1: Library import

The shell imports posture as a Python library. This is the assessment channel.

```python
from posture.engine import assess
from posture.sources import build_default_registry
from posture.policy import Policy

registry = build_default_registry()
policy = Policy.from_file("posture/policy/policy.yaml")
result = assess(device, registry, policy, conn=db_connection)
```

The library API surface:

| Module | Function | Purpose |
|---|---|---|
| `posture.engine` | `assess(device, registry, policy, conn, now)` | Assess one device across all axes |
| `posture.engine` | `DevicePosture` | Result dataclass (axes, verdicts, overall) |
| `posture.observer` | `Observer` (abstract) | Uniform contract every source implements |
| `posture.observer` | `ObserverRegistry` | Registry mapping axes to observers via policy |
| `posture.observer` | `FetchResult`, `Verdict`, `Provenance` | Data structures flowing through the engine |
| `posture.policy` | `Policy` | Versioned trust policy (observer order, bias, weight) |
| `posture.store` | `connect(path)` | Open the SQLite catalog + verdict store |
| `posture.spine` | `register_alias`, `resolve`, `reverse_resolve` | Alias graph API |
| `posture.stream` | `stream_tick(conn, ...)` | One MITRE cvelistV5 stream tick |
| `posture.refresh` | `refresh_tick(conn, devices, ...)` | Incremental NVD enrichment + re-decide |
| `posture.export` | `export_spine(conn, out_dir, ...)` | Serialize catalog to signed JSONL shards |
| `posture.export` | `verify_spine(from_dir)` | Verify shard hashes against manifest |
| `posture.export` | `verify_manifest_freshness(manifest, max_age_days)` | Fail when a served map is older than the host allows |
| `posture.export` | `import_spine(conn, from_dir)` | Import verified JSONL into local SQLite |
| `posture.export` | `publish_spine(conn, out_dir, ...)` | Export, verify, and swap the served map in one atomic step |

The engine never imports a source by name. Sources register themselves in the
default registry; the policy decides which run and in what order. Adding a
source is one module + one policy entry, not an engine change.

### Channel 2: Signed git bus

The spine is exported as sharded JSONL plus a self-auditing manifest, which CI
cosign-signs. A client (the shell, or any consumer) clones the signed
repository, verifies the signature, and imports the JSONL into its own local
SQLite database.

Export is **streaming** by design: rows walk from SQLite to each shard through
a server-side cursor with incremental sha256, so peak memory stays at one row
plus per-part bookkeeping no matter how large the catalog grows. (The catalog
outgrew a self-hosted runner's memory cap when the export assembled the whole
catalog in RAM; the streaming export is what keeps the daily build viable on a
small host.) The manifest pins every shard by sha256 + count, so importers and
verifiers are unaffected by how the bytes were produced.

```
CI ingestion pipeline          Client (shell or standalone)
─────────────────────          ───────────────────────────
stream → backfill →            git clone / git pull
ghsa → osv → kev →             ↓
apple → refresh                cosign verify-blob
↓                              (state.sig over manifest.json)
export_spine()                 ↓
↓                              import_spine(conn, from_dir)
cosign sign-blob               (recompute sha256, assert match)
↓                              ↓
commit spine/                   posture assess <device.yaml>
```

Every shard the export writes is **size-capped**: a defect month that outgrows
the cap becomes numbered parts (`2026-07-000001.jsonl`, ...), and the flat
overlay tables are capped the same way (`crosswalk-000001.jsonl`, ...). The cap
sits well below the repository host's hard per-file limit (a push containing a
file above it is rejected outright), and the export fails closed if a written
shard ever reaches that limit — an un-publishable map is never published. The
committed tree is checked by `scripts/check_spine_size.sh` (a gate of
`scripts/verify-all`).

On a host that serves the spine directory directly to clients (the single-VPS
deployment line), publication is **atomic and verified**: `publish_spine()`
exports into a staging directory, verifies the staged map against its own
manifest (every shard's sha256 + row count), and only then moves it into the
served directory with a single rename. A failed export or a failed verification
leaves the previously published map serving untouched, so the served map is
always either the last verified snapshot or the new one — never a mixture.

The catalog that backs that map only grows, and the serving host's disk does
not, so the deployment line is **bounded in growth** as well. A disk-space
guard refuses to start a build that would fill the disk; a bounded-growth
purge (`posture purge`) forgets ancient defects that are no longer relevant,
never a known-exploited defect, never a defect that is still highly
exploitable, and never one with an outstanding fix on a tracked distribution;
a weekly git maintenance pass reclaims the pack-file bloat the advisory and
CVE clones accumulate. The purge runs before the publish, so the published map
is the purged map and the export never carries rows that are about to be
forgotten.

The daily job (`scripts/vps_spine.sh`) is a shell script that calls this
package's command-line interface, so the two can drift apart. The
**deployment-line command gate** (`scripts/check_deployment_line.sh`) makes
that drift loud: every `posture ...` invocation in the daily script must
resolve against the interface this repository ships, and the check runs as a
gate of `scripts/verify-all`. A missing capability is a loud UNKNOWN, never a
silently degraded spine.

The same gate covers the systemd units and the **deployment runbook**
(`docs/deployment.md`), the operator's procedure for putting this tree on
the single-VPS host and for verifying the published map there. The runbook is
kept honest by the same mechanism: a unit it does not install, a tree path it
points at that does not exist, a command this repository does not provide, an
environment variable nothing reads, and an environment variable a shipped unit
sets but the runbook does not document are all loud at check time, so the
runbook cannot quietly stop describing the tree it installs.

The runbook also declares a **host contract**: the install root, the state
and export directories, the two environment files and the service account
the units are written against. The gate checks the units against that
contract (a unit whose `WorkingDirectory`, account, state directory,
catalog paths or environment file no longer match it is drift, and the
contract is what maps a unit's absolute script path back into this tree),
and checks the contract against the runbook's install layout table, so the
two never disagree about where the tree lives on the host.

Atomic publication hides one failure mode: when the daily build stops, the
previously published map keeps serving, intact and consistent with its own
manifest, so every check on the map's contents still passes. The map's build
timestamp (`generated_at`) is the only thing that shows the build stopped, so
`posture spine verify --max-age-days N` reads it and fails when the map is
older than the host allows. The runbook's host contract declares that age
(`map_max_age_days`), and the gate checks that the runbook's verification
uses exactly the number the contract declares.

The contract also governs the runbook's own operator commands. Every path
a runbook command names must be governed by the contract or be a standard
system path; the account the runbook creates must be the contract's
service account, with the contract's state directory as its home; an
owner or group a command names must be that account or root; a directory
the daily job writes into must be owned by the service account; and every
unit the tree ships must be installed by a command into the unit directory
its kind belongs in (a system unit in `/etc/systemd/system`, a user unit
in `~/.config/systemd/user`). One block therefore describes the whole
host the operator builds: where the tree lives, who runs it, and what the
operator's commands create.

The spine is **data-only**. It serializes these MAP tables:

| Table | Content |
|---|---|
| `defects` | All known defects (CVEs, advisories) with CVSS, severity, ranges |
| `crosswalk` | Alias equivalence edges (defect_id ↔ defect_id) |
| `candidates` | Discovered-but-not-adopted defect identifier schemes |
| `distrust_marks` | Retroactive distrust marks on sources or defects |
| `seen_defects` | Provenance log of which defects have been observed |
| `kev` | CISA Known Exploited Vulnerabilities overlay |
| `apple_fixes` | Apple advisory fix-version overlay |
| `debian_fixes` | Debian security tracker fix overlay |
| `ubuntu_fixes` | Ubuntu security tracker fix overlay |
| `epss` | FIRST.org exploitability-likelihood overlay |

It NEVER serializes `verdicts`, `device_posture`, `health_*`, `glossary`,
`repair_proposals`, or `policy_versions` — those are territory (device-specific)
or engine-internal. No device data ever leaves the engine via the spine.

The manifest carries a per-file `sha256` + `count` for every shard, so
tamper-evidence lives in the signature over the manifest, not in git history.
This frees history to be garbage-collected or squashed without losing trust: a
client verifies `state.sig` against `manifest.json`, and `manifest.json` pins
every shard. `import_spine` recomputes every shard's sha256 and asserts it
matches the manifest before loading anything.

## The assessment pipeline

`posture.engine.assess(device, registry, policy, conn)` runs five steps:

1. **Fan-out** — gather policy-authorized observers per axis, in policy order.
2. **Observe** — call `assess()` on each observer; time it; stamp provenance;
   record health.
3. **Per-axis aggregate** — a higher-authority observer (lower policy order)
   overrides a lower one on the same key.
4. **Loud degradation** — an axis with no observer, no verdicts, or an
   incomplete fetch gets `UNKNOWN`, never "clean." Incomplete fetches preserve
   stored verdicts (no-wipe).
5. **Commit** — per-axis posture + verdicts through the completeness gate.

The result is a `DevicePosture` with per-axis `AxisPosture` objects, each
carrying a status, the deciding observer, verdicts, gap reason, and commit
state.

## The six axes

posture reasons about six security dimensions (axes). They are vocabulary held
as data in the glossary, not hardcoded — a new dimension can be promoted
without an engine change, though the set is currently closed at six.

| Axis | What it asks | Example statuses |
|---|---|---|
| `vulnerability` | What is broken? (CVEs + advisories) | unpatched / patched / not_affected |
| `configuration` | What is misconfigured? | fail / pass |
| `exposure` | What is network-reachable? | exposed / closed |
| `inventory` | What is installed? (the SBOM) | present / absent |
| `threat` | What is being exploited in the wild? | targeted / clear |
| `trust` | Can you trust what is installed? (signatures) | untrusted / trusted |

All default to `unknown` when no evidence is supplied.

## Observers

Each axis is fed by observers — sources or local checks that implement one
uniform contract (`posture.observer.Observer`). The engine is source-agnostic:
it never imports a source by name.

| Observer | Axis | Input | Network? |
|---|---|---|---|
| `nvd` | vulnerability | device CPE matcher; CVE/CVSS data | yes (`--live`) |
| `ubuntu_tracker` | vulnerability | Ubuntu release + packages + CVE candidates | yes |
| `debian_tracker` | vulnerability | Debian release + packages + CVE candidates | yes |
| `apple_advisory` | vulnerability | Apple product + OS version + CVE candidates | yes |
| `cyclonedx_sbom` | inventory | supplied CycloneDX SBOM | no |
| `cis_checker` | configuration | supplied config snapshot | no |
| `local_exposure` | exposure | supplied socket capture | no |
| `kev` | threat | supplied CVE candidates vs CISA KEV | no |
| `sigverify` | trust | supplied artifacts + keys | no |

Observers run in a pure fan-out — they cannot see each other's verdicts. Each
vendor observer takes its candidate CVEs as a device input (from a prior NVD
pass or OS package list), not from the NVD observer's output.

## Architecture invariants

These invariants hold across both communication channels and must not be
violated by any change:

**Map is not territory.** A spine row is a point on the foreign-authored
NVD/MITRE/vendor map, not a fact about a machine. A verdict says "the catalog
places this defect on this device's map," never "this device has this defect"
as an absolute.

**UNKNOWN is never clean.** A dimension with no observer is loud. A clean
result only means "the map places nothing here," not "invulnerable." Unmapped
territory (unreported bugs, software with no CPE, firmware NVD never scored)
has no coordinates and is reported as `UNKNOWN`.

**No-wipe.** Incomplete fetches never delete stored verdicts. A failed or
partial pull only adds catalog rows and alias edges; it cannot replace a
device's stored state. The run-#10 fleet wipe (an empty broad-CPE pull deleting
~14000 rows) is the canonical failure mode this prevents.

**Provenance on every verdict.** Each verdict records which observer produced
it and when. Because that is stored, trust can be unwound retroactively:
`posture distrust <observer>` marks verdicts (not deletes them), so the history
of what you once believed is preserved and auditable.

**LLM-as-map, human-as-trust.** The LLM enrichment path drafts catalog fields
only (CVSS, severity, descriptions) behind an off-by-default `POSTURE_LLM`
seam. Drafts carry `source='llm:<model>'` and are structurally barred from the
assessment decide path (which selects `source='nvd'` only). The LLM never
produces a trust or DEFCON verdict. Real-source enrichment overwrites drafts.

**Policy as data.** Which observers run, in what order, with what bias and
weight, is read from a versioned YAML file (`posture/policy/policy.yaml`). It
is a configuration edit, not a code change, to re-order authority.

## Multi-repo topology (target, not day-1 mandate)

The incremental topology:

1. **posture** — engine library + CLI, all core work (this repository).
2. **posture-spine** — public signed data repository (JSONL shards + manifest +
   signature; produced by CI, cloned by clients).
3. **posture-digest** — thin CI repository (workflow YAML + secrets +
   self-hosted runner configuration; calls posture as a library; pushes signed
   commits to posture-spine). Thin on purpose: all logic lives in posture.
4. **forebode** — professional CLI product (imports posture for assessment +
   pulls/verifies the signed spine + presents to the user).
5. **posture-archive** (optional) — full advisory history, separate to keep
   posture-spine small.

Today, posture and the spine live in one repository (the interim
single-repo topology). The split into separate repositories happens when size,
scope, or operational concerns demand it. The two communication channels
(library import + signed git bus) are stable across the split.

## Ingestion and publication

The map is built and published by the **daily job on the serving host** (a
systemd timer → `scripts/vps_spine.sh`): stream → backfill → ingest
(GHSA/NVD-CPE/OSV/KEV/Apple/Ubuntu/Debian/EPSS) → refresh (no devices) →
course-correction → bounded-growth purge → export → sign → publish atomically.
Clients pull the published map from the host.

`--no-devices` is the contract: the daily job runs catalog enrichment only — no
fleet, no verdicts, no device data. The published map is data-only.

The repository's own workflow is a test run (the canonical verification path).
The catalog is a build artifact of the host, not source, so it is not committed:
tracking it put a gigabyte of generated data in every clone.

A credentialed lane for gated commercial sources is scaffolded in CI but
dormant — no credentialed observers are wired and no credentialed-only records
exist yet.

## State, recovery, and durability

- The local catalog lives in SQLite at `~/.local/share/posture/posture.db`.
- The signed spine lives in `spine/` (JSONL shards + manifest + signature),
  committed to the repository by CI.
- A local MITRE stream timer (`systemd/posture-stream.timer`) fires at a
  10–17 minute cadence for forward-only CVE detection.
- A local reconciliation timer (`systemd/posture-reconcile.timer`) fires at a
  20–24 hour cadence for vocabulary monitoring and repair reconciliation.
- State is preserved across restarts: the stream cursor, backfill cursor, and
  all catalog state are in the SQLite database. A reboot resumes from the last
  committed cursor — no catch-up, no data loss.
- The spine import is idempotent: `import_spine` uses `INSERT OR REPLACE`, so
  re-importing the same spine is a no-op. A failed or interrupted import leaves
  the local database unchanged (the verification step runs before any writes).

## Verification

The canonical verification path:

```bash
python -m pip install -e .
python -m pip install pytest
python -m pytest
```

Tests are hermetic (no network, no real providers). The LLM enrichment path
uses a stubbed draft function. The full suite runs offline.
