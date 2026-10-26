# Deploying posture on the single-VPS spine host

This is the operator's runbook for the deployment line: the single small host
that builds the signed public map (the spine) once a day and serves it to
clients that pull and verify it.

The tree ships four things that the host runs:

| Shipped artifact | What it does on the host |
| --- | --- |
| `scripts/vps_spine.sh` | the daily data-plane job: stream, backfill, peer overlays, distro-tracker overlays, catalog refresh, monitor and repair sweep, bounded-growth purge, and one atomic verified publish |
| `systemd/posture-spine.service` and `systemd/posture-spine.timer` | the daily build, scheduled at 03:07 UTC |
| `systemd/posture-stream.service` and `systemd/posture-stream.timer` | the incremental CVE stream tick, 10 to 17 minutes apart |
| `systemd/posture-reconcile.service` and `systemd/posture-reconcile.timer` | the self-course-correction sweep (vocabulary monitor and repair reconcile), 20 to 24 hours apart |

Everything else in this runbook is a consequence of what those artifacts do.
`docs/architecture.md` explains how the spine is built and published;
`docs/sources.md` explains where the defect data comes from.

This runbook is itself checked. `scripts/check_deployment_line.sh` has a
runbook dimension that makes the drift between this document and the shipped
tree loud at check time rather than at 03:07 UTC; `scripts/verify-all` runs
it.

## Prerequisites

- A host with systemd, Python 3.11 or newer, and about 8 GB of free disk for
  the catalog and the published map.
- Outbound network access to the upstream sources the daily job pulls: the
  MITRE CVE list, the GitHub Advisory Database, OSV, the CISA Known Exploited
  Vulnerabilities catalog, the Ubuntu and Debian security trackers, and the
  Apple advisories.
- An NVD request credential in `NVD_API_KEY`, if you want the higher NVD
  request allowance. It is never written into this tree; the daily job and
  the units read it from the environment.
- Root access for the system units, and a normal login for the two user
  units.

## Install layout

The units are written against one layout. Keep it exactly as written, or the
units will point at paths that do not exist.

| Path | Holds |
| --- | --- |
| `/opt/posture` | this repository's tree, including `scripts/vps_spine.sh` and the units |
| `/opt/posture/.venv` | the Python environment the units put first on `PATH` |
| `/var/lib/posture` | the catalog database, the source clones, and the published map |
| `/var/lib/posture/posture.db` | the persistent catalog database |
| `/var/lib/posture/spine` | the published map a client pulls: the manifest, the signature, and the shards |
| `/var/lib/posture/spine/manifest.json` | the published map's manifest: shard digests and row counts |
| `/var/lib/posture/spine/defects` | the published defect shards, one file per published month |
| `/etc/posture/posture.env` | the environment overrides for the system units |
| `/etc/posture/signing_key.pem` | the manifest signing key (the ed25519 private key), when the manifest is signed (readable by the posture group) |
| `/etc/posture/signing_pub.pem` | the manifest signature verification key (the ed25519 public key) the operator's verification and every client use to check `state.sig` |
| `~/.config/posture/env` | the environment overrides for the two user units |

### The host contract

The layout above is prose, and prose drifts silently. This block is the same
layout in machine-readable form, and the deployment-line gate checks the
units against it: a unit whose `WorkingDirectory`, service account, state
directory, catalog paths or environment file no longer match this block is
reported as drift at check time, instead of pointing at a path that does not
exist at 03:07 UTC. The paths here must stay in step with the install layout
table above; the gate checks that too. The contract governs the commands
in this runbook as well: the directories they create, the account they
create, the ownership they set, and the directory each unit is installed
into. The gate checks those against the contract, so a change to the
contract that is not carried into the commands is reported here rather
than on the host.

```yaml
install_root: /opt/posture
state_dir: /var/lib/posture
export_dir: /var/lib/posture
served_map_dir: /var/lib/posture/spine
system_env_file: /etc/posture/posture.env
user_env_file: ~/.config/posture/env
service_account: posture
disk_warn_gb: 5
disk_crit_gb: 2
sign_key: /etc/posture/signing_key.pem
sign_pub_key: /etc/posture/signing_pub.pem
served_dir_owner: posture
map_max_age_days: 2
publish_cadence_days: 1
required_overlays: ubuntu_fixes,debian_fixes
overlay_ubuntu_releases: resolute,noble,jammy,focal
overlay_ubuntu_packages: linux,linux-nvidia
overlay_debian_releases: trixie,bookworm
overlay_debian_packages: linux
overlay_ubuntu_min_rows: 1
overlay_debian_min_rows: 1
overlay_max_age_days: 2
overlay_ubuntu_min_package_rows: 1
overlay_debian_min_package_rows: 1
kev_min_rows: 1000
kev_max_age_days: 3
apple_fixes_min_rows: 1
apple_fixes_max_age_days: 7
apple_fixes_products: iphone_os,ipados,macos
apple_fixes_min_product_rows: 1
apple_fixes_product_max_age_days: 7
epss_min_rows: 100000
epss_max_age_days: 3
epss_score_bands: 0.9,0.95,0.99
epss_min_score_band_rows: 100
```

The last two keys are the free-space thresholds the daily job applies to the
state filesystem: below `disk_warn_gb` the job warns that the growth guard is
the only thing keeping the host alive, and below `disk_crit_gb` it refuses to
start a build. The deployment-line gate checks the job's own defaults against
these two values, so a threshold that changes in one place and not the other
is reported at check time rather than discovered on a host that is already
out of disk. The operator can still override them per host with
`POSTURE_DISK_WARN_GB` and `POSTURE_DISK_CRIT_GB` in the environment file.

When free space falls below the critical threshold, the job first runs an
emergency purge with a one-year retention instead of the configured one, and
it stops the build if that still leaves the host short of space. The
emergency purge applies the same exploitability protection floor as the
daily purge (`POSTURE_KEEP_EPSS_PERCENTILE`), so it never forgets a defect
the host's policy protects. A failed emergency purge is loud: the job marks
the run degraded and exits non-zero, so the operator sees in the journal that
the disk was not reclaimed, while the map is still published.

`served_map_dir` is the directory the published map actually lands in: the
daily job publishes into `export_dir`, and the publish step writes the map
into a `spine` directory inside it, so this is the directory a web server
serves and a client pulls. The deployment-line gate checks this key against
the publish implementation itself, so a contract that names a served
directory the code does not write to is drift at check time rather than an
empty directory on the host. The gate also checks that this runbook's
install layout names the manifest and the shard directory inside it, so
the verification steps below look at the paths that really exist.

`sign_key` is the path the operator points `POSTURE_SIGN_KEY` at when the
manifest is signed. The manifest may be left unsigned (the daily job
simply omits `--sign-key` when `POSTURE_SIGN_KEY` is unset), but the
contract still names the canonical location so a host that does sign
keeps the key inside the layout this runbook builds, not at an arbitrary
path. The deployment-line gate checks that a runbook command references
this path, so a contract that moves the key while the runbook still
builds the old location is loud at check time. `served_dir_owner` is the
account that owns the served directory (`export_dir`) the daily job
publishes the map into; the gate checks that the runbook command that
creates that directory sets its owner to this value, so a contract that
changes the owner while the runbook still creates the directory as the
old account describes a host the daily job cannot publish into.

`map_max_age_days` is how old the published map is allowed to be before
the operator is told that the daily build has stopped. The publish is
atomic, so a build that has been failing for days leaves the previously
published map serving, intact and internally consistent: every check on
the map's contents still passes, and the only thing that shows the build
has stopped is the map's own build timestamp. The contract declares the
age the operator's verification step enforces, and the deployment-line
gate checks that the runbook's verification uses exactly this number.

`publish_cadence_days` is how often the host expects the publish timer to
run a build, and it must be strictly less than `map_max_age_days`. The
spine timer fires daily, so a build that succeeds keeps the served map
within the two-day freshness allowance with a day of margin for a missed
run; a timer that fired weekly against a two-day allowance would be a host
that can never satisfy its own freshness rule, because a single missed run
leaves the served map past its allowed age even when the next build
succeeds. The deployment-line gate checks that the contract's
`publish_cadence_days` is strictly less than `map_max_age_days`, and that
the timer that schedules the publish actually fires at least as often as
the contract declares, so a timer whose schedule is less frequent than the
contract promises is reported at check time rather than discovered when the
served map is already stale.

`required_overlays` is the list of overlay tables the published map must
carry: the vendor fix-status overlays this host serves. The Ubuntu and
Debian tracker overlays are what clear NVD's unknown-fix false positives
on a fully-updated host, so a map without them reports patched packages
as unpatched. The publish is atomic, so a build that produced a map
without those rows leaves the previously published map serving: intact,
consistent with its own manifest, correctly signed and fresh. Every check
on that map still passes, and the only thing that shows the rows are gone
is the map's own row counts. The contract therefore declares which
overlays the host requires, the verification step below requires them,
the nightly job checks them after every publish, and the deployment-line
gate checks that the runbook and the job still require exactly the
overlays the contract declares.

`overlay_ubuntu_releases`, `overlay_ubuntu_packages`, `overlay_debian_releases` and
`overlay_debian_packages` are the ingest scope the nightly job must keep for each distro-tracker overlay the host requires. The Ubuntu and Debian tracker overlays are ingested per release and per source package (`posture ingest ubuntu --release <codename> --package <source>`), and the ingest is best-effort: a transient tracker outage must not block the daily spine build, and the catalog is not wiped between runs, so the rows for a release the job stops ingesting are retained from the last run that did. That retention is what makes a narrowed scope silent: drop a `--release` from the nightly job and the served map still carries that release's fix-status rows, the overlay coverage check above still passes, and the only thing that changes is that those rows stop being refreshed and quietly go stale — a patched kernel on the dropped release is then reported as unpatched, exactly the false positive the overlay exists to clear. The contract therefore declares the releases and the packages the job must ingest for each required distro-tracker overlay, and the deployment-line gate checks the nightly job's `posture ingest ubuntu` and `posture ingest debian` invocations against it: a `--release` or `--package` the contract declares but the job no longer carries is reported as drift at check time, and a value the job carries that the contract does not declare is reported too, so the contract and the job never disagree about which releases and packages the host refreshes. The operator owns the public-spine editorial choice of which releases and packages that is; the contract makes the choice loud and binding rather than free to shrink silently.

`overlay_ubuntu_min_rows` and `overlay_debian_min_rows` are the row floors the served map must meet for every release of that overlay's declared scope, and `overlay_max_age_days` is how old those rows may be. The two checks above are per-table: they say that the `ubuntu_fixes` table holds rows, not that it holds the rows of every release the host requires. The per-(release, package) refresh deletes the rows it is about to replace, so a release whose tracker feed returned nothing ends up with no rows at all while the table as a whole still holds the other releases' rows — the presence check still passes, the map is still intact, signed and fresh, and the missing release reports patched packages as unpatched, which is exactly the false positive the overlay exists to clear. The published map therefore states, per release, how many rows it carries and when the most recent of them was fetched, and the verification step below requires every declared release to meet the floor and to be fresher than the allowance. The shipped floor of one row is the conservative "this release is present and populated" expectation; raise it to the row count actually observed on the host once it is known. The freshness allowance catches the other silent direction: a release the nightly job stops ingesting keeps its last-known-good rows, so only the age of those rows shows that they stopped being refreshed. The deployment-line gate checks that the contract declares a floor and an allowance for every required distro-tracker overlay, and that the runbook and the nightly job require exactly the releases and the floor the contract declares.

`overlay_ubuntu_min_package_rows` and `overlay_debian_min_package_rows` are the row floors the served map must meet for every source package of every release of that overlay's declared scope. The per-release floor above is a per-release question, and a per-release answer hides a per-package failure: the nightly job ingests each distro-tracker overlay per release and per source package, and the per-(release, package) refresh deletes the rows it is about to replace, so a source package whose tracker feed returned nothing ends up with no rows at all while the release as a whole still holds the other packages' rows and the per-release floor still passes — the missing package's fix-status rows are gone, and a patched package of that source on that release is reported as unpatched, which is exactly the false positive the overlay exists to clear. The published map already states, per release, which source packages contributed rows and how many, so the verification step below requires every (release, package) pair the contract's ingest scope declares to meet the per-package floor. The shipped floor of one row is the conservative "this package of this release is present and populated" expectation; raise it to the count observed on the host once it is known. The deployment-line gate checks that the contract declares a per-package floor for every required distro-tracker overlay, and that the runbook and the nightly job require exactly the (release, package) pairs and the floor the contract declares.

`kev_min_rows` and `kev_max_age_days` are the row floor and the freshness
allowance for the known-exploited set the served map must carry. CISA's
Known Exploited Vulnerabilities catalog is the map's statement about what
is being exploited in the wild, and it is what the threat axis reads, so a
map without it is not merely a less-informed map: it is a map whose
threat axis is blind. The KEV ingest is a no-wipe full refresh of a static
file, so a fetch that fails leaves the last-known-good rows in place: the
served map stays intact, signed, fresh and consistent with its own
manifest, every other check on it still passes, and the only thing that
shows the known-exploited set stopped being refreshed is the age of its
rows. The published map therefore states how many known-exploited entries
it carries and when the newest of them was fetched, and the verification
step below requires that count to meet the floor and that newest row to be
within the allowance. The shipped floor of one thousand rows is the
conservative "the known-exploited set is present and populated"
expectation for a catalog of this size; raise it to the count observed on
the host once it is known. The allowance of three days is the daily
refresh plus a margin for a missed run. The deployment-line gate checks
that the contract declares both values, and that the runbook and the
nightly job require exactly the floor and the allowance the contract
declares.

`apple_fixes_min_rows` and `apple_fixes_max_age_days` are the row floor and the freshness allowance for the Apple fix overlay the served map must carry. Apple's own security advisories are authoritative for iOS, iPadOS and macOS fix versions (NVD's Apple coverage is thin: it records the CPE but often no version range), so the `apple_fixes` overlay is what clears NVD's unknown-fix false positives on a fully-updated Apple host. The ingest is a per-product full refresh (DELETE WHERE product + INSERT) that is no-wipe on the caller side, so a fetch that fails leaves the last-known-good rows in place: the served map stays intact, signed, fresh and consistent with its own manifest, every other check on it still passes, and only the age of the `apple_fixes` rows shows the overlay stopped being refreshed. The published map therefore states how many Apple fix entries it carries and when the newest of them was fetched, and the verification step below requires that count to meet the floor and that newest row to be within the allowance. The shipped floor of one row is the conservative "the Apple fix overlay is present and populated" expectation; raise it to the count observed on the host once it is known. The allowance of seven days covers Apple's advisory cadence plus a margin for a missed run. The deployment-line gate checks that the contract declares both values, and that the runbook and the nightly job require exactly the floor and the allowance the contract declares.

`apple_fixes_products`, `apple_fixes_min_product_rows` and `apple_fixes_product_max_age_days` are the per-product expectations for the same Apple fix overlay. The table-level floor is a per-table question, and a per-table answer hides a per-product failure: the `apple_fixes` ingest is a per-product full refresh (DELETE WHERE product + INSERT), so a product whose Apple advisory feed returned nothing loses its rows entirely while the other products keep theirs, the table still holds rows, and the table-level row floor and freshness allowance both still pass. The map is then quietly narrow in a direction that matters — the missing product's fix versions are gone, so a patched device of that product is reported as unpatched, which is exactly the false positive the Apple fix overlay exists to clear. The published map therefore states, per product, how many Apple fix entries it carries and when the newest of them was fetched, and the verification step below requires every product the contract names to be present, populated and fresh. Each product is refreshed on its own, so the per-product fetch time is that product's own fetch and the per-product freshness allowance is honest. The shipped product scope (`iphone_os`, `ipados`, `macos`) is the set the nightly job ingests by default, the shipped per-product floor of one row is the conservative "this product is present and populated" expectation, and the shipped per-product allowance of seven days matches the table-level allowance. The deployment-line gate checks that the contract declares all three values, and that the runbook and the nightly job require exactly the products, the floor and the allowance the contract declares.

`epss_min_rows` and `epss_max_age_days` are the row floor and the freshness allowance for the EPSS (exploitability-probability) overlay the served map must carry. FIRST.org's EPSS model scores every published CVE daily with a probability of exploitation in the next thirty days plus a percentile, and it is complementary to the known-exploited set: KEV names the roughly seventeen hundred confirmed-exploited vulnerabilities, while EPSS scores the long tail. The EPSS ingest is a full refresh (DELETE all + INSERT) that is no-wipe on the caller side, so a fetch that fails leaves the last-known-good rows in place: the served map stays intact, signed, fresh and consistent with its own manifest, every other check on it still passes, and only the age of the `epss` rows shows the overlay stopped being refreshed. The published map therefore states how many EPSS entries it carries and when the newest of them was fetched, and the verification step below requires that count to meet the floor and that newest row to be within the allowance. The shipped floor of one hundred thousand rows is the conservative "the EPSS overlay is present and populated" expectation for a model that scores over two hundred thousand CVEs; raise it to the count observed on the host once it is known. The allowance of three days is the daily refresh plus a margin for a missed run. The deployment-line gate checks that the contract declares both values, and that the runbook and the nightly job require exactly the floor and the allowance the contract declares.

`epss_score_bands` and `epss_min_score_band_rows` are the per-percentile-band expectations for the same EPSS overlay. The table-level floor is a per-table question, and a per-table answer hides a distribution failure: the EPSS ingest scores every published CVE with a probability of exploitation and a percentile, so a map that holds 270 thousand rows passes the table-level floor while quietly losing every CVE in the top percentile bands if the model distribution shifted or a partial fetch narrowed the set. The map is then quietly blind in the direction that matters most — the high-severity CVEs, the ones an operator triages first, are gone, so the prioritization surface the EPSS overlay exists to provide is silently narrowed while every other check on the served map still passes. The published map therefore states, for each standard percentile threshold, how many CVEs it carries at or above that threshold, and the verification step below requires every band the contract names to meet the floor. The shipped band scope (`0.9`, `0.95`, `0.99`) covers the top 10 percent, the top 5 percent and the top 1 percent most likely to be exploited, and the shipped per-band floor of one hundred rows is the conservative "the band is present and populated" expectation; raise it to the count observed on the host once it is known. The deployment-line gate checks that the contract declares both values, and that the runbook and the nightly job require exactly the bands and the floor the contract declares.

The environment table below states a default for every knob the daily job
reads. Those defaults live in the job itself, as the values it falls back
to when the environment file sets nothing, and the deployment-line gate
checks the two against each other: a runbook that documents a default the
job no longer uses describes a host the operator sizes against numbers
that are not in effect, and the difference only shows up in the nightly
job's behaviour.

## Step 1 — the service account and the directories

The daily build runs as an unprivileged account, `posture`, and writes only
under `/var/lib/posture`.

```bash
sudo useradd --system --home-dir /var/lib/posture --shell /usr/sbin/nologin posture
sudo install -d -o posture -g posture /var/lib/posture
sudo install -d -o posture -g posture /var/lib/posture/cvelist
sudo install -d -o posture -g posture /var/lib/posture/ghsa
sudo install -d /opt/posture
sudo install -d -o root -g root -m 0750 /etc/posture
```

## Step 2 — install the tree and the package

The units' `WorkingDirectory` is `/opt/posture` and the daily job is invoked
as `bash /opt/posture/scripts/vps_spine.sh`, so the tree must live at
`/opt/posture`.

```bash
cd /opt/posture
git pull --ff-only
python3 -m venv /opt/posture/.venv
/opt/posture/.venv/bin/pip install --upgrade pip
/opt/posture/.venv/bin/pip install /opt/posture
sudo install -d -o posture -g posture -m 0755 /opt/posture/scripts
```

## Step 3 — install the units

The daily build is a system unit; the stream tick and the reconciliation
sweep are user units, because they read their environment from the operator's
own home directory.

```bash
sudo install -m 0644 /opt/posture/systemd/posture-spine.service /etc/systemd/system/posture-spine.service
sudo install -m 0644 /opt/posture/systemd/posture-spine.timer /etc/systemd/system/posture-spine.timer
install -m 0644 /opt/posture/systemd/posture-stream.service ~/.config/systemd/user/posture-stream.service
install -m 0644 /opt/posture/systemd/posture-stream.timer ~/.config/systemd/user/posture-stream.timer
install -m 0644 /opt/posture/systemd/posture-reconcile.service ~/.config/systemd/user/posture-reconcile.service
install -m 0644 /opt/posture/systemd/posture-reconcile.timer ~/.config/systemd/user/posture-reconcile.timer
sudo systemctl daemon-reload
systemctl --user daemon-reload
```

## Step 4 — the environment files

The units set sensible defaults inline; the environment files override them.
The system unit reads `/etc/posture/posture.env`, and the two user units read
`~/.config/posture/env`. A value set in the file wins over the unit's own
default, because the unit lists `EnvironmentFile=` after its `Environment=`
lines.

```bash
sudo install -m 0640 -o root -g posture /dev/null /etc/posture/posture.env
sudoedit /etc/posture/posture.env
install -m 0600 /dev/null ~/.config/posture/env
```

If you sign the manifest, place the private key at the contract's
`sign_key` path and point `POSTURE_SIGN_KEY` at it in the environment
file. The key is root-owned and readable by the posture group, so the
daily job (which runs as `posture`) can read it to sign without the key
ever being owned by the service account:

```bash
sudo install -m 0640 -o root -g posture /dev/null /etc/posture/signing_key.pem
sudoedit /etc/posture/signing_key.pem
```

Place the matching public key at the contract's `sign_pub_key` path. This is
the key the operator's verification step (and every client) uses to check the
served manifest's signature, so it must live inside the layout this runbook
builds, not at an arbitrary path. It is world-readable (a public key is not a
secret) and root-owned, so only the operator can replace it:

```bash
sudo install -m 0644 -o root -g root /dev/null /etc/posture/signing_pub.pem
sudoedit /etc/posture/signing_pub.pem
```

Write the private half of the keypair to `sign_key` and the public half to
`sign_pub_key`.

The variables the daily job reads:

| Variable | Meaning | Default |
| --- | --- | --- |
| `POSTURE_STATE_DIR` | the state directory (database, source clones) | `/var/lib/posture` |
| `POSTURE_EXPORT_DIR` | the served directory the map is published into | `/var/lib/posture` |
| `POSTURE_DB_PATH` | the catalog database file | `$POSTURE_STATE_DIR/posture.db` |
| `POSTURE_CVELIST_DIR` | the MITRE CVE list clone | `$POSTURE_STATE_DIR/cvelist` |
| `POSTURE_GHSA_DIR` | the GitHub Advisory Database clone | `$POSTURE_STATE_DIR/ghsa` |
| `POSTURE_BACKFILL_CAP` | the one-time historical backfill cap | `5000` |
| `POSTURE_OSV_CAP` | the cap per peer-overlay ingest | `5000` |
| `POSTURE_REFRESH_CAP` | the cap on the per-run catalog refresh | `200` |
| `POSTURE_PURGE_AGE_DAYS` | the retention the bounded-growth purge applies | `3650` |
| `POSTURE_KEEP_EPSS_PERCENTILE` | the exploitability percentile the purge keeps | `0.90` |
| `POSTURE_DISK_WARN_GB` | free-space warning threshold | `5` |
| `POSTURE_DISK_CRIT_GB` | free-space threshold that refuses to build | `2` |
| `POSTURE_GC_INTERVAL_DAYS` | days between the source-clone maintenance pass | `7` |
| `POSTURE_SIGN_KEY` | the manifest signing key; set to the contract's `sign_key` path (`/etc/posture/signing_key.pem`) when the manifest is signed; when unset the manifest is unsigned | unset |
| `NVD_API_KEY` | the NVD request credential; it travels in a request header, never in a query string | unset |

## Step 5 — enable the timers

```bash
sudo systemctl enable --now posture-spine.timer
systemctl --user enable --now posture-stream.timer
systemctl --user enable --now posture-reconcile.timer
systemctl list-timers 'posture-*'
systemctl --user list-timers 'posture-*'
```

## Step 6 — run the daily build once, by hand

Do this before you trust the timer. The job prints a warning per degraded
step and exits non-zero, so a failed first run is visible rather than
silent.

```bash
sudo systemctl start posture-spine.service
journalctl -u posture-spine.service -n 200 --no-pager
```

Every step of the daily build except the publish is best-effort: the stream,
the backfill, every peer and distro-tracker overlay, the catalog refresh, the
three maintenance passes (the vocabulary monitor scan, the repair reconcile
and the horizon scan), the bounded-growth purge and the weekly source-clone
maintenance (the `git gc` and `git remote prune` pass that reclaims the
pack-object bloat the advisory-database and cvelistV5 clones accumulate) all
report a failure as a degraded step, print a warning naming the step, and let
the build continue, because none of them writes the map, the verdicts or the
trust, and the catalog keeps its last-known-good rows when a fetch fails. The
run ends with a non-zero exit, so a degraded build is visible in the journal
and to the timer, while the publish still happens and the host serves a fresh
map. The publish step is the exception: if it fails, the build fails, and the
previously published map keeps serving, because a half-written map is one no
client can import. The source-clone maintenance stamp is only written when
the pass actually ran on a clone and did not fail, so a failed `git gc` is
retried on the next daily build instead of waiting a full
`POSTURE_GC_INTERVAL_DAYS` with the clones still bloated.

## Step 7 — verify the published map

The publish step writes the map to a staging directory, checks it against its
own manifest, and then swaps it into the served directory with one rename.
After a successful run the served directory holds the new manifest and its
shards, and the previous map is gone only because the swap succeeded.

```bash
posture health --db /var/lib/posture/posture.db
posture catalog --db /var/lib/posture/posture.db --limit 5
posture spine verify --from /var/lib/posture --max-age-days 2 --require-overlay ubuntu_fixes --require-overlay debian_fixes \
  --require-overlay-release ubuntu_fixes:resolute:1 \
  --require-overlay-release ubuntu_fixes:noble:1 \
  --require-overlay-release ubuntu_fixes:jammy:1 \
  --require-overlay-release ubuntu_fixes:focal:1 \
  --require-overlay-release debian_fixes:trixie:1 \
  --require-overlay-release debian_fixes:bookworm:1 \
  --require-overlay-package ubuntu_fixes:resolute:linux:1 \
  --require-overlay-package ubuntu_fixes:resolute:linux-nvidia:1 \
  --require-overlay-package ubuntu_fixes:noble:linux:1 \
  --require-overlay-package ubuntu_fixes:noble:linux-nvidia:1 \
  --require-overlay-package ubuntu_fixes:jammy:linux:1 \
  --require-overlay-package ubuntu_fixes:jammy:linux-nvidia:1 \
  --require-overlay-package ubuntu_fixes:focal:linux:1 \
  --require-overlay-package ubuntu_fixes:focal:linux-nvidia:1 \
  --require-overlay-package debian_fixes:trixie:linux:1 \
  --require-overlay-package debian_fixes:bookworm:linux:1 \
  --require-overlay-max-age-days 2 \
  --require-kev 1000 \
  --require-kev-max-age-days 3 \
  --require-apple-fixes 1 \
  --require-apple-fixes-max-age-days 7 \
  --require-apple-fixes-product iphone_os:1 \
  --require-apple-fixes-product ipados:1 \
  --require-apple-fixes-product macos:1 \
  --require-apple-fixes-product-max-age-days 7 \
  --require-epss 100000 \
  --require-epss-max-age-days 3 \
  --require-epss-score-band 0.9:100 \
  --require-epss-score-band 0.95:100 \
  --require-epss-score-band 0.99:100
sudo ls -l /var/lib/posture/spine/manifest.json
sudo ls -l /var/lib/posture/spine/defects
```

`posture spine verify` re-reads the served map's own manifest and recomputes
every shard's sha256 and row count. That is the same check a client performs
after it pulls the map, so the operator's confirmation of the published map
is the confirmation the client will make, and not the weaker one that only
looks at the file listing. A failure here means the served directory does
not hold the map its manifest describes: read the last run's journal before
doing anything else, and leave the served map alone. A failed build leaves
the previously published map serving, so the map that is up is still the
last good one.

`--max-age-days 2` is the contract's `map_max_age_days`: the served map's
manifest carries the timestamp of the build that produced it, and the
check fails when that timestamp is older than the number of days the
contract allows. A map that is too old is not a broken map — it is an
intact map that the daily job has stopped rebuilding, which is the
failure the atomic publish otherwise hides: the last good map keeps
serving, so every content check on it still passes while the data behind
it grows stale. When this check fails, read the last run's journal before
doing anything else; the served map is still the last good one.

`--require-overlay ubuntu_fixes --require-overlay debian_fixes` are the
contract's `required_overlays`: the vendor fix-status rows the map must
carry. The check reads the map's own row counts and fails when a required
overlay table is missing or empty. A map without those rows is not a
broken map: it is an intact, fresh, correctly signed map that is quietly
wrong about which packages are patched, because the tracker overlays that
clear NVD's unknown-fix false positives on a fully-updated host are not in
it. When this check fails, read the last run's journal: the nightly job
makes the same check after every publish and reports the same failure as
a degraded run.

`--require-overlay-release <table>:<release>:<rows>` and
`--require-overlay-max-age-days 2` are the contract's per-release
expectations: every release of the contract's overlay scope must carry at
least the stated number of rows in the served map, and those rows must have
been fetched within the stated number of days. The map's manifest states
what it carries per release, so this check reads the map's own per-release
row counts and fetch times. A failure here is a map that is quietly narrow
or quietly stale: a release whose tracker feed returned nothing has no
rows, or a release the nightly job stopped ingesting still carries the
rows of an older run. Either way the missing or stale rows are the ones
that clear NVD's unknown-fix false positives on that release. When this
check fails, read the last run's journal: the nightly job makes the same
check after every publish and reports the same failure as a degraded run.

`--require-overlay-package <table>:<release>:<package>:<rows>` are the contract's per-package expectations: every source package of every release of the contract's overlay scope must carry at least the stated number of rows in the served map. The map's manifest already states, per release, which source packages contributed rows and how many, so this check reads the map's own per-package counts. A failure here is a map that is quietly narrow in the narrowest direction: a source package whose tracker feed returned nothing has no rows while its release still looks populated and passes the per-release floor, so the missing package's fix-status rows are gone and a patched package of that source on that release is reported as unpatched. When this check fails, read the last run's journal: the nightly job makes the same check after every publish and reports the same failure as a degraded run.

`--require-kev 1000` and `--require-kev-max-age-days 3` are the contract's
expectations for the known-exploited set. The check reads the map's own
manifest, which states how many known-exploited entries the map carries
and when the newest of them was fetched. A failure here is a map whose
threat axis is blind or stale: the CISA KEV ingest is a no-wipe refresh,
so a fetch that failed leaves the last-known-good rows in place, and the
map keeps serving them as if they were current. The row floor catches a
map that carries too few known-exploited entries, and the freshness
allowance catches a set that is present but has stopped being refreshed.
When this check fails, read the last run's journal: the nightly job makes
the same check after every publish and reports the same failure as a
degraded run.

`--require-apple-fixes 1` and `--require-apple-fixes-max-age-days 7` are the contract's expectations for the Apple fix overlay. The check reads the map's own manifest, which states how many Apple fix entries the map carries and when the newest of them was fetched. A failure here is a map that is quietly wrong about which Apple packages are patched: the ingest is a per-product full refresh that is no-wipe on the caller side, so a fetch that failed leaves the last-known-good rows in place, and the map keeps serving them as if they were current. The row floor catches a map that carries too few Apple fix entries, and the freshness allowance catches an overlay that is present but has stopped being refreshed. When this check fails, read the last run's journal: the nightly job makes the same check after every publish and reports the same failure as a degraded run.

`--require-apple-fixes-product iphone_os:1`, `--require-apple-fixes-product ipados:1` and `--require-apple-fixes-product macos:1`, with `--require-apple-fixes-product-max-age-days 7`, are the contract's per-product expectations for the Apple fix overlay. The check reads the map's own manifest, which states, per product, how many Apple fix entries the map carries and when the newest of them were fetched. A failure here is a map that is quietly narrow in one product: the ingest is a per-product full refresh, so a product whose advisory feed returned nothing has had its rows deleted and never replaced, while the other products' rows keep the table-level floor passing. The per-product floor catches a product with no fix versions at all, and the per-product freshness allowance catches a product that stopped being refreshed. When this check fails, read the last run's journal: the nightly job makes the same check after every publish and reports the same failure as a degraded run.

`--require-epss 100000` and `--require-epss-max-age-days 3` are the contract's expectations for the EPSS exploitability-probability overlay. The check reads the map's own manifest, which states how many EPSS entries the map carries and when the newest of them was fetched. A failure here is a map that is quietly wrong about exploitability: the EPSS ingest is a full refresh that is no-wipe on the caller side, so a fetch that failed leaves the last-known-good rows in place, and the map keeps serving them as if they were current. The row floor catches a map that carries too few EPSS entries, and the freshness allowance catches an overlay that is present but has stopped being refreshed. When this check fails, read the last run's journal: the nightly job makes the same check after every publish and reports the same failure as a degraded run.

`--require-epss-score-band 0.9:100`, `--require-epss-score-band 0.95:100` and `--require-epss-score-band 0.99:100` are the contract's per-band expectations for the same EPSS overlay. The table-level check above asks whether the overlay holds rows; a per-table answer hides a distribution failure: the EPSS model scores every CVE with a percentile, so a map that holds 270 thousand rows passes the table-level floor while quietly losing every CVE in the top percentile bands if the model distribution shifted or a partial fetch narrowed the set. The check reads the map's own manifest, which states, for each standard percentile threshold, how many CVEs the map carries at or above that threshold. A failure here is a map that is quietly blind in the direction that matters most: the high-severity CVEs, the ones an operator triages first, are gone, so the prioritization surface the EPSS overlay exists to provide is silently narrowed. When this check fails, read the last run's journal: the nightly job makes the same check after every publish and reports the same failure as a degraded run.

A client that pulls the map verifies the manifest's shard digests before it
imports anything, so a half-written map is refused rather than believed.

If you sign the manifest, also verify the served map's signature against the
contract's `sign_pub_key` public key. `posture spine verify` re-checks the
map's internal consistency (the manifest's shard digests); adding `--verify-sig`
with `--signature-key` re-checks the manifest's ed25519 signature first, which
is the cryptographic trust check a client runs before it imports anything. A
failure here means the served manifest was tampered with after the daily job
signed it, or was signed by a different key than the one the contract builds:
read the last run's journal before doing anything else, and leave the served
map alone. The map that is up is still the last good one the daily job
published and signed.

```bash
posture spine verify --from /var/lib/posture --verify-sig --signature-key /etc/posture/signing_pub.pem --max-age-days 2 --require-overlay ubuntu_fixes --require-overlay debian_fixes \
  --require-overlay-release ubuntu_fixes:resolute:1 \
  --require-overlay-release ubuntu_fixes:noble:1 \
  --require-overlay-release ubuntu_fixes:jammy:1 \
  --require-overlay-release ubuntu_fixes:focal:1 \
  --require-overlay-release debian_fixes:trixie:1 \
  --require-overlay-release debian_fixes:bookworm:1 \
  --require-overlay-package ubuntu_fixes:resolute:linux:1 \
  --require-overlay-package ubuntu_fixes:resolute:linux-nvidia:1 \
  --require-overlay-package ubuntu_fixes:noble:linux:1 \
  --require-overlay-package ubuntu_fixes:noble:linux-nvidia:1 \
  --require-overlay-package ubuntu_fixes:jammy:linux:1 \
  --require-overlay-package ubuntu_fixes:jammy:linux-nvidia:1 \
  --require-overlay-package ubuntu_fixes:focal:linux:1 \
  --require-overlay-package ubuntu_fixes:focal:linux-nvidia:1 \
  --require-overlay-package debian_fixes:trixie:linux:1 \
  --require-overlay-package debian_fixes:bookworm:linux:1 \
  --require-overlay-max-age-days 2 \
  --require-kev 1000 \
  --require-kev-max-age-days 3 \
  --require-apple-fixes 1 \
  --require-apple-fixes-max-age-days 7 \
  --require-apple-fixes-product iphone_os:1 \
  --require-apple-fixes-product ipados:1 \
  --require-apple-fixes-product macos:1 \
  --require-apple-fixes-product-max-age-days 7 \
  --require-epss 100000 \
  --require-epss-max-age-days 3 \
  --require-epss-score-band 0.9:100 \
  --require-epss-score-band 0.95:100 \
  --require-epss-score-band 0.99:100
```

## Step 8 — check the tree before you deploy it

Run the repository's own checks on the tree you are about to put on the
host. The deployment-line gate is the one that matters most here: it proves
that every command, option, script path, environment variable and timer
schedule in the daily job and the units still matches this tree, and that
this runbook still matches the tree.

```bash
cd /opt/posture
scripts/check_deployment_line.sh
scripts/verify-all
```

## Updating the host

```bash
cd /opt/posture
git pull --ff-only
/opt/posture/.venv/bin/pip install /opt/posture
sudo systemctl daemon-reload
systemctl --user daemon-reload
```

The next scheduled run picks up the new code. Because the publish is atomic
and verified, a bad build leaves the previously published map serving.

## Removing the deployment

```bash
sudo systemctl disable --now posture-spine.timer
systemctl --user disable --now posture-stream.timer
systemctl --user disable --now posture-reconcile.timer
sudo rm -f /etc/systemd/system/posture-spine.service /etc/systemd/system/posture-spine.timer
rm -f ~/.config/systemd/user/posture-stream.service ~/.config/systemd/user/posture-stream.timer
rm -f ~/.config/systemd/user/posture-reconcile.service ~/.config/systemd/user/posture-reconcile.timer
sudo systemctl daemon-reload
systemctl --user daemon-reload
```

The published map stays where it is until you remove it, so clients keep
pulling the last good map while you are tearing the host down.

## What the runbook gate checks

`scripts/check_deployment_line.sh` treats this document as part of the
deployment line, and makes these kinds of drift loud:

1. **Unit coverage** — every unit file this tree ships must be named here.
   A unit the runbook does not install is a unit that never runs.
2. **Tree paths** — every path this document points at (`scripts/...`,
   `systemd/...`, `posture/...`, `docs/...`, `tests/...`, `spine/...`,
   `config/...`) must exist in the tree.
3. **Commands** — every `posture ...` command shown here must resolve
   against the command-line interface this repository ships, with option
   names the parser accepts.
4. **Documented environment variables** — every `POSTURE_*` or `NVD_API_KEY`
   variable this document names must be read by the posture package or by the
   daily job. A documented knob that nothing reads is drift.
5. **Unit environment coverage** — every `POSTURE_*` or `NVD_API_KEY`
   variable a shipped unit sets must be documented here, so the
   environment file an operator writes is complete.
6. **The host contract** — the block above names the paths and the service
   account the units are written against. A unit whose `WorkingDirectory`,
   `User`, `Group`, `StateDirectory`, catalog paths or `EnvironmentFile`
   no longer match it is drift. Every environment file the contract names
   must be loaded by a unit of the matching kind (a system unit loads the
   system file, a user unit loads the user file), so an environment file
   the operator creates is never dead configuration.
7. **Install layout coverage** — every path in the install layout table
   must be covered by the host contract, and every path in the host
   contract must appear in that table, so the two never disagree about
   where the tree lives on the host.
8. **Host command contract** — the commands in this runbook are bound to
   the host contract as well, not only the units. Every path a command
   names must be governed by the contract (or be a standard system
   path), the account the runbook creates must be the contract's service
   account with the contract's state directory as its home, an owner or
   group a command names must be that account or root, a directory the
   daily job writes into must be owned by the service account, every
   unit this tree ships must be installed by a command into the unit
   directory its kind belongs in — a system unit in
   `/etc/systemd/system`, a user unit in `~/.config/systemd/user` — and
   every unit the runbook installs must also be removed by a command, so
   a unit added to the tree but never torn down is reported as drift
   rather than left stale on the host after teardown. A contract that
   changes while the commands do not describes a host nobody builds.
9. **Growth-guard thresholds** — the free-space thresholds the host
   contract declares must be the ones the daily job's own defaults use, and
   the critical threshold must be below the warning threshold. A contract
   that raises the warning threshold while the job still warns at the old
   value describes a host that warns later than the operator believes it
   does.
10. **Manifest signing key and served-directory ownership** — the host
    contract declares where the manifest signing key lives, where the
    matching signature verification key lives, and who owns the served
    directory. A runbook command must reference the contract's signing
    key path and its public key path, and the command that creates the
    served directory must set its owner to the contract's served
    directory owner. A contract that moves either key or changes the
    owner while the runbook still builds the old host is drift rather
    than a host nobody builds.
11. **Published-map layout** — the host contract declares the directory the
    published map lands in, and the gate checks that directory against the
    publish implementation's own layout (the `spine` directory the publish
    step writes inside the export directory). The install layout must name
    the manifest and the defect-shard directory inside it, and must not
    name a published-map file anywhere else: a runbook that tells the
    operator to check a path the code never writes is a verification step
    that can never pass, and a map a client is told to pull from a
    directory that does not exist is a map nobody receives.
12. **Documented environment defaults** — every default the environment
    table above states must be the default the daily job actually falls
    back to. A runbook that documents a cap, a path, a retention or a
    threshold the job no longer uses tells the operator to size the host
    against numbers that are not in effect, and the drift is invisible
    until the nightly job behaves differently from the runbook.
13. **Published-map verification** — the runbook's verification of the
    published map must actually verify it: it must show a
    `posture spine verify` command whose `--from` directory is the one
    that holds the served map the host contract declares. A runbook that
    only lists the manifest file tells the operator that a file exists,
    which is a weaker confirmation than the one every client makes, and
    one that cannot see a truncated or tampered shard. The verification
    step must point at the map the host serves, not at a directory that
    happens to hold a copy. When the verification also checks the
    manifest signature (`--verify-sig`), it must carry `--signature-key`
    naming the public key path the contract declares (`sign_pub_key`), so
    a runbook that verifies the signature against a key the contract does
    not build is drift at check time.
14. **Published-map freshness** — the runbook's verification must also say
    how old the served map is allowed to be, and the age it allows must be
    the one the host contract declares (`map_max_age_days`). The publish
    is atomic, so a daily build that has been failing for days leaves the
    last good map serving, intact and consistent with its own manifest;
    only the map's build timestamp shows that the build stopped. A
    runbook that verifies the map's contents but never its age confirms a
    map that may have been frozen for a week, and a runbook that allows a
    different age than the contract declares describes a host the
    operator and the contract disagree about.
15. **Publish cadence against the freshness allowance** — the host
    contract declares how often the publish timer is expected to run
    (`publish_cadence_days`) as well as how old the served map may be
    (`map_max_age_days`). The cadence must be strictly less than the
    maximum age, because a timer that fires at the same cadence as or
    less often than the maximum map age is a host that can never keep the
    served map within its own freshness allowance: even one missed run
    pushes the map past the allowed age. The timer that schedules the
    publish must fire at least as often as the contract declares, so a
    timer whose nominal interval is greater than `publish_cadence_days`
    is a host whose publish runs less often than the operator expects.
16. **Overlay coverage of the served map** — the host contract declares
    which overlay tables the published map must carry
    (`required_overlays`), and the gate checks that every
    `posture spine verify` command the runbook shows, and the check the
    nightly job runs after its publish, requires exactly those overlays.
    The publish is atomic, so a map that lost its vendor fix-status rows
    keeps serving intact, signed and fresh, and every other check on it
    still passes: only the map's own row counts show that the rows are
    gone. A contract that names an overlay table the map cannot carry, a
    runbook that verifies the map without requiring the overlays the
    contract declares, and a nightly job that never checks them are all
    drift at check time, because the operator's question — does the map
    this host serves still say which packages are patched? — would
    otherwise have no answer.
17. **Overlay ingest scope of the nightly job** — the host contract declares the per-distro ingest scope for every distro-tracker overlay it requires (`overlay_ubuntu_releases`, `overlay_ubuntu_packages`, `overlay_debian_releases`, `overlay_debian_packages`), and the gate checks the nightly job's `posture ingest ubuntu` and `posture ingest debian` invocations against it. The ingest is best-effort and the catalog is not wiped, so a dropped `--release` leaves the last-known-good rows for that release in place: the served map still carries the overlay rows, the overlay coverage check (item 16) still passes, and the only thing that changes is that the rows for the dropped release stop being refreshed and quietly go stale. A `--release` or `--package` the contract declares but the job no longer carries is reported as drift at check time, and a value the job carries that the contract does not declare is reported too, so the contract and the nightly job never disagree about which releases and packages the host refreshes. A contract that declares scope for a distro whose overlay it does not require, or that names no releases or no packages for a required overlay, is drift too, because the gate would otherwise have nothing to bind the job's arguments to.
18. **Per-release overlay coverage of the served map** — the host contract declares a row floor for every distro-tracker overlay it requires (`overlay_ubuntu_min_rows`, `overlay_debian_min_rows`) and a freshness allowance for the overlay rows (`overlay_max_age_days`), and the gate checks that every `posture spine verify` command the runbook shows, and the check the nightly job runs after its publish, requires exactly the releases the contract's overlay scope declares, at the floor the contract declares, with the freshness allowance the contract declares. The overlay coverage check (item 16) is a per-table question, and a per-table answer hides a per-release failure: the per-(release, package) refresh deletes the rows it is about to replace, so a release whose tracker feed returned nothing ends up with no rows at all while the table as a whole still holds the other releases' rows, and the presence check still passes. The published map therefore states, per release, how many rows it carries and when the most recent of them was fetched, so the check can require the declared releases to be present, populated and fresh. A contract with no floor or no allowance for a required overlay, a runbook that requires the tables but not the releases inside them, and a nightly job that never checks the per-release coverage are all drift at check time, because the operator's question — does the map this host serves still say which packages are patched, on every release it claims to cover? — would otherwise have no answer.

19. **Per-package overlay coverage of the served map** — the host contract declares a row floor for every source package of every release of the distro-tracker overlays it requires (`overlay_ubuntu_min_package_rows`, `overlay_debian_min_package_rows`), and the gate checks that every `posture spine verify` command the runbook shows, and the check the nightly job runs after its publish, requires exactly the (release, package) pairs the contract's overlay scope declares, at the per-package floor the contract declares. The per-release coverage check (item 18) is a per-release question, and a per-release answer hides a per-package failure: the nightly job ingests each distro-tracker overlay per release and per source package, and the per-(release, package) refresh deletes the rows it is about to replace, so a source package whose tracker feed returned nothing ends up with no rows at all while the release as a whole still holds the other packages' rows and the per-release floor still passes. The published map already states, per release, which source packages contributed rows and how many, so the check can require the declared (release, package) pairs to be present and populated. A contract with no per-package floor for a required overlay, a runbook that requires the releases but not the packages inside them, and a nightly job that never checks the per-package coverage are all drift at check time, because the operator's question — does the map this host serves still carry, for every source package it claims to cover, the fix-status rows that clear NVD's unknown-fix false positives? — would otherwise have no answer.
20. **Known-exploited coverage of the served map** — the host contract declares a row floor and a freshness allowance for the known-exploited set the served map must carry (`kev_min_rows`, `kev_max_age_days`), and the gate checks that every `posture spine verify` command the runbook shows, and the check the nightly job runs after its publish, requires exactly the floor and the allowance the contract declares. The overlay coverage checks above (items 16 to 19) bind the vendor fix-status overlays; none of them binds the known-exploited set, which is what the map says about what is being exploited in the wild and what the threat axis reads. The KEV ingest is a no-wipe full refresh of a static file, so a fetch that fails leaves the last-known-good rows in place: the served map stays intact, signed, fresh and consistent with its own manifest, every other check on it still passes, and the only thing that shows the known-exploited set stopped being refreshed is the age of its rows. The published map therefore states how many known-exploited entries it carries and when the newest of them was fetched, so the check can require the set to be present and fresh. A contract with no floor or no allowance, a runbook that checks the fix-status overlays but not the known-exploited set, and a nightly job that never checks it are all drift at check time, because the operator's question — does the map this host serves still say what is being exploited right now? — would otherwise have no answer.
21. **Flat overlay coverage of the served map (Apple fix and EPSS)** — the host contract declares a row floor and a freshness allowance for the Apple fix overlay (`apple_fixes_min_rows`, `apple_fixes_max_age_days`) and for the EPSS exploitability-probability overlay (`epss_min_rows`, `epss_max_age_days`), and the gate checks that every `posture spine verify` command the runbook shows, and the check the nightly job runs after its publish, requires exactly the floor and the allowance the contract declares for each. The overlay coverage checks above (items 16 to 19) bind the distro-tracker overlays at every granularity; the known-exploited coverage check (item 20) binds the confirmed-exploited set; none of them binds the Apple fix overlay or the EPSS overlay, which are flat tables the export writes with no per-release or per-package structure. Both ingests are no-wipe on the caller side, so a failed fetch leaves the last-known-good rows in place: the served map stays intact, signed, fresh and consistent with its own manifest, every other check on it still passes, and only the age of those rows shows the overlay stopped being refreshed. The Apple fix overlay is what clears NVD's unknown-fix false positives on a fully-updated Apple host, and the EPSS overlay is the exploitability-probability signal that complements the known-exploited set. The published map therefore states how many entries each overlay carries and when the newest of them was fetched, so the check can require each overlay to be present and fresh. A contract with no floor or no allowance for either overlay, a runbook that checks the other overlays but not these, and a nightly job that never checks them are all drift at check time, because the operator's question — does the map this host serves still say which Apple packages are patched, and what is the exploitability likelihood of every CVE? — would otherwise have no answer.
22. **Per-product Apple fix coverage of the served map** — the host contract declares the Apple products the served map must carry (`apple_fixes_products`), the row floor each of them must meet (`apple_fixes_min_product_rows`) and the freshness allowance for their rows (`apple_fixes_product_max_age_days`), and the gate checks that every `posture spine verify` command the runbook shows, and the check the nightly job runs after its publish, requires exactly the products, the floor and the allowance the contract declares. The flat overlay coverage check (item 21) is a per-table question, and a per-table answer hides a per-product failure: the `apple_fixes` ingest is a per-product full refresh (DELETE WHERE product + INSERT), so a product whose Apple advisory feed returned nothing has its rows deleted and never replaced, while the other products keep theirs, the table still holds rows, and the table-level row floor and freshness allowance both still pass. The published map therefore states, per product, how many entries it carries and when the newest of them were fetched, so the check can require every declared product to be present, populated and fresh; each product is refreshed on its own, so the per-product fetch time is that product's own fetch. A contract with no product scope, no per-product floor or no per-product allowance, a runbook that requires the table but not the products inside it, and a nightly job that never checks the per-product coverage are all drift at check time, because the operator's question — does the map this host serves still say which versions fix a CVE on every Apple product it claims to cover? — would otherwise have no answer.

23. **Per-EPSS-score-band coverage of the served map** — the host contract declares the EPSS percentile thresholds the served map must carry per band (`epss_score_bands`) and the row floor each band must meet (`epss_min_score_band_rows`), and the gate checks that every `posture spine verify` command the runbook shows, and the check the nightly job runs after its publish, requires exactly the bands and the floor the contract declares. The flat overlay coverage check (item 21) is a per-table question, and a per-table answer hides a distribution failure: the EPSS ingest scores every published CVE with a probability of exploitation and a percentile, so a map that holds 270 thousand rows passes the table-level floor while quietly losing every CVE in the top percentile bands if the model distribution shifted or a partial fetch narrowed the set. The map is then quietly blind in the direction that matters most — the high-severity CVEs, the ones an operator triages first, are gone, so the prioritization surface the EPSS overlay exists to provide is silently narrowed while every other check on the served map still passes. The published map therefore states, for each standard percentile threshold, how many CVEs it carries at or above that threshold, so the check can require every declared band to be populated. A contract with no band scope or no per-band floor, a runbook that requires the table but not the bands inside it, and a nightly job that never checks the per-band coverage are all drift at check time, because the operator's question — does the map this host serves still carry the high-severity CVEs the prioritization surface depends on? — would otherwise have no answer.
