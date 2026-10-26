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
| `/var/lib/posture/manifest.json` | the published map's manifest: shard digests and row counts |
| `/etc/posture/posture.env` | the environment overrides for the system units |
| `/etc/posture/signing_key.pem` | the manifest signing key, when the manifest is signed (readable by the posture group) |
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
system_env_file: /etc/posture/posture.env
user_env_file: ~/.config/posture/env
service_account: posture
disk_warn_gb: 5
disk_crit_gb: 2
sign_key: /etc/posture/signing_key.pem
served_dir_owner: posture
```

The last two keys are the free-space thresholds the daily job applies to the
state filesystem: below `disk_warn_gb` the job warns that the growth guard is
the only thing keeping the host alive, and below `disk_crit_gb` it refuses to
start a build. The deployment-line gate checks the job's own defaults against
these two values, so a threshold that changes in one place and not the other
is reported at check time rather than discovered on a host that is already
out of disk. The operator can still override them per host with
`POSTURE_DISK_WARN_GB` and `POSTURE_DISK_CRIT_GB` in the environment file.

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

## Step 7 — verify the published map

The publish step writes the map to a staging directory, checks it against its
own manifest, and then swaps it into the served directory with one rename.
After a successful run the served directory holds the new manifest and its
shards, and the previous map is gone only because the swap succeeded.

```bash
posture health --db /var/lib/posture/posture.db
posture catalog --db /var/lib/posture/posture.db --limit 5
sudo ls -l /var/lib/posture/manifest.json
sudo ls -l /var/lib/posture/defects
```

A client that pulls the map verifies the manifest's shard digests before it
imports anything, so a half-written map is refused rather than believed.

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
deployment line, and makes five kinds of drift loud:

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
    contract declares where the manifest signing key lives and who owns
    the served directory. A runbook command must reference the contract's
    signing key path, and the command that creates the served directory
    must set its owner to the contract's served directory owner. A
    contract that moves the key or changes the owner while the runbook
    still builds the old host is drift rather than a host nobody builds.
