#!/usr/bin/env bash
# check_deployment_line — the command gate for the daily spine job.
#
# The daily spine script (scripts/vps_spine.sh) and the systemd units
# (systemd/*.service) both call this repository's command-line interface.
# When the script, a unit, and the package drift apart — a branch that
# keeps the script but not the command, or a merge that takes one side of
# each — the job calls a command that does not exist. The shell then
# reports "command not found", the script's best-effort handlers swallow
# it, and the spine silently loses a capability: a missing growth guard, a
# missing overlay, a missing publish step. posture's rule is that a missing
# capability is a loud UNKNOWN, never a silent "clean".
#
# This gate closes that window in three dimensions for shell scripts, and
# four parallel dimensions for systemd units:
#
#   Shell scripts (scripts/vps_spine.sh and any referenced script):
#
#     1. Command and subcommand shape — every `posture <command>` and
#        `posture <command> <subcommand>` in the daily script must resolve
#        against the command-line interface this repository actually ships.
#
#     2. Option names — every `--option` the daily script passes to a
#        `posture` invocation must be an option the corresponding parser
#        accepts. A renamed option (e.g. `--cap` becoming `--limit`) silently
#        drops a capability the same way a missing command did: the shell
#        passes an unknown option, argparse rejects it at run time, and the
#        best-effort handler swallows the failure. The gate makes that drift
#        loud at check time, before the job ever runs.
#
#   Systemd units (systemd/*.service and systemd/*.timer):
#
#     3a. Unit invocations — every `posture <command>` in an ExecStart or
#         ExecStartPre line must resolve against the CLI, with the same
#         command, subcommand, and option-name validation as shell scripts.
#         A unit that calls an unknown command drifts silently the same way
#         a script does.
#
#     3b. Unit script paths — when a unit's ExecStart runs `bash <script>`,
#         the script must exist in this tree (mapped from the unit's
#         WorkingDirectory or the conventional /opt/posture deployment root).
#         A unit that references a script this tree no longer ships fails
#         loudly instead of at 03:07 UTC.
#
#     3c. Unit environment contract — every `POSTURE_*` or `NVD_API_KEY`
#         variable a unit sets via `Environment=` must be read by the
#         invocation target (the referenced shell script, the posture
#         package, or both). A variable the unit sets but nothing reads is
#         a silent drift: the unit thinks it is configuring a capability
#         that was removed or renamed. Runtime variables (PYTHONUNBUFFERED,
#         PATH, etc.) are allowlisted and not checked.
#
#     3d. Timer scheduling contract — a timer unit decides WHEN the job
#         runs, and a timer that is malformed or unscheduled is a job that
#         never fires: a timer with no schedule directive, a timer whose
#         Unit= names a service this tree does not ship, a timer that sets
#         Persistent=true without an OnCalendar (systemd ignores Persistent
#         for a monotonic timer, so a missed run is never caught up), a
#         timer whose [Install] WantedBy names a target that does not
#         exist, a timer whose duration directive carries a value systemd
#         cannot parse, and a timer that carries an ExecStart (which
#         belongs to the service it schedules). The gate makes each of
#         those loud.
#
#     3e. Service scheduling coverage — every service in a directory that
#         has timers in scope must be scheduled by one of those timers. A
#         service nothing triggers is a capability that never runs.
#
#     3f. Host contract — the runbook declares, in machine-readable form,
#         the paths and the service account the units are written against
#         (the install root, the state and export directories, the two
#         environment files, the service account). Every unit must match
#         that contract: its WorkingDirectory, its User and Group, its
#         StateDirectory, the catalog paths it points at, and the
#         environment file it loads. The environment file a unit loads must
#         also be the one its kind loads (a system unit loads the system
#         file, a user unit the user file), and every environment file the
#         contract names must be loaded by a unit of that kind, so an
#         environment file the operator creates is never dead
#         configuration. The contract is also what maps a unit's absolute
#         script path back into this tree, so the deployment root lives in
#         one place instead of two.
#
#   Deployment runbook (docs/deployment.md):
#
#     4a. Unit coverage — every unit file this tree ships must be named in
#         the runbook. A unit the runbook does not install is a unit the
#         operator never puts on the host, so its capability never runs.
#
#     4b. Tree paths — every path the runbook points at (scripts/...,
#         systemd/..., posture/..., docs/..., tests/..., spine/...,
#         config/...) must exist in this tree. A runbook that names a file
#         this tree no longer ships sends the operator to a missing file.
#
#     4c. Commands — every `posture ...` command the runbook shows must
#         resolve against the command-line interface this repository ships,
#         with option names the parser accepts. A runbook that shows a
#         renamed command is a runbook that fails on the host.
#
#     4d. Documented environment variables — every POSTURE_* or NVD_API_KEY
#         variable the runbook names must be read by the posture package or
#         by the daily job. A documented knob that nothing reads is drift.
#
#     4e. Unit environment coverage — every POSTURE_* or NVD_API_KEY
#         variable a shipped unit sets must be documented in the runbook, so
#         the environment file the operator writes is complete.
#
#     4f. Install layout coverage — the runbook's host contract and its
#         install layout table must agree: every path the contract names
#         must appear in the table, and every path in the table must be
#         covered by the contract. The two describe the same host, so
#         neither may drift away from the other.
#
#     4h. Growth-guard thresholds — the daily job refuses to start a
#          build when the state filesystem has less free space than the
#          contract's critical threshold, and warns below the warning
#          threshold. The contract declares both, and the gate checks the
#          job's own defaults against them: a contract that raises a
#          threshold while the job keeps the old one describes a host that
#          warns later (or refuses to build later) than the operator
#          believes it does, and that difference is only visible on a host
#          that is already out of disk.
#
#     4g. Host command contract — the runbook's own operator commands are
#         bound to the host contract, not only the units. Every path a
#         command names must be governed by the contract (or be a
#         standard system path); the account the runbook creates must be
#         the contract's service account, with the contract's state
#         directory as its home; an owner or group a command names must
#         be the contract's account or root; a directory the daily job
#         writes into must be owned by the service account; and every
#         unit this tree ships must be installed by a command into the
#         unit directory its kind belongs in. A contract that changes
#         while the commands do not describes a host nobody builds.
#
#     4i. Manifest signing key and served-directory ownership — the host
#         contract declares where the manifest signing key lives (the path
#         the operator points POSTURE_SIGN_KEY at when the manifest is
#         signed) and who owns the served directory the daily job
#         publishes the map into. The runbook's operator commands are
#         bound to both: a command must reference the contract's signing
#         key path (so the runbook tells the operator where the key lives
#         and the contract cannot move it silently), and the command that
#         creates the served directory must set its owner to the
#         contract's served directory owner (so a contract that changes
#         the owner while the runbook still creates the directory as the
#         old account describes a host the daily job cannot publish into).
#
#     4j. Published-map layout — the publish implementation writes the map
#         into a `spine` directory inside the export directory, so the
#         manifest and the defect shards a client pulls live at
#         `<export_dir>/spine/...`. The host contract names that directory
#         (served_map_dir) and is checked against the publish
#         implementation's own layout, and the install layout must name
#         the manifest and the shard directory inside it. A runbook that
#         documents the published map anywhere else describes a path the
#         code never writes: the operator's verification step checks a
#         file that does not exist, and a client told to pull from that
#         directory gets nothing.
#
#     4l. Published-map verification — the runbook's verification of the
#         published map must actually verify it: it must show a
#         `posture spine verify` command whose `--from` directory is the
#         one that holds the served map the host contract declares. A
#         runbook that only lists the manifest file tells the operator
#         that a file exists, which is a weaker confirmation than the one
#         every client makes, and one that cannot see a truncated or
#         tampered shard. When the verification also checks the manifest
#         signature (`--verify-sig`), it must carry `--signature-key`
#         naming the public key path the contract declares (sign_pub_key),
#         so a runbook that verifies the signature against a key the
#         contract does not build is drift at check time.
#
#     4m. Published-map freshness — the publish is atomic, so a daily build
#          that has been failing for days leaves the previously published
#          map serving, intact and internally consistent. Every check on
#          the map's contents still passes; only the map's own build
#          timestamp (the manifest's `generated_at`) shows that the build
#          stopped. The runbook's verification must therefore say how old
#          the served map is allowed to be (`--max-age-days`), and the age
#          it allows must be the one the host contract declares
#          (`map_max_age_days`). A runbook that checks the map's contents
#          but never its age confirms a map that may have been frozen for a
#          week; one that allows a different age than the contract
#          describes a host the operator and the contract disagree about.
#
#     4n. Publish cadence against the freshness allowance — the contract
#         declares how often the host expects a publish to run
#         (`publish_cadence_days`) as well as how old the served map may be
#         (`map_max_age_days`). A cadence that is not strictly less than the
#         maximum age describes a host that can never satisfy its own
#         freshness rule: a timer that fires weekly against a two-day
#         allowance leaves the map past its allowed age after a single
#         missed run. The timer that schedules the publish must fire at
#         least as often as the declared cadence, so a timer whose nominal
#         interval is greater than `publish_cadence_days` is a host whose
#         publish runs less often than the contract promises. The nominal
#         interval is the base period of the timer's schedule (the
#         `OnCalendar` expression or the repeating monotonic directive);
#         `RandomizedDelaySec` jitter is ignored, because it moves the
#         exact fire time within a window without changing how often the
#         timer fires.
#
#     4p. Overlay ingest scope of the nightly job — the contract declares
#         which overlay tables the served map must carry (required_overlays)
#         and, for every distro-tracker overlay it requires (an overlay named
#         <distro>_fixes whose <distro> ingest subcommand carries
#         --release/--package scope), the contract also declares the ingest
#         scope: overlay_<distro>_releases and overlay_<distro>_packages. The
#         nightly job's `posture ingest <distro>` invocation must carry
#         exactly the --release and --package values the contract declares.
#         The ingest is best-effort and the catalog is not wiped, so a
#         dropped --release leaves the last-known-good rows for that release
#         in place: the served map still carries the overlay rows, the
#         coverage check (4o) still passes, and the only thing that changes
#         is that the rows for the dropped release stop being refreshed and
#         quietly go stale. Binding the job's arguments to the contract makes
#         a scope that shrinks in the job while the contract still describes
#         the full scope loud at check time, rather than discovered when a
#         patched kernel on a dropped release is reported as unpatched.
#
#     4k. Documented environment defaults — the runbook's environment table
#         states a default for every knob the daily job reads: the state
#         and export directories, the catalog and clone paths, the
#         backfill and overlay caps, the refresh cap, the purge retention
#         and exploitability percentile, the free-space thresholds, and the
#         maintenance interval. Those defaults live in the daily job as
#         shell parameter expansions, and the gate checks the runbook's
#         stated default against the default the job actually falls back
#         to. A runbook that documents a default the job no longer uses
#         sizes the host and writes the environment file against numbers
#         that are not in effect, and the drift is invisible until a
#         nightly job behaves differently from what the runbook says.
#
# Usage: check_deployment_line.sh [FILE ...]
#   Default: scripts/vps_spine.sh plus every systemd/*.service and
#   systemd/*.timer unit.
#   Each FILE is classified by extension: .service and .timer files are
#   parsed as systemd units; everything else is parsed as a shell script.
# Exits 0 when every invocation resolves and every contract holds, 1 otherwise.
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_root}"

FILES=("$@")
if [ "${#FILES[@]}" -eq 0 ]; then
  FILES=("scripts/vps_spine.sh")
  for u in systemd/*.service systemd/*.timer; do
    [ -f "$u" ] && FILES+=("$u")
  done
  [ -f "docs/deployment.md" ] && FILES+=("docs/deployment.md")
fi

python3 - "${FILES[@]}" <<'PY'
import argparse
import re
import sys
from pathlib import Path

from posture.cli import build_parser
from posture.export import DEFECTS_DIR, MANIFEST_NAME, OVERLAY_TABLES, SPINE_DIR

# A `posture` invocation at the start of a command line in the script.
_CALL = re.compile(r"^\s*posture\s+([^\n;&|]*)", re.MULTILINE)
# A clean long option flag: --word or --word-word (letters, digits, hyphens).
_LONG_FLAG = re.compile(r"^--[a-zA-Z][a-zA-Z0-9_-]*$")
# A clean short option flag: -X (single letter).
_SHORT_FLAG = re.compile(r"^-[a-zA-Z]$")

# --- Unit-file parsing ---
# ExecStart and ExecStartPre lines (capture the directive name and value).
_EXEC_RE = re.compile(r"^\s*(ExecStart(?:Pre)?)\s*=\s*(.*)$", re.MULTILINE)
# Environment= lines.
_ENV_RE = re.compile(r"^\s*Environment\s*=\s*(.*)$", re.MULTILINE)
# WorkingDirectory= line.
_WORKDIR_RE = re.compile(r"^\s*WorkingDirectory\s*=\s+(\S+)", re.MULTILINE)
# A KEY=VALUE pair inside an Environment= value (quoted or bare).
_ENV_PAIR_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|\'([^\']*)\'|(\S*))')
# A posture-specific variable name: POSTURE_FOO_BAR or NVD_API_KEY.
_VAR_NAME_RE = re.compile(r'\b(POSTURE_[A-Z_]+|NVD_API_KEY)\b')
# A systemd section header: [Unit], [Service], [Timer], [Install].
_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
# The standard systemd targets a unit may be enabled into. A [Install]
# WantedBy= naming anything else is drift: the timer is never enabled.
_STANDARD_TARGETS = frozenset({
    "basic.target", "default.target", "timers.target", "multi-user.target",
    "graphical.target", "sysinit.target", "shutdown.target",
    "sockets.target", "paths.target", "swap.target",
})
# The monotonic duration directives a timer may carry. Their values must be
# systemd durations; OnCalendar is excluded because it is a calendar
# expression, not a duration.
_DURATION_DIRECTIVES = (
    "OnBootSec", "OnUnitActiveSec", "OnUnitInactiveSec",
    "RandomizedDelaySec", "AccuracySec",
)
# A systemd duration: a bare number of seconds, or a sequence of
# number+unit terms such as "1h30min", "1h 30min", "20h" or "500ms".
_DURATION_RE = re.compile(
    r"^(?:\d+(?:\.\d+)?(?:us|\u00b5s|ms|s|min|h|d|w|month|year)\s*)+$"
    r"|^\d+$")
# The conventional deployment root, used only when no runbook in scope
# carries a host contract.
_DEFAULT_INSTALL_ROOT = "/opt/posture"
# Runtime/system variables that are not posture-specific and need no
# contract check. These are set for the process environment, not read by
# posture's own code.
_RUNTIME_VARS = frozenset({
    "PYTHONUNBUFFERED", "PATH", "LANG", "LC_ALL", "HOME",
    "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "USER", "GROUP",
    "TZ", "TERM",
})


def _invocations(text: str):
    """Every `posture ...` invocation in a shell script, in order.

    Returns (command_words, raw_invocation_text) tuples.

    Line continuations are joined first, and shell expansions are dropped
    from the command-word extraction: the gate checks the SHAPE of the
    invocation (which command, which subcommand), not the values the
    variables hold at run time. The raw invocation text is retained so
    option flags can be extracted and validated separately.
    """
    joined = text.replace("\\\n", " ")
    for raw in _CALL.finditer(joined):
        invocation_text = raw.group(1)
        # keep only the leading command words: stop at the first option
        command_words = []
        for token in invocation_text.split():
            token = token.strip("\"'")
            if token.startswith("-") or "${" in token or "$(" in token:
                break
            command_words.append(token)
        if command_words:
            yield command_words, invocation_text


def _option_flags(invocation_text: str) -> set[str]:
    """Extract --option flags from an invocation string.

    Shell expansions (${...}, $(...)) and variable values are skipped: a
    flag embedded in a ${VAR:+--flag ...} conditional expansion is not
    statically visible and cannot be checked at gate time. Only clean
    option tokens (--word or -X) are extracted.
    """
    flags: set[str] = set()
    for token in invocation_text.split():
        token = token.strip("\"'")
        if _LONG_FLAG.match(token) or _SHORT_FLAG.match(token):
            flags.add(token)
    return flags


def _subcommands(parser: argparse.ArgumentParser) -> set[str]:
    """The second words a command accepts, whether they are subparsers or a
    positional with a fixed set of choices."""
    words: set[str] = set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            words |= set(action.choices)
        elif action.choices and action.dest == "sub":
            words |= {str(c) for c in action.choices}
    return words


def _accepted_options(parser: argparse.ArgumentParser) -> set[str]:
    """All option strings a parser accepts (--long and -short forms)."""
    opts: set[str] = set()
    for action in parser._actions:
        opts.update(action.option_strings)
    return opts


def _resolve_parser(
    top: argparse._SubParsersAction,
    command: str,
    subcommand: str | None,
) -> argparse.ArgumentParser:
    """Return the parser whose options apply to the invocation.

    Commands that use _SubParsersAction (e.g. ingest) give each
    subcommand its own parser with its own option set. Commands that use a
    positional with choices (e.g. monitor, spine) share a single
    parser: the subcommand is just a positional argument and the options
    live on the command parser itself.
    """
    cmd_parser = top.choices[command]
    if subcommand is None:
        return cmd_parser
    for action in cmd_parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            if subcommand in action.choices:
                return action.choices[subcommand]
            # Subcommand exists as a choice but is not a subparser entry;
            # fall through to the command parser.
            break
    return cmd_parser


# ---------------------------------------------------------------------------
# Unit-file parsing
# ---------------------------------------------------------------------------

def _is_unit_file(path: str) -> bool:
    return path.endswith(".service")


def _is_timer_file(path: str) -> bool:
    return path.endswith(".timer")


def _strip_runner_prefix(value: str) -> str:
    """Strip systemd command prefixes and /usr/bin/env or /usr/bin/ runner
    prefixes from an ExecStart or ExecStartPre value.

    systemd allows a leading command-prefix character before the executable
    path: '-' (ignore exit status), '@' (separate session), ':' (privileged
    but no cgroup), '+' (full privileges), '!' (elevated privileges). These
    prefixes are not part of the command path and must be stripped before
    checking whether the invocation targets the posture CLI, otherwise a
    '-'-prefixed ExecStart (e.g. an ignore-failure maintenance command) is
    not recognized and the gate silently skips its command and option
    validation.
    """
    value = value.strip()
    # Strip any leading systemd command-prefix characters. Multiple
    # prefixes may appear in any order (e.g. '-@' or '@-').
    while value and value[0] in "-@:+!":
        value = value[1:].lstrip()
    for prefix in ("/usr/bin/env ", "/usr/bin/", "env "):
        if value.startswith(prefix):
            return value[len(prefix):].strip()
    return value


def _unit_exec_values(text: str) -> list[str]:
    """All ExecStart and ExecStartPre values from a unit file, in order."""
    return [m.group(2) for m in _EXEC_RE.finditer(text)]


def _unit_workdir(text: str) -> str | None:
    m = _WORKDIR_RE.search(text)
    return m.group(1) if m else None


def _unit_posture_calls(text: str) -> list[tuple[list[str], str]]:
    """Extract posture invocations from ExecStart/ExecStartPre values.

    Returns (command_words, invocation_text) tuples, where command_words
    are the leading non-option words and invocation_text is the full
    posture argument string (everything after posture).
    """
    calls: list[tuple[list[str], str]] = []
    for value in _unit_exec_values(text):
        stripped = _strip_runner_prefix(value)
        tokens = stripped.split()
        # The executable must be exactly `posture`: a command that merely
        # starts with the same letters (`posture-helper`) is not this
        # repository's command-line interface.
        if not tokens or tokens[0] != "posture":
            continue
        invocation_text = stripped[len("posture"):].strip()
        command_words: list[str] = []
        for token in invocation_text.split():
            token = token.strip("\"'")
            if token.startswith("-") or "${" in token or "$(" in token:
                break
            command_words.append(token)
        if command_words:
            calls.append((command_words, invocation_text))
    return calls


def _map_to_tree(
    abs_path: str,
    workdir: str | None,
    install_root: str = _DEFAULT_INSTALL_ROOT,
) -> str | None:
    """Map an absolute path from a unit to a tree-relative path.

    Tries the unit's WorkingDirectory prefix first, then the deployment
    root the runbook's host contract names. Returns the tree-relative path
    string if the mapping is found (the file may or may not exist), or None
    if no known prefix matches.
    """
    p = abs_path.strip("\"'")
    for prefix in (workdir, install_root):
        if prefix and p.startswith(prefix + "/"):
            return p[len(prefix) + 1:]
    return None


def _unit_script_refs(
    text: str,
    workdir: str | None,
    install_root: str = _DEFAULT_INSTALL_ROOT,
) -> list[tuple[str, str | None]]:
    """Extract bash-script references from ExecStart values.

    Returns (absolute_path, tree_relative_path_or_None) tuples. Only
    bash <file.sh> invocations are extracted; bash -c '...' inline
    scripts are skipped (they do not reference a file in this tree).
    """
    refs: list[tuple[str, str | None]] = []
    for value in _unit_exec_values(text):
        stripped = _strip_runner_prefix(value)
        if not stripped.startswith("bash"):
            continue
        tokens = stripped.split()
        for tok in tokens[1:]:
            tok = tok.strip("\"'")
            if tok == "-c":
                break  # inline script, not a file reference
            if tok.endswith(".sh"):
                rel = _map_to_tree(tok, workdir, install_root)
                refs.append((tok, rel))
                break
    return refs


def _unit_env_settings(text: str) -> dict[str, str]:
    """All KEY=VALUE pairs from Environment= lines in a unit file."""
    envs: dict[str, str] = {}
    for m in _ENV_RE.finditer(text):
        value = m.group(1)
        for pair in _ENV_PAIR_RE.finditer(value):
            key = pair.group(1)
            val = pair.group(2) if pair.group(2) is not None else (
                pair.group(3) if pair.group(3) is not None else (
                    pair.group(4) or ""))
            envs[key] = val
    return envs


def _package_env_vars() -> set[str]:
    """POSTURE_* and NVD_API_KEY variables read by the posture package source."""
    found: set[str] = set()
    for py in Path("posture").rglob("*.py"):
        try:
            text = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found.update(m.group(1) for m in _VAR_NAME_RE.finditer(text))
    return found


def _script_env_vars(path: str) -> set[str]:
    """POSTURE_* and NVD_API_KEY variables read by a shell script."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    return set(m.group(1) for m in _VAR_NAME_RE.finditer(text))


# ---------------------------------------------------------------------------
# Unit-file sections
# ---------------------------------------------------------------------------

def _unit_sections(text: str) -> dict:
    """Parse a unit file into sections of (key, value) directives.

    Comment and blank lines are skipped, as is any line that is neither a
    section header nor a key=value pair.
    """
    sections: dict[str, list[tuple[str, str]]] = {}
    current = None
    for line in text.splitlines():
        header = _SECTION_RE.match(line)
        if header:
            current = header.group(1).strip()
            sections.setdefault(current, [])
            continue
        if current is None:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        sections[current].append((key.strip(), value.strip()))
    return sections


def _directive_values(sections: dict, section: str, key: str) -> list[str]:
    """Every value a directive carries in a section, in file order."""
    return [v for k, v in sections.get(section, []) if k == key]


def _directive_value(sections: dict, section: str, key: str) -> str | None:
    """The last value a directive carries in a section, or None."""
    values = _directive_values(sections, section, key)
    return values[-1] if values else None


# ---------------------------------------------------------------------------
# Validation (shared by shell scripts and unit-file posture calls)
# ---------------------------------------------------------------------------

def _validate_one_invocation(
    words: list[str],
    invocation_text: str,
    path: str,
    top: argparse._SubParsersAction,
    failures: list[str],
) -> None:
    """Validate a single posture invocation's shape and option names."""
    command = words[0]
    if command not in top.choices:
        failures.append(
            f"{path}: `posture {command}` is not a command "
            f"this repository provides")
        return
    cmd_parser = top.choices[command]
    subcommand = None
    if len(words) >= 2:
        accepted_subs = _subcommands(cmd_parser)
        if words[1] not in accepted_subs:
            failures.append(
                f"{path}: `posture {' '.join(words[:2])}` is not "
                f"available (`posture {command}` accepts: "
                f"{', '.join(sorted(accepted_subs)) or 'no subcommand'})")
            return
        subcommand = words[1]

    # Validate option names against the resolved parser.
    target_parser = _resolve_parser(top, command, subcommand)
    accepted_opts = _accepted_options(target_parser)
    used_opts = _option_flags(invocation_text)
    unknown = used_opts - accepted_opts
    if unknown:
        label = (f"posture {' '.join(words[:2])}" if subcommand
                 else f"posture {command}")
        failures.append(
            f"{path}: `{label}` uses unknown option(s) "
            f"{', '.join(sorted(unknown))} (`{label}` accepts: "
            f"{', '.join(sorted(accepted_opts)) or 'no options'})")


# ---------------------------------------------------------------------------
# Timer scheduling contract (3d) and service scheduling coverage (3e)
# ---------------------------------------------------------------------------

def _shipped_service_names() -> set[str]:
    """The set of service filenames this tree ships (systemd/*.service)."""
    names: set[str] = set()
    systemd = Path("systemd")
    if systemd.is_dir():
        for entry in systemd.glob("*.service"):
            names.add(entry.name)
    return names


def _validate_timer(
    text: str,
    path: str,
    shipped_services: set[str],
    failures: list[str],
) -> None:
    """Validate a timer unit's scheduling contract (dimension 3d).

    A timer decides WHEN the job runs. A timer that is malformed or
    unscheduled is a job that never fires, so each of these is made loud:

      - no schedule directive at all (neither OnCalendar nor a monotonic
        timer directive);
      - Unit= names a service this tree does not ship;
      - Persistent=true without OnCalendar (systemd ignores Persistent for
        monotonic timers, so a missed run is never caught up);
      - [Install] WantedBy names a target that does not exist;
      - the timer carries an ExecStart (which belongs to the service it
        schedules, not the timer itself).
    """
    sections = _unit_sections(text)
    timer_dirs = sections.get("Timer", [])

    has_calendar = any(k == "OnCalendar" for k, _ in timer_dirs)
    has_monotonic = any(
        k in ("OnBootSec", "OnUnitActiveSec", "OnUnitInactiveSec")
        for k, _ in timer_dirs
    )

    # 3d-1. No schedule directive.
    if not has_calendar and not has_monotonic:
        failures.append(
            f"{path}: timer has no schedule directive (neither OnCalendar "
            f"nor a monotonic timer directive OnBootSec/OnUnitActiveSec/"
            f"OnUnitInactiveSec)")

    # 3d-2. Unit= names a service this tree does not ship.  When Unit= is
    #       omitted systemd defaults to <timer-stem>.service.
    unit_target = _directive_value(sections, "Timer", "Unit")
    if unit_target is None:
        unit_target = Path(path).name.replace(".timer", ".service")
    if unit_target not in shipped_services:
        failures.append(
            f"{path}: Unit={unit_target} names a service this tree does "
            f"not ship (shipped services: "
            f"{', '.join(sorted(shipped_services)) or 'none'})")

    # 3d-3. Persistent=true without OnCalendar.
    persistent = _directive_value(sections, "Timer", "Persistent")
    if (persistent and persistent.strip().lower() == "true"
            and not has_calendar):
        failures.append(
            f"{path}: Persistent=true is set but there is no OnCalendar "
            f"directive (systemd ignores Persistent for monotonic timers, "
            f"so a missed run is never caught up)")

    # 3d-4. [Install] WantedBy names a non-standard target.
    for target in _directive_values(sections, "Install", "WantedBy"):
        if target not in _STANDARD_TARGETS:
            failures.append(
                f"{path}: [Install] WantedBy={target} is not a standard "
                f"systemd target (the timer would never be enabled)")

    # 3d-5. Timer carries an ExecStart (belongs to the service, not the timer).
    if _unit_exec_values(text):
        failures.append(
            f"{path}: timer unit carries an ExecStart directive "
            f"(ExecStart belongs to the service the timer schedules, "
            f"not the timer itself)")

    # 3d-6. Duration directives must carry a valid systemd duration. A
    #       mistyped value (OnUnitInactiveSec=20hours) is a timer systemd
    #       refuses to load, so the job never runs.
    for directive in _DURATION_DIRECTIVES:
        for value in _directive_values(sections, "Timer", directive):
            if not _DURATION_RE.match(value):
                failures.append(
                    f"{path}: {directive}={value} is not a valid systemd "
                    f"duration (expected a value such as '20h', '10min' or "
                    f"'500ms')")


def _check_service_coverage(
    service_paths: list[str],
    timer_paths: list[str],
    failures: list[str],
) -> None:
    """3e: every service must be scheduled by at least one timer in scope.

    A service nothing triggers is a capability that never runs. When timers
    are in the checked set, every service in the checked set must be named
    by some timer's Unit= directive. When no timers are in scope the check
    does not apply.
    """
    if not service_paths or not timer_paths:
        return
    scheduled: set[str] = set()
    for tpath in timer_paths:
        try:
            ttext = open(tpath, encoding="utf-8").read()
        except OSError:
            continue
        tsections = _unit_sections(ttext)
        unit_target = _directive_value(tsections, "Timer", "Unit")
        if unit_target is None:
            unit_target = Path(tpath).name.replace(".timer", ".service")
        scheduled.add(unit_target)
    for spath in service_paths:
        sname = Path(spath).name
        if sname not in scheduled:
            failures.append(
                f"{spath}: service is not scheduled by any timer in scope "
                f"(a service nothing triggers is a capability that never "
                f"runs)")


# ---------------------------------------------------------------------------
# Deployment runbook contract (4a-4e)
# ---------------------------------------------------------------------------

# The tree directories a runbook path reference may point into. A reference
# that starts with one of these names a file in this tree, so it must exist.
_TREE_DIRS = ("scripts", "systemd", "posture", "docs", "tests", "spine",
              "config")
# A code span in a markdown document: `like this`.
_CODE_SPAN_RE = re.compile(r"`([^`\n]+)`")


def _is_runbook(path: str) -> bool:
    """A markdown document is a runbook for the gate's purposes."""
    return path.endswith(".md")


def _code_spans(text: str) -> list[str]:
    """Every inline code span in a markdown document, stripped.

    A span that contains an ellipsis is a placeholder, not a reference, and
    is skipped by the callers.
    """
    return [m.group(1).strip() for m in _CODE_SPAN_RE.finditer(text)]


def _code_blocks(text: str) -> list[str]:
    """Every fenced code block in a markdown document, as plain text.

    A runbook shows its commands in fenced blocks, so those blocks are part
    of the runbook's contract: the commands in them are the commands the
    operator copies.
    """
    blocks: list[str] = []
    in_block = False
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_block:
                blocks.append("\n".join(current))
                current = []
            in_block = not in_block
            continue
        if in_block:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def _runbook_invocations(spans: list[str]):
    """Every `posture ...` command shown in a runbook.

    Returns (command_words, invocation_text) tuples, where command_words are
    the leading non-option words after `posture` and invocation_text is the
    argument string the option names are taken from.
    """
    for span in spans:
        if "..." in span:
            continue  # a placeholder, not a command
        text = span.strip()
        if not text.startswith("posture "):
            continue
        rest = text[len("posture"):].strip()
        words: list[str] = []
        for token in rest.split():
            token = token.strip("\"'")
            if token.startswith("-") or "${" in token or "$(" in token:
                break
            words.append(token)
        if words:
            yield words, rest


def _runbook_tree_paths(spans: list[str], blocks: list[str]) -> list[str]:
    """Every tree-relative path a runbook points at.

    Inline code spans and the lines of fenced code blocks are both read: a
    runbook may name a path in prose or in a command the operator copies.
    """
    paths: list[str] = []
    candidates: list[str] = list(spans)
    for block in blocks:
        for line in block.splitlines():
            candidates.extend(line.split())
    for candidate in candidates:
        if "..." in candidate:
            continue
        token = candidate.strip().strip("\"'").rstrip(",.;:")
        if token.startswith(tuple(d + "/" for d in _TREE_DIRS)):
            paths.append(token)
    return paths


def _shipped_unit_files() -> list[Path]:
    """Every systemd unit file this tree ships."""
    systemd = Path("systemd")
    if not systemd.is_dir():
        return []
    units = sorted(systemd.glob("*.service")) + sorted(systemd.glob("*.timer"))
    return units


def _validate_runbook(
    path: str,
    text: str,
    top: argparse._SubParsersAction,
    package_vars: set[str],
    script_vars: set[str],
    failures: list[str],
) -> int:
    """Validate the runbook's deployment contract (dimensions 4a-4e).

    Returns the number of posture invocations checked in the runbook.
    """
    spans = _code_spans(text)
    blocks = _code_blocks(text)
    read_vars = set(package_vars) | set(script_vars)
    checked = 0

    # 4a. Unit coverage: every shipped unit must be named in the runbook.
    for unit in _shipped_unit_files():
        if unit.name not in text:
            failures.append(
                f"{path}: the runbook does not name {unit.name} (a unit the "
                f"runbook does not install is a unit the operator never puts "
                f"on the host)")

    # 4b. Tree paths: every path the runbook points at must exist.
    for token in _runbook_tree_paths(spans, blocks):
        if not Path(token).exists():
            failures.append(
                f"{path}: the runbook points at `{token}` which does not "
                f"exist in this tree")

    # 4c. Commands: every posture command shown must resolve. The commands
    #     a runbook shows live in inline code spans and in fenced code
    #     blocks; both are the commands the operator copies.
    for words, invocation_text in _runbook_invocations(spans):
        checked += 1
        _validate_one_invocation(words, invocation_text, path, top, failures)
    for block in blocks:
        for words, invocation_text in _invocations(block):
            checked += 1
            _validate_one_invocation(
                words, invocation_text, path, top, failures)

    # 4d. Documented environment variables: every variable the runbook
    #     names must be read by the package or the daily job.
    for var in sorted(set(_VAR_NAME_RE.findall(text))):
        if var not in read_vars:
            failures.append(
                f"{path}: the runbook documents `{var}` but nothing in the "
                f"posture package or the daily job reads it (a documented "
                f"knob that does nothing is drift)")

    # 4e. Unit environment coverage: every variable a shipped unit sets must
    #     be documented in the runbook.
    for unit in _shipped_unit_files():
        try:
            utext = unit.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for key in sorted(_unit_env_settings(utext)):
            if not _VAR_NAME_RE.fullmatch(key):
                continue
            if key not in text:
                failures.append(
                    f"{path}: the runbook does not document `{key}`, which "
                    f"{unit.name} sets (the environment file the operator "
                    f"writes would be incomplete)")

    return checked


# ---------------------------------------------------------------------------
# Host contract (3f) and install layout coverage (4f)
# ---------------------------------------------------------------------------

# The keys the runbook's host contract block must carry.
_CONTRACT_KEYS = (
    "install_root",
    "state_dir",
    "export_dir",
    "served_map_dir",
    "system_env_file",
    "user_env_file",
    "service_account",
    "disk_warn_gb",
    "disk_crit_gb",
    "sign_key",
    "sign_pub_key",
    "served_dir_owner",
    "map_max_age_days",
    "publish_cadence_days",
    "required_overlays",
    "overlay_ubuntu_releases",
    "overlay_ubuntu_packages",
    "overlay_debian_releases",
    "overlay_debian_packages",
    "overlay_ubuntu_min_rows",
    "overlay_debian_min_rows",
    "overlay_max_age_days",
    "overlay_ubuntu_min_package_rows",
    "overlay_debian_min_package_rows",
    "kev_min_rows",
    "kev_max_age_days",
    "apple_fixes_min_rows",
    "apple_fixes_max_age_days",
    "apple_fixes_products",
    "apple_fixes_min_product_rows",
    "apple_fixes_product_max_age_days",
    "epss_min_rows",
    "epss_max_age_days",
    "epss_score_bands",
    "epss_min_score_band_rows",
)
# The contract keys that name a path on the host.
_CONTRACT_PATH_KEYS = (
    "install_root",
    "state_dir",
    "export_dir",
    "served_map_dir",
    "system_env_file",
    "user_env_file",
    "sign_key",
    "sign_pub_key",
)
def _host_contract(blocks: list[str]) -> dict[str, str] | None:
    """The host contract a runbook declares, or None.

    The contract is a fenced block of `key: value` lines that starts with
    the `install_root:` key. The first block that carries that key is the
    contract; every other block is documentation.
    """
    for block in blocks:
        if not any(line.strip().startswith("install_root:")
                   for line in block.splitlines()):
            continue
        contract: dict[str, str] = {}
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()
            if not key or not value:
                continue
            contract[key] = value
        return contract
    return None


def _normalize_host_path(value: str) -> str:
    """Normalize a host path so two spellings of it can be compared.

    systemd spells the user's home as %h and the runbook spells it as ~;
    both are normalized to ~. Trailing slashes are dropped.
    """
    v = value.strip().strip('"').strip("'")
    if v.startswith("%h"):
        v = "~" + v[len("%h"):]
    if len(v) > 1:
        v = v.rstrip("/")
    return v or "/"


def _is_under(path: str, root: str) -> bool:
    """True when path is root itself or lies under it."""
    if path == root:
        return True
    return path.startswith(root.rstrip("/") + "/")


def _layout_table_paths(text: str) -> list[str]:
    """The absolute host paths the runbook's install layout table names.

    Only the first cell of a table row is read, and only when it names an
    absolute path (one that starts with / or ~). A table of environment
    variables or of shipped artifacts is not a layout table.
    """
    paths: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if not cells:
            continue
        first = cells[0].strip("`").strip()
        if first.startswith("/") or first.startswith("~"):
            paths.append(_normalize_host_path(first))
    return paths


def _contract_roots(contract: dict[str, str]) -> list[str]:
    """The contract paths that other paths may live under."""
    roots = []
    for key in ("install_root", "state_dir", "export_dir"):
        if key in contract:
            roots.append(_normalize_host_path(contract[key]))
    return roots


def _validate_unit_contract(
    path: str,
    text: str,
    contract: dict[str, str],
    failures: list[str],
) -> str | None:
    """Validate one service unit against the host contract (dimension 3f).

    Returns the normalized environment-file path the unit loads, or None.
    """
    sections = _unit_sections(text)
    install_root = _normalize_host_path(contract["install_root"])
    state_dir = _normalize_host_path(contract["state_dir"])
    export_dir = _normalize_host_path(contract["export_dir"])
    system_env = _normalize_host_path(contract["system_env_file"])
    user_env = _normalize_host_path(contract["user_env_file"])
    account = contract["service_account"].strip()

    # A system unit runs as a named account; a user unit runs as the
    # operator. The kind decides which environment file it may load.
    user = _directive_value(sections, "Service", "User")
    is_system_unit = user is not None

    workdir = _directive_value(sections, "Service", "WorkingDirectory")
    if workdir is not None:
        if _normalize_host_path(workdir) != install_root:
            failures.append(
                f"{path}: WorkingDirectory={workdir} does not match the "
                f"runbook's install root ({install_root})")

    for directive in ("User", "Group"):
        value = _directive_value(sections, "Service", directive)
        if value is None:
            continue
        if value.strip() != account:
            failures.append(
                f"{path}: {directive}={value} is not the runbook's service "
                f"account ({account})")

    state_directory = _directive_value(sections, "Service", "StateDirectory")
    if state_directory is not None:
        expected = state_dir.rsplit("/", 1)[-1]
        if state_directory.strip() != expected:
            failures.append(
                f"{path}: StateDirectory={state_directory} does not match the "
                f"runbook's state directory ({state_dir})")

    for key, value in _unit_env_settings(text).items():
        if "$" in value:
            # The value is expanded at run time; it cannot be checked
            # statically, exactly like the shell expansions elsewhere.
            continue
        if key == "POSTURE_STATE_DIR":
            if _normalize_host_path(value) != state_dir:
                failures.append(
                    f"{path}: POSTURE_STATE_DIR={value} does not match the "
                    f"runbook's state directory ({state_dir})")
            continue
        if key == "POSTURE_EXPORT_DIR":
            if _normalize_host_path(value) != export_dir:
                failures.append(
                    f"{path}: POSTURE_EXPORT_DIR={value} does not match the "
                    f"runbook's export directory ({export_dir})")
            continue
        if not key.endswith(("_DIR", "_PATH")):
            continue
        normalized = _normalize_host_path(value)
        if not (_is_under(normalized, state_dir)
                or _is_under(normalized, export_dir)):
            failures.append(
                f"{path}: {key}={value} points outside the runbook's state "
                f"and export directories ({state_dir}, {export_dir})")

    env_file = _directive_value(sections, "Service", "EnvironmentFile")
    if env_file is None:
        return None
    raw = env_file.strip()
    if raw.startswith("-"):
        # A leading dash marks the file as optional; the path is the rest.
        raw = raw[1:].strip()
    loaded = _normalize_host_path(raw)
    expected = system_env if is_system_unit else user_env
    if loaded != expected:
        kind = "system" if is_system_unit else "user"
        failures.append(
            f"{path}: EnvironmentFile={env_file} is not the {kind} "
            f"environment file the runbook declares ({expected})")
    return loaded


def _validate_host_contract(
    path: str,
    text: str,
    contract: dict[str, str] | None,
    failures: list[str],
) -> None:
    """Validate the runbook's host contract and install layout (4f)."""
    if contract is None:
        failures.append(
            f"{path}: the runbook carries no host contract block (a fenced "
            f"block of `key: value` lines that starts with `install_root:`) "
            f"for the deployment-line gate to check the units against")
        return

    missing = [key for key in _CONTRACT_KEYS if key not in contract]
    if missing:
        failures.append(
            f"{path}: the host contract is missing "
            f"{', '.join(sorted(missing))}")
    unknown = [key for key in contract if key not in _CONTRACT_KEYS]
    if unknown:
        failures.append(
            f"{path}: the host contract carries unknown key(s) "
            f"{', '.join(sorted(unknown))}")

    layout = _layout_table_paths(text)
    contract_paths = []
    for key in _CONTRACT_PATH_KEYS:
        if key not in contract:
            continue
        normalized = _normalize_host_path(contract[key])
        contract_paths.append((key, normalized))
        if normalized not in layout:
            failures.append(
                f"{path}: the host contract's {key} ({normalized}) is not in "
                f"the install layout table")

    roots = _contract_roots(contract)
    for layout_path in layout:
        if any(_is_under(layout_path, root) for root in roots):
            continue
        if any(layout_path == normalized
               for _key, normalized in contract_paths):
            continue
        failures.append(
            f"{path}: the install layout names `{layout_path}` which no host "
            f"contract path covers")


# ---------------------------------------------------------------------------
# Published-map layout (4j)
# ---------------------------------------------------------------------------

def _validate_served_map_layout(
    path: str,
    text: str,
    contract: dict[str, str] | None,
    failures: list[str],
) -> None:
    """Check the runbook's published-map layout (dimension 4j).

    The publish implementation writes the map into a spine directory
    inside the export directory, so the manifest and the defect shards a
    client pulls live at <export_dir>/spine/.... The host contract
    names that directory (served_map_dir), and the install layout must
    name the manifest and the shard directory inside it.

    A runbook that documents the published map anywhere else describes a
    path the code never writes: the operator's verification step checks a
    file that does not exist, and a client told to pull from that
    directory gets nothing. That is drift, and it is loud at check time
    rather than discovered on the host.
    """
    if contract is None:
        return
    served = contract.get("served_map_dir", "").strip()
    if not served:
        # The missing contract key is reported by the contract check.
        return
    served = _normalize_host_path(served)
    export_dir = _normalize_host_path(contract.get("export_dir", ""))
    expected = (_normalize_host_path(f"{export_dir}/{SPINE_DIR}")
                if export_dir else "")
    if expected and served != expected:
        failures.append(
            f"{path}: the host contract's served_map_dir ({served}) is not "
            f"the directory the publish implementation writes ({expected}: "
            f"the export directory plus the `{SPINE_DIR}` directory the "
            f"publish step creates)")

    layout = _layout_table_paths(text)
    manifest_path = _normalize_host_path(f"{served}/{MANIFEST_NAME}")
    defects_path = _normalize_host_path(f"{served}/{DEFECTS_DIR}")
    if manifest_path not in layout:
        failures.append(
            f"{path}: the install layout does not name the published map's "
            f"manifest ({manifest_path}); the publish implementation writes "
            f"it there, so the operator's verification step would check a "
            f"path that does not exist")
    if defects_path not in layout:
        failures.append(
            f"{path}: the install layout does not name the published map's "
            f"defect shards ({defects_path}); the publish implementation "
            f"writes them there")
    for layout_path in layout:
        if _is_under(layout_path, served):
            continue
        if layout_path.endswith(f"/{MANIFEST_NAME}"):
            failures.append(
                f"{path}: the install layout names the published map's "
                f"manifest at {layout_path}, but the publish implementation "
                f"writes it inside the served map directory ({manifest_path})")
        elif layout_path.endswith(f"/{DEFECTS_DIR}"):
            failures.append(
                f"{path}: the install layout names the published map's "
                f"defect shards at {layout_path}, but the publish "
                f"implementation writes them inside the served map "
                f"directory ({defects_path})")


# ---------------------------------------------------------------------------
# Published-map verification (4l)
# ---------------------------------------------------------------------------


def _option_value(invocation_text: str, option: str) -> str | None:
    """The value an option carries in an invocation string.

    Returns None when the option is not present at all, and an empty
    string when the option is present without a value.
    """
    tokens = invocation_text.split()
    for index, token in enumerate(tokens):
        token = token.strip("\"'")
        if token == option:
            if index + 1 < len(tokens):
                return tokens[index + 1].strip("\"'")
            return ""
        if token.startswith(option + "="):
            return token[len(option) + 1:].strip("\"'")
    return None


def _runbook_spine_verify_commands(text: str) -> list[str]:
    """Every `posture spine verify` command a runbook shows.

    Only the fenced code blocks are read: a block is a command the
    operator copies and runs, while an inline mention in the prose is a
    description of the check rather than the check itself.
    """
    commands: list[str] = []
    for block in _code_blocks(text):
        for words, invocation_text in _invocations(block):
            if words[:2] == ["spine", "verify"]:
                commands.append(invocation_text)
    return commands


def _validate_published_map_verification(
    path: str,
    text: str,
    contract: dict[str, str] | None,
    failures: list[str],
) -> None:
    """Check the runbook's verification of the published map (dimension 4l).

    The runbook's operator-facing verification step is how the operator
    confirms that the host serves the map it is supposed to serve. Listing
    the manifest file only shows that a file exists; it cannot see a
    truncated or tampered shard. The tree ships the real check
    (`posture spine verify`), and it is the same check every client runs
    after it pulls the map, so the runbook must show it, pointed at the
    directory that holds the served map the host contract declares.

    When the runbook's verification also checks the manifest's signature
    (`--verify-sig`), it must carry `--signature-key` naming the public key
    path the host contract declares (`sign_pub_key`). A runbook that
    verifies the signature against a key path the contract does not name
    describes a host whose trust anchor the contract does not build, so the
    operator's confirmation and the contract drift apart silently.
    """
    if contract is None:
        return
    served = _normalize_host_path(contract.get("served_map_dir", ""))
    if not served or served == "/":
        # The missing contract key is reported by the contract check.
        return
    sign_pub_key = _normalize_host_path(contract.get("sign_pub_key", ""))
    expected: set[str] = set()
    export_dir = _normalize_host_path(contract.get("export_dir", ""))
    if export_dir and export_dir != "/":
        expected.add(export_dir)
    expected.add(str(Path(served).parent))

    commands = _runbook_spine_verify_commands(text)
    if not commands:
        failures.append(
            f"{path}: the runbook does not verify the published map; it "
            f"must show `posture spine verify --from "
            f"{', '.join(sorted(expected))}` (listing the manifest file is "
            f"not a verification: a truncated or tampered shard still "
            f"lists)")
        return
    for invocation in commands:
        value = _option_value(invocation, "--from")
        if value is None:
            failures.append(
                f"{path}: the runbook verifies the published map with "
                f"`posture spine verify` but does not say which directory it "
                f"verifies; the command must carry `--from` naming the "
                f"directory that holds the served map")
            continue
        normalized = _normalize_host_path(value)
        if normalized not in expected:
            failures.append(
                f"{path}: the runbook verifies the published map at "
                f"{normalized}, which is not the directory that holds the "
                f"served map the host contract declares "
                f"({', '.join(sorted(expected))}); the verification must "
                f"check the map the host actually serves")
        # (4l-b) When the verification also checks the manifest signature,
        #        it must name the public key the contract declares, so a
        #        contract that moves the public key while the runbook still
        #        verifies against the old path is loud at check time.
        if "--verify-sig" in invocation:
            sig_key = _option_value(invocation, "--signature-key")
            if sig_key is None:
                failures.append(
                    f"{path}: the runbook verifies the published map's "
                    f"signature with `--verify-sig` but does not name the "
                    f"public key to verify against; the command must carry "
                    f"`--signature-key` naming the contract's sign_pub_key "
                    f"path ({sign_pub_key})")
            elif sign_pub_key and _normalize_host_path(sig_key) != sign_pub_key:
                failures.append(
                    f"{path}: the runbook verifies the published map's "
                    f"signature against {_normalize_host_path(sig_key)}, "
                    f"which is not the public key the host contract "
                    f"declares at its sign_pub_key location ({sign_pub_key}); "
                    f"the signature verification must use the key the "
                    f"contract builds, so a contract that moves the key "
                    f"while the runbook verifies against the old path is "
                    f"drift at check time")

# ---------------------------------------------------------------------------
# Published-map freshness (4m)
# ---------------------------------------------------------------------------


def _validate_published_map_freshness(
    path: str,
    text: str,
    contract: dict[str, str] | None,
    failures: list[str],
) -> None:
    """Check the runbook's freshness check on the served map (dimension 4m).

    The publish is atomic, so a daily build that has been failing for days
    leaves the previously published map serving, intact and internally
    consistent. Every check on the map's contents still passes; only the
    map's own build timestamp (the manifest's generated_at) shows that
    the build has stopped. The runbook's verification must therefore say
    how old the served map is allowed to be, and the age it allows must be
    the one the host contract declares.
    """
    if contract is None:
        return
    declared = contract.get("map_max_age_days", "").strip()
    if not declared:
        # The missing contract key is reported by the contract check.
        return
    try:
        allowed = float(declared)
    except ValueError:
        failures.append(
            f"{path}: the host contract's map_max_age_days ({declared}) is "
            f"not a number of days (the contract states how old the served "
            f"map is allowed to be)")
        return
    if allowed <= 0:
        failures.append(
            f"{path}: the host contract's map_max_age_days ({declared}) must "
            f"be a positive number of days (a map of any age would fail the "
            f"check, or the check would mean nothing)")
        return

    commands = _runbook_spine_verify_commands(text)
    if not commands:
        # The missing verification is reported by dimension 4l.
        return
    for invocation in commands:
        value = _option_value(invocation, "--max-age-days")
        if value is None:
            failures.append(
                f"{path}: the runbook verifies the published map but does not "
                f"say how old the map is allowed to be; the command must "
                f"carry `--max-age-days {allowed:g}` (the publish is atomic, "
                f"so a daily build that has been failing for days leaves the "
                f"last good map serving and every content check on it still "
                f"passes)")
            continue
        try:
            stated = float(value)
        except ValueError:
            failures.append(
                f"{path}: the runbook checks the served map's age with "
                f"`--max-age-days {value}`, which is not a number of days")
            continue
        if stated != allowed:
            failures.append(
                f"{path}: the runbook allows the served map to be "
                f"{stated:g} day(s) old, but the host contract declares "
                f"{allowed:g} day(s) (the contract states how stale a map may "
                f"be before the operator is told the daily build has stopped)")


# ---------------------------------------------------------------------------
# Publish cadence against the freshness allowance (4n)
# ---------------------------------------------------------------------------

# The systemd duration units, mapped to seconds. These match the units the
# duration regular expression above accepts, so a value that validates as a
# systemd duration can be parsed into seconds here.
_DURATION_UNIT_SECONDS = {
    "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1.0, "min": 60.0,
    "h": 3600.0, "d": 86400.0, "w": 604800.0, "month": 2629800.0,
    "year": 31557600.0,
}
_DURATION_TERM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(us|\u00b5s|ms|s|min|h|d|w|month|year)?")
# The weekday names systemd accepts in an OnCalendar expression, mapped to
# their day-of-week index (Monday=0). A weekday prefix restricts the calendar
# event to those days, so the nominal interval between fires is the largest
# gap between consecutive named days (wrapping past Sunday back to Monday).
_WEEKDAY_INDEX = {
    "mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6,
}


def _duration_to_seconds(value: str) -> float | None:
    """Parse a systemd duration string into seconds, or None if unparseable.

    A bare number is a number of seconds. A sequence of number+unit terms
    such as 1h 30min or 20h is summed. Whitespace between terms is
    allowed; the duration regular expression has already validated the
    shape when this is called from the timer path, but this parser is also
    safe to call on an arbitrary string (it returns None rather than
    raising).
    """
    value = value.strip()
    if not value:
        return None
    total = 0.0
    pos = 0
    matched_any = False
    while pos < len(value):
        while pos < len(value) and value[pos].isspace():
            pos += 1
        if pos >= len(value):
            break
        m = _DURATION_TERM_RE.match(value, pos)
        if not m or m.end() == pos:
            return None
        number = float(m.group(1))
        unit = m.group(2)
        if unit is None:
            # A bare number is seconds.
            total += number
        else:
            total += number * _DURATION_UNIT_SECONDS[unit]
        pos = m.end()
        matched_any = True
    return total if matched_any else None


def _weekday_max_gap(spec: str) -> float | None:
    """The largest day-gap a weekday prefix in an OnCalendar expression implies.

    Mon -> 7 (weekly). Mon..Fri -> 3 (Friday to Monday). Mon,Thu
    -> 4 (Thursday to Monday). Returns None when the spec is not a weekday
    prefix this parser recognises.
    """
    spec = spec.strip().lower()
    days: list[int] = []
    if ".." in spec:
        a, b = spec.split("..", 1)
        start = _WEEKDAY_INDEX.get(a.strip())
        end = _WEEKDAY_INDEX.get(b.strip())
        if start is None or end is None:
            return None
        i = start
        days.append(i)
        while i != end:
            i = (i + 1) % 7
            days.append(i)
    elif "," in spec:
        for part in spec.split(","):
            idx = _WEEKDAY_INDEX.get(part.strip())
            if idx is None:
                return None
            days.append(idx)
    else:
        idx = _WEEKDAY_INDEX.get(spec)
        if idx is None:
            return None
        days.append(idx)
    if not days:
        return None
    ordered = sorted(set(days))
    if len(ordered) == 1:
        return 7.0
    max_gap = 0.0
    for i in range(len(ordered)):
        nxt = ordered[(i + 1) % len(ordered)]
        gap = (nxt - ordered[i]) % 7
        if gap > max_gap:
            max_gap = float(gap)
    return max_gap


def _calendar_nominal_interval_days(expr: str) -> float | None:
    """The nominal interval (in days) an OnCalendar expression fires at.

    This is the base period of the calendar event, NOT the worst case
    including RandomizedDelaySec jitter: jitter moves the exact fire
    time within a window but does not change how often the timer fires,
    so the freshness relationship rides on the base period. Returns None
    when the expression's cadence cannot be determined (an expression
    this parser does not recognise is reported by the gate rather than
    silently accepted).
    """
    expr = expr.strip()
    low = expr.lower()
    if low == "hourly":
        return 1.0 / 24.0
    if low == "daily":
        return 1.0
    if low == "weekly":
        return 7.0
    if low == "monthly":
        return 30.0
    if low == "yearly":
        return 365.0
    # A calendar expression is whitespace-separated fields: an optional
    # weekday prefix, a date component, a time component, and an optional
    # timezone. The date component governs the base period when no weekday
    # prefix restricts it; a weekday prefix governs the base period instead
    # (it widens the gap between fires).
    tokens = expr.split()
    weekday_gap: float | None = None
    date_gap: float | None = None
    for token in tokens:
        stripped = token.rstrip(",")
        # A weekday field may be a list or a range; a date or time field
        # contains a digit or an asterisk.
        if all(p.lower() in _WEEKDAY_INDEX for p in
               re.split(r"[,.]", stripped) if p):
            gap = _weekday_max_gap(stripped)
            if gap is None:
                return None
            if weekday_gap is None or gap > weekday_gap:
                weekday_gap = gap
            continue
        if "*" in token and "-" in token and ":" not in token:
            # A date component like *-*-* (every day) or *-*-01
            # (a specific day of every month).
            parts = token.split("-")
            if len(parts) == 3 and parts[0] == "*" and parts[1] == "*":
                if parts[2] == "*":
                    date_gap = 1.0
                else:
                    # A specific day of every month: the largest gap is
                    # the long month length (31 days), conservatively.
                    date_gap = 31.0
            elif len(parts) == 3 and parts[1] == "*" and parts[2] == "*":
                # A specific month, every day: ~30 day gap annually.
                date_gap = 365.0
            else:
                return None
    if weekday_gap is not None:
        return weekday_gap
    if date_gap is not None:
        return date_gap
    return None


def _timer_nominal_interval_days(sections: dict) -> float | None:
    """The nominal interval (in days) a timer fires at, or None if unknown.

    A calendar timer's nominal interval is the base period of its
    OnCalendar expression. A monotonic timer's nominal interval is the
    repeating gap it declares (OnUnitInactiveSec or
    OnUnitActiveSec); OnBootSec alone is one-shot and carries no
    repeating cadence, so it returns None. RandomizedDelaySec and
    AccuracySec are jitter, not cadence, and are ignored.
    """
    calendars = _directive_values(sections, "Timer", "OnCalendar")
    if calendars:
        return _calendar_nominal_interval_days(calendars[-1])
    for directive in ("OnUnitInactiveSec", "OnUnitActiveSec"):
        values = _directive_values(sections, "Timer", directive)
        if values:
            seconds = _duration_to_seconds(values[-1])
            if seconds is not None:
                return seconds / 86400.0
    return None


def _publish_timer(
    timer_paths: list[str],
    unit_paths: list[str],
) -> tuple[str | None, str | None]:
    """The timer that schedules the service that publishes the map.

    The publish service is the service whose ExecStart runs the daily
    spine script (scripts/vps_spine.sh); the publish timer is the
    timer whose Unit= targets that service (or, when Unit= is
    omitted, defaults to the matching <timer-stem>.service). Returns
    (timer_path, timer_text) or (None, None) when no publish
    timer is in scope.
    """
    publish_services: set[str] = set()
    for spath in unit_paths:
        try:
            stext = open(spath, encoding="utf-8").read()
        except OSError:
            continue
        for value in _unit_exec_values(stext):
            if "vps_spine.sh" in value:
                publish_services.add(Path(spath).name)
                break
    if not publish_services:
        return None, None
    for tpath in timer_paths:
        try:
            ttext = open(tpath, encoding="utf-8").read()
        except OSError:
            continue
        sections = _unit_sections(ttext)
        target = _directive_value(sections, "Timer", "Unit")
        if target is None:
            target = Path(tpath).name.replace(".timer", ".service")
        if target in publish_services:
            return tpath, ttext
    return None, None


def _contract_days_value(
    contract: dict[str, str], key: str,
) -> tuple[float | None, str | None]:
    """Parse a contract key that names a number of days.

    Returns (value, error) where exactly one is set: value is the
    parsed float when the key is present and numeric, and error is a
    ready-to-report failure message when the key is missing, non-numeric,
    or not positive. A missing key is reported by the contract-key check,
    so the caller decides whether a missing key is its own failure.
    """
    raw = contract.get(key, "").strip()
    if not raw:
        return None, None
    try:
        return float(raw), None
    except ValueError:
        return None, (
            f"the host contract's {key} ({raw}) is not a number of days "
            f"(the contract states a cadence or an age in days)")


def _validate_publish_cadence_contract(
    path: str,
    text: str,
    contract: dict[str, str] | None,
    failures: list[str],
) -> None:
    """Check the contract's publish cadence against the freshness allowance.

    The publish is atomic, so a daily build that succeeds keeps the served
    map within the freshness allowance only when the timer that publishes
    fires more often than the map is allowed to age. The contract declares
    both: publish_cadence_days (how often the host expects a publish to
    run) and map_max_age_days (how old the served map may be). A
    cadence that is not strictly less than the maximum age describes a host
    that can never satisfy its own freshness rule: a timer that fires
    weekly against a two-day allowance leaves the map past its allowed age
    after a single missed run, and a timer that fires exactly at the
    allowance has no margin for a build that runs late in its window.
    """
    if contract is None:
        return
    cadence, err = _contract_days_value(contract, "publish_cadence_days")
    if err is not None:
        failures.append(f"{path}: {err}")
        return
    if cadence is None:
        # The missing contract key is reported by the contract-key check.
        return
    if cadence <= 0:
        failures.append(
            f"{path}: the host contract's publish_cadence_days "
            f"({contract.get('publish_cadence_days', '').strip()}) must "
            f"be a positive number of days (a cadence of zero or less means "
            f"the timer never publishes, so the served map can never stay "
            f"within its freshness allowance)")
        return
    age, age_err = _contract_days_value(contract, "map_max_age_days")
    if age_err is not None:
        # The malformed age is reported by dimension 4m.
        return
    if age is None or age <= 0:
        # The missing or non-positive age is reported by dimension 4m.
        return
    if cadence >= age:
        failures.append(
            f"{path}: the host contract's publish_cadence_days "
            f"({cadence:g}) must be strictly less than map_max_age_days "
            f"({age:g}) (a timer that fires at the same cadence as or less "
            f"often than the maximum map age is a host that can never keep "
            f"the served map within its own freshness allowance: the last "
            f"good map keeps serving while the data behind it grows stale, "
            f"and even one missed run pushes the map past the allowed age)")


def _validate_publish_cadence_timer(
    contract: dict[str, str] | None,
    contract_source: str | None,
    timer_paths: list[str],
    unit_paths: list[str],
    failures: list[str],
) -> None:
    """Check the publish timer's actual cadence against the declared one.

    The contract declares how often the host expects a publish to run
    (publish_cadence_days); the timer that schedules the publish must
    fire at least that often. A timer whose nominal interval is greater
    than the declared cadence is a host whose publish runs less often
    than the contract promises, so the served map can age past the
    freshness allowance even when every build succeeds.
    """
    if contract is None or not timer_paths:
        return
    cadence, err = _contract_days_value(contract, "publish_cadence_days")
    if err is not None or cadence is None or cadence <= 0:
        # Reported by the contract-level cadence check (or the contract-key
        # check); do not double-report against the timer.
        return
    timer_path, timer_text = _publish_timer(timer_paths, unit_paths)
    if timer_path is None or timer_text is None:
        # No publish timer in scope: nothing to check here. A shipped
        # publish timer that is not in scope is not this dimension's
        # concern (the service-coverage dimension governs that).
        return
    sections = _unit_sections(timer_text)
    interval = _timer_nominal_interval_days(sections)
    if interval is None:
        failures.append(
            f"{timer_path}: the publish timer's schedule cannot be turned "
            f"into a cadence this gate can compare to the host contract's "
            f"publish_cadence_days ({cadence:g}) (the OnCalendar expression "
            f"or monotonic directive does not resolve to a nominal interval "
            f"in days, so the gate cannot verify the timer fires often "
            f"enough to keep the served map within its freshness allowance)")
        return
    if interval > cadence:
        failures.append(
            f"{timer_path}: the publish timer fires every {interval:g} "
            f"day(s) but the host contract declares "
            f"publish_cadence_days {cadence:g} (a timer less frequent than "
            f"the contract declares is a host whose publish runs less often "
            f"than the operator expects, so the served map can age past the "
            f"freshness allowance {contract_source or 'the host contract'} "
            f"declares even when every build succeeds)")


# ---------------------------------------------------------------------------
# Overlay coverage of the served map (4o)
# ---------------------------------------------------------------------------


def _contract_overlays(contract: dict[str, str]) -> list[str]:
    """The overlay tables the host contract requires the map to carry.

    The contract states them as one comma-separated value; each name is
    one overlay table of the published map.
    """
    raw = contract.get("required_overlays", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _option_values(invocation_text: str, option: str) -> list[str]:
    """Every value an option carries in an invocation string.

    A repeatable option carries one value per use, so the values are
    collected in the order they appear. An option present without a value
    contributes an empty string.
    """
    values: list[str] = []
    tokens = invocation_text.split()
    for index, token in enumerate(tokens):
        token = token.strip("\"'")
        if token == option:
            if index + 1 < len(tokens):
                values.append(tokens[index + 1].strip("\"'"))
            else:
                values.append("")
        elif token.startswith(option + "="):
            values.append(token[len(option) + 1:].strip("\"'"))
    return values


def _validate_overlay_coverage_contract(
    path: str,
    contract: dict[str, str] | None,
    failures: list[str],
) -> None:
    """Check the contract's declared overlay coverage (dimension 4o).

    The contract names the overlay tables the published map must carry. A
    contract that names a table the map cannot carry describes a
    requirement that can never be met, and a requirement that names
    nothing describes a host that is happy with a map missing the rows
    that say which packages are patched.
    """
    if contract is None:
        return
    raw = contract.get("required_overlays", "").strip()
    if not raw:
        # The missing contract key is reported by the contract-key check.
        return
    for name in _contract_overlays(contract):
        if name not in OVERLAY_TABLES:
            failures.append(
                f"{path}: the host contract's required_overlays names "
                f"{name}, which is not an overlay table the published map can "
                f"carry (the overlay tables are: {', '.join(OVERLAY_TABLES)})")


def _validate_overlay_coverage_verification(
    path: str,
    text: str,
    contract: dict[str, str] | None,
    failures: list[str],
) -> None:
    """Check the runbook's overlay-coverage requirement (dimension 4o).

    The publish is atomic, so a map that lost its vendor fix-status rows
    keeps serving: intact, consistent with its own manifest, correctly
    signed and fresh. Every check on that map still passes, and only the
    map's own row counts show that the rows are gone. The runbook's
    verification must therefore require the overlays the contract
    declares, or the operator's confirmation of the served map says
    nothing about the rows that say which packages are patched.
    """
    if contract is None:
        return
    required = _contract_overlays(contract)
    if not required:
        return
    commands = _runbook_spine_verify_commands(text)
    if not commands:
        # The missing verification is reported by dimension 4l.
        return
    for invocation in commands:
        stated = _option_values(invocation, "--require-overlay")
        missing = [name for name in required if name not in stated]
        if missing:
            failures.append(
                f"{path}: the runbook verifies the served map but does not "
                f"require the overlay rows the host contract declares "
                f"({', '.join(missing)}); the command must carry "
                f"`--require-overlay <table>` for each of them (a map that "
                f"lost its vendor fix-status rows keeps serving intact, "
                f"signed and fresh, so only the overlay check shows that "
                f"the rows are gone)")


def _validate_overlay_coverage_job(
    path: str,
    script_text: str,
    contract: dict[str, str] | None,
    failures: list[str],
) -> None:
    """Check the nightly job's overlay-coverage check (dimension 4o).

    The operator checks the served map by hand; the nightly job is the
    thing that builds it. A job that publishes a map without the vendor
    fix-status rows and never looks is a quiet success every night, and
    the operator finds out only when a patched kernel is reported as
    unpatched. The job must make the same check the runbook shows, right
    after it publishes.
    """
    if contract is None or not script_text:
        return
    required = _contract_overlays(contract)
    if not required:
        return
    commands = [invocation for words, invocation in _invocations(script_text)
                if words[:2] == ["spine", "verify"]]
    if not commands:
        failures.append(
            f"{path}: the daily job never checks the served map's overlay "
            f"coverage, so a build that publishes a map without the vendor "
            f"fix-status rows the host contract declares "
            f"({', '.join(required)}) is a quiet success instead of a "
            f"degraded run")
        return
    for invocation in commands:
        stated = _option_values(invocation, "--require-overlay")
        missing = [name for name in required if name not in stated]
        if missing:
            failures.append(
                f"{path}: the daily job checks the served map but does not "
                f"require the overlay rows the host contract declares "
                f"({', '.join(missing)}); the check must carry "
                f"`--require-overlay <table>` for each of them (a build that "
                f"publishes a map without the vendor fix-status rows would "
                f"otherwise be a quiet success)")


# ---------------------------------------------------------------------------
# Overlay ingest scope of the nightly job (4p)
# ---------------------------------------------------------------------------

# The distro-tracker overlays whose ingest subcommand carries
# --release/--package scope. Each distro D here serves an overlay table
# named D_fixes, and the nightly job ingests it with `posture ingest D`.
# Other overlays (kev, apple_fixes) do not carry per-release/per-package
# scope, so the ingest-scope contract does not govern them.
_OVERLAY_INGEST_DISTROS = ("ubuntu", "debian")


def _required_overlay_distros(contract: dict[str, str]) -> list[str]:
    """The distro-tracker distros whose overlay the contract requires.

    An overlay table named <distro>_fixes is a distro-tracker overlay
    whose ingest subcommand carries --release/--package scope. The
    contract therefore declares the ingest scope for that distro, and the
    nightly job must ingest it with exactly that scope. Other overlays
    (kev, apple_fixes) are not distro-tracker overlays and do not
    carry per-release/per-package scope.
    """
    distros: list[str] = []
    for name in _contract_overlays(contract):
        if name.endswith("_fixes"):
            distro = name[: -len("_fixes")]
            if distro in _OVERLAY_INGEST_DISTROS:
                distros.append(distro)
    return distros


def _declared_overlay_scope(
        contract: dict[str, str]) -> dict[str, dict[str, list[str]]]:
    """The per-distro overlay ingest scope the contract declares.

    Returns {distro: {"releases": [...], "packages": [...]}} for every
    distro the contract carries overlay_<distro>_releases or
    overlay_<distro>_packages for. A distro is present even when only
    one of the two keys is declared, so a half-declared scope is reported
    rather than treated as undeclared.
    """
    scope: dict[str, dict[str, list[str]]] = {}
    for distro in _OVERLAY_INGEST_DISTROS:
        releases_raw = contract.get(
            f"overlay_{distro}_releases", "").strip()
        packages_raw = contract.get(
            f"overlay_{distro}_packages", "").strip()
        if not releases_raw and not packages_raw:
            continue
        scope[distro] = {
            "releases": [r.strip() for r in releases_raw.split(",")
                         if r.strip()],
            "packages": [p.strip() for p in packages_raw.split(",")
                         if p.strip()],
        }
    return scope


def _validate_overlay_ingest_scope_contract(
        path: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the contract's declared overlay ingest scope (dimension 4p).

    The contract declares which overlay tables the served map must carry
    (required_overlays); for every distro-tracker overlay it requires,
    the contract must also declare the ingest scope (the releases and the
    packages the nightly job must ingest), or the gate has nothing to bind
    the job's arguments to. A contract that declares scope for a distro
    whose overlay the host does not require describes ingest work the host
    does not serve, and a scope that names no releases or no packages
    describes an ingest that produces no overlay rows.
    """
    if contract is None:
        return
    required_distros = _required_overlay_distros(contract)
    declared = _declared_overlay_scope(contract)
    for distro in required_distros:
        releases = declared.get(distro, {}).get("releases", [])
        packages = declared.get(distro, {}).get("packages", [])
        if not releases:
            failures.append(
                f"{path}: the host contract requires the {distro}_fixes "
                f"overlay but declares no overlay_{distro}_releases, so the "
                f"gate cannot bind the nightly job's --release arguments to "
                f"the scope the host expects (a dropped --release narrows "
                f"the overlay silently while the coverage check still "
                f"passes, because the no-wipe ingest retains last-known-good "
                f"rows for the dropped release)")
        if not packages:
            failures.append(
                f"{path}: the host contract requires the {distro}_fixes "
                f"overlay but declares no overlay_{distro}_packages, so the "
                f"gate cannot bind the nightly job's --package arguments to "
                f"the scope the host expects (a dropped --package narrows "
                f"the overlay silently while the coverage check still "
                f"passes)")
    for distro in declared:
        if distro not in required_distros:
            failures.append(
                f"{path}: the host contract declares overlay_{distro}_"
                f"releases/packages but does not require the {distro}_fixes "
                f"overlay, so it describes ingest scope for an overlay the "
                f"host does not serve")


def _validate_overlay_ingest_scope_job(
        path: str,
        script_text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the nightly job's overlay ingest scope (dimension 4p).

    The nightly job ingests each distro-tracker overlay with
    posture ingest <distro> --release <r> ... --package <p> .... The
    ingest is best-effort and the catalog is not wiped, so a dropped
    --release leaves the last-known-good rows for that release in
    place: the served map still carries the overlay rows, the coverage
    check (4o) still passes, and the only thing that changed is that the
    rows for the dropped release stop being refreshed and quietly go
    stale. The job's --release and --package arguments must
    therefore be exactly the ones the contract declares, so a scope that
    shrinks in the job while the contract still describes the full scope
    is loud at check time rather than discovered when a patched kernel on
    a dropped release is reported as unpatched.
    """
    if contract is None or not script_text:
        return
    required_distros = _required_overlay_distros(contract)
    if not required_distros:
        return
    declared = _declared_overlay_scope(contract)
    for distro in required_distros:
        invocations = [invocation for words, invocation
                       in _invocations(script_text)
                       if words[:2] == ["ingest", distro]]
        if not invocations:
            failures.append(
                f"{path}: the host contract requires the {distro}_fixes "
                f"overlay but the daily job never runs `posture ingest "
                f"{distro}`, so the overlay rows are not refreshed and the "
                f"coverage check passes against rows that grow stale")
            continue
        job_releases: list[str] = []
        job_packages: list[str] = []
        for invocation in invocations:
            job_releases.extend(_option_values(invocation, "--release"))
            job_packages.extend(_option_values(invocation, "--package"))
        want_releases = declared.get(distro, {}).get("releases", [])
        want_packages = declared.get(distro, {}).get("packages", [])
        missing_releases = [r for r in want_releases
                            if r not in job_releases]
        extra_releases = [r for r in job_releases if r not in want_releases]
        missing_packages = [p for p in want_packages
                            if p not in job_packages]
        extra_packages = [p for p in job_packages if p not in want_packages]
        if missing_releases:
            failures.append(
                f"{path}: the daily job ingests {distro} without the "
                f"--release {', '.join(missing_releases)} the host contract "
                f"declares, so the {distro}_fixes overlay silently narrows "
                f"to the releases the job still ingests while the coverage "
                f"check still passes (the no-wipe ingest retains "
                f"last-known-good rows for the dropped release)")
        if extra_releases:
            failures.append(
                f"{path}: the daily job ingests {distro} with --release "
                f"{', '.join(extra_releases)} the host contract does not "
                f"declare, so the contract describes a narrower scope than "
                f"the job")
        if missing_packages:
            failures.append(
                f"{path}: the daily job ingests {distro} without the "
                f"--package {', '.join(missing_packages)} the host contract "
                f"declares, so the {distro}_fixes overlay silently narrows "
                f"to the packages the job still ingests while the coverage "
                f"check still passes")
        if extra_packages:
            failures.append(
                f"{path}: the daily job ingests {distro} with --package "
                f"{', '.join(extra_packages)} the host contract does not "
                f"declare, so the contract describes a narrower scope than "
                f"the job")


# ---------------------------------------------------------------------------
# Per-release overlay coverage of the served map (4q)
# ---------------------------------------------------------------------------

def _contract_overlay_min_rows(contract: dict[str, str]) -> dict[str, int]:
    """The per-release row floor the contract declares for each distro.

    The contract states one floor per distro-tracker overlay it requires:
    every release of that overlay's declared scope must carry at least
    this many rows in the served map. A floor is a number of rows, not a
    per-release number, because the host's own expectation is "this
    release is present and populated", and the operator can raise the
    floor to the count observed on the host once it is known.
    """
    floors: dict[str, int] = {}
    for distro in _OVERLAY_INGEST_DISTROS:
        raw = contract.get(f"overlay_{distro}_min_rows", "").strip()
        if not raw:
            continue
        try:
            value = int(raw)
        except ValueError:
            continue  # reported by the contract-level check
        floors[distro] = value
    return floors


def _contract_overlay_max_age_days(contract: dict[str, str]) -> float | None:
    """The freshness allowance the contract declares for the overlay rows."""
    raw = contract.get("overlay_max_age_days", "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None  # reported by the contract-level check


def _expected_release_requirements(
        contract: dict[str, str]) -> list[tuple[str, str, int]]:
    """The (table, release, min_rows) requirements the contract implies.

    Every release of every required distro-tracker overlay's declared
    ingest scope must carry at least the floor the contract declares for
    that overlay.
    """
    floors = _contract_overlay_min_rows(contract)
    declared = _declared_overlay_scope(contract)
    requirements: list[tuple[str, str, int]] = []
    for distro in _required_overlay_distros(contract):
        floor = floors.get(distro)
        if floor is None:
            continue
        for release in declared.get(distro, {}).get("releases", []):
            requirements.append((f"{distro}_fixes", release, floor))
    return requirements


def _stated_release_requirements(
        invocation: str) -> list[tuple[str, str, int]]:
    """The (table, release, min_rows) requirements an invocation states."""
    stated: list[tuple[str, str, int]] = []
    for value in _option_values(invocation, "--require-overlay-release"):
        parts = value.split(":")
        if len(parts) != 3:
            continue
        try:
            min_rows = int(parts[2])
        except ValueError:
            continue
        stated.append((parts[0].strip(), parts[1].strip(), min_rows))
    return stated


def _validate_overlay_release_coverage_contract(
        path: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the contract's declared per-release overlay coverage (4q).

    The contract declares the ingest scope of every distro-tracker overlay
    it requires (4p), and the served map's overlay coverage is checked
    against the contract's required overlays (4o). Neither binds the map's
    ROWS to the scope: a release whose tracker feed returned nothing ends
    up with no rows (the per-(release, package) refresh deletes the rows
    it replaces), while the table as a whole still holds the other
    releases' rows and the presence check still passes. The contract
    therefore declares a row floor per required overlay and a freshness
    allowance for the overlay rows, so the per-release coverage of the
    served map can be required rather than assumed.
    """
    if contract is None:
        return
    required_distros = _required_overlay_distros(contract)
    for distro in required_distros:
        raw = contract.get(f"overlay_{distro}_min_rows", "").strip()
        if not raw:
            failures.append(
                f"{path}: the host contract requires the {distro}_fixes "
                f"overlay but declares no overlay_{distro}_min_rows, so the "
                f"gate cannot require the served map to carry a per-release "
                f"row floor for it (a release whose tracker feed returned "
                f"nothing leaves the overlay table populated with the other "
                f"releases' rows, so the presence check still passes while "
                f"the missing release reports patched packages as unpatched)")
            continue
        try:
            value = int(raw)
        except ValueError:
            failures.append(
                f"{path}: the host contract's overlay_{distro}_min_rows is "
                f"{raw!r}, which is not a row count")
            continue
        if value < 1:
            failures.append(
                f"{path}: the host contract's overlay_{distro}_min_rows is "
                f"{value}, which is not a positive row count")
    for distro in _OVERLAY_INGEST_DISTROS:
        if distro in required_distros:
            continue
        if contract.get(f"overlay_{distro}_min_rows", "").strip():
            failures.append(
                f"{path}: the host contract declares overlay_{distro}_min_rows "
                f"but does not require the {distro}_fixes overlay, so it "
                f"describes a row floor for an overlay the host does not "
                f"serve")
    raw_age = contract.get("overlay_max_age_days", "").strip()
    if not raw_age:
        failures.append(
            f"{path}: the host contract declares no overlay_max_age_days, so "
            f"the gate cannot require the overlay rows of a required release "
            f"to be fresh (a release the nightly job stopped ingesting "
            f"keeps its last-known-good rows, so only their age shows that "
            f"they stopped being refreshed)")
    else:
        try:
            age = float(raw_age)
        except ValueError:
            failures.append(
                f"{path}: the host contract's overlay_max_age_days is "
                f"{raw_age!r}, which is not a number of days")
        else:
            if age <= 0:
                failures.append(
                    f"{path}: the host contract's overlay_max_age_days is "
                    f"{age:g}, which is not a positive number of days")


def _validate_overlay_release_coverage_verification(
        path: str,
        text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the runbook's per-release overlay coverage (dimension 4q).

    The operator's confirmation of the served map is the check the runbook
    shows. A runbook that requires the overlay tables but not the releases
    inside them confirms a map that may be quietly narrow: the missing
    release's fix-status rows are the ones that clear NVD's unknown-fix
    false positives on that release, and their absence is invisible to a
    per-table check.
    """
    if contract is None:
        return
    expected = _expected_release_requirements(contract)
    if not expected:
        return
    max_age = _contract_overlay_max_age_days(contract)
    commands = _runbook_spine_verify_commands(text)
    if not commands:
        # The missing verification is reported by dimension 4l.
        return
    for invocation in commands:
        stated = _stated_release_requirements(invocation)
        for table, release, min_rows in expected:
            matching = [s for s in stated
                        if s[0] == table and s[1] == release]
            if not matching:
                failures.append(
                    f"{path}: the runbook verifies the served map but does "
                    f"not require the {table} rows of release {release}, "
                    f"which the host contract's overlay scope declares (the "
                    f"command must carry "
                    f"`--require-overlay-release {table}:{release}:{min_rows}`; "
                    f"a release whose tracker feed returned nothing leaves "
                    f"the table populated with the other releases' rows, so "
                    f"the per-table check still passes)")
            elif min_rows not in [s[2] for s in matching]:
                failures.append(
                    f"{path}: the runbook requires {min_rows} row(s) of "
                    f"{table} release {release} where the host contract's "
                    f"overlay_{table[:-len('_fixes')]}_min_rows floor is "
                    f"{[s[2] for s in matching][0]}")
        for table, release, min_rows in stated:
            if (table, release) not in [(t, r) for t, r, _ in expected]:
                failures.append(
                    f"{path}: the runbook requires the {table} rows of "
                    f"release {release}, which the host contract's overlay "
                    f"scope does not declare, so the runbook describes a "
                    f"different scope than the contract")
        if max_age is not None:
            stated_age = _option_values(invocation,
                                        "--require-overlay-max-age-days")
            if not stated_age:
                failures.append(
                    f"{path}: the runbook verifies the served map but does "
                    f"not require the overlay rows to be fresh within the "
                    f"host contract's overlay_max_age_days "
                    f"({max_age:g} day(s)); the command must carry "
                    f"`--require-overlay-max-age-days {max_age:g}` (a "
                    f"release the nightly job stopped ingesting keeps its "
                    f"last-known-good rows, so only their age shows that "
                    f"they went stale)")


def _validate_overlay_release_coverage_job(
        path: str,
        script_text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the nightly job's per-release overlay coverage (dimension 4q).

    The nightly job is the thing that builds the map; the operator checks
    it by hand. A job that publishes a map whose overlay rows no longer
    cover every required release, and never looks, is a quiet success every
    night: the map stays intact, signed and fresh, and only the missing
    release's fix-status rows are gone. The job must make the same
    per-release check the runbook shows, right after it publishes.
    """
    if contract is None or not script_text:
        return
    expected = _expected_release_requirements(contract)
    if not expected:
        return
    max_age = _contract_overlay_max_age_days(contract)
    commands = [invocation for words, invocation in _invocations(script_text)
                if words[:2] == ["spine", "verify"]]
    if not commands:
        failures.append(
            f"{path}: the daily job never checks the served map's per-release "
            f"overlay coverage, so a build that publishes a map whose "
            f"overlay rows no longer cover every required release is a "
            f"quiet success instead of a degraded run")
        return
    for invocation in commands:
        stated = _stated_release_requirements(invocation)
        for table, release, min_rows in expected:
            matching = [s for s in stated
                        if s[0] == table and s[1] == release]
            if not matching:
                failures.append(
                    f"{path}: the daily job checks the served map but does "
                    f"not require the {table} rows of release {release}, "
                    f"which the host contract's overlay scope declares (the "
                    f"check must carry "
                    f"`--require-overlay-release {table}:{release}:{min_rows}`; "
                    f"a release whose tracker feed returned nothing leaves "
                    f"the table populated with the other releases' rows, so "
                    f"the per-table check still passes)")
            elif min_rows not in [s[2] for s in matching]:
                failures.append(
                    f"{path}: the daily job requires "
                    f"{[s[2] for s in matching][0]} row(s) of {table} release "
                    f"{release} where the host contract's overlay scope floor "
                    f"is {min_rows}")
        for table, release, min_rows in stated:
            if (table, release) not in [(t, r) for t, r, _ in expected]:
                failures.append(
                    f"{path}: the daily job requires the {table} rows of "
                    f"release {release}, which the host contract's overlay "
                    f"scope does not declare")
        if max_age is not None:
            stated_age = _option_values(invocation,
                                        "--require-overlay-max-age-days")
            if not stated_age:
                failures.append(
                    f"{path}: the daily job checks the served map but does "
                    f"not require the overlay rows to be fresh within the "
                    f"host contract's overlay_max_age_days "
                    f"({max_age:g} day(s)); the check must carry "
                    f"`--require-overlay-max-age-days {max_age:g}`")


# ---------------------------------------------------------------------------
# Per-package overlay coverage of the served map (4r)
# ---------------------------------------------------------------------------

def _contract_overlay_min_package_rows(
        contract: dict[str, str]) -> dict[str, int]:
    """The per-package row floor the contract declares for each distro.

    The contract states one per-package floor per distro-tracker overlay
    it requires: every source package of every release of that overlay's
    declared scope must carry at least this many rows in the served map.
    The floor is a number of rows, not a per-package number, because the
    host's own expectation is "this package of this release is present and
    populated", and the operator can raise the floor to the count
    observed on the host once it is known.
    """
    floors: dict[str, int] = {}
    for distro in _OVERLAY_INGEST_DISTROS:
        raw = contract.get(
            f"overlay_{distro}_min_package_rows", "").strip()
        if not raw:
            continue
        try:
            value = int(raw)
        except ValueError:
            continue  # reported by the contract-level check
        floors[distro] = value
    return floors


def _expected_package_requirements(
        contract: dict[str, str]) -> list[tuple[str, str, str, int]]:
    """The (table, release, package, min_rows) requirements the contract
    implies.

    Every source package of every release of every required distro-tracker
    overlay's declared ingest scope must carry at least the per-package
    floor the contract declares for that overlay.
    """
    floors = _contract_overlay_min_package_rows(contract)
    declared = _declared_overlay_scope(contract)
    requirements: list[tuple[str, str, str, int]] = []
    for distro in _required_overlay_distros(contract):
        floor = floors.get(distro)
        if floor is None:
            continue
        releases = declared.get(distro, {}).get("releases", [])
        packages = declared.get(distro, {}).get("packages", [])
        for release in releases:
            for package in packages:
                requirements.append(
                    (f"{distro}_fixes", release, package, floor))
    return requirements


def _stated_package_requirements(
        invocation: str) -> list[tuple[str, str, str, int]]:
    """The (table, release, package, min_rows) requirements an invocation
    states."""
    stated: list[tuple[str, str, str, int]] = []
    for value in _option_values(invocation, "--require-overlay-package"):
        parts = value.split(":")
        if len(parts) != 4:
            continue
        try:
            min_rows = int(parts[3])
        except ValueError:
            continue
        stated.append(
            (parts[0].strip(), parts[1].strip(),
             parts[2].strip(), min_rows))
    return stated


def _validate_overlay_package_coverage_contract(
        path: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the contract's declared per-package overlay coverage (4r).

    The contract declares the ingest scope of every distro-tracker overlay
    it requires (4p) and a per-release row floor (4q). Neither binds the
    map's rows to the per-package scope: a source package whose tracker
    feed returned nothing ends up with no rows (the per-(release, package)
    refresh deletes the rows it replaces) while the release as a whole
    still holds the other packages' rows and the per-release floor still
    passes. The contract therefore declares a per-package row floor per
    required overlay, so the per-package coverage of the served map can be
    required rather than assumed.
    """
    if contract is None:
        return
    required_distros = _required_overlay_distros(contract)
    for distro in required_distros:
        raw = contract.get(
            f"overlay_{distro}_min_package_rows", "").strip()
        if not raw:
            failures.append(
                f"{path}: the host contract requires the {distro}_fixes "
                f"overlay but declares no overlay_{distro}_min_package_rows, "
                f"so the gate cannot require the served map to carry a "
                f"per-package row floor for it (a source package whose "
                f"tracker feed returned nothing leaves the release looking "
                f"populated while its fix-status rows are gone, so the "
                f"per-release floor still passes while a patched package of "
                f"that source is reported as unpatched)")
            continue
        try:
            value = int(raw)
        except ValueError:
            failures.append(
                f"{path}: the host contract's "
                f"overlay_{distro}_min_package_rows is {raw!r}, which is not "
                f"a row count")
            continue
        if value < 1:
            failures.append(
                f"{path}: the host contract's "
                f"overlay_{distro}_min_package_rows is {value}, which is not "
                f"a positive row count")
    for distro in _OVERLAY_INGEST_DISTROS:
        if distro in required_distros:
            continue
        if contract.get(
                f"overlay_{distro}_min_package_rows", "").strip():
            failures.append(
                f"{path}: the host contract declares "
                f"overlay_{distro}_min_package_rows but does not require the "
                f"{distro}_fixes overlay, so it describes a per-package row "
                f"floor for an overlay the host does not serve")


def _validate_overlay_package_coverage_verification(
        path: str,
        text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the runbook's per-package overlay coverage (dimension 4r).

    The operator's confirmation of the served map is the check the runbook
    shows. A runbook that requires the releases but not the packages
    inside them confirms a map that may be quietly narrow in the
    narrowest direction: a source package whose fix-status rows are gone
    is invisible to a per-release floor while its release still looks
    populated.
    """
    if contract is None:
        return
    expected = _expected_package_requirements(contract)
    if not expected:
        return
    commands = _runbook_spine_verify_commands(text)
    if not commands:
        # The missing verification is reported by dimension 4l.
        return
    for invocation in commands:
        stated = _stated_package_requirements(invocation)
        for table, release, package, min_rows in expected:
            matching = [s for s in stated
                        if s[0] == table and s[1] == release
                        and s[2] == package]
            if not matching:
                failures.append(
                    f"{path}: the runbook verifies the served map but does "
                    f"not require the {table} rows of release {release} "
                    f"package {package}, which the host contract's overlay "
                    f"scope declares (the command must carry "
                    f"`--require-overlay-package "
                    f"{table}:{release}:{package}:{min_rows}`; a source "
                    f"package whose tracker feed returned nothing leaves the "
                    f"release looking populated while its fix-status rows "
                    f"are gone, so the per-release floor still passes)")
            elif min_rows not in [s[3] for s in matching]:
                failures.append(
                    f"{path}: the runbook requires "
                    f"{[s[3] for s in matching][0]} row(s) of {table} "
                    f"release {release} package {package} where the host "
                    f"contract's overlay_{table[:-len('_fixes')]}"
                    f"_min_package_rows floor is {min_rows}")
        for table, release, package, min_rows in stated:
            if (table, release, package) not in [
                    (t, r, p) for t, r, p, _ in expected]:
                failures.append(
                    f"{path}: the runbook requires the {table} rows of "
                    f"release {release} package {package}, which the host "
                    f"contract's overlay scope does not declare, so the "
                    f"runbook describes a different per-package scope than "
                    f"the contract")


def _validate_overlay_package_coverage_job(
        path: str,
        script_text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the nightly job's per-package overlay coverage (dimension 4r).

    The nightly job builds the map; the operator checks it by hand. A job
    that publishes a map whose overlay rows no longer cover every required
    (release, package) pair, and never looks, is a quiet success every
    night: the map stays intact, signed and fresh, the per-release floor
    still passes, and only the missing package's fix-status rows are gone.
    The job must make the same per-package check the runbook shows, right
    after it publishes.
    """
    if contract is None or not script_text:
        return
    expected = _expected_package_requirements(contract)
    if not expected:
        return
    commands = [invocation for words, invocation in _invocations(script_text)
                if words[:2] == ["spine", "verify"]]
    if not commands:
        failures.append(
            f"{path}: the daily job never checks the served map's "
            f"per-package overlay coverage, so a build that publishes a map "
            f"whose overlay rows no longer cover every required (release, "
            f"package) pair is a quiet success instead of a degraded run")
        return
    for invocation in commands:
        stated = _stated_package_requirements(invocation)
        for table, release, package, min_rows in expected:
            matching = [s for s in stated
                        if s[0] == table and s[1] == release
                        and s[2] == package]
            if not matching:
                failures.append(
                    f"{path}: the daily job checks the served map but does "
                    f"not require the {table} rows of release {release} "
                    f"package {package}, which the host contract's overlay "
                    f"scope declares (the check must carry "
                    f"`--require-overlay-package "
                    f"{table}:{release}:{package}:{min_rows}`; a source "
                    f"package whose tracker feed returned nothing leaves the "
                    f"release looking populated while its fix-status rows "
                    f"are gone, so the per-release floor still passes)")
            elif min_rows not in [s[3] for s in matching]:
                failures.append(
                    f"{path}: the daily job requires "
                    f"{[s[3] for s in matching][0]} row(s) of {table} "
                    f"release {release} package {package} where the host "
                    f"contract's per-package floor is {min_rows}")
        for table, release, package, min_rows in stated:
            if (table, release, package) not in [
                    (t, r, p) for t, r, p, _ in expected]:
                failures.append(
                    f"{path}: the daily job requires the {table} rows of "
                    f"release {release} package {package}, which the host "
                    f"contract's overlay scope does not declare")


# ---------------------------------------------------------------------------
# Known-exploited coverage of the served map (4s)
# ---------------------------------------------------------------------------


def _contract_kev_min_rows(contract: dict[str, str]) -> int | None:
    """The row floor the contract declares for the known-exploited set."""
    raw = contract.get("kev_min_rows", "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None  # reported by the contract-level check


def _contract_kev_max_age_days(contract: dict[str, str]) -> float | None:
    """The freshness allowance the contract declares for the known-exploited
    rows."""
    raw = contract.get("kev_max_age_days", "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None  # reported by the contract-level check


def _stated_kev_requirement(invocation: str) -> int | None:
    """The known-exploited row floor an invocation states."""
    values = _option_values(invocation, "--require-kev")
    if not values:
        return None
    try:
        return int(values[0])
    except ValueError:
        return None


def _stated_kev_max_age_days(invocation: str) -> float | None:
    """The known-exploited freshness allowance an invocation states."""
    values = _option_values(invocation, "--require-kev-max-age-days")
    if not values:
        return None
    try:
        return float(values[0])
    except ValueError:
        return None


def _validate_kev_coverage_contract(
        path: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the contract's declared known-exploited coverage (4s).

    The contract declares which overlay tables the map must carry (4o),
    the distro-tracker overlays' scope (4p), and their per-release (4q) and
    per-package (4r) row floors. None of them binds the known-exploited
    set: CISA's KEV catalog is what the map says about what is being
    exploited in the wild, and its ingest is a no-wipe full refresh, so a
    fetch that fails leaves the last-known-good rows in place. The served
    map then stays intact, signed, fresh and consistent with its own
    manifest, every other check still passes, and only the age of the
    known-exploited rows shows that the set stopped being refreshed. The
    contract therefore declares a row floor and a freshness allowance for
    the known-exploited set.
    """
    if contract is None:
        return
    raw_rows = contract.get("kev_min_rows", "").strip()
    if not raw_rows:
        failures.append(
            f"{path}: the host contract declares no kev_min_rows, so the "
            f"gate cannot require the served map to carry the known-exploited "
            f"set at all (the CISA KEV ingest is a no-wipe refresh, so a "
            f"failed fetch leaves the last-known-good rows serving and the "
            f"map keeps passing every other check while the threat axis "
            f"reads a set that stopped being refreshed)")
    else:
        try:
            value = int(raw_rows)
        except ValueError:
            failures.append(
                f"{path}: the host contract's kev_min_rows is {raw_rows!r}, "
                f"which is not a row count")
        else:
            if value < 1:
                failures.append(
                    f"{path}: the host contract's kev_min_rows is {value}, "
                    f"which is not a positive row count")
    raw_age = contract.get("kev_max_age_days", "").strip()
    if not raw_age:
        failures.append(
            f"{path}: the host contract declares no kev_max_age_days, so the "
            f"gate cannot require the known-exploited rows to be fresh (the "
            f"ingest is a no-wipe refresh, so a known-exploited set that "
            f"stopped being refreshed still satisfies the row floor)")
    else:
        try:
            age = float(raw_age)
        except ValueError:
            failures.append(
                f"{path}: the host contract's kev_max_age_days is "
                f"{raw_age!r}, which is not a number of days")
        else:
            if age <= 0:
                failures.append(
                    f"{path}: the host contract's kev_max_age_days is "
                    f"{age:g}, which is not a positive number of days")


def _validate_kev_coverage_verification(
        path: str,
        text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the runbook's known-exploited coverage (dimension 4s).

    The operator's confirmation of the served map is the check the runbook
    shows. A runbook that confirms the vendor fix-status overlays but not
    the known-exploited set confirms a map whose threat axis may be blind:
    the rows are still there, but they are the rows of an older catalog
    and nothing says so.
    """
    if contract is None:
        return
    floor = _contract_kev_min_rows(contract)
    max_age = _contract_kev_max_age_days(contract)
    if floor is None and max_age is None:
        return
    commands = _runbook_spine_verify_commands(text)
    if not commands:
        # The missing verification is reported by dimension 4l.
        return
    for invocation in commands:
        stated_rows = _stated_kev_requirement(invocation)
        if floor is not None and stated_rows is None:
            failures.append(
                f"{path}: the runbook verifies the served map but does not "
                f"require the known-exploited rows, which the host "
                f"contract's kev_min_rows floor declares (the command must "
                f"carry `--require-kev {floor}`; the known-exploited set is "
                f"what the threat axis reads, and the no-wipe ingest leaves "
                f"the last-known-good rows serving when a fetch fails)")
        elif floor is not None and stated_rows != floor:
            failures.append(
                f"{path}: the runbook requires {stated_rows} known-exploited "
                f"row(s) where the host contract's kev_min_rows floor is "
                f"{floor}")
        if max_age is not None:
            stated_age = _stated_kev_max_age_days(invocation)
            if stated_age is None:
                failures.append(
                    f"{path}: the runbook verifies the served map but does "
                    f"not require the known-exploited rows to be fresh "
                    f"within the host contract's kev_max_age_days "
                    f"({max_age:g} day(s)); the command must carry "
                    f"`--require-kev-max-age-days {max_age:g}` (a "
                    f"known-exploited set that stopped being refreshed still "
                    f"satisfies the row floor)")
            elif stated_age != max_age:
                failures.append(
                    f"{path}: the runbook allows {stated_age:g} day(s) for "
                    f"the known-exploited rows where the host contract's "
                    f"kev_max_age_days is {max_age:g}")


def _validate_kev_coverage_job(
        path: str,
        script_text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the nightly job's known-exploited coverage (dimension 4s).

    The nightly job is the thing that builds the map the operator checks.
    A job that publishes a map whose known-exploited set has stopped being
    refreshed, and never looks, is a quiet success every night: the map
    stays intact, signed and fresh, and only the age of those rows shows
    it. The job must make the same check the runbook shows, right after it
    publishes.
    """
    if contract is None or not script_text:
        return
    floor = _contract_kev_min_rows(contract)
    max_age = _contract_kev_max_age_days(contract)
    if floor is None and max_age is None:
        return
    commands = [invocation for words, invocation in _invocations(script_text)
                if words[:2] == ["spine", "verify"]]
    if not commands:
        failures.append(
            f"{path}: the daily job never checks the served map's "
            f"known-exploited coverage, so a build that publishes a map "
            f"whose known-exploited set has stopped being refreshed is a "
            f"quiet success instead of a degraded run")
        return
    for invocation in commands:
        stated_rows = _stated_kev_requirement(invocation)
        if floor is not None and stated_rows is None:
            failures.append(
                f"{path}: the daily job checks the served map but does not "
                f"require the known-exploited rows, which the host "
                f"contract's kev_min_rows floor declares (the check must "
                f"carry `--require-kev {floor}`; the known-exploited set is "
                f"what the threat axis reads, and the no-wipe ingest leaves "
                f"the last-known-good rows serving when a fetch fails)")
        elif floor is not None and stated_rows != floor:
            failures.append(
                f"{path}: the daily job requires {stated_rows} "
                f"known-exploited row(s) where the host contract's "
                f"kev_min_rows floor is {floor}")
        if max_age is not None:
            stated_age = _stated_kev_max_age_days(invocation)
            if stated_age is None:
                failures.append(
                    f"{path}: the daily job checks the served map but does "
                    f"not require the known-exploited rows to be fresh "
                    f"within the host contract's kev_max_age_days "
                    f"({max_age:g} day(s)); the check must carry "
                    f"`--require-kev-max-age-days {max_age:g}`")
            elif stated_age != max_age:
                failures.append(
                    f"{path}: the daily job allows {stated_age:g} day(s) for "
                    f"the known-exploited rows where the host contract's "
                    f"kev_max_age_days is {max_age:g}")


# ---------------------------------------------------------------------------
# Flat overlay coverage (4t) -- Apple fix overlay and EPSS overlay
# ---------------------------------------------------------------------------

# The Apple fix overlay (apple_fixes) and the exploitability-probability
# overlay (epss) are flat tables the export writes with a coverage record
# (rows, newest_fetched_at) but no per-release or per-package structure.
# Both ingests are no-wipe on the caller side, so a failed fetch leaves the
# last-known-good rows serving while every other check on the served map
# still passes. The contract declares a row floor and a freshness allowance
# for each, and the gate checks that every `posture spine verify` command
# the runbook shows, and the check the nightly job runs after its publish,
# requires exactly the floor and the allowance the contract declares.


def _contract_int_floor(contract: dict[str, str], key: str) -> int | None:
    """The integer row floor a contract key declares (or None)."""
    raw = contract.get(key, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None  # reported by the contract-level check


def _contract_float_days(contract: dict[str, str], key: str) -> float | None:
    """The float freshness allowance a contract key declares (or None)."""
    raw = contract.get(key, "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None  # reported by the contract-level check


def _stated_int_option(invocation: str, option: str) -> int | None:
    """The integer value an invocation states for option (or None)."""
    values = _option_values(invocation, option)
    if not values:
        return None
    try:
        return int(values[0])
    except ValueError:
        return None


def _stated_float_option(invocation: str, option: str) -> float | None:
    """The float value an invocation states for option (or None)."""
    values = _option_values(invocation, option)
    if not values:
        return None
    try:
        return float(values[0])
    except ValueError:
        return None


def _validate_flat_overlay_coverage_contract(
        path: str,
        contract: dict[str, str] | None,
        failures: list[str],
        rows_key: str,
        age_key: str,
        label: str,
) -> None:
    """Check the contract's declared flat-overlay coverage (4t)."""
    if contract is None:
        return
    raw_rows = contract.get(rows_key, "").strip()
    if not raw_rows:
        failures.append(
            f"{path}: the host contract declares no {rows_key}, so the "
            f"gate cannot require the served map to carry the {label} "
            f"overlay at all (the ingest is no-wipe on the caller side, "
            f"so a failed fetch leaves the last-known-good rows serving "
            f"and the map keeps passing every other check while the "
            f"overlay quietly went stale)")
    else:
        try:
            value = int(raw_rows)
        except ValueError:
            failures.append(
                f"{path}: the host contract's {rows_key} is "
                f"{raw_rows!r}, which is not a row count")
        else:
            if value < 1:
                failures.append(
                    f"{path}: the host contract's {rows_key} is {value}, "
                    f"which is not a positive row count")
    raw_age = contract.get(age_key, "").strip()
    if not raw_age:
        failures.append(
            f"{path}: the host contract declares no {age_key}, so the "
            f"gate cannot require the {label} rows to be fresh (the "
            f"ingest is no-wipe on the caller side, so a {label} overlay "
            f"that stopped being refreshed still satisfies the row floor)")
    else:
        try:
            age = float(raw_age)
        except ValueError:
            failures.append(
                f"{path}: the host contract's {age_key} is "
                f"{raw_age!r}, which is not a number of days")
        else:
            if age <= 0:
                failures.append(
                    f"{path}: the host contract's {age_key} is "
                    f"{age:g}, which is not a positive number of days")


def _validate_flat_overlay_coverage_verification(
        path: str,
        text: str,
        contract: dict[str, str] | None,
        failures: list[str],
        rows_key: str,
        age_key: str,
        rows_option: str,
        age_option: str,
        label: str,
) -> None:
    """Check the runbook's flat-overlay coverage (dimension 4t)."""
    if contract is None:
        return
    floor = _contract_int_floor(contract, rows_key)
    max_age = _contract_float_days(contract, age_key)
    if floor is None and max_age is None:
        return
    commands = _runbook_spine_verify_commands(text)
    if not commands:
        # The missing verification is reported by dimension 4l.
        return
    for invocation in commands:
        stated_rows = _stated_int_option(invocation, rows_option)
        if floor is not None and stated_rows is None:
            failures.append(
                f"{path}: the runbook verifies the served map but does not "
                f"require the {label} rows, which the host contract's "
                f"{rows_key} floor declares (the command must carry "
                f"`{rows_option} {floor}`; the {label} overlay is what "
                f"the map says about that axis, and the no-wipe ingest "
                f"leaves the last-known-good rows serving when a fetch "
                f"fails)")
        elif floor is not None and stated_rows != floor:
            failures.append(
                f"{path}: the runbook requires {stated_rows} {label} "
                f"row(s) where the host contract's {rows_key} floor is "
                f"{floor}")
        if max_age is not None:
            stated_age = _stated_float_option(invocation, age_option)
            if stated_age is None:
                failures.append(
                    f"{path}: the runbook verifies the served map but does "
                    f"not require the {label} rows to be fresh within the "
                    f"host contract's {age_key} ({max_age:g} day(s)); the "
                    f"command must carry `{age_option} {max_age:g}` (a "
                    f"{label} overlay that stopped being refreshed still "
                    f"satisfies the row floor)")
            elif stated_age != max_age:
                failures.append(
                    f"{path}: the runbook allows {stated_age:g} day(s) for "
                    f"the {label} rows where the host contract's "
                    f"{age_key} is {max_age:g}")


def _validate_flat_overlay_coverage_job(
        path: str,
        script_text: str,
        contract: dict[str, str] | None,
        failures: list[str],
        rows_key: str,
        age_key: str,
        rows_option: str,
        age_option: str,
        label: str,
) -> None:
    """Check the nightly job's flat-overlay coverage (dimension 4t)."""
    if contract is None or not script_text:
        return
    floor = _contract_int_floor(contract, rows_key)
    max_age = _contract_float_days(contract, age_key)
    if floor is None and max_age is None:
        return
    commands = [invocation for words, invocation in _invocations(script_text)
                if words[:2] == ["spine", "verify"]]
    if not commands:
        failures.append(
            f"{path}: the daily job never checks the served map's "
            f"{label} coverage, so a build that publishes a map whose "
            f"{label} overlay has stopped being refreshed is a quiet "
            f"success instead of a degraded run")
        return
    for invocation in commands:
        stated_rows = _stated_int_option(invocation, rows_option)
        if floor is not None and stated_rows is None:
            failures.append(
                f"{path}: the daily job checks the served map but does not "
                f"require the {label} rows, which the host contract's "
                f"{rows_key} floor declares (the check must carry "
                f"`{rows_option} {floor}`; the {label} overlay is what "
                f"the map says about that axis, and the no-wipe ingest "
                f"leaves the last-known-good rows serving when a fetch "
                f"fails)")
        elif floor is not None and stated_rows != floor:
            failures.append(
                f"{path}: the daily job requires {stated_rows} {label} "
                f"row(s) where the host contract's {rows_key} floor is "
                f"{floor}")
        if max_age is not None:
            stated_age = _stated_float_option(invocation, age_option)
            if stated_age is None:
                failures.append(
                    f"{path}: the daily job checks the served map but does "
                    f"not require the {label} rows to be fresh within the "
                    f"host contract's {age_key} ({max_age:g} day(s)); the "
                    f"check must carry `{age_option} {max_age:g}`")
            elif stated_age != max_age:
                failures.append(
                    f"{path}: the daily job allows {stated_age:g} day(s) "
                    f"for the {label} rows where the host contract's "
                    f"{age_key} is {max_age:g}")


# ---------------------------------------------------------------------------
# Apple fix coverage per product (4u)
# ---------------------------------------------------------------------------


def _contract_apple_products(contract: dict[str, str]) -> list[str]:
    """The Apple products the host contract requires the map to carry.

    The contract states them as one comma-separated value; each name is
    one product of the apple_fixes overlay (iphone_os, ipados, macos).
    """
    raw = contract.get("apple_fixes_products", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _validate_apple_product_coverage_contract(
        path: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the contract's declared per-product Apple coverage (4u).

    The contract names the Apple products the served map must carry, the
    row floor each product must meet, and the freshness allowance for
    those rows. A contract that names no product describes a host that
    never requires a per-product Apple fix row, so a product whose
    advisory feed returned nothing (the apple_fixes ingest is a
    per-product full refresh, so that product's rows are deleted and
    never replaced) is invisible while the table-level floor still
    passes.
    """
    if contract is None:
        return
    products = _contract_apple_products(contract)
    if not products:
        failures.append(
            f"{path}: the host contract declares no apple_fixes_products, "
            f"so the gate cannot require the served map to carry Apple fix "
            f"rows for any product (the apple_fixes ingest is a per-product "
            f"full refresh, so a product whose advisory feed returned "
            f"nothing loses its rows while the table-level floor still "
            f"passes)")
    raw_rows = contract.get("apple_fixes_min_product_rows", "").strip()
    if not raw_rows:
        failures.append(
            f"{path}: the host contract declares no "
            f"apple_fixes_min_product_rows, so the gate cannot require "
            f"each Apple product's rows to be present (a product whose "
            f"advisory feed returned nothing leaves that product with no "
            f"fix versions at all)")
    else:
        try:
            value = int(raw_rows)
        except ValueError:
            failures.append(
                f"{path}: the host contract's apple_fixes_min_product_rows "
                f"is {raw_rows!r}, which is not a row count")
        else:
            if value < 1:
                failures.append(
                    f"{path}: the host contract's "
                    f"apple_fixes_min_product_rows is {value}, which is not "
                    f"a positive row count")
    raw_age = contract.get("apple_fixes_product_max_age_days", "").strip()
    if not raw_age:
        failures.append(
            f"{path}: the host contract declares no "
            f"apple_fixes_product_max_age_days, so the gate cannot require "
            f"the per-product Apple fix rows to be fresh (each product is "
            f"refreshed on its own, so a product that stopped being "
            f"refreshed still satisfies the per-product row floor)")
    else:
        try:
            age = float(raw_age)
        except ValueError:
            failures.append(
                f"{path}: the host contract's "
                f"apple_fixes_product_max_age_days is {raw_age!r}, which is "
                f"not a number of days")
        else:
            if age <= 0:
                failures.append(
                    f"{path}: the host contract's "
                    f"apple_fixes_product_max_age_days is {age:g}, which is "
                    f"not a positive number of days")


def _validate_apple_product_coverage_verification(
        path: str,
        text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the runbook's per-product Apple coverage (dimension 4u)."""
    if contract is None:
        return
    products = _contract_apple_products(contract)
    floor = _contract_int_floor(contract, "apple_fixes_min_product_rows")
    max_age = _contract_float_days(contract, "apple_fixes_product_max_age_days")
    if not products or (floor is None and max_age is None):
        return
    commands = _runbook_spine_verify_commands(text)
    if not commands:
        # The missing verification is reported by dimension 4l.
        return
    for invocation in commands:
        stated: dict[str, int] = {}
        for value in _option_values(invocation, "--require-apple-fixes-product"):
            product, _, rows = str(value).partition(":")
            product = product.strip()
            if not product:
                continue
            try:
                stated[product] = int(rows)
            except ValueError:
                failures.append(
                    f"{path}: the runbook states `--require-apple-fixes-"
                    f"product {value}`, which does not name a row count")
        for product in products:
            if product not in stated:
                failures.append(
                    f"{path}: the runbook verifies the served map but does "
                    f"not require the Apple fix rows of {product}, which the "
                    f"host contract's apple_fixes_products scope declares "
                    f"(the command must carry "
                    f"`--require-apple-fixes-product {product}:{floor}`; the "
                    f"apple_fixes ingest is a per-product full refresh, so a "
                    f"product whose advisory feed returned nothing loses its "
                    f"rows while the table-level floor still passes)")
            elif floor is not None and stated[product] != floor:
                failures.append(
                    f"{path}: the runbook requires {stated[product]} Apple "
                    f"fix row(s) for {product} where the host contract's "
                    f"apple_fixes_min_product_rows floor is {floor}")
        if max_age is not None:
            stated_age = _stated_float_option(
                invocation, "--require-apple-fixes-product-max-age-days")
            if stated_age is None:
                failures.append(
                    f"{path}: the runbook verifies the served map but does "
                    f"not require the per-product Apple fix rows to be fresh "
                    f"within the host contract's "
                    f"apple_fixes_product_max_age_days ({max_age:g} day(s)); "
                    f"the command must carry "
                    f"`--require-apple-fixes-product-max-age-days "
                    f"{max_age:g}` (each product is refreshed on its own, so "
                    f"a product that stopped being refreshed still "
                    f"satisfies its row floor)")
            elif stated_age != max_age:
                failures.append(
                    f"{path}: the runbook allows {stated_age:g} day(s) for "
                    f"the per-product Apple fix rows where the host "
                    f"contract's apple_fixes_product_max_age_days is "
                    f"{max_age:g}")


def _validate_apple_product_coverage_job(
        path: str,
        script_text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the nightly job's per-product Apple coverage (dimension 4u)."""
    if contract is None or not script_text:
        return
    products = _contract_apple_products(contract)
    floor = _contract_int_floor(contract, "apple_fixes_min_product_rows")
    max_age = _contract_float_days(contract, "apple_fixes_product_max_age_days")
    if not products or (floor is None and max_age is None):
        return
    commands = [invocation for words, invocation in _invocations(script_text)
                if words[:2] == ["spine", "verify"]]
    if not commands:
        failures.append(
            f"{path}: the daily job never checks the served map's "
            f"per-product Apple fix coverage, so a build that publishes a "
            f"map whose Apple fix rows went missing for a product is a "
            f"quiet success instead of a degraded run")
        return
    for invocation in commands:
        stated: dict[str, int] = {}
        for value in _option_values(invocation, "--require-apple-fixes-product"):
            product, _, rows = str(value).partition(":")
            product = product.strip()
            if not product:
                continue
            try:
                stated[product] = int(rows)
            except ValueError:
                failures.append(
                    f"{path}: the daily job states `--require-apple-fixes-"
                    f"product {value}`, which does not name a row count")
        for product in products:
            if product not in stated:
                failures.append(
                    f"{path}: the daily job checks the served map but does "
                    f"not require the Apple fix rows of {product}, which the "
                    f"host contract's apple_fixes_products scope declares "
                    f"(the check must carry "
                    f"`--require-apple-fixes-product {product}:{floor}`; the "
                    f"apple_fixes ingest is a per-product full refresh, so a "
                    f"product whose advisory feed returned nothing loses its "
                    f"rows while the table-level floor still passes)")
            elif floor is not None and stated[product] != floor:
                failures.append(
                    f"{path}: the daily job requires {stated[product]} Apple "
                    f"fix row(s) for {product} where the host contract's "
                    f"apple_fixes_min_product_rows floor is {floor}")
        if max_age is not None:
            stated_age = _stated_float_option(
                invocation, "--require-apple-fixes-product-max-age-days")
            if stated_age is None:
                failures.append(
                    f"{path}: the daily job checks the served map but does "
                    f"not require the per-product Apple fix rows to be fresh "
                    f"within the host contract's "
                    f"apple_fixes_product_max_age_days ({max_age:g} day(s)); "
                    f"the check must carry "
                    f"`--require-apple-fixes-product-max-age-days "
                    f"{max_age:g}`")
            elif stated_age != max_age:
                failures.append(
                    f"{path}: the daily job allows {stated_age:g} day(s) for "
                    f"the per-product Apple fix rows where the host "
                    f"contract's apple_fixes_product_max_age_days is "
                    f"{max_age:g}")


# ---------------------------------------------------------------------------
# EPSS coverage per score band (4v)
# ---------------------------------------------------------------------------


def _contract_epss_score_bands(
        contract: dict[str, str]) -> list[float]:
    """The EPSS percentile thresholds the host contract requires the map
    to carry per band.

    The contract states them as one comma-separated value; each item is a
    float in 0..1 (the EPSS percentile at or above which the band counts
    CVEs). A threshold of 0.9 is the top 10 percent most likely to be
    exploited.
    """
    raw = contract.get("epss_score_bands", "")
    bands: list[float] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            bands.append(float(item))
        except ValueError:
            pass  # reported by the contract-level check
    return bands


def _validate_epss_score_band_coverage_contract(
        path: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the contract's declared per-band EPSS coverage (4v).

    The contract names the EPSS percentile thresholds the served map must
    carry per band, and the row floor each band must meet. A contract that
    names no band describes a host that never requires a per-band EPSS
    count, so a map that quietly lost every high-severity CVE (the ones in
    the top percentile bands the prioritization surface depends on) is
    invisible while the table-level floor still passes.
    """
    if contract is None:
        return
    raw_bands = contract.get("epss_score_bands", "").strip()
    if not raw_bands:
        failures.append(
            f"{path}: the host contract declares no epss_score_bands, so "
            f"the gate cannot require the served map to carry EPSS rows "
            f"in any percentile band (the EPSS overlay scores every CVE "
            f"with a percentile, so a map that holds 270k rows passes the "
            f"table-level floor while quietly losing every high-severity "
            f"CVE if the model distribution shifted or a partial fetch "
            f"narrowed the set)")
    else:
        for item in raw_bands.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                value = float(item)
            except ValueError:
                failures.append(
                    f"{path}: the host contract's epss_score_bands "
                    f"contains {item!r}, which is not a percentile "
                    f"threshold")
                continue
            if value < 0 or value > 1:
                failures.append(
                    f"{path}: the host contract's epss_score_bands "
                    f"contains {value:g}, which is outside the 0..1 "
                    f"range EPSS percentiles occupy")
    raw_rows = contract.get("epss_min_score_band_rows", "").strip()
    if not raw_rows:
        failures.append(
            f"{path}: the host contract declares no "
            f"epss_min_score_band_rows, so the gate cannot require each "
            f"EPSS percentile band to be populated (a band that quietly "
            f"went empty still passes the table-level row floor)")
    else:
        try:
            value = int(raw_rows)
        except ValueError:
            failures.append(
                f"{path}: the host contract's "
                f"epss_min_score_band_rows is {raw_rows!r}, which is "
                f"not a row count")
        else:
            if value < 1:
                failures.append(
                    f"{path}: the host contract's "
                    f"epss_min_score_band_rows is {value}, which is not "
                    f"a positive row count")


def _validate_epss_score_band_coverage_verification(
        path: str,
        text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the runbook's per-band EPSS coverage (dimension 4v)."""
    if contract is None:
        return
    bands = _contract_epss_score_bands(contract)
    floor = _contract_int_floor(contract, "epss_min_score_band_rows")
    if not bands or floor is None:
        return
    commands = _runbook_spine_verify_commands(text)
    if not commands:
        # The missing verification is reported by dimension 4l.
        return
    for invocation in commands:
        stated: dict[str, int] = {}
        for value in _option_values(
                invocation, "--require-epss-score-band"):
            percentile_str, _, rows_str = str(value).partition(":")
            percentile_str = percentile_str.strip()
            if not percentile_str:
                continue
            try:
                pval = float(percentile_str)
            except ValueError:
                failures.append(
                    f"{path}: the runbook states "
                    f"`--require-epss-score-band {value}`, which does not "
                    f"name a percentile threshold")
                continue
            try:
                stated[str(pval)] = int(rows_str)
            except ValueError:
                failures.append(
                    f"{path}: the runbook states "
                    f"`--require-epss-score-band {value}`, which does not "
                    f"name a row count")
        for band in bands:
            key = str(band)
            if key not in stated:
                failures.append(
                    f"{path}: the runbook verifies the served map but "
                    f"does not require the EPSS percentile band {key}, "
                    f"which the host contract's epss_score_bands scope "
                    f"declares (the command must carry "
                    f"`--require-epss-score-band {key}:{floor}`; the EPSS "
                    f"overlay scores every CVE with a percentile, so a "
                    f"map that holds 270k rows passes the table-level "
                    f"floor while quietly losing every high-severity CVE "
                    f"in that band)")
            elif stated[key] != floor:
                failures.append(
                    f"{path}: the runbook requires {stated[key]} EPSS "
                    f"row(s) for percentile band {key} where the host "
                    f"contract's epss_min_score_band_rows floor is "
                    f"{floor}")


def _validate_epss_score_band_coverage_job(
        path: str,
        script_text: str,
        contract: dict[str, str] | None,
        failures: list[str],
) -> None:
    """Check the nightly job's per-band EPSS coverage (dimension 4v)."""
    if contract is None or not script_text:
        return
    bands = _contract_epss_score_bands(contract)
    floor = _contract_int_floor(contract, "epss_min_score_band_rows")
    if not bands or floor is None:
        return
    commands = [invocation for words, invocation in _invocations(script_text)
                if words[:2] == ["spine", "verify"]]
    if not commands:
        failures.append(
            f"{path}: the daily job never checks the served map's "
            f"per-band EPSS coverage, so a build that publishes a map "
            f"whose high-severity percentile bands went empty is a quiet "
            f"success instead of a degraded run")
        return
    for invocation in commands:
        stated: dict[str, int] = {}
        for value in _option_values(
                invocation, "--require-epss-score-band"):
            percentile_str, _, rows_str = str(value).partition(":")
            percentile_str = percentile_str.strip()
            if not percentile_str:
                continue
            try:
                pval = float(percentile_str)
            except ValueError:
                failures.append(
                    f"{path}: the daily job states "
                    f"`--require-epss-score-band {value}`, which does not "
                    f"name a percentile threshold")
                continue
            try:
                stated[str(pval)] = int(rows_str)
            except ValueError:
                failures.append(
                    f"{path}: the daily job states "
                    f"`--require-epss-score-band {value}`, which does not "
                    f"name a row count")
        for band in bands:
            key = str(band)
            if key not in stated:
                failures.append(
                    f"{path}: the daily job checks the served map but "
                    f"does not require the EPSS percentile band {key}, "
                    f"which the host contract's epss_score_bands scope "
                    f"declares (the check must carry "
                    f"`--require-epss-score-band {key}:{floor}`; the EPSS "
                    f"overlay scores every CVE with a percentile, so a "
                    f"map that holds 270k rows passes the table-level "
                    f"floor while quietly losing every high-severity CVE "
                    f"in that band)")
            elif stated[key] != floor:
                failures.append(
                    f"{path}: the daily job requires {stated[key]} EPSS "
                    f"row(s) for percentile band {key} where the host "
                    f"contract's epss_min_score_band_rows floor is "
                    f"{floor}")


# ---------------------------------------------------------------------------
# Host command contract (4g)
# ---------------------------------------------------------------------------

# The standard systemd unit directories. A runbook installs the system
# units in the system directory and the user units in the operator's own
# directory. These are systemd's own conventions rather than this
# repository's choices, so they are fixed here instead of being declared
# in the host contract.
_SYSTEMD_UNIT_DIRS = ("/etc/systemd/system", "~/.config/systemd/user")
# The standard system paths a runbook command may name without the host
# contract governing them: device nodes, process information, temporary
# files, the system binaries, and the system log.
_SYSTEM_PATHS = ("/dev", "/proc", "/sys", "/tmp", "/var/tmp", "/usr",
                 "/var/log")
# A command that creates or installs something on the host.
_INSTALL_COMMAND_RE = re.compile(r"^(sudo\s+)?install\b")
# A command that creates a system account.
_USERADD_RE = re.compile(r"\b(useradd|adduser)\b")
# The owner and group a command names.
_OWNER_RE = re.compile(r"(?:^|\s)(?:-o|--owner)\s+(\S+)")
_GROUP_RE = re.compile(r"(?:^|\s)(?:-g|--group)\s+(\S+)")
_RM_RE = re.compile(r"^(sudo\s+)?rm\b")


def _fenced_shell_blocks(text: str) -> list[str]:
    """Every fenced shell block in a markdown document.

    A runbook's operator commands live in fenced blocks; the blocks that
    declare data (the host contract is a YAML block) are not commands and
    are not read here.
    """
    blocks: list[str] = []
    in_block = False
    language = ""
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_block:
                if language in ("", "bash", "sh", "shell", "console"):
                    blocks.append("\n".join(current))
                current = []
                language = ""
            else:
                info = stripped[3:].strip()
                language = info.split()[0] if info else ""
            in_block = not in_block
            continue
        if in_block:
            current.append(line)
    return blocks


def _command_path_tokens(line: str) -> list[str]:
    """The absolute and home-relative paths a command line names.

    A token that carries a shell expansion is skipped: its value is not
    visible statically, the same way the gate treats shell expansions
    elsewhere.
    """
    tokens: list[str] = []
    for raw in line.split():
        token = raw.strip("\"'").rstrip(",;:")
        if not token or "..." in token or "$" in token:
            continue
        if token.startswith("/") or token.startswith("~/"):
            tokens.append(_normalize_host_path(token))
    return tokens


def _contract_governed_roots(contract: dict[str, str]) -> list[str]:
    """The host paths the contract governs, as directory roots.

    The install root, the state and export directories, and the two
    directories the environment files live in. A path the operator's
    commands name must live under one of these, or be a standard system
    path, or the contract does not describe the host the commands build.
    """
    roots: list[str] = []
    for key in ("install_root", "state_dir", "export_dir"):
        if key in contract:
            roots.append(_normalize_host_path(contract[key]))
    for key in ("system_env_file", "user_env_file"):
        if key in contract:
            value = _normalize_host_path(contract[key])
            parent = value.rsplit("/", 1)[0] if "/" in value else value
            if parent:
                roots.append(parent)
    return roots


def _unit_is_system_unit(name: str) -> bool:
    """True when a shipped unit belongs in the system unit directory.

    A service that names a `User=` runs as that account on the host and
    is installed in the system unit directory; a service that does not
    runs as the operator and is installed in the user's own unit
    directory. A timer takes the kind of the service it schedules, so a
    timer and the service it fires are always installed together.
    """
    unit = Path("systemd") / name
    try:
        text = unit.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    sections = _unit_sections(text)
    if _directive_value(sections, "Service", "User") is not None:
        return True
    if name.endswith(".timer"):
        scheduled = _directive_value(sections, "Timer", "Unit")
        if scheduled:
            scheduled = scheduled.strip()
            if scheduled in {u.name for u in _shipped_unit_files()}:
                return _unit_is_system_unit(scheduled)
        return True
    return False


def _validate_runbook_host_commands(
    path: str,
    text: str,
    contract: dict[str, str] | None,
    failures: list[str],
) -> int:
    """Validate the runbook's host commands against the contract (4g).

    The host contract binds the units to the runbook, but the runbook's
    own operator commands were still unbound text: the directories they
    create, the account they create, the ownership they set, and the
    directory they install each unit into. A contract that changes while
    the commands do not describes a host nobody builds. This dimension
    binds them: every path a command names must be governed by the
    contract or be a standard system path, the account the runbook
    creates must be the contract's service account with the contract's
    state directory as its home, an owner or group a command names must
    be the contract's account or root, a writable directory the runbook
    creates must be owned by the service account, every unit this tree
    ships must be installed into the unit directory its kind belongs in,
    and every unit the runbook installs must also be removed by a
    command so a unit added to the tree but never torn down is reported
    as drift rather than left stale on the host after teardown. The
    manifest signing key and the served directory's ownership are
    bound too (dimension 4i): a command must reference the contract's
    signing key path, and the command that creates the served
    directory must set its owner to the contract's served directory
    owner.

    Returns the number of host commands checked.
    """
    blocks = _fenced_shell_blocks(text)
    if not blocks or contract is None:
        return 0

    account = contract.get("service_account", "").strip()
    state_dir = _normalize_host_path(contract.get("state_dir", ""))
    export_dir = _normalize_host_path(contract.get("export_dir", ""))
    roots = _contract_governed_roots(contract)
    writable_roots = [d for d in (state_dir, export_dir) if d]
    standard = list(_SYSTEMD_UNIT_DIRS) + list(_SYSTEM_PATHS)
    shipped_units = {u.name for u in _shipped_unit_files()}
    installed: dict[str, str] = {}
    removed: set[str] = set()
    checked = 0
    sign_key = _normalize_host_path(contract.get("sign_key", ""))
    sign_pub_key = _normalize_host_path(contract.get("sign_pub_key", ""))
    served_dir_owner = contract.get("served_dir_owner", "").strip()
    referenced_sign_key = False
    referenced_sign_pub_key = False

    for block in blocks:
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            checked += 1
            path_tokens = _command_path_tokens(stripped)

            # (4i-a) Track whether any operator command references the
            #        contract's manifest signing key path, and the public
            #        key path the operator's verification uses. A contract
            #        that declares where a key lives but a runbook that
            #        never names that path does not build the key location
            #        the contract describes.
            if sign_key and sign_key in path_tokens:
                referenced_sign_key = True
            if sign_pub_key and sign_pub_key in path_tokens:
                referenced_sign_pub_key = True

            # (a) Every path a command names must be governed by the
            #     contract or be a standard system path.
            for token in path_tokens:
                if any(_is_under(token, root) for root in roots):
                    continue
                if any(token == root for root in roots):
                    continue
                if any(_is_under(token, root) or token == root
                       for root in standard):
                    continue
                failures.append(
                    f"{path}: the command `{stripped}` names `{token}`, which "
                    f"the host contract does not govern (the contract's "
                    f"paths are {', '.join(roots)}; a command that builds a "
                    f"path the contract does not describe builds a different "
                    f"host)")

            # (b) The account the runbook creates must be the contract's
            #     service account, with the contract's state directory as
            #     its home.
            if _USERADD_RE.search(stripped):
                home = re.search(r"--home-dir\s+(\S+)", stripped)
                if home is not None and state_dir:
                    if _normalize_host_path(home.group(1)) != state_dir:
                        failures.append(
                            f"{path}: the command `{stripped}` creates the "
                            f"service account with home "
                            f"{_normalize_host_path(home.group(1))}, which is "
                            f"not the contract's state directory "
                            f"({state_dir})")
                words = stripped.split()
                if words and not words[-1].startswith("-"):
                    if account and words[-1] != account:
                        failures.append(
                            f"{path}: the command `{stripped}` creates the "
                            f"account `{words[-1]}`, which is not the "
                            f"contract's service account ({account})")

            # (c) The owner and group a command names must be the contract's
            #     service account or root.
            for match in _OWNER_RE.finditer(stripped):
                owner = match.group(1).strip("\"'")
                if account and owner not in ("root", account):
                    failures.append(
                        f"{path}: the command `{stripped}` sets the owner "
                        f"`{owner}`, which is neither the contract's service "
                        f"account ({account}) nor root")
            for match in _GROUP_RE.finditer(stripped):
                group = match.group(1).strip("\"'")
                if account and group not in ("root", account):
                    failures.append(
                        f"{path}: the command `{stripped}` sets the group "
                        f"`{group}`, which is neither the contract's service "
                        f"account ({account}) nor root")

            # (c) A directory the daily job writes into must be owned by
            #     the service account, or the job cannot write to it.
            if _INSTALL_COMMAND_RE.match(stripped) and writable_roots:
                destination = path_tokens[-1] if path_tokens else None
                if destination and any(_is_under(destination, root)
                                       for root in writable_roots):
                    owners = [m.group(1).strip("\"'")
                              for m in _OWNER_RE.finditer(stripped)]
                    if account and account not in owners:
                        failures.append(
                            f"{path}: the command `{stripped}` creates "
                            f"`{destination}` without giving it to the "
                            f"contract's service account ({account}) (the "
                            f"daily job cannot write to a directory it does "
                            f"not own)")

            # (4i-b) The command that creates the served directory (the
            #        export directory the daily job publishes the map
            #        into) must set its owner to the contract's served
            #        directory owner. A contract that changes the owner
            #        while the runbook still creates the directory as the
            #        old account describes a host the daily job cannot
            #        publish into.
            if (_INSTALL_COMMAND_RE.match(stripped) and path_tokens
                    and served_dir_owner and export_dir):
                destination = path_tokens[-1]
                if destination == export_dir:
                    owners = [m.group(1).strip("\"'")
                              for m in _OWNER_RE.finditer(stripped)]
                    if served_dir_owner not in owners:
                        failures.append(
                            f"{path}: the command `{stripped}` creates the "
                            f"served directory `{destination}` with owner "
                            f"{owners or 'none'}, which is not the "
                            f"contract's served directory owner "
                            f"({served_dir_owner}) (the daily job publishes "
                            f"the map into this directory, so the contract "
                            f"and the runbook must agree on who owns it)")

            # (d) Every unit this tree ships must be installed by a
            #     runbook command, into the unit directory its kind
            #     belongs in.
            if _INSTALL_COMMAND_RE.match(stripped) and path_tokens:
                destination = path_tokens[-1]
                name = destination.rsplit("/", 1)[-1]
                if name in shipped_units:
                    installed[name] = destination.rsplit("/", 1)[0]

            # (e) Every unit the runbook installs must also be removed by
            #     a command, so a unit added to the tree but never torn
            #     down is reported as drift rather than left stale on the
            #     host after teardown.
            if _RM_RE.match(stripped):
                for token in path_tokens:
                    rm_name = token.rsplit("/", 1)[-1]
                    if rm_name in shipped_units:
                        removed.add(rm_name)

    for name in sorted(shipped_units):
        if name not in installed:
            failures.append(
                f"{path}: the runbook never installs `{name}` with a "
                f"command (a unit the runbook only names in prose is a unit "
                f"the operator never puts on the host)")
            continue
        expected = ("/etc/systemd/system" if _unit_is_system_unit(name)
                    else "~/.config/systemd/user")
        if _normalize_host_path(installed[name]) != expected:
            kind = "system" if _unit_is_system_unit(name) else "user"
            failures.append(
                f"{path}: the runbook installs `{name}` into "
                f"{installed[name]}, which is not the {kind} unit directory "
                f"({expected}) (a unit installed into the wrong directory "
                f"runs with the wrong identity and the wrong environment "
                f"file)")

    for name in sorted(shipped_units):
        if name in installed and name not in removed:
            failures.append(
                f"{path}: the runbook installs `{name}` but never removes "
                f"it with a command (a unit the runbook puts on the host "
                f"but never tears down leaves stale files after removal)")

    if sign_key and not referenced_sign_key:
        failures.append(
            f"{path}: the runbook never references the manifest signing key "
            f"at the contract's sign_key location ({sign_key}) (the contract "
            f"declares where the key lives but no operator command names that "
            f"path, so the runbook does not build the key location the "
            f"contract describes)")
    if sign_pub_key and not referenced_sign_pub_key:
        failures.append(
            f"{path}: the runbook never references the manifest signature "
            f"verification key at the contract's sign_pub_key location "
            f"({sign_pub_key}) (the contract declares where the public key "
            f"lives but no operator command names that path, so the runbook "
            f"does not build the public key location the contract describes, "
            f"and the operator's signature verification cannot point at it)")

    return checked


# ---------------------------------------------------------------------------
# Growth-guard thresholds (4h)
# ---------------------------------------------------------------------------

# The contract key that declares each free-space threshold, and the
# environment variable the daily job reads that threshold from.
_GROWTH_GUARD_VARS = (
    ("disk_warn_gb", "POSTURE_DISK_WARN_GB"),
    ("disk_crit_gb", "POSTURE_DISK_CRIT_GB"),
)


def _script_growth_guard_default(text: str, variable: str) -> int | None:
    """The default a script uses for a growth-guard variable, or None.

    The daily job reads its thresholds as
    ${POSTURE_DISK_WARN_GB:-5}: the value in the environment file
    wins, and the number after the :- is the default the job falls
    back to. That default is what the contract must describe.
    """
    match = re.search(re.escape(variable) + r":-(\d+)", text)
    return int(match.group(1)) if match else None


def _validate_growth_guard(
    contract: dict[str, str],
    source: str,
    script_paths: list[str],
    failures: list[str],
) -> int:
    """The daily job's free-space thresholds against the host contract.

    The contract declares the warning and the critical free-space
    thresholds; the daily job carries its own defaults for the same two
    numbers. Both must agree, and the critical threshold must be below the
    warning threshold, or the job refuses to build at a level of free space
    the operator believes is still acceptable.

    Returns the number of thresholds checked.
    """
    values: dict[str, int] = {}
    for key, variable in _GROWTH_GUARD_VARS:
        raw = contract.get(key, "").strip()
        if not raw:
            continue
        try:
            values[key] = int(raw)
        except ValueError:
            failures.append(
                f"{source}: the host contract's {key} ({raw}) is not a whole "
                f"number of gigabytes (the daily job compares free space in "
                f"whole gigabytes, so a fractional threshold cannot be "
                f"checked against it)")

    warn = values.get("disk_warn_gb")
    crit = values.get("disk_crit_gb")
    if warn is not None and crit is not None and crit >= warn:
        failures.append(
            f"{source}: the host contract's critical free-space threshold "
            f"(disk_crit_gb: {crit}) is not below its warning threshold "
            f"(disk_warn_gb: {warn}) (the job warns first and then refuses "
            f"to build, so the critical threshold must be the lower of the "
            f"two)")

    checked = 0
    for path in script_paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for key, variable in _GROWTH_GUARD_VARS:
            if key not in values:
                continue
            default = _script_growth_guard_default(text, variable)
            if default is None:
                continue
            checked += 1
            if default != values[key]:
                failures.append(
                    f"{path}: the daily job's {variable} default "
                    f"({default}) does not match the host contract's {key} "
                    f"({values[key]}) (the job would warn or refuse to build "
                    f"at a different level of free space than the contract "
                    f"describes)")
    return checked


# ---------------------------------------------------------------------------
# Documented environment defaults (4k)
# ---------------------------------------------------------------------------

# An assignment of the form the daily job uses to read a knob:
#     STATE_DIR="${POSTURE_STATE_DIR:-/var/lib/posture}"
# The environment variable is the name the operator writes in the
# environment file; the text after the :- is the default the job falls
# back to when the operator sets nothing.
_JOB_ASSIGN_RE = re.compile(
    r'^\s*(?P<shell>[A-Z_][A-Z0-9_]*)="\$\{(?P<var>[A-Z_][A-Z0-9_]*)'
    r'(?::-(?P<default>[^}]*))?\}"', re.MULTILINE)

# A shell variable reference inside a default value.
_SHELL_REF_RE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _expand_default(text: str, shell_values: dict[str, str],
                    env_defaults: dict[str, str]) -> str:
    """Expand the shell variable references inside a default value.

    A default may be written in terms of another variable the job
    already resolved ($STATE_DIR/cvelist), so the references are
    expanded against the values known so far.
    """
    out = text
    for _ in range(5):
        def replace(match: re.Match) -> str:
            name = match.group(1) or match.group(2)
            if name in shell_values:
                return shell_values[name]
            if name in env_defaults:
                return env_defaults[name]
            return match.group(0)
        expanded = _SHELL_REF_RE.sub(replace, out)
        if expanded == out:
            break
        out = expanded
    return out


def _script_env_defaults(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """The defaults the daily job falls back to, per environment variable.

    Returns the environment-variable defaults (POSTURE_* -> the value the
    job uses when the operator sets nothing) and the shell-variable
    values the same assignments carry, both resolved.
    """
    env_defaults: dict[str, str] = {}
    shell_values: dict[str, str] = {}
    for match in _JOB_ASSIGN_RE.finditer(text):
        shell = match.group("shell")
        variable = match.group("var")
        default = match.group("default") or ""
        value = _expand_default(default, shell_values, env_defaults)
        shell_values[shell] = value
        env_defaults[variable] = value
    return env_defaults, shell_values


def _runbook_env_defaults(text: str) -> dict[str, str]:
    """The default the runbook's environment table states per variable.

    The table's first column names the variable and its last column
    states the default. Any other table in the runbook (the install
    layout, the shipped artifacts) has a different first column and is
    not read here.
    """
    defaults: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cells) < 3:
            continue
        name = cells[0].strip("`").strip()
        if not re.fullmatch(r"POSTURE_[A-Z_]+|NVD_API_KEY", name):
            continue
        defaults[name] = cells[-1].strip()
    return defaults


def _normalize_default(value: str) -> str:
    """Normalize a documented default for comparison.

    Backticks and surrounding whitespace are noise; an empty default is
    the same statement as "unset".
    """
    cleaned = value.strip().strip("`").strip()
    if not cleaned:
        return "unset"
    return cleaned


def _defaults_agree(documented: str, actual: str) -> bool:
    """True when a documented default is the default the job uses."""
    if documented == actual:
        return True
    try:
        return float(documented) == float(actual)
    except ValueError:
        return False


def _validate_documented_defaults(
    runbook_path: str,
    runbook_text: str,
    script_text: str,
    failures: list[str],
) -> int:
    """The runbook's documented defaults against the daily job's defaults.

    The runbook's environment table tells the operator what each knob
    does and what it is set to when the environment file says nothing.
    The daily job carries its own defaults for the same knobs. Both must
    agree, or the operator sizes the host and writes the environment file
    against numbers the job does not use.

    Returns the number of defaults checked.
    """
    env_defaults, shell_values = _script_env_defaults(script_text)
    documented = _runbook_env_defaults(runbook_text)
    checked = 0
    for name, cell in sorted(documented.items()):
        if name not in env_defaults:
            # The job does not read this variable with a default of its
            # own (the package reads it, or it is optional): there is
            # nothing here to compare against.
            continue
        wanted = _normalize_default(_expand_default(
            _normalize_default(cell), shell_values, env_defaults))
        actual = _normalize_default(env_defaults[name])
        checked += 1
        if _defaults_agree(wanted, actual):
            continue
        failures.append(
            f"{runbook_path}: the runbook documents `{name}` with a default "
            f"of {wanted}, but the daily job falls back to {actual} (the "
            f"runbook's stated default is the number the operator sizes the "
            f"host against, and it is not the number the job uses)")
    return checked


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(paths: list[str]) -> int:
    parser = build_parser()
    top = None
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            top = action
            break
    if top is None:  # pragma: no cover - the CLI always has subcommands
        print("check_deployment_line: FAILED — the CLI exposes no subcommands")
        return 1

    failures: list[str] = []
    checked = 0  # posture invocations validated

    # Separate shell scripts, service units, timer units, and runbooks.
    script_paths: list[str] = []
    unit_paths: list[str] = []
    timer_paths: list[str] = []
    runbook_paths: list[str] = []
    for p in paths:
        if _is_runbook(p):
            runbook_paths.append(p)
        elif _is_timer_file(p):
            timer_paths.append(p)
        elif _is_unit_file(p):
            unit_paths.append(p)
        else:
            script_paths.append(p)

    # --- The host contract the runbook declares (3f, 4f) ---
    # The contract is the runbook's machine-readable statement of the
    # paths and the service account the units are written against. It is
    # read from a runbook in scope; when no runbook is in scope the
    # repository's own deployment runbook is the source of truth.
    # Every runbook in scope is checked against the contract IT declares;
    # the contract the units are checked against is the first one declared
    # in scope, or the repository's own runbook when no runbook is in
    # scope.
    runbook_contracts: dict[str, dict[str, str]] = {}
    for candidate in runbook_paths:
        try:
            ctext = Path(candidate).read_text(encoding="utf-8")
        except OSError:
            continue
        found = _host_contract(_code_blocks(ctext))
        if found is not None:
            runbook_contracts[candidate] = found
    contract: dict[str, str] | None = None
    contract_source: str | None = None
    for candidate in runbook_paths:
        if candidate in runbook_contracts:
            contract = runbook_contracts[candidate]
            contract_source = candidate
            break
    default_runbook = Path("docs/deployment.md")
    if contract is None and default_runbook.is_file():
        try:
            dtext = default_runbook.read_text(encoding="utf-8")
        except OSError:
            dtext = ""
        found = _host_contract(_code_blocks(dtext))
        if found is not None:
            contract = found
            contract_source = str(default_runbook)
    install_root = _DEFAULT_INSTALL_ROOT
    if contract is not None and "install_root" in contract:
        install_root = _normalize_host_path(contract["install_root"])

    # --- Shell scripts: invocation + option validation (existing logic) ---
    for path in script_paths:
        try:
            text = open(path, encoding="utf-8").read()
        except OSError as exc:
            failures.append(f"{path}: cannot read ({exc})")
            continue
        for words, invocation_text in _invocations(text):
            checked += 1
            _validate_one_invocation(words, invocation_text, path, top, failures)

    # --- Unit files: invocations, script paths, env contract ---
    package_vars = _package_env_vars() if unit_paths else set()

    for path in unit_paths:
        try:
            text = open(path, encoding="utf-8").read()
        except OSError as exc:
            failures.append(f"{path}: cannot read ({exc})")
            continue

        # 3a. Unit invocations: validate posture calls in ExecStart/ExecStartPre.
        for words, invocation_text in _unit_posture_calls(text):
            checked += 1
            _validate_one_invocation(words, invocation_text, path, top, failures)

        # 3b. Unit script paths: verify referenced bash scripts exist in tree.
        workdir = _unit_workdir(text)
        for abs_path, rel_path in _unit_script_refs(
                text, workdir, install_root):
            if rel_path is None:
                failures.append(
                    f"{path}: ExecStart references `{abs_path}` which does "
                    f"not map to a path in this tree (WorkingDirectory="
                    f"{workdir or '<unset>'})")
                continue
            if not Path(rel_path).exists():
                failures.append(
                    f"{path}: ExecStart references `{abs_path}` -> "
                    f"{rel_path} which does not exist in this tree")
                continue
            # The referenced script is also checked for invocations if it
            # has not already been passed explicitly.
            if rel_path not in script_paths:
                script_paths.append(rel_path)
                try:
                    stext = open(rel_path, encoding="utf-8").read()
                except OSError as exc:
                    failures.append(f"{rel_path}: cannot read ({exc})")
                    continue
                for words2, inv2 in _invocations(stext):
                    checked += 1
                    _validate_one_invocation(
                        words2, inv2, rel_path, top, failures)

        # 3c. Unit environment contract: every POSTURE_*/NVD_API_KEY var set
        #     via Environment= must be read by the invocation target.
        env_settings = _unit_env_settings(text)
        # Build the read-set for this unit: package vars plus any referenced
        # script's vars (the script calls posture, so both are in the chain).
        read_vars = set(package_vars)
        for _abs, rel in _unit_script_refs(text, workdir, install_root):
            if rel and Path(rel).exists():
                read_vars |= _script_env_vars(rel)

        for key in sorted(env_settings):
            if key in _RUNTIME_VARS:
                continue
            if not _VAR_NAME_RE.fullmatch(key):
                # Not a posture-specific variable; no contract to check.
                continue
            if key not in read_vars:
                failures.append(
                    f"{path}: Environment= sets `{key}` but nothing in the "
                    f"invocation chain reads it (the posture package and "
                    f"any referenced script do not reference `{key}`)")

    # --- Host contract: the units against the contract the runbook
    #     declares (3f), and the environment files that contract names
    #     against the units that load them.
    if contract is not None and unit_paths:
        system_env = _normalize_host_path(contract.get(
            "system_env_file", "/etc/posture/posture.env"))
        user_env = _normalize_host_path(contract.get(
            "user_env_file", "~/.config/posture/env"))
        loaded_system = False
        loaded_user = False
        for path in unit_paths:
            try:
                utext = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            loaded = _validate_unit_contract(path, utext, contract, failures)
            if loaded is None:
                continue
            if loaded == system_env:
                loaded_system = True
            if loaded == user_env:
                loaded_user = True
        # The environment-file coverage is a claim about every unit the
        # operator installs, so it is only checked when every shipped
        # service unit is in scope.
        in_scope = {Path(p).name for p in unit_paths}
        whole_set = in_scope >= _shipped_service_names()
        if not whole_set:
            loaded_system = loaded_user = True
        if "system_env_file" in contract and not loaded_system:
            failures.append(
                f"{contract_source}: the host contract's system_env_file "
                f"({system_env}) is not loaded by any unit that runs as the "
                f"system service account (an environment file the operator "
                f"creates that no unit reads is dead configuration)")
        if "user_env_file" in contract and not loaded_user:
            failures.append(
                f"{contract_source}: the host contract's user_env_file "
                f"({user_env}) is not loaded by any unit that runs as the "
                f"operator (an environment file the operator creates that no "
                f"unit reads is dead configuration)")

    # --- Timer units: scheduling contract (3d) ---
    shipped_services = _shipped_service_names() if timer_paths else set()
    for path in timer_paths:
        try:
            text = open(path, encoding="utf-8").read()
        except OSError as exc:
            failures.append(f"{path}: cannot read ({exc})")
            continue
        _validate_timer(text, path, shipped_services, failures)
        # A timer may carry posture invocations too (unusual but possible).
        for words, invocation_text in _unit_posture_calls(text):
            checked += 1
            _validate_one_invocation(words, invocation_text, path, top, failures)

    # 3e. Service scheduling coverage: every service must be scheduled by
    #     a timer in scope.
    _check_service_coverage(unit_paths, timer_paths, failures)

    # 4n (timer side). The publish timer's actual cadence against the
    #     cadence the host contract declares. The contract-level half of
    #     this dimension (cadence strictly less than the maximum map age)
    #     is checked per runbook above; this half needs the timer that
    #     schedules the publish, so it runs here against the first contract
    #     in scope (or the repository's own runbook when no runbook is in
    #     scope).
    if contract is not None:
        _validate_publish_cadence_timer(
            contract, contract_source, timer_paths, unit_paths, failures)

    # 4h. The daily job's growth-guard thresholds against the contract.
    #     The daily job is always checked, even when the gate is run on
    #     the runbook alone, because the contract describes the job's
    #     thresholds whether or not the job's script is in scope.
    if contract is not None:
        growth_scripts = list(script_paths)
        daily_script = "scripts/vps_spine.sh"
        if daily_script not in growth_scripts and Path(daily_script).is_file():
            growth_scripts.append(daily_script)
        _validate_growth_guard(
            contract, contract_source or "the host contract",
            growth_scripts, failures)

    # --- Deployment runbook: unit coverage, tree paths, commands, and the
    #     environment contract between the runbook and the shipped tree
    #     (4a-4e).
    # The daily job's own defaults, read from the shipped script. The
    # runbook's environment table states a default for every knob the
    # job reads, so the daily job is always read, even when the gate is
    # run on the runbook alone.
    daily_script_text = ""
    daily_script_path = Path("scripts/vps_spine.sh")
    if daily_script_path.is_file():
        try:
            daily_script_text = daily_script_path.read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            daily_script_text = ""

    if runbook_paths:
        runbook_package_vars = _package_env_vars()
        runbook_script_vars = _script_env_vars("scripts/vps_spine.sh")
        for path in runbook_paths:
            try:
                text = open(path, encoding="utf-8").read()
            except OSError as exc:
                failures.append(f"{path}: cannot read ({exc})")
                continue
            checked += _validate_runbook(
                path, text, top, runbook_package_vars, runbook_script_vars,
                failures)
            _validate_host_contract(
                path, text, runbook_contracts.get(path), failures)
            _validate_served_map_layout(
                path, text, runbook_contracts.get(path), failures)
            _validate_published_map_verification(
                path, text, runbook_contracts.get(path), failures)
            _validate_published_map_freshness(
                path, text, runbook_contracts.get(path), failures)
            _validate_publish_cadence_contract(
                path, text, runbook_contracts.get(path), failures)
            _validate_overlay_coverage_contract(
                path, runbook_contracts.get(path), failures)
            _validate_overlay_coverage_verification(
                path, text, runbook_contracts.get(path), failures)
            _validate_overlay_ingest_scope_contract(
                path, runbook_contracts.get(path), failures)
            _validate_overlay_release_coverage_contract(
                path, runbook_contracts.get(path), failures)
            _validate_overlay_release_coverage_verification(
                path, text, runbook_contracts.get(path), failures)
            _validate_overlay_package_coverage_contract(
                path, runbook_contracts.get(path), failures)
            _validate_overlay_package_coverage_verification(
                path, text, runbook_contracts.get(path), failures)
            _validate_kev_coverage_contract(
                path, runbook_contracts.get(path), failures)
            _validate_kev_coverage_verification(
                path, text, runbook_contracts.get(path), failures)
            _validate_flat_overlay_coverage_contract(
                path, runbook_contracts.get(path), failures,
                "apple_fixes_min_rows", "apple_fixes_max_age_days",
                "Apple fix")
            _validate_flat_overlay_coverage_verification(
                path, text, runbook_contracts.get(path), failures,
                "apple_fixes_min_rows", "apple_fixes_max_age_days",
                "--require-apple-fixes",
                "--require-apple-fixes-max-age-days", "Apple fix")
            _validate_flat_overlay_coverage_contract(
                path, runbook_contracts.get(path), failures,
                "epss_min_rows", "epss_max_age_days", "EPSS")
            _validate_apple_product_coverage_contract(
                path, runbook_contracts.get(path), failures)
            _validate_apple_product_coverage_verification(
                path, text, runbook_contracts.get(path), failures)
            _validate_epss_score_band_coverage_contract(
                path, runbook_contracts.get(path), failures)
            _validate_epss_score_band_coverage_verification(
                path, text, runbook_contracts.get(path), failures)
            _validate_flat_overlay_coverage_verification(
                path, text, runbook_contracts.get(path), failures,
                "epss_min_rows", "epss_max_age_days",
                "--require-epss", "--require-epss-max-age-days", "EPSS")
            checked += _validate_runbook_host_commands(
                path, text, runbook_contracts.get(path), failures)
            if daily_script_text:
                _validate_documented_defaults(
                    path, text, daily_script_text, failures)

    # The nightly job is the thing that builds the map the operator checks,
    # so it must make the same overlay-coverage check the runbook shows.
    if daily_script_text and contract is not None:
        _validate_overlay_coverage_job(
            "scripts/vps_spine.sh", daily_script_text, contract, failures)

    # 4p (job side). The nightly job's overlay ingest scope must be the
    #     one the contract declares, so a dropped --release that narrows
    #     the overlay silently while the coverage check still passes is
    #     loud at check time.
    if daily_script_text and contract is not None:
        _validate_overlay_ingest_scope_job(
            "scripts/vps_spine.sh", daily_script_text, contract, failures)

    # 4q (job side). The nightly job's per-release overlay coverage must be
    #     the one the contract declares, so a release whose tracker feed
    #     returned nothing (or whose rows stopped being refreshed) is loud
    #     at check time instead of a quietly narrow overlay.
    if daily_script_text and contract is not None:
        _validate_overlay_release_coverage_job(
            "scripts/vps_spine.sh", daily_script_text, contract, failures)

    # 4r (job side). The nightly job's per-package overlay coverage
    #     must be the one the contract declares, so a source package
    #     whose tracker feed returned nothing (and whose rows are
    #     therefore gone) is loud at check time instead of a quietly
    #     narrow overlay that still passes the per-release floor.
    if daily_script_text and contract is not None:
        _validate_overlay_package_coverage_job(
            "scripts/vps_spine.sh", daily_script_text, contract, failures)

    # 4s (job side). The nightly job's known-exploited coverage must be
    #     the one the contract declares, so a known-exploited set that
    #     stopped being refreshed (the ingest is a no-wipe refresh, so a
    #     failed fetch leaves the last-known-good rows serving) is loud
    #     at check time instead of a quiet nightly success.
    if daily_script_text and contract is not None:
        _validate_kev_coverage_job(
            "scripts/vps_spine.sh", daily_script_text, contract, failures)

    # 4t (job side). The nightly job's flat-overlay coverage (Apple fix,
    #     EPSS) must be the one the contract declares, so an overlay that
    #     stopped being refreshed (both ingests are no-wipe on the caller
    #     side, so a failed fetch leaves the last-known-good rows serving)
    #     is loud at check time instead of a quiet nightly success.
    if daily_script_text and contract is not None:
        _validate_flat_overlay_coverage_job(
            "scripts/vps_spine.sh", daily_script_text, contract, failures,
            "apple_fixes_min_rows", "apple_fixes_max_age_days",
            "--require-apple-fixes",
            "--require-apple-fixes-max-age-days", "Apple fix")
        _validate_flat_overlay_coverage_job(
            "scripts/vps_spine.sh", daily_script_text, contract, failures,
            "epss_min_rows", "epss_max_age_days",
            "--require-epss", "--require-epss-max-age-days", "EPSS")

    # 4u (job side). The nightly job's per-product Apple fix coverage must
    #     be the one the contract declares, so a product whose Apple
    #     advisory feed returned nothing (the apple_fixes ingest is a
    #     per-product full refresh, so that product's rows are deleted and
    #     never replaced) is loud at check time instead of a quiet nightly
    #     success against a table that still holds the other products'
    #     rows.
    if daily_script_text and contract is not None:
        _validate_apple_product_coverage_job(
            "scripts/vps_spine.sh", daily_script_text, contract, failures)

    # 4v (job side). The nightly job's per-band EPSS coverage must be the
    #     one the contract declares, so a map that quietly lost every
    #     high-severity CVE in a percentile band (the ones the
    #     prioritization surface depends on) is loud at check time
    #     instead of a quiet nightly success against a table that still
    #     holds 270k low-percentile rows.
    if daily_script_text and contract is not None:
        _validate_epss_score_band_coverage_job(
            "scripts/vps_spine.sh", daily_script_text, contract, failures)

    for failure in failures:
        print(f"check_deployment_line: FAIL — {failure}")
    if failures:
        print(f"check_deployment_line: {len(failures)} failure(s) "
              f"out of {checked} invocation(s) checked")
        return 1
    # List the classified file sets in the summary so the operator can see
    # what was covered.
    summary_parts: list[str] = []
    if script_paths:
        summary_parts.append(f"{len(script_paths)} script(s)")
    if unit_paths:
        summary_parts.append(f"{len(unit_paths)} service unit(s)")
    if timer_paths:
        summary_parts.append(f"{len(timer_paths)} timer unit(s)")
    if runbook_paths:
        summary_parts.append(f"{len(runbook_paths)} runbook(s)")
    coverage = ", ".join(summary_parts) or "no files"
    ok_parts = [
        "every invocation resolves against this repository's CLI",
        "every unit script path exists",
        "every unit environment variable is read",
    ]
    if timer_paths:
        ok_parts.append("every timer scheduling contract holds")
    if unit_paths and timer_paths:
        ok_parts.append("every service is scheduled by a timer")
    if runbook_paths:
        ok_parts.append("every runbook reference resolves")
    if contract is not None and unit_paths:
        ok_parts.append("every unit matches the host contract")
    if runbook_paths and contract is not None:
        ok_parts.append("the host contract and the install layout agree")
    if runbook_paths and contract is not None:
        ok_parts.append("every runbook host command matches the contract")
        ok_parts.append("every installed unit is removed by the runbook")
        ok_parts.append("the manifest signing key and the served directory "
                        "owner match the contract")
        ok_parts.append("the published-map layout matches the publish "
                        "implementation")
        ok_parts.append("the published map is verified by the runbook "
                        "(including the signature check when it is signed)")
        ok_parts.append("the served map's freshness is checked against the "
                        "contract's maximum age")
        ok_parts.append("the publish cadence is strictly less than the "
                        "maximum map age and the publish timer fires at "
                        "least that often")
        ok_parts.append("the served map's overlay coverage is checked "
                        "against the contract's required overlays")
        ok_parts.append("the nightly job's overlay ingest scope matches "
                        "the contract's declared per-distro releases and "
                        "packages")
        ok_parts.append("the served map's per-release overlay coverage is "
                        "checked against the contract's row floor and "
                        "freshness allowance")
        ok_parts.append("the served map's per-package overlay coverage "
                        "is checked against the contract's per-package "
                        "row floor")
        ok_parts.append("the served map's known-exploited coverage is "
                        "checked against the contract's row floor and "
                        "freshness allowance")
        ok_parts.append("the served map's Apple fix and EPSS overlay "
                        "coverage is checked against the contract's row "
                        "floors and freshness allowances")
        ok_parts.append("the served map's per-product Apple fix coverage "
                        "is checked against the contract's product scope "
                        "and per-product row floor")
        ok_parts.append("the served map's per-band EPSS coverage is "
                        "checked against the contract's percentile band "
                        "scope and per-band row floor")
    if contract is not None:
        ok_parts.append("the growth-guard thresholds match the contract")
    if runbook_paths and daily_script_text:
        ok_parts.append("every documented environment default matches the "
                        "daily job's own default")
    ok_text = ", ".join(ok_parts)
    print(f"check_deployment_line: OK — {ok_text} ({checked} invocation(s) "
          f"checked, {coverage})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
PY
