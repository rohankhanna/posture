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
fi

python3 - "${FILES[@]}" <<'PY'
import argparse
import re
import sys
from pathlib import Path

from posture.cli import build_parser

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
    """Strip /usr/bin/env or /usr/bin/ runner prefixes from an ExecStart value."""
    value = value.strip()
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


def _map_to_tree(abs_path: str, workdir: str | None) -> str | None:
    """Map an absolute path from a unit to a tree-relative path.

    Tries the unit's WorkingDirectory prefix first, then the conventional
    /opt/posture deployment root. Returns the tree-relative path string if
    the mapping is found (the file may or may not exist), or None if no
    known prefix matches.
    """
    p = abs_path.strip("\"'")
    for prefix in (workdir, "/opt/posture"):
        if prefix and p.startswith(prefix + "/"):
            return p[len(prefix) + 1:]
    return None


def _unit_script_refs(text: str, workdir: str | None) -> list[tuple[str, str | None]]:
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
                rel = _map_to_tree(tok, workdir)
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

    # Separate shell scripts, service units, and timer units.
    script_paths: list[str] = []
    unit_paths: list[str] = []
    timer_paths: list[str] = []
    for p in paths:
        if _is_timer_file(p):
            timer_paths.append(p)
        elif _is_unit_file(p):
            unit_paths.append(p)
        else:
            script_paths.append(p)

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
        for abs_path, rel_path in _unit_script_refs(text, workdir):
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
        for _abs, rel in _unit_script_refs(text, workdir):
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
    ok_text = ", ".join(ok_parts)
    print(f"check_deployment_line: OK — {ok_text} ({checked} invocation(s) "
          f"checked, {coverage})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
PY
