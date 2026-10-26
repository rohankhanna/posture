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
    "system_env_file",
    "user_env_file",
    "service_account",
)
# The contract keys that name a path on the host.
_CONTRACT_PATH_KEYS = (
    "install_root",
    "state_dir",
    "export_dir",
    "system_env_file",
    "user_env_file",
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

    # --- Deployment runbook: unit coverage, tree paths, commands, and the
    #     environment contract between the runbook and the shipped tree
    #     (4a-4e).
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
    ok_text = ", ".join(ok_parts)
    print(f"check_deployment_line: OK — {ok_text} ({checked} invocation(s) "
          f"checked, {coverage})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
PY
