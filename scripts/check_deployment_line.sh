#!/usr/bin/env bash
# check_deployment_line — the command gate for the daily spine job.
#
# The daily spine script (scripts/vps_spine.sh) is a shell script that calls
# this repository's command-line interface. When the script and the package
# drift apart — a branch that keeps the script but not the command, or a merge
# that takes one side of each — the job calls a command that does not exist.
# The shell then reports "command not found", the script's best-effort
# handlers swallow it, and the spine silently loses a capability: a missing
# growth guard, a missing overlay, a missing publish step. posture's rule is
# that a missing capability is a loud UNKNOWN, never a silent "clean".
#
# This gate closes that window in two dimensions:
#
#   1. Command and subcommand shape — every `posture <command>` and
#      `posture <command> <subcommand>` in the daily script must resolve
#      against the command-line interface this repository actually ships.
#
#   2. Option names — every `--option` the daily script passes to a
#      `posture` invocation must be an option the corresponding parser
#      accepts. A renamed option (e.g. `--cap` becoming `--limit`) silently
#      drops a capability the same way a missing command did: the shell
#      passes an unknown option, argparse rejects it at run time, and the
#      best-effort handler swallows the failure. The gate makes that drift
#      loud at check time, before the job ever runs.
#
# Usage: check_deployment_line.sh [SCRIPT ...]   (default: scripts/vps_spine.sh)
# Exits 0 when every invocation resolves, 1 otherwise.
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_root}"

SCRIPTS=("$@")
if [ "${#SCRIPTS[@]}" -eq 0 ]; then
  SCRIPTS=("scripts/vps_spine.sh")
fi

python3 - "${SCRIPTS[@]}" <<'PY'
import argparse
import re
import sys

from posture.cli import build_parser

# A `posture` invocation at the start of a command line in the script.
_CALL = re.compile(r"^\s*posture\s+([^\n;&|]*)", re.MULTILINE)

# A clean long option flag: --word or --word-word (letters, digits, hyphens).
_LONG_FLAG = re.compile(r"^--[a-zA-Z][a-zA-Z0-9_-]*$")
# A clean short option flag: -X (single letter).
_SHORT_FLAG = re.compile(r"^-[a-zA-Z]$")


def _invocations(text: str):
    """Every `posture ...` invocation in the script, in order.

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
    checked = 0
    for path in paths:
        try:
            text = open(path, encoding="utf-8").read()
        except OSError as exc:
            failures.append(f"{path}: cannot read ({exc})")
            continue
        for words, invocation_text in _invocations(text):
            checked += 1
            command = words[0]
            if command not in top.choices:
                failures.append(f"{path}: `posture {command}` is not a command "
                                f"this repository provides")
                continue
            cmd_parser = top.choices[command]
            subcommand = None
            if len(words) >= 2:
                accepted_subs = _subcommands(cmd_parser)
                if words[1] not in accepted_subs:
                    failures.append(
                        f"{path}: `posture {' '.join(words[:2])}` is not "
                        f"available (`posture {command}` accepts: "
                        f"{', '.join(sorted(accepted_subs)) or 'no subcommand'})")
                    continue
                subcommand = words[1]

            # Validate option names against the resolved parser.
            target_parser = _resolve_parser(top, command, subcommand)
            accepted_opts = _accepted_options(target_parser)
            used_opts = _option_flags(invocation_text)
            unknown = used_opts - accepted_opts
            if unknown:
                label = f"posture {' '.join(words[:2])}" if subcommand else f"posture {command}"
                failures.append(
                    f"{path}: `{label}` uses unknown option(s) "
                    f"{', '.join(sorted(unknown))} (`{label}` accepts: "
                    f"{', '.join(sorted(accepted_opts)) or 'no options'})")

    for failure in failures:
        print(f"check_deployment_line: FAIL — {failure}")
    if failures:
        print(f"check_deployment_line: {len(failures)} unresolved invocation(s) "
              f"out of {checked} checked")
        return 1
    print(f"check_deployment_line: OK — every invocation in "
          f"{', '.join(paths)} resolves against this repository's CLI "
          f"({checked} checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
PY
