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
# This gate closes that window: every `posture ...` invocation in the daily
# script must resolve against the command-line interface this repository
# actually ships.
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


def _invocations(text: str):
    """Every `posture ...` invocation in the script, in order.

    Line continuations are joined first, and shell expansions are dropped:
    the gate checks the SHAPE of the invocation (which command, which
    subcommand), not the values the variables hold at run time.
    """
    joined = text.replace("\\\n", " ")
    for raw in _CALL.finditer(joined):
        # keep only the leading command words: stop at the first option
        command_words = []
        for token in raw.group(1).split():
            token = token.strip("\"'")
            if token.startswith("-") or "${" in token or "$(" in token:
                break
            command_words.append(token)
        if command_words:
            yield command_words


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
        for words in _invocations(text):
            checked += 1
            command = words[0]
            if command not in top.choices:
                failures.append(f"{path}: `posture {command}` is not a command "
                                f"this repository provides")
                continue
            if len(words) == 1:
                continue
            accepted = _subcommands(top.choices[command])
            if words[1] not in accepted:
                failures.append(
                    f"{path}: `posture {' '.join(words[:2])}` is not available "
                    f"(`posture {command}` accepts: "
                    f"{', '.join(sorted(accepted)) or 'no subcommand'})")

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
