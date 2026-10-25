"""The deployment-line command gate.

The daily spine script is shell; the capability it calls is this repository's
command-line interface. When the two drift apart the job loses a capability
silently (the shell reports "command not found" and the best-effort handlers
swallow it). These tests pin the gate that makes that drift loud.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GATE = REPO_ROOT / "scripts" / "check_deployment_line.sh"
DAILY_SCRIPT = REPO_ROOT / "scripts" / "vps_spine.sh"


def _run_gate(script: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        ["bash", str(GATE), str(script)],
        capture_output=True, text=True, cwd=str(REPO_ROOT), env=env,
    )


def test_gate_passes_on_the_repository_daily_script():
    result = _run_gate(DAILY_SCRIPT)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout


def test_gate_rejects_an_unknown_command(tmp_path):
    script = tmp_path / "vps_spine.sh"
    script.write_text("posture stream --db /tmp/x.db\n"
                      "posture not-a-command --db /tmp/x.db\n")
    result = _run_gate(script)
    assert result.returncode == 1
    assert "not-a-command" in result.stdout


def test_gate_rejects_an_unknown_subcommand(tmp_path):
    script = tmp_path / "vps_spine.sh"
    script.write_text("posture spine publish --db /tmp/x.db --out /tmp/out\n"
                      "posture spine not-a-sub --db /tmp/x.db\n")
    result = _run_gate(script)
    assert result.returncode == 1
    assert "not-a-sub" in result.stdout


def test_gate_rejects_an_unknown_ingest_peer(tmp_path):
    script = tmp_path / "vps_spine.sh"
    script.write_text("posture ingest not-a-peer --db /tmp/x.db\n")
    result = _run_gate(script)
    assert result.returncode == 1
    assert "not-a-peer" in result.stdout


def test_gate_accepts_a_known_command_with_no_subcommand(tmp_path):
    script = tmp_path / "vps_spine.sh"
    script.write_text("posture purge --db /tmp/x.db --max-age-days 3650\n")
    result = _run_gate(script)
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_joins_line_continuations(tmp_path):
    # The daily script calls the multi-line ubuntu ingest; a continuation
    # must not hide the command from the gate.
    script = tmp_path / "vps_spine.sh"
    script.write_text("posture ingest ubuntu \\\n"
                      "  --release noble --package linux --db /tmp/x.db\n")
    result = _run_gate(script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 checked" in result.stdout


def test_gate_ignores_shell_expansions(tmp_path):
    # A variable that expands to an option must not be mistaken for a
    # subcommand, and must not break the check.
    script = tmp_path / "vps_spine.sh"
    script.write_text('posture spine publish --db "$DB_PATH" '
                      '--out "$OUT" ${SIGN_KEY:+--sign-key "$SIGN_KEY"}\n')
    result = _run_gate(script)
    assert result.returncode == 0, result.stdout + result.stderr


def test_daily_script_calls_the_growth_guard():
    # The daily job must run the bounded-growth purge and the disk guard:
    # the catalog only grows, and the host's disk does not.
    text = DAILY_SCRIPT.read_text()
    assert "posture purge" in text
    assert "DISK_CRIT_GB" in text
    assert "posture spine publish" in text


def test_daily_script_purges_before_it_publishes():
    # The purge must run BEFORE the publish, so the published map is the
    # purged map in one atomic publish and the export never carries rows
    # that are about to be forgotten.
    text = DAILY_SCRIPT.read_text()
    assert text.index("posture purge") < text.index("posture spine publish")


@pytest.mark.parametrize("command", ["purge", "spine", "ingest"])
def test_cli_provides_the_commands_the_daily_script_uses(command):
    from posture.cli import build_parser
    parser = build_parser()
    top = None
    for action in parser._actions:
        if hasattr(action, "choices") and action.choices and hasattr(
                action, "_name_parser_map"):
            top = action
            break
    assert top is not None
    assert command in top.choices
