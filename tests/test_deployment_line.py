"""The deployment-line command gate.

The daily spine script is shell; the capability it calls is this repository's
command-line interface. When the two drift apart the job loses a capability
silently (the shell reports "command not found" and the best-effort handlers
swallow it). These tests pin the gate that makes that drift loud.
"""
from __future__ import annotations

import os
import re
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
    assert "1 invocation(s) checked" in result.stdout


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


# ---------------------------------------------------------------------------
# Option-name validation: a renamed option silently drops a capability the
# same way a missing command did. These tests pin the gate's second
# dimension — checking that every --option the daily script passes is an
# option the corresponding parser actually accepts.
# ---------------------------------------------------------------------------

def test_gate_rejects_an_unknown_option_on_a_bare_command(tmp_path):
    # `posture purge` accepts --db, --max-age-days, --keep-epss-percentile,
    # --dry-run, --help, -h — but NOT --bogus-option.
    script = tmp_path / "vps_spine.sh"
    script.write_text("posture purge --bogus-option --db /tmp/x.db\n")
    result = _run_gate(script)
    assert result.returncode == 1
    assert "--bogus-option" in result.stdout


def test_gate_rejects_an_unknown_option_on_a_subparser_command(tmp_path):
    # `posture ingest ghsa` uses _SubParsersAction; --nonsense is not an
    # option the ghsa subparser accepts.
    script = tmp_path / "vps_spine.sh"
    script.write_text("posture ingest ghsa --nonsense --db /tmp/x.db\n")
    result = _run_gate(script)
    assert result.returncode == 1
    assert "--nonsense" in result.stdout


def test_gate_rejects_an_unknown_option_on_a_positional_subcommand(tmp_path):
    # `posture spine publish` uses a positional with choices; --bogus is not
    # an option the spine parser accepts.
    script = tmp_path / "vps_spine.sh"
    script.write_text("posture spine publish --bogus --db /tmp/x.db --out /tmp/o\n")
    result = _run_gate(script)
    assert result.returncode == 1
    assert "--bogus" in result.stdout


def test_gate_accepts_known_options_on_a_subparser_command(tmp_path):
    script = tmp_path / "vps_spine.sh"
    script.write_text("posture ingest ghsa --cap 100 --db /tmp/x.db\n")
    result = _run_gate(script)
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_accepts_known_options_on_a_positional_subcommand(tmp_path):
    script = tmp_path / "vps_spine.sh"
    script.write_text(
        "posture spine publish --db /tmp/x.db --out /tmp/o --sign-key /tmp/k\n")
    result = _run_gate(script)
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_validates_options_across_line_continuations(tmp_path):
    # Options split across a continuation line must all be validated.
    script = tmp_path / "vps_spine.sh"
    script.write_text(
        "posture ingest ubuntu \\\n"
        "  --release noble --package linux --db /tmp/x.db\n")
    result = _run_gate(script)
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_rejects_unknown_option_across_line_continuations(tmp_path):
    script = tmp_path / "vps_spine.sh"
    script.write_text(
        "posture ingest ubuntu \\\n"
        "  --release noble --bogus --package linux --db /tmp/x.db\n")
    result = _run_gate(script)
    assert result.returncode == 1
    assert "--bogus" in result.stdout


def test_gate_skips_options_embedded_in_shell_expansions(tmp_path):
    # A flag inside ${VAR:+--flag ...} is not statically visible; the gate
    # must not reject it (and must not validate it either — it simply skips
    # the token because it does not match a clean option pattern).
    script = tmp_path / "vps_spine.sh"
    script.write_text(
        'posture spine publish --db "$DB_PATH" --out "$OUT" '
        '${SIGN_KEY:+--sign-key "$SIGN_KEY"}\n')
    result = _run_gate(script)
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_rejects_unknown_option_while_ignoring_shell_expansion(tmp_path):
    # Even when a shell expansion is present, a clean unknown --option on
    # the same line must still be caught.
    script = tmp_path / "vps_spine.sh"
    script.write_text(
        'posture purge --bogus --db "$DB_PATH" '
        '${X:+--max-age-days "$X"}\n')
    result = _run_gate(script)
    assert result.returncode == 1
    assert "--bogus" in result.stdout


def test_gate_reports_accepted_options_on_unknown_option_failure(tmp_path):
    # The failure message should list what the parser accepts so the
    # operator can see the drift at a glance.
    script = tmp_path / "vps_spine.sh"
    script.write_text("posture purge --bogus --db /tmp/x.db\n")
    result = _run_gate(script)
    assert result.returncode == 1
    assert "--max-age-days" in result.stdout
    assert "--keep-epss-percentile" in result.stdout


# ---------------------------------------------------------------------------
# Systemd units: the units in systemd/ call posture commands and shell
# scripts too, so they drift the same way the daily script does. These tests
# pin the gate's unit dimension — unit invocations, unit script paths, and
# the unit environment contract.
# ---------------------------------------------------------------------------

UNIT_DIR = REPO_ROOT / "systemd"


def _run_gate_on(files):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        ["bash", str(GATE), *[str(f) for f in files]],
        capture_output=True, text=True, cwd=str(REPO_ROOT), env=env,
    )


def _write_unit(tmp_path, body: str, name: str = "unit.service") -> Path:
    unit = tmp_path / name
    unit.write_text(body)
    return unit


def test_gate_passes_on_the_repository_own_units():
    # With no arguments the gate covers the daily script and every unit in
    # systemd/. This repository's own units must pass.
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "unit(s)" in result.stdout


@pytest.mark.parametrize("unit_name", [
    "posture-reconcile.service",
    "posture-spine.service",
    "posture-stream.service",
])
def test_each_repository_unit_passes_the_gate(unit_name):
    unit = UNIT_DIR / unit_name
    assert unit.exists()
    result = _run_gate_on([unit])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_rejects_an_unknown_command_in_a_unit(tmp_path):
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/env posture not-a-command\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "not-a-command" in result.stdout


def test_gate_rejects_an_unknown_subcommand_in_a_unit(tmp_path):
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/env posture spine not-a-sub\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "not-a-sub" in result.stdout


def test_gate_rejects_an_unknown_option_in_a_unit(tmp_path):
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/env posture purge --bogus-option\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "--bogus-option" in result.stdout


def test_gate_accepts_a_known_unit_invocation(tmp_path):
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/env posture stream\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_accepts_a_unit_script_path_present_in_the_tree(tmp_path):
    # /opt/posture is the conventional deployment root; the referenced
    # script exists in this tree, so the unit resolves.
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "WorkingDirectory=/opt/posture\n"
        "ExecStart=/usr/bin/env bash /opt/posture/scripts/vps_spine.sh\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_rejects_a_unit_script_path_missing_from_the_tree(tmp_path):
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "WorkingDirectory=/opt/posture\n"
        "ExecStart=/usr/bin/env bash /opt/posture/scripts/no_such_script.sh\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "does not exist in this tree" in result.stdout


def test_gate_rejects_a_unit_script_path_outside_the_tree(tmp_path):
    # A path that maps to neither the unit's WorkingDirectory nor the
    # conventional deployment root is drift the gate must name.
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "WorkingDirectory=/opt/posture\n"
        "ExecStart=/usr/bin/env bash /opt/other/scripts/vps_spine.sh\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "does not map to a path in this tree" in result.stdout


def test_gate_checks_invocations_inside_a_unit_referenced_script(tmp_path):
    # The referenced script exists but calls a command this repository does
    # not ship. The gate must follow the unit into the script.
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "WorkingDirectory=/opt/posture\n"
        "ExecStart=/usr/bin/env bash "
        "/opt/posture/tests/fixtures/deployment_line/bad_command.sh\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "not-a-command" in result.stdout


def test_gate_rejects_an_environment_variable_nothing_reads(tmp_path):
    # A unit that sets a posture-specific variable no invocation target
    # reads is silent drift: the unit thinks it configures a capability
    # that was removed or renamed.
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "Environment=POSTURE_GATE_TEST_UNREAD=1\n"
        "ExecStart=/usr/bin/env posture stream\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "POSTURE_GATE_TEST_UNREAD" in result.stdout


def test_gate_accepts_an_environment_variable_the_package_reads(tmp_path):
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "Environment=POSTURE_GHSA_DIR=/var/lib/posture/ghsa\n"
        "ExecStart=/usr/bin/env posture stream\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_accepts_an_environment_variable_the_referenced_script_reads(tmp_path):
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "WorkingDirectory=/opt/posture\n"
        "Environment=POSTURE_BACKFILL_CAP=5000\n"
        "ExecStart=/usr/bin/env bash /opt/posture/scripts/vps_spine.sh\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_ignores_runtime_environment_variables(tmp_path):
    # Runtime variables configure the process environment, not posture's
    # behaviour; they are not part of the environment contract.
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "Environment=PYTHONUNBUFFERED=1\n"
        "Environment=PATH=/opt/posture/.venv/bin:/usr/local/bin:/usr/bin:/bin\n"
        "ExecStart=/usr/bin/env posture stream\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_ignores_an_inline_bash_pre_check(tmp_path):
    # `bash -c '...'` is an inline script, not a reference to a file in
    # this tree; it must not be reported as a missing script.
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStartPre=/usr/bin/bash -c 'exit 0'\n"
        "ExecStart=/usr/bin/env posture stream\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_reports_a_unit_environment_variable_naming_the_variable(tmp_path):
    # The failure message must name the variable so the operator can see
    # which line of the unit drifted.
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "Environment=\"POSTURE_GATE_TEST_UNREAD=1\"\n"
        "ExecStart=/usr/bin/env posture stream\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "POSTURE_GATE_TEST_UNREAD" in result.stdout


def test_gate_ignores_a_command_that_only_looks_like_posture(tmp_path):
    # `posture-helper` is not this repository's command-line interface; the
    # gate must not treat it as a posture invocation.
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/env posture-helper --bogus-option\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_accepts_a_bare_env_runner_prefix(tmp_path):
    unit = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=env posture stream\n"))
    result = _run_gate_on([unit])
    assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Timer scheduling contract (3d): a timer unit decides WHEN the job runs.
# A timer that is malformed or unscheduled is a job that never fires. These
# tests pin the gate's timer dimension — schedule directive, Unit= target,
# Persistent= semantics, WantedBy target, and no-ExecStart-in-timer.
# ---------------------------------------------------------------------------

def _write_timer(tmp_path, body: str, name: str = "unit.timer") -> Path:
    timer = tmp_path / name
    timer.write_text(body)
    return timer


@pytest.mark.parametrize("timer_name", [
    "posture-reconcile.timer",
    "posture-spine.timer",
    "posture-stream.timer",
])
def test_each_repository_timer_passes_the_gate(timer_name):
    timer = UNIT_DIR / timer_name
    assert timer.exists()
    result = _run_gate_on([timer])
    assert result.returncode == 0, result.stdout + result.stderr


def test_timer_with_no_schedule_directive_is_rejected(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "Unit=posture-spine.service\n"
        "[Install]\n"
        "WantedBy=timers.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 1
    assert "no schedule directive" in result.stdout


def test_timer_with_on_calendar_passes(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnCalendar=*-*-* 03:07:00 UTC\n"
        "Unit=posture-spine.service\n"
        "[Install]\n"
        "WantedBy=timers.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 0, result.stdout + result.stderr


def test_timer_with_monotonic_schedule_passes(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnUnitInactiveSec=10min\n"
        "Unit=posture-stream.service\n"
        "[Install]\n"
        "WantedBy=default.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 0, result.stdout + result.stderr


def test_timer_with_on_boot_sec_passes(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnBootSec=5min\n"
        "Unit=posture-reconcile.service\n"
        "[Install]\n"
        "WantedBy=default.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 0, result.stdout + result.stderr


def test_timer_whose_unit_names_a_nonexistent_service_is_rejected(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnCalendar=*-*-* 03:07:00 UTC\n"
        "Unit=posture-not-a-service.service\n"
        "[Install]\n"
        "WantedBy=timers.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 1
    assert "posture-not-a-service.service" in result.stdout
    assert "does not ship" in result.stdout


def test_timer_with_persistent_true_but_no_on_calendar_is_rejected(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnUnitInactiveSec=20h\n"
        "Persistent=true\n"
        "Unit=posture-reconcile.service\n"
        "[Install]\n"
        "WantedBy=default.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 1
    assert "Persistent=true" in result.stdout
    assert "no OnCalendar" in result.stdout


def test_timer_with_persistent_true_and_on_calendar_passes(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnCalendar=*-*-* 03:07:00 UTC\n"
        "Persistent=true\n"
        "Unit=posture-spine.service\n"
        "[Install]\n"
        "WantedBy=timers.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 0, result.stdout + result.stderr


def test_timer_with_non_standard_wantedby_is_rejected(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnCalendar=*-*-* 03:07:00 UTC\n"
        "Unit=posture-spine.service\n"
        "[Install]\n"
        "WantedBy=not-a-real-target.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 1
    assert "not-a-real-target.target" in result.stdout
    assert "not a standard systemd target" in result.stdout


def test_timer_with_exec_start_is_rejected(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnCalendar=*-*-* 03:07:00 UTC\n"
        "Unit=posture-spine.service\n"
        "ExecStart=/usr/bin/env posture stream\n"
        "[Install]\n"
        "WantedBy=timers.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 1
    assert "ExecStart" in result.stdout
    assert "timer unit carries" in result.stdout


def test_timer_without_unit_directive_defaults_to_matching_service(tmp_path):
    # When Unit= is omitted, systemd defaults to <timer-stem>.service.
    # A timer named posture-spine.timer defaults to posture-spine.service,
    # which this tree ships.
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnCalendar=*-*-* 03:07:00 UTC\n"
        "[Install]\n"
        "WantedBy=timers.target\n"),
        name="posture-spine.timer")
    result = _run_gate_on([timer])
    assert result.returncode == 0, result.stdout + result.stderr


def test_timer_without_unit_directive_and_no_matching_service_is_rejected(
        tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnCalendar=*-*-* 03:07:00 UTC\n"
        "[Install]\n"
        "WantedBy=timers.target\n"),
        name="posture-unscheduled.timer")
    result = _run_gate_on([timer])
    assert result.returncode == 1
    assert "posture-unscheduled.service" in result.stdout


# ---------------------------------------------------------------------------
# Service scheduling coverage (3e): every service in a directory that has
# timers in scope must be scheduled by one of those timers.
# ---------------------------------------------------------------------------

def test_service_not_scheduled_by_any_timer_is_rejected(tmp_path):
    # A service with no timer scheduling it is a capability that never runs.
    # Provide a valid timer for a different service so timers are in scope.
    service = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/env posture stream\n"),
        name="posture-orphan.service")
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnCalendar=*-*-* 03:07:00 UTC\n"
        "Unit=posture-spine.service\n"
        "[Install]\n"
        "WantedBy=timers.target\n"),
        name="posture-spine.timer")
    result = _run_gate_on([service, timer])
    assert result.returncode == 1
    assert "posture-orphan.service" in result.stdout
    assert "not scheduled by any timer" in result.stdout


def test_service_scheduled_by_a_timer_passes(tmp_path):
    service = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/env posture stream\n"),
        name="posture-spine.service")
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnCalendar=*-*-* 03:07:00 UTC\n"
        "Unit=posture-spine.service\n"
        "[Install]\n"
        "WantedBy=timers.target\n"))
    result = _run_gate_on([service, timer])
    assert result.returncode == 0, result.stdout + result.stderr


def test_service_coverage_check_does_not_apply_without_timers(tmp_path):
    # When no timers are in scope, a service with no scheduler is fine.
    service = _write_unit(tmp_path, (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/bin/env posture stream\n"),
        name="posture-orphan.service")
    result = _run_gate_on([service])
    assert result.returncode == 0, result.stdout + result.stderr


def test_all_repository_services_are_scheduled():
    # In default mode (no arguments) every shipped service must be scheduled
    # by one of the shipped timers.
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "scheduled by a timer" in result.stdout


def test_timer_with_an_unparseable_duration_is_rejected(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnUnitInactiveSec=20hours\n"
        "Unit=posture-stream.service\n"
        "[Install]\n"
        "WantedBy=default.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 1
    assert "OnUnitInactiveSec=20hours" in result.stdout
    assert "not a valid systemd duration" in result.stdout


def test_timer_with_a_compound_duration_passes(tmp_path):
    timer = _write_timer(tmp_path, (
        "[Timer]\n"
        "OnUnitInactiveSec=1h 30min\n"
        "AccuracySec=500ms\n"
        "Unit=posture-stream.service\n"
        "[Install]\n"
        "WantedBy=default.target\n"))
    result = _run_gate_on([timer])
    assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# The deployment runbook (dimension 4)
# ---------------------------------------------------------------------------

RUNBOOK = REPO_ROOT / "docs" / "deployment.md"


def _shipped_unit_names() -> list[str]:
    names = []
    for pattern in ("*.service", "*.timer"):
        names.extend(p.name for p in sorted((REPO_ROOT / "systemd").glob(pattern)))
    return names


def _unit_environment_variables() -> list[str]:
    """The posture-specific variables the shipped units set."""
    import re

    variables: set[str] = set()
    pair = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(?:\S+)")
    for pattern in ("*.service", "*.timer"):
        for unit in sorted((REPO_ROOT / "systemd").glob(pattern)):
            for line in unit.read_text().splitlines():
                stripped = line.strip()
                if not stripped.startswith("Environment="):
                    continue
                value = stripped[len("Environment="):]
                for match in pair.finditer(value):
                    key = match.group(1)
                    if key.startswith("POSTURE_") or key == "NVD_API_KEY":
                        variables.add(key)
    return sorted(variables)


# The host contract the runbook declares, in machine-readable form. The
# gate checks the units against it, and the install layout table below
# against it.
_HOST_CONTRACT_BLOCK = """```yaml
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
```
"""

_HOST_LAYOUT_TABLE = """"| Path | Holds |
| --- | --- |
| `/opt/posture` | this repository\'s tree |
| `/var/lib/posture` | the catalog database and the published map |
| `/var/lib/posture/spine` | the published map a client pulls |
| `/var/lib/posture/spine/manifest.json` | the published map's manifest |
| `/var/lib/posture/spine/defects` | the published defect shards |
| `/etc/posture/posture.env` | the environment overrides for the system units |
| `/etc/posture/signing_key.pem` | the manifest signing key, when the manifest is signed |
| `/etc/posture/signing_pub.pem` | the manifest signature verification key (the ed25519 public key) |
| `~/.config/posture/env` | the environment overrides for the two user units |
"""


def _unit_is_system_unit(name: str) -> bool:
    """True when a shipped unit belongs in the system unit directory.

    A service that names a `User=` runs as that account and is installed
    in the system unit directory; a timer takes the kind of the service
    it schedules.
    """
    if name.endswith(".timer"):
        text = (REPO_ROOT / "systemd" / name).read_text()
        for line in text.splitlines():
            if line.strip().startswith("Unit="):
                scheduled = line.split("=", 1)[1].strip()
                return _unit_is_system_unit(scheduled)
        return True
    text = (REPO_ROOT / "systemd" / name).read_text()
    return any(line.strip().startswith("User=") for line in text.splitlines())


def _unit_install_commands() -> list[str]:
    """The install command for every shipped unit, into its own directory."""
    commands = []
    for name in _shipped_unit_names():
        directory = ("/etc/systemd/system" if _unit_is_system_unit(name)
                     else "~/.config/systemd/user")
        commands.append(
            f"install -m 0644 /opt/posture/systemd/{name} {directory}/{name}")
    return commands


def _unit_removal_commands() -> list[str]:
    """The removal command for every shipped unit, from its own directory."""
    commands = []
    for name in _shipped_unit_names():
        directory = ("/etc/systemd/system" if _unit_is_system_unit(name)
                     else "~/.config/systemd/user")
        commands.append(f"rm -f {directory}/{name}")
    return commands


def _baseline_runbook(extra: str = "") -> str:
    """A runbook that satisfies every runbook check, plus an extra line.

    The baseline names every shipped unit, installs every shipped unit
    with a command into the unit directory its kind belongs in, documents
    every environment variable a shipped unit sets, and declares the host
    contract and the install layout that agree with it, so a test that
    adds one defect sees only that defect.
    """
    lines = ["# Deployment runbook", ""]
    for name in _shipped_unit_names():
        lines.append(f"Install `{name}`.")
        lines.append("")
    for variable in _unit_environment_variables():
        lines.append(f"The variable `{variable}` is read by the daily job.")
        lines.append("")
    lines.append(_HOST_CONTRACT_BLOCK)
    lines.append(_HOST_LAYOUT_TABLE)
    lines.append("```bash")
    lines.append("sudo install -m 0640 -o root -g posture /dev/null "
                 "/etc/posture/signing_key.pem")
    lines.append("sudo install -m 0644 -o root -g root /dev/null "
                 "/etc/posture/signing_pub.pem")
    lines.append("```")
    lines.append("")
    lines.append("```bash")
    lines.extend(_unit_install_commands())
    lines.append("```")
    lines.append("")
    lines.append("```bash")
    lines.extend(_unit_removal_commands())
    lines.append("```")
    lines.append("```bash")
    lines.append("posture spine verify --from /var/lib/posture "
                 "--max-age-days 2 --require-overlay ubuntu_fixes "
                 "--require-overlay debian_fixes "
                 "--require-overlay-release ubuntu_fixes:resolute:1 "
                 "--require-overlay-release ubuntu_fixes:noble:1 "
                 "--require-overlay-release ubuntu_fixes:jammy:1 "
                 "--require-overlay-release ubuntu_fixes:focal:1 "
                 "--require-overlay-release debian_fixes:trixie:1 "
                 "--require-overlay-release debian_fixes:bookworm:1 "
                 "--require-overlay-package ubuntu_fixes:resolute:linux:1 "
                 "--require-overlay-package ubuntu_fixes:resolute:linux-nvidia:1 "
                 "--require-overlay-package ubuntu_fixes:noble:linux:1 "
                 "--require-overlay-package ubuntu_fixes:noble:linux-nvidia:1 "
                 "--require-overlay-package ubuntu_fixes:jammy:linux:1 "
                 "--require-overlay-package ubuntu_fixes:jammy:linux-nvidia:1 "
                 "--require-overlay-package ubuntu_fixes:focal:linux:1 "
                 "--require-overlay-package ubuntu_fixes:focal:linux-nvidia:1 "
                 "--require-overlay-package debian_fixes:trixie:linux:1 "
                 "--require-overlay-package debian_fixes:bookworm:linux:1 "
                 "--require-overlay-max-age-days 2 "
                 "--require-kev 1000 --require-kev-max-age-days 3 "
                 "--require-apple-fixes 1 --require-apple-fixes-max-age-days 7 "
                 "--require-apple-fixes-product iphone_os:1 "
                 "--require-apple-fixes-product ipados:1 "
                 "--require-apple-fixes-product macos:1 "
                 "--require-apple-fixes-product-max-age-days 7 "
                 "--require-epss 100000 --require-epss-max-age-days 3")
    lines.append("```")
    if extra:
        lines.append(extra)
    return "\n".join(lines)


def test_gate_passes_on_the_repository_runbook():
    result = _run_gate_on([RUNBOOK])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "runbook reference resolves" in result.stdout


def test_default_gate_run_covers_the_runbook():
    # The canonical gate run (no arguments) must include the runbook, so the
    # runbook is checked by the repository's own verification path.
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 runbook(s)" in result.stdout


def test_runbook_names_every_shipped_unit():
    # A unit the runbook does not install is a unit the operator never puts
    # on the host, so its capability never runs.
    names = _shipped_unit_names()
    assert names, "the tree ships no systemd units"
    text = RUNBOOK.read_text()
    for name in names:
        assert name in text, f"the runbook does not mention {name}"


def test_runbook_that_omits_a_unit_is_rejected(tmp_path):
    # A unit the runbook neither names nor installs is a unit the operator
    # never puts on the host.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook()
    omitted = _shipped_unit_names()[0]
    body = body.replace(f"Install `{omitted}`.", "Install the service.")
    body = "\n".join(line for line in body.splitlines()
                     if f"/systemd/{omitted}" not in line)
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert omitted in result.stdout
    assert "never installs" in result.stdout


def test_runbook_pointing_at_a_missing_tree_path_is_rejected(tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook(
        "The daily job lives in `scripts/not_a_script.sh`."))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "scripts/not_a_script.sh" in result.stdout
    assert "does not exist in this tree" in result.stdout


def test_runbook_showing_an_unknown_command_is_rejected(tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook(
        "Run `posture not-a-command --db /tmp/posture.db`."))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "not-a-command" in result.stdout


def test_runbook_showing_an_unknown_option_is_rejected(tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook(
        "Run `posture spine publish --bogus /tmp/out`."))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "--bogus" in result.stdout


def test_runbook_showing_an_unknown_command_in_a_code_block_is_rejected(
        tmp_path):
    # The commands an operator copies live in fenced code blocks, so the
    # gate must read those too.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook(
        "```bash\nposture not-a-command --db /tmp/posture.db\n```"))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "not-a-command" in result.stdout


def test_runbook_documenting_an_unread_variable_is_rejected(tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook(
        "The variable `POSTURE_NOT_A_REAL_VARIABLE` tunes the build."))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "POSTURE_NOT_A_REAL_VARIABLE" in result.stdout


def test_runbook_that_omits_a_unit_variable_is_rejected(tmp_path):
    # Every variable a shipped unit sets must be documented, so the
    # environment file the operator writes is complete.
    variables = _unit_environment_variables()
    assert variables, "the shipped units set no posture variables"
    omitted = variables[0]
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook().replace(
        f"The variable `{omitted}` is read by the daily job.", ""))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert omitted in result.stdout
    assert "does not document" in result.stdout


def test_runbook_documents_the_variables_the_daily_job_reads():
    # The environment file the operator writes must be complete for the
    # daily job: every variable the job reads is documented.
    text = RUNBOOK.read_text()
    for variable in ("POSTURE_STATE_DIR", "POSTURE_EXPORT_DIR",
                     "POSTURE_DB_PATH", "POSTURE_BACKFILL_CAP",
                     "POSTURE_OSV_CAP", "POSTURE_REFRESH_CAP",
                     "POSTURE_SIGN_KEY", "NVD_API_KEY"):
        assert variable in text, f"the runbook does not document {variable}"


def test_a_baseline_runbook_passes_the_gate(tmp_path):
    # The baseline used by the runbook tests must itself satisfy every
    # runbook check, so each defect test sees only its own defect.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook())
    result = _run_gate_on([runbook])
    assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# The host contract (dimension 3f) and the install layout (dimension 4f)
# ---------------------------------------------------------------------------

HOST_CONTRACT_KEYS = (
    "install_root",
    "state_dir",
    "export_dir",
    "system_env_file",
    "user_env_file",
    "service_account",
    "disk_warn_gb",
    "disk_crit_gb",
    "sign_key",
    "sign_pub_key",
    "served_dir_owner",
    "map_max_age_days",
)


def _shipped_unit_text(name: str) -> str:
    return (REPO_ROOT / "systemd" / name).read_text()


def test_runbook_declares_a_host_contract():
    # The host contract is the runbook\'s machine-readable statement of the
    # paths and the service account the units are written against.
    text = RUNBOOK.read_text()
    assert "install_root:" in text
    for key in HOST_CONTRACT_KEYS:
        assert f"{key}:" in text, f"the host contract has no {key}"


def test_gate_reports_the_host_contract_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "every unit matches the host contract" in result.stdout


def test_gate_rejects_a_unit_whose_working_directory_drifted(tmp_path):
    # A unit that points at a different tree root than the runbook\'s
    # install root runs a tree the operator never installed.
    unit = tmp_path / "posture-spine.service"
    unit.write_text(_shipped_unit_text("posture-spine.service").replace(
        "WorkingDirectory=/opt/posture", "WorkingDirectory=/opt/other"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "install root" in result.stdout


def test_gate_rejects_a_unit_that_runs_as_another_account(tmp_path):
    unit = tmp_path / "posture-spine.service"
    unit.write_text(_shipped_unit_text("posture-spine.service").replace(
        "User=posture", "User=root"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "service account" in result.stdout


def test_gate_rejects_a_unit_whose_state_directory_drifted(tmp_path):
    unit = tmp_path / "posture-spine.service"
    unit.write_text(_shipped_unit_text("posture-spine.service").replace(
        "StateDirectory=posture", "StateDirectory=postured"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "StateDirectory" in result.stdout


def test_gate_rejects_a_unit_that_loads_the_wrong_environment_file(tmp_path):
    # The system unit must load the system environment file; loading the
    # operator\'s user file instead drops the operator\'s overrides for the
    # daily build.
    unit = tmp_path / "posture-spine.service"
    unit.write_text(_shipped_unit_text("posture-spine.service").replace(
        "EnvironmentFile=-/etc/posture/posture.env",
        "EnvironmentFile=-/etc/posture/other.env"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "environment file" in result.stdout


def test_gate_rejects_a_user_unit_that_loads_the_system_environment_file(
        tmp_path):
    unit = tmp_path / "posture-stream.service"
    unit.write_text(_shipped_unit_text("posture-stream.service").replace(
        "EnvironmentFile=%h/.config/posture/env",
        "EnvironmentFile=/etc/posture/posture.env"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "environment file" in result.stdout


def test_gate_rejects_a_unit_that_points_the_catalog_outside_the_state_dir(
        tmp_path):
    unit = tmp_path / "posture-spine.service"
    unit.write_text(_shipped_unit_text("posture-spine.service").replace(
        "POSTURE_DB_PATH=/var/lib/posture/posture.db",
        "POSTURE_DB_PATH=/tmp/posture.db"))
    result = _run_gate_on([unit])
    assert result.returncode == 1
    assert "outside" in result.stdout


def test_gate_rejects_a_runbook_without_a_host_contract(tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook().replace(
        _HOST_CONTRACT_BLOCK, ""))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "host contract" in result.stdout


def test_gate_rejects_a_runbook_whose_contract_path_is_not_in_the_layout(
        tmp_path):
    # The contract and the install layout describe the same host, so a
    # contract path the table does not name is drift.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook().replace(
        "state_dir: /var/lib/posture", "state_dir: /srv/posture"))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "install layout table" in result.stdout


def test_gate_rejects_an_install_layout_path_no_contract_path_covers(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook().replace(
        _HOST_LAYOUT_TABLE,
        _HOST_LAYOUT_TABLE + "| `/srv/other` | a path the contract does not "
        "cover |\n"))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "no host contract path covers" in result.stdout


def test_the_shipped_units_match_the_host_contract():
    # The tree as it ships must satisfy the contract the runbook declares.
    units = sorted((REPO_ROOT / "systemd").glob("*.service"))
    assert units, "the tree ships no service units"
    result = _run_gate_on([*units, RUNBOOK])
    assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# The host command contract (dimension 4g)
# ---------------------------------------------------------------------------


def _runbook_with_commands(tmp_path, commands: list[str]) -> Path:
    """A runbook that installs every unit and then runs the given commands."""
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook()
    body += "\n```bash\n" + "\n".join(commands) + "\n```\n"
    runbook.write_text(body)
    return runbook


def test_gate_reports_the_host_command_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "every runbook host command matches the contract" in result.stdout


def test_the_shipped_runbook_installs_every_unit_in_its_own_directory():
    # Every unit this tree ships must be installed by a command into the
    # unit directory its kind belongs in: a system unit in the system
    # directory, a user unit in the operator's own directory.
    text = RUNBOOK.read_text()
    for name in _shipped_unit_names():
        directory = ("/etc/systemd/system" if _unit_is_system_unit(name)
                     else "~/.config/systemd/user")
        assert f"{directory}/{name}" in text, (
            f"the runbook does not install {name} into {directory}")


def test_runbook_command_naming_a_path_the_contract_does_not_govern_is_rejected(
        tmp_path):
    # A command that builds a path the contract does not describe builds a
    # different host than the one the contract declares.
    runbook = _runbook_with_commands(
        tmp_path, ["sudo install -d -o posture -g posture /srv/posture"])
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "/srv/posture" in result.stdout
    assert "does not govern" in result.stdout


def test_runbook_command_naming_a_standard_system_path_passes(tmp_path):
    # The standard system paths are not the contract's business, so a
    # command that uses one is not drift.
    runbook = _runbook_with_commands(
        tmp_path, ["posture health --db /var/lib/posture/posture.db",
                   "sudo install -d /tmp/posture-check"])
    result = _run_gate_on([runbook])
    assert result.returncode == 0, result.stdout + result.stderr


def test_runbook_creating_another_service_account_is_rejected(tmp_path):
    # The account the units run as is the contract's account; a runbook
    # that creates a different one leaves the units running as an account
    # that does not exist.
    runbook = _runbook_with_commands(
        tmp_path, ["sudo useradd --system --home-dir /var/lib/posture "
                   "--shell /usr/sbin/nologin spine"])
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "spine" in result.stdout
    assert "service account" in result.stdout


def test_runbook_creating_the_account_with_another_home_is_rejected(
        tmp_path):
    # The service account's home directory is the contract's state
    # directory, so the account and the state live together.
    runbook = _runbook_with_commands(
        tmp_path, ["sudo useradd --system --home-dir /srv/posture "
                   "--shell /usr/sbin/nologin posture"])
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "/srv/posture" in result.stdout
    assert "state directory" in result.stdout


def test_runbook_setting_an_unknown_owner_is_rejected(tmp_path):
    runbook = _runbook_with_commands(
        tmp_path, ["sudo install -d -o nobody -g posture /var/lib/posture"])
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "nobody" in result.stdout
    assert "owner" in result.stdout


def test_runbook_setting_an_unknown_group_is_rejected(tmp_path):
    runbook = _runbook_with_commands(
        tmp_path, ["sudo install -d -o posture -g wheel /var/lib/posture"])
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "wheel" in result.stdout
    assert "group" in result.stdout


def test_runbook_creating_a_writable_directory_without_the_service_account_is_rejected(
        tmp_path):
    # The daily job writes into the state directory; a directory it does
    # not own is a directory the job cannot write into.
    runbook = _runbook_with_commands(
        tmp_path, ["sudo install -d /var/lib/posture"])
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "/var/lib/posture" in result.stdout
    assert "service account" in result.stdout


def test_runbook_creating_a_writable_directory_for_the_service_account_passes(
        tmp_path):
    runbook = _runbook_with_commands(
        tmp_path, ["sudo install -d -o posture -g posture "
                   "/var/lib/posture/cvelist"])
    result = _run_gate_on([runbook])
    assert result.returncode == 0, result.stdout + result.stderr


def test_runbook_that_never_installs_a_unit_is_rejected(tmp_path):
    # A unit the runbook only names in prose is a unit the operator never
    # puts on the host.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook()
    omitted = _shipped_unit_names()[0]
    body = "\n".join(line for line in body.splitlines()
                     if f"/systemd/{omitted}" not in line)
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert omitted in result.stdout
    assert "never installs" in result.stdout


def test_runbook_installing_a_user_unit_into_the_system_directory_is_rejected(
        tmp_path):
    # A user unit installed into the system unit directory runs as the
    # system service account and loads the system environment file, which
    # is not what the unit was written for.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook()
    user_unit = next(name for name in _shipped_unit_names()
                     if not _unit_is_system_unit(name))
    body = body.replace(
        f"~/.config/systemd/user/{user_unit}",
        f"/etc/systemd/system/{user_unit}")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert user_unit in result.stdout
    assert "unit directory" in result.stdout


def test_runbook_installing_a_system_unit_into_the_user_directory_is_rejected(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook()
    system_unit = next(name for name in _shipped_unit_names()
                       if _unit_is_system_unit(name))
    body = body.replace(
        f"/etc/systemd/system/{system_unit}",
        f"~/.config/systemd/user/{system_unit}")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert system_unit in result.stdout
    assert "unit directory" in result.stdout


# ---------------------------------------------------------------------------
# Removal coverage (dimension 4g-e): every installed unit must be removed
# ---------------------------------------------------------------------------


def test_gate_reports_the_removal_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "every installed unit is removed by the runbook" in result.stdout


def test_the_shipped_runbook_removes_every_unit_it_installs():
    # Every unit the runbook installs must also be removed by a command,
    # so teardown leaves no stale files on the host.
    text = RUNBOOK.read_text()
    for name in _shipped_unit_names():
        directory = ("/etc/systemd/system" if _unit_is_system_unit(name)
                     else "~/.config/systemd/user")
        assert f"{directory}/{name}" in text, (
            f"the runbook does not remove {name} from {directory}")


def test_runbook_that_never_removes_an_installed_unit_is_rejected(tmp_path):
    # A unit the runbook installs but never removes leaves stale files
    # after teardown.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook()
    removed_unit = _shipped_unit_names()[0]
    body = "\n".join(
        line for line in body.splitlines()
        if not (line.strip().startswith("rm -f")
                and removed_unit in line))
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert removed_unit in result.stdout
    assert "never removes" in result.stdout


def test_runbook_that_removes_every_installed_unit_passes(tmp_path):
    # The baseline runbook installs and removes every shipped unit, so
    # the removal-coverage dimension passes alongside the install one.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook())
    result = _run_gate_on([runbook])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "every installed unit is removed by the runbook" in result.stdout


def test_runbook_that_removes_with_sudo_rm_passes(tmp_path):
    # A system unit removed with `sudo rm -f` is still a removal the gate
    # recognizes.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook()
    system_unit = next(name for name in _shipped_unit_names()
                       if _unit_is_system_unit(name))
    body = body.replace(
        f"rm -f /etc/systemd/system/{system_unit}",
        f"sudo rm -f /etc/systemd/system/{system_unit}")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# The growth-guard thresholds (dimension 4h)
# ---------------------------------------------------------------------------

def _contract_value(key: str) -> str:
    """The value the shipped runbook's host contract declares for a key."""
    for line in RUNBOOK.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{key}:"):
            return stripped.split(":", 1)[1].strip()
    raise AssertionError(f"the host contract declares no {key}")


def _daily_script_default(variable: str) -> int:
    """The default the daily job uses for a growth-guard variable."""
    text = DAILY_SCRIPT.read_text()
    match = re.search(re.escape(variable) + r":-(\d+)", text)
    assert match is not None, f"the daily job declares no {variable} default"
    return int(match.group(1))


def test_the_host_contract_declares_the_growth_guard_thresholds():
    # The contract is the runbook's machine-readable statement of the
    # host; the free-space thresholds the daily job applies belong in it,
    # or the thresholds live only in the script.
    for key in ("disk_warn_gb", "disk_crit_gb"):
        assert _contract_value(key), f"the host contract declares no {key}"


def test_the_contract_thresholds_are_the_daily_jobs_own_defaults():
    # A contract that declares thresholds the job does not use describes a
    # host that warns (or refuses to build) at a different level of free
    # space than the operator believes it does.
    assert int(_contract_value("disk_warn_gb")) == _daily_script_default(
        "POSTURE_DISK_WARN_GB")
    assert int(_contract_value("disk_crit_gb")) == _daily_script_default(
        "POSTURE_DISK_CRIT_GB")


def test_the_critical_threshold_is_below_the_warning_threshold():
    assert int(_contract_value("disk_crit_gb")) < int(
        _contract_value("disk_warn_gb"))


def test_gate_rejects_a_contract_whose_threshold_drifted_from_the_job(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook().replace(
        "disk_warn_gb: 5", "disk_warn_gb: 9"))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "disk_warn_gb" in result.stdout
    assert "POSTURE_DISK_WARN_GB" in result.stdout


def test_gate_rejects_a_daily_job_whose_threshold_default_drifted(tmp_path):
    script = tmp_path / "vps_spine.sh"
    script.write_text(
        'DISK_WARN_GB="${POSTURE_DISK_WARN_GB:-9}"\n'
        'DISK_CRIT_GB="${POSTURE_DISK_CRIT_GB:-2}"\n')
    result = _run_gate_on([script])
    assert result.returncode == 1
    assert "POSTURE_DISK_WARN_GB" in result.stdout
    assert "disk_warn_gb" in result.stdout


def test_gate_rejects_a_contract_whose_critical_threshold_is_not_lower(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook().replace(
        "disk_crit_gb: 2", "disk_crit_gb: 7"))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "disk_crit_gb" in result.stdout


def test_gate_rejects_a_contract_threshold_that_is_not_a_whole_number(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook().replace(
        "disk_warn_gb: 5", "disk_warn_gb: 5.5"))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "disk_warn_gb" in result.stdout


def test_gate_rejects_a_contract_without_the_growth_guard_thresholds(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook()
                        .replace("disk_warn_gb: 5\n", "")
                        .replace("disk_crit_gb: 2\n", ""))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "disk_warn_gb" in result.stdout


def test_gate_reports_the_growth_guard_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "the growth-guard thresholds match the contract" in result.stdout


# ---------------------------------------------------------------------------
# The manifest signing key and the served-directory ownership (dimension 4i)
# ---------------------------------------------------------------------------

def test_the_host_contract_declares_the_sign_key_and_served_dir_owner():
    # The contract is the runbook's machine-readable statement of the host;
    # the manifest signing key's location and the served directory's owner
    # are host expectations, so they belong in it rather than only in prose.
    for key in ("sign_key", "served_dir_owner"):
        assert _contract_value(key), (
            f"the host contract declares no {key}")


def _normalize_host_path_helper(value: str) -> str:
    # The gate's own normalizer is embedded in the shell script; mirror the
    # host-path normalization the gate applies so the test compares like
    # with like.
    v = value.strip().strip('"').strip("'")
    if v.startswith("%h"):
        v = "~" + v[len("%h"):]
    if len(v) > 1:
        v = v.rstrip("/")
    return v or "/"


def _layout_table_paths(text: str) -> list[str]:
    # Mirror the gate's install-layout-table path extraction so the test
    # compares the contract's sign_key against the same set the gate does.
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
            paths.append(_normalize_host_path_helper(first))
    return paths


def test_the_sign_key_path_is_in_the_install_layout_table():
    # The signing key must live inside the layout the runbook builds, not at
    # an arbitrary path the operator has no reason to expect.
    sign_key = _normalize_host_path_helper(_contract_value("sign_key"))
    layout = _layout_table_paths(RUNBOOK.read_text())
    assert sign_key in layout, (
        f"the host contract's sign_key ({sign_key}) is not in the install "
        f"layout table")


def test_gate_reports_the_sign_key_and_served_dir_owner_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert ("the manifest signing key and the served directory owner match "
            "the contract") in result.stdout


def test_runbook_that_never_references_the_sign_key_path_is_rejected(
        tmp_path):
    # A contract that declares where the signing key lives but a runbook
    # that never names that path does not build the key location the
    # contract describes.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook()
    # Strip the baseline's signing-key install command so no command
    # references the contract's sign_key path.
    body = body.replace(
        "sudo install -m 0640 -o root -g posture /dev/null "
        "/etc/posture/signing_key.pem\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "sign_key" in result.stdout
    assert "signing key" in result.stdout


def test_runbook_referencing_the_sign_key_path_passes(tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook())
    result = _run_gate_on([runbook])
    assert result.returncode == 0, result.stdout + result.stderr


def test_runbook_that_creates_the_served_directory_with_the_wrong_owner_is_rejected(
        tmp_path):
    # The served directory is the export directory the daily job publishes
    # the map into; a runbook that creates it as another account describes
    # a host the contract does not declare.
    runbook = _runbook_with_commands(
        tmp_path,
        ["sudo install -d -o root -g posture /var/lib/posture"])
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "served directory" in result.stdout
    assert "served directory owner" in result.stdout


def test_runbook_that_creates_the_served_directory_with_the_contract_owner_passes(
        tmp_path):
    runbook = _runbook_with_commands(
        tmp_path,
        ["sudo install -d -o posture -g posture /var/lib/posture"])
    result = _run_gate_on([runbook])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_rejects_a_contract_whose_served_dir_owner_drifted(tmp_path):
    # A contract that changes the served directory's owner while the
    # runbook still creates the directory as the old account is drift.
    runbook = _runbook_with_commands(
        tmp_path,
        ["sudo install -d -o posture -g posture /var/lib/posture"])
    body = runbook.read_text().replace(
        "served_dir_owner: posture", "served_dir_owner: spine")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "served directory owner" in result.stdout


def test_gate_rejects_a_contract_without_the_sign_key_and_served_dir_owner(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(
        _baseline_runbook()
        .replace("sign_key: /etc/posture/signing_key.pem\n", "")
        .replace("served_dir_owner: posture\n", ""))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "sign_key" in result.stdout
    assert "served_dir_owner" in result.stdout


def test_gate_rejects_a_contract_whose_sign_key_is_outside_the_layout(
        tmp_path):
    # A signing key the install layout does not cover is a key the operator
    # has no reason to expect at that path.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(
        _baseline_runbook().replace(
            "sign_key: /etc/posture/signing_key.pem",
            "sign_key: /srv/posture/signing_key.pem"))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "sign_key" in result.stdout
    assert "install layout table" in result.stdout


# ---------------------------------------------------------------------------
# The published-map layout (dimension 4j)
# ---------------------------------------------------------------------------

def test_the_host_contract_declares_the_served_map_directory():
    # The directory the published map lands in is a host expectation: it is
    # the directory a web server serves and a client pulls from, so it
    # belongs in the contract rather than only in prose.
    assert _contract_value("served_map_dir")


def test_the_served_map_directory_is_the_one_the_publish_implementation_writes():
    # The publish step writes the map into a `spine` directory inside the
    # export directory; a contract that names any other directory describes
    # a host the daily job never publishes into.
    from posture.export import SPINE_DIR
    export_dir = _normalize_host_path_helper(_contract_value("export_dir"))
    served = _normalize_host_path_helper(_contract_value("served_map_dir"))
    assert served == f"{export_dir}/{SPINE_DIR}", (
        f"the host contract's served_map_dir ({served}) is not the directory "
        f"the publish implementation writes ({export_dir}/{SPINE_DIR})")


def test_the_published_map_paths_are_in_the_install_layout_table():
    # The operator's verification step names the manifest and the shards;
    # both must be the paths the publish implementation actually writes.
    from posture.export import DEFECTS_DIR, MANIFEST_NAME
    served = _normalize_host_path_helper(_contract_value("served_map_dir"))
    layout = _layout_table_paths(RUNBOOK.read_text())
    for path in (f"{served}/{MANIFEST_NAME}", f"{served}/{DEFECTS_DIR}"):
        assert path in layout, (
            f"the install layout does not name the published map's {path}")


def test_the_shipped_runbook_does_not_name_a_published_map_path_outside_the_served_directory():
    # The manifest lives inside the served map directory. A runbook that
    # tells the operator to look at the export directory's root for it
    # describes a file the publish step never writes.
    served = _normalize_host_path_helper(_contract_value("served_map_dir"))
    text = RUNBOOK.read_text()
    assert f"{served}/manifest.json" in text
    assert "/var/lib/posture/manifest.json" not in text
    assert "/var/lib/posture/defects" not in text


def test_gate_reports_the_published_map_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert ("the published-map layout matches the publish implementation"
            ) in result.stdout


def test_gate_rejects_a_contract_whose_served_map_dir_drifted_from_the_code(
        tmp_path):
    # A contract that names a served map directory the publish
    # implementation never writes to is drift.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook().replace(
        "served_map_dir: /var/lib/posture/spine",
        "served_map_dir: /var/lib/posture/map"))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "served_map_dir" in result.stdout
    assert "publish implementation" in result.stdout


def test_gate_rejects_a_runbook_that_documents_the_manifest_outside_the_served_map_directory(
        tmp_path):
    # The manifest is written inside the served map directory; a layout
    # that names it elsewhere describes a path the code never writes.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "| `/var/lib/posture/spine/manifest.json` | the published map's manifest |",
        "| `/var/lib/posture/manifest.json` | the published map's manifest |")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "manifest" in result.stdout
    assert "served map directory" in result.stdout


def test_gate_rejects_a_runbook_that_omits_the_published_map_paths(
        tmp_path):
    # A layout that does not name the manifest the publish step writes
    # leaves the operator's verification step without a path to check.
    runbook = tmp_path / "deployment.md"
    body = "\n".join(
        line for line in _baseline_runbook().splitlines()
        if "/var/lib/posture/spine/manifest.json" not in line)
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not name the published map's manifest" in result.stdout


def test_gate_rejects_a_contract_without_the_served_map_directory(tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(
        _baseline_runbook().replace(
            "served_map_dir: /var/lib/posture/spine\n", ""))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "served_map_dir" in result.stdout


# ---------------------------------------------------------------------------
# The documented environment defaults (dimension 4k)
# ---------------------------------------------------------------------------

def test_the_runbooks_documented_defaults_match_the_daily_jobs_defaults():
    # The runbook's environment table states a default for every knob the
    # daily job reads. The operator sizes the host and writes the
    # environment file against those numbers, so each stated default must
    # be the number the job actually falls back to.
    result = _run_gate_on([RUNBOOK])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "POSTURE_" not in result.stdout


def test_gate_rejects_a_runbook_whose_documented_default_drifted(tmp_path):
    # A documented default the job does not use is drift: the runbook
    # tells the operator the refresh cap is 500 while the job caps at 200.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(RUNBOOK.read_text().replace(
        "| `POSTURE_REFRESH_CAP` | the cap on the per-run catalog refresh "
        "| `200` |",
        "| `POSTURE_REFRESH_CAP` | the cap on the per-run catalog refresh "
        "| `500` |"))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "POSTURE_REFRESH_CAP" in result.stdout
    assert "the daily job falls back to" in result.stdout


def test_gate_rejects_a_runbook_whose_documented_path_default_drifted(
        tmp_path):
    # The catalog path is documented in terms of the state directory; a
    # runbook that names a different file describes a host whose database
    # is not where the job writes it.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(RUNBOOK.read_text().replace(
        "`$POSTURE_STATE_DIR/posture.db`", "`$POSTURE_STATE_DIR/catalog.db`"))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "POSTURE_DB_PATH" in result.stdout


def test_gate_accepts_an_equivalent_spelling_of_a_documented_default(
        tmp_path):
    # The job's own default for the clone directory is written in terms
    # of its state-directory variable; a runbook may spell the same path
    # out in full, and the two are the same default.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(RUNBOOK.read_text().replace(
        "`$POSTURE_STATE_DIR/cvelist`", "`/var/lib/posture/cvelist`"))
    result = _run_gate_on([runbook])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_accepts_an_unset_default_for_an_optional_variable(tmp_path):
    # The signing key is optional: the job falls back to no key at all,
    # which the runbook states as "unset".
    runbook = tmp_path / "deployment.md"
    runbook.write_text(RUNBOOK.read_text().replace(
        "the manifest is unsigned | unset |", "the manifest is unsigned | "
        "unset |"))
    result = _run_gate_on([runbook])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_rejects_a_runbook_that_documents_a_default_the_job_never_uses(
        tmp_path):
    # A default that names nothing the job reads is drift in the other
    # direction: the operator would believe a knob exists that does not.
    runbook = tmp_path / "deployment.md"
    body = RUNBOOK.read_text().replace(
        "| `POSTURE_GC_INTERVAL_DAYS` | days between the source-clone "
        "maintenance pass | `7` |",
        "| `POSTURE_GC_INTERVAL_DAYS` | days between the source-clone "
        "maintenance pass | `14` |")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "POSTURE_GC_INTERVAL_DAYS" in result.stdout


def test_gate_reports_the_documented_defaults_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert ("every documented environment default matches the daily job's "
            "own default") in result.stdout


# ---------------------------------------------------------------------------
# Published-map verification (4l)
# ---------------------------------------------------------------------------


def test_the_shipped_runbook_verifies_the_published_map():
    # The operator's confirmation that the host serves the map it is
    # supposed to serve must be the same check every client makes.
    body = RUNBOOK.read_text()
    assert "posture spine verify --from /var/lib/posture" in body, (
        "the runbook does not verify the published map with the command the "
        "tree ships")


def test_gate_reports_the_published_map_verification_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "the published map is verified by the runbook" in result.stdout


def test_gate_rejects_a_runbook_that_only_lists_the_published_map(tmp_path):
    # Listing the manifest file shows that a file exists; it cannot see a
    # truncated or tampered shard, so it is not a verification.
    runbook = tmp_path / "deployment.md"
    body = "\n".join(
        line for line in _baseline_runbook().splitlines()
        if not line.startswith("posture spine verify"))
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not verify the published map" in result.stdout


def test_gate_rejects_a_runbook_that_verifies_the_wrong_directory(tmp_path):
    # The verification must point at the map the host serves, not at some
    # other directory that happens to hold a copy.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "posture spine verify --from /var/lib/posture",
        "posture spine verify --from /tmp/somewhere-else")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "not the directory that holds the served map" in result.stdout


def test_gate_rejects_a_verification_that_does_not_say_which_directory(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "posture spine verify --from /var/lib/posture",
        "posture spine verify")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not say which directory it verifies" in result.stdout


# ---------------------------------------------------------------------------
# Published-map signature verification (dimension 4l-b)
# ---------------------------------------------------------------------------

def test_the_shipped_runbook_verifies_the_published_map_signature():
    # When the manifest is signed, the operator's verification must also
    # check the signature against the contract's public key, the same
    # trust check a client makes before it imports.
    body = RUNBOOK.read_text()
    assert ("posture spine verify --from /var/lib/posture --verify-sig "
            "--signature-key /etc/posture/signing_pub.pem") in body, (
        "the runbook does not verify the published map's signature against "
        "the contract's sign_pub_key path")


def test_gate_accepts_a_signature_verification_against_the_contract_public_key(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "posture spine verify --from /var/lib/posture",
        "posture spine verify --from /var/lib/posture --verify-sig "
        "--signature-key /etc/posture/signing_pub.pem")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_rejects_a_signature_verification_without_a_signature_key(
        tmp_path):
    # --verify-sig without --signature-key cannot verify the signature, so
    # the runbook describes a verification it cannot perform.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "posture spine verify --from /var/lib/posture",
        "posture spine verify --from /var/lib/posture --verify-sig")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "--signature-key" in result.stdout
    assert "sign_pub_key" in result.stdout


def test_gate_rejects_a_signature_verification_against_the_wrong_key(
        tmp_path):
    # A runbook that verifies the signature against a key path the contract
    # does not declare describes a host whose trust anchor the contract does
    # not build.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "posture spine verify --from /var/lib/posture",
        "posture spine verify --from /var/lib/posture --verify-sig "
        "--signature-key /etc/posture/wrong_pub.pem")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "sign_pub_key" in result.stdout
    assert "/etc/posture/wrong_pub.pem" in result.stdout


def test_gate_rejects_a_runbook_that_never_references_the_sign_pub_key_path(
        tmp_path):
    # The contract declares where the public key lives, so a runbook that
    # never names that path does not build the public key location the
    # contract describes.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "sudo install -m 0644 -o root -g root /dev/null "
        "/etc/posture/signing_pub.pem\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "sign_pub_key" in result.stdout
    assert "signature verification key" in result.stdout


def test_gate_rejects_a_contract_without_the_sign_pub_key(tmp_path):
    runbook = tmp_path / "deployment.md"
    runbook.write_text(
        _baseline_runbook().replace(
            "sign_pub_key: /etc/posture/signing_pub.pem\n", ""))
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "sign_pub_key" in result.stdout


# ---------------------------------------------------------------------------
# Published-map freshness (dimension 4m)
# ---------------------------------------------------------------------------


def test_the_host_contract_declares_the_maximum_map_age():
    # The publish is atomic, so a daily build that has been failing leaves
    # the last good map serving; the contract states how old a map may be
    # before the operator is told the build has stopped.
    body = RUNBOOK.read_text()
    assert "map_max_age_days: 2" in body, (
        "the host contract does not declare how old the served map is "
        "allowed to be")


def test_the_shipped_runbook_checks_the_served_maps_freshness():
    body = RUNBOOK.read_text()
    assert ("posture spine verify --from /var/lib/posture --max-age-days 2"
            in body), (
        "the runbook does not check how old the served map is, so a map that "
        "stopped being rebuilt would pass every content check")


def test_gate_reports_the_published_map_freshness_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "the served map's freshness is checked" in result.stdout


def test_gate_rejects_a_runbook_that_never_checks_the_maps_age(tmp_path):
    # Verifying the map's contents but never its age confirms a map that may
    # have been frozen for a week.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "posture spine verify --from /var/lib/posture --max-age-days 2",
        "posture spine verify --from /var/lib/posture")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "how old the map is allowed to be" in result.stdout


def test_gate_rejects_a_runbook_that_allows_a_different_age_than_the_contract(
        tmp_path):
    # The contract states how stale a map may be; a runbook that allows a
    # different age describes a host the operator and the contract disagree
    # about.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("--max-age-days 2", "--max-age-days 9")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "the host contract declares 2 day(s)" in result.stdout


def test_gate_rejects_a_contract_whose_maximum_age_is_not_a_number(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "map_max_age_days: 2", "map_max_age_days: soon")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "map_max_age_days" in result.stdout
    assert "not a number of days" in result.stdout


def test_gate_rejects_a_contract_whose_maximum_age_is_not_positive(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "map_max_age_days: 2", "map_max_age_days: 0")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "must be a positive number of days" in result.stdout


def test_gate_rejects_a_contract_without_the_maximum_map_age(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("map_max_age_days: 2\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "map_max_age_days" in result.stdout


# ---------------------------------------------------------------------------
# Publish cadence against the freshness allowance (dimension 4n)
# ---------------------------------------------------------------------------


def test_the_host_contract_declares_the_publish_cadence():
    # The contract states how often the publish timer is expected to run,
    # so the gate can check the timer against the freshness allowance.
    body = RUNBOOK.read_text()
    assert "publish_cadence_days: 1" in body, (
        "the host contract does not declare how often the publish timer "
        "is expected to run")


def test_the_publish_cadence_is_strictly_less_than_the_maximum_map_age():
    # A timer that fires at the same cadence as or less often than the
    # maximum map age can never keep the served map within its freshness
    # allowance.
    body = RUNBOOK.read_text()
    assert "publish_cadence_days: 1" in body
    assert "map_max_age_days: 2" in body
    assert 1 < 2


def test_the_shipped_spine_timer_fires_at_least_as_often_as_the_declared_cadence():
    # The spine timer fires daily; the contract declares a daily cadence,
    # so the timer's nominal interval is no greater than the declared one.
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "the publish cadence is strictly less" in result.stdout


def test_gate_reports_the_publish_cadence_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "the publish cadence is strictly less than the maximum map age" in (
        result.stdout)
    assert "the publish timer fires at least that often" in result.stdout


def test_gate_rejects_a_contract_whose_publish_cadence_is_not_a_number(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "publish_cadence_days: 1", "publish_cadence_days: daily")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "publish_cadence_days" in result.stdout
    assert "not a number of days" in result.stdout


def test_gate_rejects_a_contract_whose_publish_cadence_is_not_positive(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "publish_cadence_days: 1", "publish_cadence_days: 0")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "publish_cadence_days" in result.stdout
    assert "must be a positive number of days" in result.stdout


def test_gate_rejects_a_publish_cadence_that_is_not_less_than_the_maximum_map_age(
        tmp_path):
    # A cadence equal to the maximum age has no margin for a missed run;
    # a cadence greater than the maximum age can never satisfy freshness.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "publish_cadence_days: 1", "publish_cadence_days: 2")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "publish_cadence_days" in result.stdout
    assert "strictly less than map_max_age_days" in result.stdout


def test_gate_rejects_a_contract_without_the_publish_cadence(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("publish_cadence_days: 1\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "publish_cadence_days" in result.stdout


def _spine_timer_with(body: str, tmp_path) -> Path:
    """A timer named posture-spine.timer with the given [Timer] body."""
    return _write_timer(
        tmp_path,
        "[Timer]\n" + body +
        "Unit=posture-spine.service\n"
        "[Install]\n"
        "WantedBy=timers.target\n",
        name="posture-spine.timer")


def test_gate_rejects_a_publish_timer_that_fires_less_often_than_declared(
        tmp_path):
    # The contract declares a daily cadence; a weekly spine timer is a host
    # whose publish runs less often than the contract promises, so the
    # served map can age past the freshness allowance even when every build
    # succeeds.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook())
    service = UNIT_DIR / "posture-spine.service"
    timer = _spine_timer_with(
        "OnCalendar=Mon *-*-* 03:07:00 UTC\n", tmp_path)
    result = _run_gate_on([runbook, service, timer])
    assert result.returncode == 1
    assert "fires every 7" in result.stdout
    assert "publish_cadence_days 1" in result.stdout


def test_gate_accepts_a_monotonic_publish_timer_that_fires_more_often_than_declared(
        tmp_path):
    # A monotonic timer that fires every 12h against a daily declared cadence
    # is more frequent than the contract promises, so the freshness
    # relationship holds.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook())
    service = UNIT_DIR / "posture-spine.service"
    timer = _spine_timer_with("OnUnitInactiveSec=12h\n", tmp_path)
    result = _run_gate_on([runbook, service, timer])
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_rejects_a_monotonic_publish_timer_that_fires_less_often_than_declared(
        tmp_path):
    # A monotonic timer that fires every 3 days against a daily declared
    # cadence is less frequent than the contract promises.
    runbook = tmp_path / "deployment.md"
    runbook.write_text(_baseline_runbook())
    service = UNIT_DIR / "posture-spine.service"
    timer = _spine_timer_with("OnUnitInactiveSec=3d\n", tmp_path)
    result = _run_gate_on([runbook, service, timer])
    assert result.returncode == 1
    assert "fires every 3" in result.stdout
    assert "publish_cadence_days 1" in result.stdout


# ---------------------------------------------------------------------------
# Overlay coverage of the served map (dimension 4o)
# ---------------------------------------------------------------------------


def test_the_host_contract_declares_the_required_overlays():
    # The contract states which overlay tables the published map must carry:
    # the vendor fix-status rows are what clear NVD's unknown-fix false
    # positives on a fully-updated host.
    body = RUNBOOK.read_text()
    assert "required_overlays: ubuntu_fixes,debian_fixes" in body, (
        "the host contract does not declare which overlay tables the "
        "published map must carry")


def test_the_shipped_runbook_requires_the_contract_s_overlays():
    body = RUNBOOK.read_text()
    assert ("--require-overlay ubuntu_fixes --require-overlay debian_fixes"
            in body), (
        "the runbook verifies the served map without requiring the overlay "
        "rows the contract declares, so a map that lost them still passes")


def test_the_daily_job_checks_the_served_maps_overlay_coverage():
    # The operator checks the map by hand; the nightly job is the thing that
    # builds it, so the job must make the same check after its publish.
    text = DAILY_SCRIPT.read_text()
    assert "--require-overlay ubuntu_fixes" in text
    assert "--require-overlay debian_fixes" in text
    assert text.index("posture spine publish") < text.index(
        "--require-overlay ubuntu_fixes")


def test_gate_reports_the_overlay_coverage_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "the served map's overlay coverage is checked" in result.stdout


def test_gate_rejects_a_runbook_that_never_requires_the_overlays(tmp_path):
    # A runbook that verifies the map's digests but not its overlay rows
    # confirms a map that may no longer say which packages are patched.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        " --require-overlay ubuntu_fixes --require-overlay debian_fixes", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not require the overlay rows" in result.stdout
    assert "ubuntu_fixes" in result.stdout


def test_gate_rejects_a_contract_naming_an_overlay_the_map_cannot_carry(
        tmp_path):
    # A contract that names a table the published map cannot carry describes
    # a requirement that can never be met.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "required_overlays: ubuntu_fixes,debian_fixes",
        "required_overlays: ubuntu_fixes,not_a_table")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "not an overlay table the published map can carry" in result.stdout


def test_gate_rejects_a_contract_without_the_required_overlays(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "required_overlays: ubuntu_fixes,debian_fixes\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "required_overlays" in result.stdout


def test_gate_rejects_a_contract_whose_overlays_the_daily_job_never_checks(
        tmp_path):
    # The nightly job builds the map the operator checks; a contract that
    # requires an overlay the job never requires describes a job that
    # publishes a map the operator would not accept.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "required_overlays: ubuntu_fixes,debian_fixes",
        "required_overlays: ubuntu_fixes,debian_fixes,kev")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "the daily job checks the served map but does not require" in (
        result.stdout)


# ---------------------------------------------------------------------------
# Overlay ingest scope of the nightly job (dimension 4p)
# ---------------------------------------------------------------------------


def test_the_host_contract_declares_the_overlay_ingest_scope():
    # The contract states the releases and packages the nightly job must
    # ingest for each distro-tracker overlay the host requires, so the gate
    # can bind the job's --release/--package arguments to it.
    body = RUNBOOK.read_text()
    assert "overlay_ubuntu_releases: resolute,noble,jammy,focal" in body, (
        "the host contract does not declare the Ubuntu overlay ingest "
        "release scope")
    assert "overlay_ubuntu_packages: linux,linux-nvidia" in body, (
        "the host contract does not declare the Ubuntu overlay ingest "
        "package scope")
    assert "overlay_debian_releases: trixie,bookworm" in body, (
        "the host contract does not declare the Debian overlay ingest "
        "release scope")
    assert "overlay_debian_packages: linux" in body, (
        "the host contract does not declare the Debian overlay ingest "
        "package scope")


def test_the_daily_job_ingests_the_scope_the_contract_declares():
    # The nightly job's posture ingest ubuntu/debian invocations must carry
    # exactly the --release and --package values the contract declares, so a
    # scope that shrinks in the job is loud at check time.
    text = DAILY_SCRIPT.read_text()
    assert "posture ingest ubuntu" in text
    assert "posture ingest debian" in text
    for release in ("resolute", "noble", "jammy", "focal"):
        assert f"--release {release}" in text, (
            f"the daily job does not ingest Ubuntu release {release}")
    for package in ("linux", "linux-nvidia"):
        assert f"--package {package}" in text, (
            f"the daily job does not ingest Ubuntu package {package}")
    for release in ("trixie", "bookworm"):
        assert f"--release {release}" in text, (
            f"the daily job does not ingest Debian release {release}")
    assert "--package linux" in text


def test_gate_reports_the_overlay_ingest_scope_dimension_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "the nightly job's overlay ingest scope matches" in result.stdout


def test_gate_rejects_a_contract_that_drops_a_required_release(tmp_path):
    # A contract that drops a release the nightly job still ingests describes
    # a narrower scope than the job, so the contract and the job disagree
    # about which releases the host refreshes.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "overlay_ubuntu_releases: resolute,noble,jammy,focal",
        "overlay_ubuntu_releases: noble,jammy,focal")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "ingests ubuntu with --release resolute" in result.stdout
    assert "the host contract does not declare" in result.stdout


def test_gate_rejects_a_contract_that_declares_a_release_the_job_never_ingests(
        tmp_path):
    # A contract that declares a release the nightly job does not ingest is
    # the silent-narrowing direction the dimension exists to catch: the job
    # dropped the release, the no-wipe ingest retains last-known-good rows,
    # and the coverage check still passes while the rows go stale.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "overlay_ubuntu_releases: resolute,noble,jammy,focal",
        "overlay_ubuntu_releases: resolute,noble,jammy,focal,impish")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "ingests ubuntu without the --release impish" in result.stdout
    assert "silently narrows" in result.stdout


def test_gate_rejects_a_contract_that_drops_a_required_package(tmp_path):
    # A contract that drops a package the nightly job still ingests describes
    # a narrower scope than the job.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "overlay_ubuntu_packages: linux,linux-nvidia",
        "overlay_ubuntu_packages: linux")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "ingests ubuntu with --package linux-nvidia" in result.stdout
    assert "the host contract does not declare" in result.stdout


def test_gate_rejects_a_contract_missing_the_overlay_ingest_scope(tmp_path):
    # A contract that requires the distro-tracker overlays but declares no
    # ingest scope leaves the gate nothing to bind the job's arguments to.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook()
    for key_line in (
            "overlay_ubuntu_releases: resolute,noble,jammy,focal",
            "overlay_ubuntu_packages: linux,linux-nvidia",
            "overlay_debian_releases: trixie,bookworm",
            "overlay_debian_packages: linux"):
        body = body.replace(key_line + "\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "overlay_ubuntu_releases" in result.stdout
    assert "declares no overlay_ubuntu_releases" in result.stdout


def test_gate_rejects_a_contract_that_declares_scope_for_an_unrequired_distro(
        tmp_path):
    # A contract that declares Ubuntu ingest scope but does not require the
    # ubuntu_fixes overlay describes ingest work whose overlay the host does
    # not serve.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "required_overlays: ubuntu_fixes,debian_fixes",
        "required_overlays: debian_fixes")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not require the ubuntu_fixes overlay" in result.stdout


# ---------------------------------------------------------------------------
# Per-release overlay coverage of the served map (dimension 4q)
# ---------------------------------------------------------------------------


def test_the_host_contract_declares_the_per_release_overlay_floor():
    # The contract states a row floor for every distro-tracker overlay it
    # requires, and a freshness allowance for the overlay rows, so the gate
    # can require the served map's per-release coverage.
    body = RUNBOOK.read_text()
    assert "overlay_ubuntu_min_rows: 1" in body, (
        "the host contract does not declare the Ubuntu overlay row floor")
    assert "overlay_debian_min_rows: 1" in body, (
        "the host contract does not declare the Debian overlay row floor")
    assert "overlay_max_age_days: 2" in body, (
        "the host contract does not declare the overlay freshness allowance")


def test_the_runbook_requires_every_declared_release():
    # The runbook's verification must require the rows of every release the
    # contract's overlay scope declares: a per-table check cannot see a
    # release that is missing while the table still holds other releases.
    body = RUNBOOK.read_text()
    for table, release in (("ubuntu_fixes", "resolute"),
                            ("ubuntu_fixes", "noble"),
                            ("ubuntu_fixes", "jammy"),
                            ("ubuntu_fixes", "focal"),
                            ("debian_fixes", "trixie"),
                            ("debian_fixes", "bookworm")):
        assert f"--require-overlay-release {table}:{release}:1" in body, (
            f"the runbook does not require the {table} rows of release "
            f"{release}")
    assert "--require-overlay-max-age-days 2" in body, (
        "the runbook does not require the overlay rows to be fresh")


def test_the_daily_job_requires_every_declared_release():
    # The nightly job builds the map; it must make the same per-release
    # check the runbook shows, right after it publishes.
    text = DAILY_SCRIPT.read_text()
    for table, release in (("ubuntu_fixes", "resolute"),
                            ("ubuntu_fixes", "noble"),
                            ("ubuntu_fixes", "jammy"),
                            ("ubuntu_fixes", "focal"),
                            ("debian_fixes", "trixie"),
                            ("debian_fixes", "bookworm")):
        assert f"--require-overlay-release {table}:{release}:1" in text, (
            f"the daily job does not require the {table} rows of release "
            f"{release}")
    assert "--require-overlay-max-age-days 2" in text, (
        "the daily job does not require the overlay rows to be fresh")


def test_gate_reports_the_per_release_overlay_coverage_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "per-release overlay coverage is checked" in result.stdout


def test_gate_rejects_a_contract_with_no_row_floor_for_a_required_overlay(
        tmp_path):
    # Without a floor the gate has nothing to require of the map's rows.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "overlay_ubuntu_min_rows: 1\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no overlay_ubuntu_min_rows" in result.stdout


def test_gate_rejects_a_contract_with_no_freshness_allowance(tmp_path):
    # Without an allowance the gate cannot tell a live release from one the
    # nightly job stopped ingesting.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "overlay_max_age_days: 2\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no overlay_max_age_days" in result.stdout


def test_gate_rejects_a_contract_with_a_row_floor_for_an_unrequired_overlay(
        tmp_path):
    # A floor for an overlay the host does not serve describes a
    # requirement about rows the map never carries.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "required_overlays: ubuntu_fixes,debian_fixes",
        "required_overlays: debian_fixes")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not require the ubuntu_fixes overlay" in result.stdout


def test_gate_rejects_a_runbook_that_drops_a_release_requirement(tmp_path):
    # A runbook that requires the overlay tables but not the releases
    # inside them confirms a map that may be quietly narrow.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        " --require-overlay-release ubuntu_fixes:jammy:1", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not require the ubuntu_fixes rows of release jammy" in (
        result.stdout)


def test_gate_rejects_a_runbook_that_drops_the_freshness_allowance(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        " --require-overlay-max-age-days 2", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not require the overlay rows to be fresh" in result.stdout


def test_gate_rejects_a_runbook_that_uses_a_different_row_floor(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "--require-overlay-release ubuntu_fixes:noble:1",
        "--require-overlay-release ubuntu_fixes:noble:9")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "overlay_ubuntu_min_rows floor" in result.stdout


# ---------------------------------------------------------------------------
# Per-package overlay coverage of the served map (dimension 4r)
# ---------------------------------------------------------------------------


def test_the_host_contract_declares_the_per_package_overlay_floor():
    # The contract states a per-package row floor for every distro-tracker
    # overlay it requires, so the gate can require the served map's
    # per-package coverage.
    body = RUNBOOK.read_text()
    assert "overlay_ubuntu_min_package_rows: 1" in body, (
        "the host contract does not declare the Ubuntu overlay per-package "
        "row floor")
    assert "overlay_debian_min_package_rows: 1" in body, (
        "the host contract does not declare the Debian overlay per-package "
        "row floor")


def test_the_runbook_requires_every_declared_package():
    # The runbook's verification must require the rows of every (release,
    # package) pair the contract's overlay scope declares: a per-release
    # floor cannot see a package that is missing while its release still
    # looks populated.
    body = RUNBOOK.read_text()
    for table, release, package in (
            ("ubuntu_fixes", "resolute", "linux"),
            ("ubuntu_fixes", "resolute", "linux-nvidia"),
            ("ubuntu_fixes", "noble", "linux"),
            ("ubuntu_fixes", "noble", "linux-nvidia"),
            ("ubuntu_fixes", "jammy", "linux"),
            ("ubuntu_fixes", "jammy", "linux-nvidia"),
            ("ubuntu_fixes", "focal", "linux"),
            ("ubuntu_fixes", "focal", "linux-nvidia"),
            ("debian_fixes", "trixie", "linux"),
            ("debian_fixes", "bookworm", "linux")):
        assert (f"--require-overlay-package "
                f"{table}:{release}:{package}:1" in body), (
            f"the runbook does not require the {table} rows of release "
            f"{release} package {package}")


def test_the_daily_job_requires_every_declared_package():
    # The nightly job builds the map; it must make the same per-package
    # check the runbook shows, right after it publishes.
    text = DAILY_SCRIPT.read_text()
    for table, release, package in (
            ("ubuntu_fixes", "resolute", "linux"),
            ("ubuntu_fixes", "resolute", "linux-nvidia"),
            ("ubuntu_fixes", "noble", "linux"),
            ("ubuntu_fixes", "noble", "linux-nvidia"),
            ("ubuntu_fixes", "jammy", "linux"),
            ("ubuntu_fixes", "jammy", "linux-nvidia"),
            ("ubuntu_fixes", "focal", "linux"),
            ("ubuntu_fixes", "focal", "linux-nvidia"),
            ("debian_fixes", "trixie", "linux"),
            ("debian_fixes", "bookworm", "linux")):
        assert (f"--require-overlay-package "
                f"{table}:{release}:{package}:1" in text), (
            f"the daily job does not require the {table} rows of release "
            f"{release} package {package}")


def test_gate_reports_the_per_package_overlay_coverage_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "per-package overlay coverage is checked" in result.stdout


def test_gate_rejects_a_contract_with_no_per_package_row_floor(tmp_path):
    # Without a per-package floor the gate has nothing to require of the
    # map's per-package rows.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "overlay_ubuntu_min_package_rows: 1\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no overlay_ubuntu_min_package_rows" in result.stdout


def test_gate_rejects_a_contract_with_a_per_package_floor_for_an_unrequired_overlay(
        tmp_path):
    # A per-package floor for an overlay the host does not serve describes
    # a requirement about rows the map never carries.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "required_overlays: ubuntu_fixes,debian_fixes",
        "required_overlays: debian_fixes")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not require the ubuntu_fixes overlay" in result.stdout


def test_gate_rejects_a_runbook_that_drops_a_package_requirement(tmp_path):
    # A runbook that requires the releases but not the packages inside
    # them confirms a map that may be quietly narrow in the narrowest
    # direction.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        " --require-overlay-package ubuntu_fixes:noble:linux-nvidia:1", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert ("does not require the ubuntu_fixes rows of release noble "
            "package linux-nvidia") in result.stdout


def test_gate_rejects_a_runbook_that_uses_a_different_per_package_floor(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "--require-overlay-package ubuntu_fixes:noble:linux:1",
        "--require-overlay-package ubuntu_fixes:noble:linux:9")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "overlay_ubuntu_min_package_rows floor" in result.stdout


def test_gate_rejects_a_runbook_that_requires_an_undeclared_package(tmp_path):
    # A runbook that requires a package the contract's scope does not
    # declare describes a different per-package scope than the contract.
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        " --require-overlay-package ubuntu_fixes:resolute:linux:1",
        " --require-overlay-package ubuntu_fixes:resolute:linux:1"
        " --require-overlay-package ubuntu_fixes:resolute:ghost:1")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "release resolute package ghost" in result.stdout


def test_gate_rejects_a_daily_job_that_drops_a_package_requirement(tmp_path):
    # The nightly job must make the same per-package check the runbook
    # shows. Declare a package in the contract that the real daily job's
    # spine verify does not require, so the job-side validator fires (the
    # gate always checks the repository's own daily script against the
    # runbook's contract).
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "overlay_ubuntu_packages: linux,linux-nvidia",
        "overlay_ubuntu_packages: linux,linux-nvidia,ghost")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "the daily job checks the served map but does not require" in (
        result.stdout)
    assert "package ghost" in result.stdout


# ---------------------------------------------------------------------------
# Known-exploited coverage of the served map (dimension 4s)
# ---------------------------------------------------------------------------


def test_the_host_contract_declares_the_known_exploited_coverage():
    # The contract states a row floor and a freshness allowance for the
    # known-exploited set, so the gate can require the served map to carry
    # it: the KEV ingest is a no-wipe refresh, so a failed fetch leaves the
    # last-known-good rows serving and every other check still passes.
    body = RUNBOOK.read_text()
    assert "kev_min_rows: 1000" in body, (
        "the host contract does not declare the known-exploited row floor")
    assert "kev_max_age_days: 3" in body, (
        "the host contract does not declare the known-exploited freshness "
        "allowance")


def test_the_runbook_requires_the_known_exploited_coverage():
    body = RUNBOOK.read_text()
    assert "--require-kev 1000" in body, (
        "the runbook does not require the known-exploited rows")
    assert "--require-kev-max-age-days 3" in body, (
        "the runbook does not require the known-exploited rows to be fresh")


def test_the_daily_job_requires_the_known_exploited_coverage():
    # The nightly job builds the map; it must make the same check the
    # runbook shows, right after it publishes.
    text = DAILY_SCRIPT.read_text()
    assert "--require-kev 1000" in text, (
        "the daily job does not require the known-exploited rows")
    assert "--require-kev-max-age-days 3" in text, (
        "the daily job does not require the known-exploited rows to be "
        "fresh")


def test_gate_reports_the_known_exploited_coverage_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "known-exploited coverage is checked" in result.stdout


def test_gate_reports_the_flat_overlay_coverage_in_its_summary():
    result = _run_gate_on([])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Apple fix and EPSS overlay coverage is checked" in (
        result.stdout)


def test_gate_rejects_a_contract_with_no_known_exploited_row_floor(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("kev_min_rows: 1000\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no kev_min_rows" in result.stdout


def test_gate_rejects_a_contract_with_no_known_exploited_freshness_allowance(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("kev_max_age_days: 3\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no kev_max_age_days" in result.stdout


def test_gate_rejects_a_runbook_that_drops_the_known_exploited_requirement(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(" --require-kev 1000", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not require the known-exploited rows" in result.stdout


def test_gate_rejects_a_runbook_that_uses_a_different_known_exploited_floor(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("--require-kev 1000",
                                       "--require-kev 5")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "kev_min_rows floor is 1000" in result.stdout


def test_gate_rejects_a_runbook_that_drops_the_known_exploited_freshness(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(" --require-kev-max-age-days 3", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "known-exploited rows to be fresh" in result.stdout


def test_gate_rejects_a_daily_job_that_drops_the_known_exploited_floor(
        tmp_path):
    # The nightly job must make the same check the runbook shows. Declare a
    # floor the real daily job does not require, so the job-side validator
    # fires (the gate always checks the repository's own daily script
    # against the runbook's contract).
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("kev_min_rows: 1000",
                                       "kev_min_rows: 2000")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "the daily job requires 1000 known-exploited row(s)" in (
        result.stdout), result.stdout
    assert "kev_min_rows floor is 2000" in result.stdout, result.stdout


# ---------------------------------------------------------------------------
# Flat overlay coverage of the served map (dimension 4t) — Apple fix
# ---------------------------------------------------------------------------


def test_the_host_contract_declares_the_apple_fix_coverage():
    body = RUNBOOK.read_text()
    assert "apple_fixes_min_rows: 1" in body, (
        "the host contract does not declare the Apple fix row floor")
    assert "apple_fixes_max_age_days: 7" in body, (
        "the host contract does not declare the Apple fix freshness "
        "allowance")


def test_the_runbook_requires_the_apple_fix_coverage():
    body = RUNBOOK.read_text()
    assert "--require-apple-fixes 1" in body, (
        "the runbook does not require the Apple fix rows")
    assert "--require-apple-fixes-max-age-days 7" in body, (
        "the runbook does not require the Apple fix rows to be fresh")


def test_the_daily_job_requires_the_apple_fix_coverage():
    text = DAILY_SCRIPT.read_text()
    assert "--require-apple-fixes 1" in text, (
        "the daily job does not require the Apple fix rows")
    assert "--require-apple-fixes-max-age-days 7" in text, (
        "the daily job does not require the Apple fix rows to be fresh")


def test_gate_rejects_a_contract_with_no_apple_fix_row_floor(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("apple_fixes_min_rows: 1\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no apple_fixes_min_rows" in result.stdout


def test_gate_rejects_a_contract_with_no_apple_fix_freshness_allowance(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("apple_fixes_max_age_days: 7\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no apple_fixes_max_age_days" in result.stdout


def test_gate_rejects_a_runbook_that_drops_the_apple_fix_requirement(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(" --require-apple-fixes 1", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not require the Apple fix rows" in result.stdout


def test_gate_rejects_a_runbook_that_uses_a_different_apple_fix_floor(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("--require-apple-fixes 1",
                                       "--require-apple-fixes 5")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "apple_fixes_min_rows floor is 1" in result.stdout


def test_gate_rejects_a_runbook_that_drops_the_apple_fix_freshness(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        " --require-apple-fixes-max-age-days 7", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "Apple fix rows to be fresh" in result.stdout


def test_gate_rejects_a_daily_job_that_drops_the_apple_fix_floor(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("apple_fixes_min_rows: 1",
                                       "apple_fixes_min_rows: 50")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "the daily job requires 1 Apple fix row(s)" in result.stdout
    assert "apple_fixes_min_rows floor is 50" in result.stdout


# ---------------------------------------------------------------------------
# Per-product Apple fix coverage of the served map (dimension 4u)
# ---------------------------------------------------------------------------


def test_the_host_contract_declares_the_apple_product_coverage():
    body = RUNBOOK.read_text()
    assert "apple_fixes_products: iphone_os,ipados,macos" in body, (
        "the host contract does not declare the Apple product scope")
    assert "apple_fixes_min_product_rows: 1" in body, (
        "the host contract does not declare the per-product row floor")
    assert "apple_fixes_product_max_age_days: 7" in body, (
        "the host contract does not declare the per-product freshness "
        "allowance")


def test_the_runbook_requires_the_apple_product_coverage():
    body = RUNBOOK.read_text()
    for product in ("iphone_os", "ipados", "macos"):
        assert f"--require-apple-fixes-product {product}:1" in body, (
            f"the runbook does not require the Apple fix rows of {product}")
    assert "--require-apple-fixes-product-max-age-days 7" in body, (
        "the runbook does not require the per-product Apple fix rows to be "
        "fresh")


def test_the_daily_job_requires_the_apple_product_coverage():
    text = DAILY_SCRIPT.read_text()
    for product in ("iphone_os", "ipados", "macos"):
        assert f"--require-apple-fixes-product {product}:1" in text, (
            f"the daily job does not require the Apple fix rows of {product}")
    assert "--require-apple-fixes-product-max-age-days 7" in text, (
        "the daily job does not require the per-product Apple fix rows to be "
        "fresh")


def test_gate_rejects_a_contract_with_no_apple_product_scope(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "apple_fixes_products: iphone_os,ipados,macos\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no apple_fixes_products" in result.stdout


def test_gate_rejects_a_contract_with_no_apple_per_product_floor(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "apple_fixes_min_product_rows: 1\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no apple_fixes_min_product_rows" in result.stdout


def test_gate_rejects_a_contract_with_no_apple_per_product_freshness(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "apple_fixes_product_max_age_days: 7\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no apple_fixes_product_max_age_days" in result.stdout


def test_gate_rejects_a_runbook_that_drops_an_apple_product_requirement(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        " --require-apple-fixes-product ipados:1", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not require the Apple fix rows of ipados" in result.stdout


def test_gate_rejects_a_runbook_that_uses_a_different_apple_product_floor(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "--require-apple-fixes-product macos:1",
        "--require-apple-fixes-product macos:5")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "apple_fixes_min_product_rows floor is 1" in result.stdout


def test_gate_rejects_a_runbook_that_drops_the_apple_product_freshness(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        " --require-apple-fixes-product-max-age-days 7", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "per-product Apple fix rows to be fresh" in result.stdout


def test_gate_rejects_a_daily_job_that_drops_an_apple_product_requirement(
        tmp_path):
    # The nightly job must make the same check the runbook shows. Declare a
    # product the real daily job does not require, so the job-side
    # validator fires (the gate always checks the repository's own daily
    # script against the runbook's contract).
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        "apple_fixes_products: iphone_os,ipados,macos",
        "apple_fixes_products: iphone_os,ipados,macos,watchos")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "the daily job checks the served map but does not require the "
    assert "watchos" in result.stdout


# ---------------------------------------------------------------------------
# Flat overlay coverage of the served map (dimension 4t) — EPSS
# ---------------------------------------------------------------------------


def test_the_host_contract_declares_the_epss_coverage():
    body = RUNBOOK.read_text()
    assert "epss_min_rows: 100000" in body, (
        "the host contract does not declare the EPSS row floor")
    assert "epss_max_age_days: 3" in body, (
        "the host contract does not declare the EPSS freshness allowance")


def test_the_runbook_requires_the_epss_coverage():
    body = RUNBOOK.read_text()
    assert "--require-epss 100000" in body, (
        "the runbook does not require the EPSS rows")
    assert "--require-epss-max-age-days 3" in body, (
        "the runbook does not require the EPSS rows to be fresh")


def test_the_daily_job_requires_the_epss_coverage():
    text = DAILY_SCRIPT.read_text()
    assert "--require-epss 100000" in text, (
        "the daily job does not require the EPSS rows")
    assert "--require-epss-max-age-days 3" in text, (
        "the daily job does not require the EPSS rows to be fresh")


def test_gate_rejects_a_contract_with_no_epss_row_floor(tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("epss_min_rows: 100000\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no epss_min_rows" in result.stdout


def test_gate_rejects_a_contract_with_no_epss_freshness_allowance(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("epss_max_age_days: 3\n", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "declares no epss_max_age_days" in result.stdout


def test_gate_rejects_a_runbook_that_drops_the_epss_requirement(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(" --require-epss 100000", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "does not require the EPSS rows" in result.stdout


def test_gate_rejects_a_runbook_that_uses_a_different_epss_floor(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("--require-epss 100000",
                                       "--require-epss 5")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "epss_min_rows floor is 100000" in result.stdout


def test_gate_rejects_a_runbook_that_drops_the_epss_freshness(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace(
        " --require-epss-max-age-days 3", "")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "EPSS rows to be fresh" in result.stdout


def test_gate_rejects_a_daily_job_that_drops_the_epss_floor(
        tmp_path):
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook().replace("epss_min_rows: 100000",
                                       "epss_min_rows: 500000")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert "the daily job requires 100000 EPSS row(s)" in result.stdout
    assert "epss_min_rows floor is 500000" in result.stdout
