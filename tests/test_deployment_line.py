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


def _baseline_runbook(extra: str = "") -> str:
    """A runbook that satisfies every runbook check, plus an extra line.

    The baseline names every shipped unit and documents every environment
    variable a shipped unit sets, so a test that adds one defect sees only
    that defect.
    """
    lines = ["# Deployment runbook", ""]
    for name in _shipped_unit_names():
        lines.append(f"Install `{name}`.")
        lines.append("")
    for variable in _unit_environment_variables():
        lines.append(f"The variable `{variable}` is read by the daily job.")
        lines.append("")
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
    runbook = tmp_path / "deployment.md"
    body = _baseline_runbook()
    omitted = _shipped_unit_names()[0]
    body = body.replace(f"Install `{omitted}`.", "Install the service.")
    runbook.write_text(body)
    result = _run_gate_on([runbook])
    assert result.returncode == 1
    assert omitted in result.stdout
    assert "does not name" in result.stdout


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
