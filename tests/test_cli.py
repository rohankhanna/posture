"""CLI surface smoke tests — lock the argparse routing for the CI-spine
commands so a regression in the subparser wiring is caught before it reaches a
workflow run. Does not execute the handlers (no DB/network); only asserts the
parser routes the right flags to the right function.
"""
from __future__ import annotations

from posture.cli import build_parser, _cmd_spine, _cmd_refresh


def _parse(*argv):
    return build_parser().parse_args(list(argv))


def test_spine_export_routes():
    args = _parse("spine", "export", "--out", "/tmp/sp")
    assert args.sub == "export"
    assert args.func is _cmd_spine
    assert args.out == "/tmp/sp"


def test_spine_import_routes():
    args = _parse("spine", "import", "--from", "/tmp/sp", "--no-verify")
    assert args.sub == "import"
    assert args.func is _cmd_spine
    assert args.from_dir == "/tmp/sp"
    assert args.no_verify is True


def test_spine_show_still_routes_after_extension():
    # the show surface must survive the export/import addition (rebind is retired)
    args = _parse("spine", "show")
    assert args.sub == "show" and args.func is _cmd_spine


def test_refresh_no_devices_flag_routes():
    args = _parse("refresh", "--no-devices", "--cap", "50")
    assert args.func is _cmd_refresh
    assert args.no_devices is True
    assert args.cap == 50


def test_refresh_default_keeps_devices():
    args = _parse("refresh")
    assert args.no_devices is False
    assert args.devices  # defaults to DEFAULT_DEVICES, not None


def test_cmd_demo_runs_end_to_end_installs_policy(tmp_path):
    """Regression: ``posture demo`` runs end-to-end through
    ``_install_policy_if_needed`` (which reads ``policy.supersedes``) +
    ``_inject_catalog_overlays`` + ``engine.assess`` without raising. The
    argparse routing smoke tests above never execute a handler, so an
    attribute typo in ``_install_policy_if_needed`` (supersedes -> supcedes)
    once shipped green locally and only surfaced in CI's Stream step. This
    pins the policy-attribute access + the territory injection path that the
    routing tests don't reach."""
    from posture.cli import build_parser, _cmd_demo

    db = tmp_path / "demo.db"
    args = build_parser().parse_args(["demo", "--db", str(db)])
    rc = _cmd_demo(args)
    assert rc == 0
    # the policy version row was written (install_policy_if_needed ran clean).
    from posture import store
    conn = store.connect(str(db), readonly=True)
    rows = conn.execute(
        "SELECT version FROM policy_versions").fetchall()
    assert len(rows) >= 1