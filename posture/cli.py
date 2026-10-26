"""posture CLI — argparse subparsers (mirrors forebode/cli.py's pattern).

  posture demo                    offline: full 6-axis posture from the fixture
  posture assess <device.yaml> [--live] [--db PATH]
  posture axes
  posture policy {show|log|validate} [file]
  posture observers
  posture health [observer] / posture health add-dossier ...
  posture distrust <observer> [--reason]
  posture audit <observer>
  posture crosswalk {add|show} ...
  posture discover
  posture source-history {list|show <id>|source <src>}   public-infrastructure event ledger
  posture purge [--dry-run]              bounded-growth: forget ancient, irrelevant defects

The report footer emits NVD attribution whenever the NVD observer was actually
used (project rule: the map is foreign-authored; say so).
"""

from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path

import yaml

from . import __version__
from .axis import Axis, AXES, AXIS_META
from . import policy as _policy_mod
from . import store as _store
from . import engine as _engine
from . import provenance as _prov
from . import health as _health
from . import source_history as _source_history
from . import discovery as _discovery
from . import spine as _spine
from . import glossary as _glossary
from . import vocab_monitor as _vocab
from . import repair as _repair
from . import attribution as _attr
from . import stream as _stream
from . import refresh as _refresh
from . import export as _export
from . import llm_enrich as _llm_enrich
from . import source_history as _source_history
from .sources import build_default_registry
from .sources.nvd_cve import NvdCveObserver
from .sources import kev as _kev_mod
from .sources import ghsa as _ghsa_mod
from .sources import osv as _osv_mod
from .sources import apple_ingest as _apple_ingest_mod
from .sources import debian_ingest as _debian_ingest_mod
from .sources import ubuntu_ingest as _ubuntu_ingest_mod
from .sources import epss as _epss_mod
from .sources.ubuntu_tracker import UbuntuTrackerObserver
from .sources.debian_tracker import DebianTrackerObserver
from .sources.apple_advisory import AppleAdvisoryObserver

DEFAULT_DB = str(Path.home() / ".local/share/posture/posture.db")
DEFAULT_DEVICES = str(Path.home() / ".config/posture/devices.yaml")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_policy(path: str | None = None) -> "Policy":  # type: ignore[name-defined]
    p = Path(path) if path else _policy_mod.default_policy_path()
    return _policy_mod.Policy.from_file(p)


def _open_db(path: str, readonly: bool = False):
    return _store.connect(path, readonly=readonly)


def _load_device(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"device file not found: {p}")
    return yaml.safe_load(p.read_text())


def _install_policy_if_needed(conn, policy) -> None:
    _store.install_policy_version(
        conn, policy.version, policy.supersedes, policy.dated,
        policy.rationale, policy.raw_yaml,
    )
    conn.commit()


def _inject_catalog_overlays(device: dict, conn) -> None:
    """Territory-side pre-pass: load signed-spine catalog overlays a device's
    observers consume (the MAP half of the map/territory split) and inject them
    as device INPUTS before assess. The observer contract forbids DB access
    in assess() (no conn), so the territory pre-loads overlays here —
    this is the "consume locally" half of "feed and enrich in CI, consume
    locally".

    Additive and never clobbers: a device that already supplies an overlay
    (explicit operator input, hermetic tests) is left untouched. No-op when the
    device declares no apple_product or the local store has no overlay rows
    for that product (the observer then falls back to its per-assess replay).

    Four overlays are consumed today:
      * apple_fixes — the Apple fix-version map (per apple_product).
      * catalog_defects — the imported spine defects table keyed by CPE
        head, consumed by :class:`NvdCveObserver`'s catalog-backed fetch path
        so the vulnerability axis decides from the spine with NO network.
      * debian_fixes — the Debian security-tracker status overlay,
        reconstructed to the bulk-data dict shape DebianTrackerObserver's
        _decide consumes, so the distro axis decides from the spine with NO
        network (mirrors the NvdCveObserver catalog path).
      * ubuntu_fixes — the Ubuntu security-tracker status overlay, keyed
        per-CVE per-package, normalized at assess time by
        :class:`UbuntuTrackerObserver`'s catalog path. kev remains
        operator-supplied (device["kev"] / kev_path).
    """
    _inject_apple_fixes_overlay(device, conn)
    _inject_catalog_defects(device, conn)
    _inject_debian_fixes_overlay(device, conn)
    _inject_ubuntu_fixes_overlay(device, conn)


def _inject_apple_fixes_overlay(device: dict, conn) -> None:
    product = str(device.get("apple_product") or "").strip().lower()
    if not product or "apple_fixes" in device:
        return
    try:
        rows = _store.apple_fixes_for_product(conn, product)
    except Exception:
        return  # no overlay table / unreadable -> skip; observer falls back to replay
    if rows:
        device["apple_fixes"] = {r["cve_id"]: r["fixed_in"]
                                 for r in rows if r.get("fixed_in")}


def _inject_catalog_defects(device: dict, conn) -> None:
    """Inject the imported-spine defects a device's NVD observer will consume,
    keyed by CPE head, so the vulnerability axis assesses from the spine with
    NO network path (the catalog-backed assess release condition).

    Only injected when the DB actually carries NVD-sourced catalog rows — i.e.
    this is a real spine mirror, not a fresh/demo DB. A fresh demo DB has none,
    so catalog_defects is left ABSENT and the observer falls back to its
    bundled fixture (the demo corpus), preserving posture demo. Once a
    spine IS present, every nvd_cpe head is injected (empty heads -> []),
    so a head the spine doesn't cover is a COMPLETE-absent answer, NOT a
    fixture leak (the bundled sample CVEs must never surface as a real
    client's verdicts). Additive: a device that pre-supplies
    catalog_defects (operator input / hermetic test) is left untouched.
    """
    if "catalog_defects" in device:
        return
    from .sources.nvd_cve import _cpe_head
    heads = {_cpe_head(m["cpe"]) for m in device.get("matchers", [])
             if m.get("type") == "nvd_cpe" and m.get("cpe")}
    if not heads:
        return
    try:
        has_catalog = conn.execute(
            "SELECT 1 FROM defects WHERE source='nvd' LIMIT 1").fetchone()
    except Exception:
        return  # no defects table / unreadable -> skip; observer falls back
    if not has_catalog:
        return
    device["catalog_defects"] = {h: _store.defects_for_cpe_head(conn, h) for h in heads}


def _inject_debian_fixes_overlay(device: dict, conn) -> None:
    """Inject the Debian security-tracker status overlay a device's
    :class:`DebianTrackerObserver` consumes, reconstructed to the bulk-data dict
    shape its _decide reads, so the distro axis assesses from the spine with
    NO network path (the catalog-backed assess path, mirroring
    :class:`NvdCveObserver`).

    Only injected when the DB carries debian_fixes rows — a fresh/demo DB has
    none, so debian_fixes is left ABSENT and the observer falls back to its
    bundled fixture (preserving posture demo). Once the overlay IS present,
    the bulk dict is rebuilt from the device's debian_release +
    debian_packages (an uncovered release/package yields an empty block ->
    _decide returns None -> NVD stands: a COMPLETE-absent answer, NOT a
    fixture leak). Additive: a device that pre-supplies debian_fixes
    (operator input / hermetic test) is left untouched.
    """
    release = str(device.get("debian_release") or "").strip().lower()
    packages = [p for p in (device.get("debian_packages") or []) if p]
    if not release or not packages or "debian_fixes" in device:
        return
    try:
        has_overlay = conn.execute("SELECT 1 FROM debian_fixes LIMIT 1").fetchone()
    except Exception:
        return  # no overlay table / unreadable -> skip; observer falls back to fixture
    if not has_overlay:
        return
    # Rebuild the bulk-data dict shape _decide consults:
    # {package: {cve_id: {"releases": {release: {"status", "fixed_version"}}}}}.
    # The overlay's fixed_in column maps to the tracker's fixed_version.
    data: dict = {}
    for pkg in packages:
        pblock: dict = {}
        for r in _store.debian_fixes_for_release_package(conn, release, pkg):
            pblock[r["cve_id"]] = {"releases": {release: {
                "status": r.get("status"), "fixed_version": r.get("fixed_in")}}}
        if pblock:
            data[pkg] = pblock
    device["debian_fixes"] = data


def _inject_ubuntu_fixes_overlay(device: dict, conn) -> None:
    """Inject the Ubuntu security-tracker status overlay a device's
    :class:`UbuntuTrackerObserver` consumes, keyed per-CVE per-package, so the
    distro axis assesses from the spine with NO network path (the catalog-backed
    assess path, mirroring :class:`NvdCveObserver`).

    The overlay stores the RAW tracker status words (released /
    needed / needs-triage / not-affected / DNE / ignored /
    deferred); the observer normalizes them at assess time to the same
    {pkg: (status, fixed_in)} shape :func:`parse_cve_page` produces, so
    _decide runs UNCHANGED (one decision path, not a second one for the
    catalog). Same fresh-DB / complete-absent / no-clobber contract as the
    Debian injector above.
    """
    release = str(device.get("ubuntu_release") or "").strip().lower()
    packages = [p for p in (device.get("ubuntu_packages") or []) if p]
    if not release or not packages or "ubuntu_fixes" in device:
        return
    try:
        has_overlay = conn.execute("SELECT 1 FROM ubuntu_fixes LIMIT 1").fetchone()
    except Exception:
        return  # no overlay table / unreadable -> skip; observer falls back to fixture
    if not has_overlay:
        return
    # Per-CVE -> {package: (raw_status, fixed_in)}; the observer normalizes this
    # to the found shape _decide consumes (mirrors parse_cve_page).
    by_cve: dict = {}
    for pkg in packages:
        for r in _store.ubuntu_fixes_for_release_package(conn, release, pkg):
            by_cve.setdefault(r["cve_id"], {})[pkg] = (r.get("status"), r.get("fixed_in"))
    device["ubuntu_fixes"] = by_cve


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def _render_posture(dp: "_engine.DevicePosture", out=sys.stdout) -> None:
    print(f"posture {__version__}  ·  device {dp.device_id}  ·  "
          f"policy {dp.policy_version}  ·  {dp.computed_at}", file=out)
    print(f"overall: {dp.overall}", file=out)
    print("=" * 72, file=out)
    for ap in dp.axes:
        meta = AXIS_META.get(Axis(ap.axis), {})
        flag = "!" if ap.status in {"unpatched", "fail", "exposed", "targeted",
                                    "untrusted", "unknown"} else " "
        gap = f"   GAP: {ap.gap}" if ap.gap else ""
        dec = f"  (decided by {ap.deciding_observer}"
        if ap.bias:
            dec += f", bias={ap.bias}"
        dec += ")" if ap.deciding_observer else ")"
        print(f"{flag} [{ap.axis}] {ap.status.upper()}"
              f"  ({len(ap.verdicts)} verdicts, complete={ap.complete}, "
              f"commit={ap.commit_state})", file=out)
        print(f"     {meta.get('desc', '')}", file=out)
        if ap.deciding_observer:
            print(f"     decided by {ap.deciding_observer}"
                  f"{f' (bias={ap.bias})' if ap.bias else ''}", file=out)
        if gap:
            print(gap, file=out)
        # show up to 5 verdicts per axis
        for v in ap.verdicts[:5]:
            sev = f" [{v['severity']}]" if v.get("severity") else ""
            fi = f" fixed_in={v['fixed_in']}" if v.get("fixed_in") else ""
            print(f"       - {v['key']} {v['status']}{sev}{fi}", file=out)
        if len(ap.verdicts) > 5:
            print(f"       ... +{len(ap.verdicts) - 5} more", file=out)
    print("=" * 72, file=out)
    # attribution: only for observers actually used that require it
    for line in _attr.all_attributions(dp.used_observers):
        print(f"  {line}", file=out)


# ---------------------------------------------------------------------------
# command handlers
# ---------------------------------------------------------------------------

def _cmd_demo(args) -> int:
    policy = _load_policy(args.policy)
    reg = build_default_registry()
    device = yaml.safe_load(
        (Path(__file__).resolve().parent / "fixtures/sample_device.yaml").read_text()
    )
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        _inject_catalog_overlays(device, conn)
        dp = _engine.assess(device, reg, policy, conn=conn)
    _render_posture(dp)
    return 0


def _cmd_assess(args) -> int:
    policy = _load_policy(args.policy)
    device = _load_device(args.device)
    reg = build_default_registry()
    if args.live:
        # swap the offline NVD observer for a live one
        nvd_live = NvdCveObserver(live=True)
        # registry has the offline one at id "nvd"; replace it
        reg._by_id["nvd"] = nvd_live  # type: ignore[attr-defined]
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        _inject_catalog_overlays(device, conn)
        dp = _engine.assess(device, reg, policy, conn=conn)
    _render_posture(dp)
    return 0


def _cmd_axes(args) -> int:
    for a in AXES():
        m = AXIS_META[a]
        print(f"{a.value:14} {m['desc']}")
        print(f"               key: {m['key_kind']}  statuses: {m['status_set']}")
    return 0


def _cmd_policy(args) -> int:
    if args.sub == "show":
        policy = _load_policy(args.file)
        print(json.dumps(policy.to_summary(), indent=2))
        return 0
    if args.sub == "validate":
        policy = _load_policy(args.file)
        print(f"OK  version={policy.version}  observers={len(policy.observers)}  "
              f"degradation={len(policy.degradation)}")
        return 0
    if args.sub == "log":
        with _open_db(args.db, readonly=True) as conn:
            for row in _store.policy_log(conn):
                print(f"{row['version']:18} supersedes={row['supersedes']!s:16} "
                      f"{row['dated']}  installed={row['installed_at']}")
                if row["rationale"]:
                    print(f"  {row['rationale'][:120]}")
        return 0
    return 2


def _cmd_observers(args) -> int:
    policy = _load_policy(args.policy)
    reg = build_default_registry()
    with _open_db(args.db, readonly=True) as conn:
        now = _engine._now()
        for w in reg.all():
            in_policy = policy.has_observer(w.id)
            deg = _health.degradation_action(conn, w.id, policy, now) if in_policy else "n/a"
            axes = ",".join(a.value for a in w.axes)
            print(f"{w.id:12} axes=[{axes:24}] bias={policy.observer_bias(w.id):12} "
                  f"weight={policy.observer_weight(w.id):7} order={policy.observer_order(w.id):3} "
                  f"policy={'yes' if in_policy else 'NO ':3} health={deg}")
    return 0


def _cmd_health(args) -> int:
    policy = _load_policy(args.policy)
    with _open_db(args.db) as conn:
        if args.add_dossier:
            if not (args.observer and args.date and args.claim and args.citation):
                raise SystemExit(
                    "health --add-dossier requires <observer> --date --claim --citation"
                )
            _health.add_dossier_entry(
                conn, args.observer, args.date, args.axis, args.claim,
                args.citation, args.direction,
            )
            conn.commit()
            print(f"recorded dossier entry for {args.observer}")
            return 0
        # default: show health report
        observer = args.observer
        if not observer:
            # show all observers that have any samples
            rows = conn.execute(
                "SELECT DISTINCT observer FROM health_samples ORDER BY observer"
            ).fetchall()
            observers = [r["observer"] for r in rows] or [w.id for w in build_default_registry().all()]
        else:
            observers = [observer]
        now = _engine._now()
        ledger = None if args.no_source_history else _source_history.default_ledger()
        for wid in observers:
            rep = _health.health_report(conn, wid, policy, now, ledger=ledger)
            op = rep["operational"]
            print(f"== {wid} ==")
            print(f"  operational: samples={op['samples']} "
                  f"success_rate={op['success_rate']} "
                  f"mean_latency_ms={op['mean_latency_ms']} "
                  f"last_complete={op['last_complete_at']}")
            print(f"  last_reason: {op['last_reason']}")
            print(f"  degradation: {rep['degradation']}  "
                  f"policy={rep['policy_degradation']}")
            if rep["dossier"]:
                print(f"  dossier ({len(rep['dossier'])} entries):")
                for d in rep["dossier"][:5]:
                    print(f"    {d['date']} [{d['axis']}] ({d['direction']}) "
                          f"{d['claim'][:80]}  | {d['citation']}")
            else:
                print("  dossier: (empty — add with `posture health --add-dossier`)")
            print(f"  drift: {_health.drift_flag(conn, wid)}")
            sh = rep.get("source_history")
            if sh and sh["active_events"]:
                tag = "DEGRADED" if sh["degraded"] else "context"
                print(f"  source_history ({tag}, {len(sh['active_events'])} active):")
                for e in sh["active_events"]:
                    print(f"    {e['date']} [{e['event_type']}/{e['status']}] "
                          f"{e['summary'][:70]}")
                    if e["interpretation"]:
                        print(f"      -> {e['interpretation'][:100]}")
    return 0


def _cmd_distrust(args) -> int:
    with _open_db(args.db) as conn:
        affected = _prov.audit(conn, args.observer)
        n = _prov.distrust(conn, args.observer, args.reason or "(unspecified)")
        conn.commit()
        print(f"marked {n} verdict(s) resting on '{args.observer}' as distrusted "
              f"(reason: {args.reason or '(unspecified)'}).")
        print(f"({len(affected)} total verdicts audit on this observer; "
              f"records retained, not deleted.)")
        if args.verbose:
            for v in affected[:20]:
                print(f"  {v['device_id']} [{v['axis']}] {v['key']} {v['status']} "
                      f"(policy {v['policy_version']}, fetched {v['fetched_at']})")
    return 0


def _cmd_audit(args) -> int:
    with _open_db(args.db, readonly=True) as conn:
        rows = _prov.audit(conn, args.observer)
        print(f"{len(rows)} verdict(s) rest on observer '{args.observer}':")
        for v in rows:
            mark = " DISTRUSTED" if v["distrusted"] else ""
            print(f"  {v['device_id']} [{v['axis']}] {v['key']} {v['status']}"
                  f"  policy={v['policy_version']}  fetched={v['fetched_at']}{mark}")
    return 0


def _cmd_crosswalk(args) -> int:
    with _open_db(args.db) as conn:
        if args.sub == "add":
            _spine.register(conn, args.defect_id, args.alias, args.kind)
            conn.commit()
            print(f"crosswalk: {args.defect_id} = {args.alias} ({args.kind})")
            return 0
        if args.sub == "show":
            aliases = _spine.resolve(conn, args.defect_id)
            if not aliases:
                print(f"{args.defect_id}: no aliases recorded")
            else:
                print(f"{args.defect_id}:")
                for a in aliases:
                    print(f"  {a['alias']}  ({a['kind']})")
            return 0
    return 2


def _cmd_discover(args) -> int:
    with _open_db(args.db) as conn:
        cands = (_discovery.horizon_scan_live(conn) if getattr(args, "fetch", False)
                 else _discovery.horizon_scan(conn))
        for c in cands:
            _discovery.register_candidate(conn, c)   # idempotent on url (v3)
        conn.commit()
    print(f"horizon scan — {len(cands)} candidate source(s) surfaced for review:")
    print("(the machine notices; the human decides to trust. NOT auto-adopted.)")
    for c in cands:
        std = _discovery.STANDARD_FORMATS.get(c.fmt, c.fmt)
        print(f"  [{c.axis:14}] {c.name:32} fmt={c.fmt:10} ({std})")
        print(f"      {c.url}")
        print(f"      {c.note}")
    if not cands:
        print("  (no new aggregators since the last scan — the delta is empty.)")
    print("\nReview each, then `posture` (future) to adopt — record the decision in")
    print("the source-alignment repo with evidence before trusting.")
    return 0


# ---------------------------------------------------------------------------
# glossary / monitor / repair / spine — the growing-vocabulary surface
# ---------------------------------------------------------------------------

def _cmd_glossary(args) -> int:
    with _open_db(args.db) as conn:
        _glossary.ensure_seeded(conn)
        conn.commit()
        if args.sub == "list":
            terms = _glossary.all(conn, status=args.status) if args.status \
                else _glossary.all(conn)
            print(f"{'id':14} {'kind':18} {'status':10} roles")
            print("-" * 72)
            for t in terms:
                print(f"{t.id:14} {t.kind:18} {t.status:10} "
                      f"{','.join(t.roles) or '-'}")
                if t.citation:
                    print(f"  cite: {t.citation}")
            return 0
        if args.sub == "roles":
            for r in sorted(_glossary.ROLES):
                print(r)
            return 0
        if args.sub == "show":
            t = _glossary.get(conn, args.term)
            if not t:
                print(f"unknown term: {args.term}")
                return 1
            print(json.dumps(t.to_dict(), indent=2))
            return 0
        if args.sub == "add":
            roles = (args.roles or "").split(",") if args.roles else []
            roles = [r.strip() for r in roles if r.strip()]
            t = _glossary.Term(id=args.term, label=args.label or args.term,
                              kind=args.kind or "other", roles=roles,
                              status="candidate", citation=args.citation or "")
            _glossary.add_term(conn, t, actor="cli", version="",
                               now=_engine._now())
            conn.commit()
            print(f"added term {args.term} (candidate — promote to trust it)")
            return 0
        if args.sub == "promote":
            _glossary.promote_term(conn, args.term, actor="cli",
                                   now=_engine._now())
            conn.commit()
            print(f"promoted {args.term} -> known (TRUST change recorded)")
            return 0
        if args.sub == "deprecate":
            if not args.successor:
                raise SystemExit("deprecate requires --successor <term_id>")
            _glossary.deprecate_term(conn, args.term, args.successor,
                                     actor="cli", now=_engine._now())
            conn.commit()
            print(f"deprecated {args.term} -> successor {args.successor} "
                  f"(course-correction recorded)")
            return 0
    return 2


def _cmd_monitor(args) -> int:
    with _open_db(args.db) as conn:
        _glossary.ensure_seeded(conn)
        if args.sub == "run":
            sigs = _vocab.scan_structured(conn, now=_engine._now())
            conn.commit()
            print(f"structured scan: {len(sigs)} new candidate term(s) surfaced.")
            print("(the machine notices; the human decides to trust. NOT auto-promoted.)")
            for s in sigs:
                print(f"  [{s.kind}] {s.label}  ({s.context})")
            return 0
        if args.sub == "queue":
            cands = _vocab.queue(conn)
            sigs = _vocab.open_signals(conn)
            print(f"candidate terms awaiting review ({len(cands)}):")
            for c in cands:
                print(f"  {c['id']:14} {c.get('label','')}  [{c['kind']}]  "
                      f"cite={c.get('citation','')}")
            print(f"open signals: {len(sigs)}")
            return 0
    return 2


def _cmd_repair(args) -> int:
    with _open_db(args.db) as conn:
        _glossary.ensure_seeded(conn)
        if args.sub == "list":
            props = _repair.list_open(conn)
            if not props:
                print("no open repair proposals.")
                return 0
            print(f"{len(props)} open repair proposal(s):")
            for p in props:
                print(f"  [{p['kind']}] {p['id']}")
                print(f"      {p['detail']}")
                print(f"      action: {json.dumps(p['proposed_action'])}")
            print("Apply a trust repair with: posture repair apply <id>")
            return 0
        if args.sub == "apply":
            summary = _repair.apply(conn, args.proposal_id, actor="cli",
                                    now=_engine._now())
            conn.commit()
            print(f"applied {summary['id']} ({summary['kind']}): "
                  f"{', '.join(summary['done']) or 'advisory (marked applied)'}")
            return 0
        if args.sub == "reconcile":
            # Sweep system state for drift and raise RepairProposals (AUTO to
            # raise; HUMAN to apply any that touch trust). Pairs with the vocab
            # monitor's structured scan as the daily self-course-correction
            # sweep driven by posture-reconcile.timer.
            policy = _load_policy(args.policy)
            props = _repair.reconcile(conn, policy, now_iso=_engine._now())
            conn.commit()
            print(f"reconcile: {len(props)} new proposal(s) raised.")
            print("(the machine notices; the human decides to trust. "
                  "NOT auto-applied.)")
            for p in props:
                print(f"  [{p.kind}] {p.id}")
                print(f"      {p.detail}")
            if props:
                print("Apply a trust repair with: posture repair apply <id>")
            return 0
    return 2


def _max_age_days(value: str) -> float:
    """Parse a maximum map age in days, refusing a non-positive one.

    A maximum age of zero days would make every map fail, and a negative
    one has no meaning at all: both are an operator mistake, caught while
    the command line is parsed rather than after the map is read.
    """
    try:
        days = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a number of days") from None
    if days <= 0:
        raise argparse.ArgumentTypeError(
            "the maximum map age must be a positive number of days")
    return days


def _parse_overlay_release_requirements(
        values: list[str] | None) -> list[tuple[str, str, int]]:
    """Parse the --require-overlay-release values into requirements.

    Each value names the overlay table, the release, and the minimum number
    of rows the map must carry for that release: TABLE:RELEASE:MIN_ROWS.
    A malformed value is a mistake on the command line, so it is refused
    while the arguments are parsed rather than after the map is read.
    """
    requirements: list[tuple[str, str, int]] = []
    for value in values or []:
        parts = str(value).split(":")
        if len(parts) != 3 or not parts[0].strip() or not parts[1].strip():
            raise ValueError(
                f"{value!r} is not a release coverage requirement; the form "
                f"is TABLE:RELEASE:MIN_ROWS (for example "
                f"ubuntu_fixes:noble:100)")
        try:
            min_rows = int(parts[2])
        except ValueError:
            raise ValueError(
                f"{value!r} does not name a row count; MIN_ROWS must be a "
                f"whole number") from None
        if min_rows < 1:
            raise ValueError(
                f"{value!r} asks for fewer than one row; the minimum is one")
        requirements.append((parts[0].strip(), parts[1].strip(), min_rows))
    return requirements


def _parse_overlay_package_requirements(
        values: list[str] | None) -> list[tuple[str, str, str, int]]:
    """Parse the --require-overlay-package values into requirements.

    Each value names the overlay table, the release, the source package,
    and the minimum number of rows the map must carry for that package of
    that release: TABLE:RELEASE:PACKAGE:MIN_ROWS. A malformed value is
    a mistake on the command line, so it is refused while the arguments
    are parsed rather than after the map is read.
    """
    requirements: list[tuple[str, str, str, int]] = []
    for value in values or []:
        parts = str(value).split(":")
        if (len(parts) != 4 or not parts[0].strip() or not parts[1].strip()
                or not parts[2].strip()):
            raise ValueError(
                f"{value!r} is not a package coverage requirement; the form "
                f"is TABLE:RELEASE:PACKAGE:MIN_ROWS (for example "
                f"ubuntu_fixes:noble:linux:1)")
        try:
            min_rows = int(parts[3])
        except ValueError:
            raise ValueError(
                f"{value!r} does not name a row count; MIN_ROWS must be a "
                f"whole number") from None
        if min_rows < 1:
            raise ValueError(
                f"{value!r} asks for fewer than one row; the minimum is one")
        requirements.append(
            (parts[0].strip(), parts[1].strip(), parts[2].strip(), min_rows))
    return requirements


def _cmd_spine(args) -> int:
    # export is read-only over the DB and produces no trust change; it serializes
    # the catalog (the MAP) to sharded JSONL + a manifest that CI cosign-signs.
    if args.sub == "export":
        policy = _load_policy(args.policy)
        with _open_db(args.db, readonly=True) as conn:
            manifest = _export.export_spine(conn, out_dir=args.out,
                                             policy_version=policy.version)
        print(f"spine export: {manifest['counts']} -> {args.out}/{_export.SPINE_DIR}/")
        if getattr(args, "sign_key", None):
            sig = _export.sign_manifest(args.out, args.sign_key)
            print(f"  signed manifest -> {args.out}/{_export.SPINE_DIR}/state.sig")
        else:
            print(f"  sign it: cosign sign-blob --output-signature "
                  f"{args.out}/{_export.SPINE_DIR}/state.sig "
                  f"{args.out}/{_export.SPINE_DIR}/manifest.json")
            print(f"  or: posture spine export --sign-key <private_key.pem> ...")
        print("  serving this directory directly? use `posture spine publish` "
              "(verify + atomic swap)")
        return 0
    # verify re-checks a spine directory against its own manifest (every shard's
    # sha256 + row count). It is the gate the deployment line runs before it
    # publishes a new map, and the same check a client can run on a pulled map.
    # When the operator passes --verify-sig, the manifest's ed25519 signature
    # (state.sig) is verified against the supplied public key after the
    # internal consistency check passes, so the operator's confirmation of the
    # served map is the same trust check a client makes before it imports.
    if args.sub == "verify":
        try:
            manifest = _export.verify_spine(args.from_dir)
        except (ValueError, OSError) as exc:
            print(f"spine verify: FAILED — {exc}")
            return 1
        if getattr(args, "verify_sig", False):
            signature_key = getattr(args, "signature_key", None)
            if not signature_key:
                print("spine verify: FAILED --verify-sig requires "
                      "--signature-key (the ed25519 public key PEM)")
                return 1
            try:
                _export.verify_manifest_signature(args.from_dir, signature_key)
            except (ValueError, OSError) as exc:
                print(f"spine verify: FAILED — {exc}")
                return 1
            signature_note = "signature verified"
        else:
            signature_note = ""
        # The publish is atomic, so a daily build that has been failing for
        # days leaves the last good map serving, intact and internally
        # consistent. Only the map's own build timestamp shows that the
        # build stopped, so the freshness check reads it.
        max_age_days = getattr(args, "max_age_days", None)
        freshness_note = ""
        if max_age_days is not None:
            try:
                age = _export.verify_manifest_freshness(manifest, max_age_days)
            except (ValueError, OSError) as exc:
                print(f"spine verify: FAILED — {exc}")
                return 1
            freshness_note = (
                f", generated {manifest['generated_at']} "
                f"({age:.1f} day(s) old)")
        # The map can be intact, signed, fresh and consistent with its own
        # manifest while an overlay table is empty: the vendor fix-status
        # rows are simply gone, and the map is quietly wrong about which
        # packages are patched. A host that requires those rows says so,
        # and the check fails loudly instead of passing.
        required_overlays = getattr(args, "require_overlay", None) or []
        overlay_note = ""
        if required_overlays:
            try:
                coverage = _export.verify_overlay_coverage(manifest,
                                                           required_overlays)
            except ValueError as exc:
                print(f"spine verify: FAILED — {exc}")
                return 1
            overlay_note = ", overlay coverage OK (" + ", ".join(
                f"{name} {count} row(s)" for name, count in coverage.items()) + ")"
        # The per-table overlay check above cannot see a release that is
        # missing while the table as a whole still holds rows: the
        # per-(release, package) refresh deletes the rows it replaces, so a
        # release whose tracker feed returned nothing ends up empty while
        # the presence check still passes. The per-release requirement says
        # which releases the host needs and how many rows each must carry.
        release_note = ""
        try:
            release_requirements = _parse_overlay_release_requirements(
                getattr(args, "require_overlay_release", None))
        except ValueError as exc:
            print(f"spine verify: FAILED — {exc}")
            return 1
        overlay_max_age_days = getattr(args, "require_overlay_max_age_days", None)
        if release_requirements or overlay_max_age_days is not None:
            try:
                release_coverage = _export.verify_overlay_release_coverage(
                    manifest, release_requirements,
                    max_age_days=overlay_max_age_days)
            except ValueError as exc:
                print(f"spine verify: FAILED — {exc}")
                return 1
            release_note = ", per-release overlay coverage OK (" + ", ".join(
                f"{table} {release} {entry['rows']} row(s)"
                for table, releases in release_coverage.items()
                for release, entry in releases.items()) + ")"
        # The per-release floor cannot see a package that stopped
        # returning rows while its release still looks populated: the
        # per-(release, package) refresh deletes the rows it replaces, so
        # a source package whose tracker feed went empty leaves that
        # (release, package) pair with no rows while the release's row
        # total and freshness still pass. The per-package requirement says
        # which (release, package) pairs the host needs and how many rows
        # each must carry.
        package_note = ""
        try:
            package_requirements = _parse_overlay_package_requirements(
                getattr(args, "require_overlay_package", None))
        except ValueError as exc:
            print(f"spine verify: FAILED — {exc}")
            return 1
        if package_requirements:
            try:
                package_coverage = _export.verify_overlay_package_coverage(
                    manifest, package_requirements)
            except ValueError as exc:
                print(f"spine verify: FAILED — {exc}")
                return 1
            package_note = ", per-package overlay coverage OK (" + ", ".join(
                f"{table} {release} {package} {rows} row(s)"
                for table, releases in package_coverage.items()
                for release, packages in releases.items()
                for package, rows in packages.items()) + ")"
        # The known-exploited set is the map's statement about what is
        # being exploited in the wild, and it is what the threat axis
        # reads. The CISA KEV ingest is a no-wipe full refresh, so a fetch
        # that fails leaves the last-known-good rows in place: the map
        # stays intact, signed, fresh and consistent with its own
        # manifest, every other check still passes, and only the age of
        # the known-exploited rows shows that the set stopped being
        # refreshed. The requirement says how many rows the host needs
        # and how old they may be.
        kev_note = ""
        kev_min_rows = getattr(args, "require_kev", None)
        kev_max_age_days = getattr(args, "require_kev_max_age_days", None)
        if kev_min_rows is not None or kev_max_age_days is not None:
            try:
                kev_coverage = _export.verify_kev_coverage(
                    manifest, min_rows=kev_min_rows,
                    max_age_days=kev_max_age_days)
            except ValueError as exc:
                print(f"spine verify: FAILED — {exc}")
                return 1
            kev_note = (f", known-exploited coverage OK "
                        f"({kev_coverage['rows']} row(s))")
        # The Apple fix overlay is authoritative for iOS/iPadOS/macOS fix
        # versions (NVD's Apple coverage is thin). The ingest is a per-product
        # full refresh that is no-wipe on the caller side, so a failed fetch
        # leaves the last-known-good rows serving while every other check
        # still passes. The requirement says how many rows the host needs and
        # how old they may be.
        apple_note = ""
        apple_min_rows = getattr(args, "require_apple_fixes", None)
        apple_max_age_days = getattr(args, "require_apple_fixes_max_age_days",
                                     None)
        if apple_min_rows is not None or apple_max_age_days is not None:
            try:
                apple_coverage = _export.verify_apple_fixes_coverage(
                    manifest, min_rows=apple_min_rows,
                    max_age_days=apple_max_age_days)
            except ValueError as exc:
                print(f"spine verify: FAILED — {exc}")
                return 1
            apple_note = (f", Apple fix coverage OK "
                          f"({apple_coverage['rows']} row(s))")
        # The EPSS overlay scores every published CVE daily with a
        # probability of exploitation. The ingest is a full refresh that is
        # no-wipe on the caller side, so a failed fetch leaves the
        # last-known-good rows serving while every other check still passes.
        # The requirement says how many rows the host needs and how old they
        # may be.
        epss_note = ""
        epss_min_rows = getattr(args, "require_epss", None)
        epss_max_age_days = getattr(args, "require_epss_max_age_days", None)
        if epss_min_rows is not None or epss_max_age_days is not None:
            try:
                epss_coverage = _export.verify_epss_coverage(
                    manifest, min_rows=epss_min_rows,
                    max_age_days=epss_max_age_days)
            except ValueError as exc:
                print(f"spine verify: FAILED — {exc}")
                return 1
            epss_note = (f", EPSS coverage OK "
                         f"({epss_coverage['rows']} row(s))")
        ok_line = f"spine verify: OK — {len(manifest['files'])} shard(s), "
        ok_line += f"{manifest['counts']}"
        if signature_note:
            ok_line += f", {signature_note}"
        ok_line += freshness_note
        ok_line += overlay_note
        ok_line += release_note
        ok_line += package_note
        ok_line += kev_note
        ok_line += apple_note
        ok_line += epss_note
        print(ok_line)
        return 0
    # publish is the deployment line's serving path: export into a staging
    # directory, verify it, and swap it into the served directory in one step.
    # A failed export or a failed verification leaves the previously published
    # map untouched — the served map is never half-written.
    if args.sub == "publish":
        policy = _load_policy(args.policy)
        with _open_db(args.db, readonly=True) as conn:
            manifest = _export.publish_spine(
                conn, out_dir=args.out, policy_version=policy.version,
                sign_key=getattr(args, "sign_key", None))
        print(f"spine publish: {manifest['counts']} -> {args.out}/{_export.SPINE_DIR}/ "
              f"(verified, published atomically)")
        if not getattr(args, "sign_key", None):
            print(f"  sign it: cosign sign-blob --output-signature "
                  f"{args.out}/{_export.SPINE_DIR}/state.sig "
                  f"{args.out}/{_export.SPINE_DIR}/manifest.json")
        return 0
    # import is the client consumption path: load the signed spine JSONL into a
    # local DB, then run `assess` over private devices. Data-only — never touches
    # verdicts (the territory stays local + client-authored).
    if args.sub == "import":
        if getattr(args, "verify_sig", False) and getattr(args, "signature_key", None):
            _export.verify_manifest_signature(args.from_dir, args.signature_key)
            print(f"  signature verified -> {args.from_dir}/{_export.SPINE_DIR}/state.sig")
        # A client that pulls the map can refuse a map that is older than it
        # is willing to trust, for the same reason the operator does: a
        # served map that stopped being rebuilt stays intact and passes
        # every digest check.
        max_age_days = getattr(args, "max_age_days", None)
        if max_age_days is not None:
            try:
                age = _export.verify_manifest_freshness(
                    _export.read_manifest(args.from_dir), max_age_days)
            except (ValueError, OSError) as exc:
                print(f"spine import: FAILED — {exc}")
                return 1
            print(f"  map is {age:.1f} day(s) old (within the "
                  f"{max_age_days:g} day(s) allowed)")
        with _open_db(args.db) as conn:
            _glossary.ensure_seeded(conn)
            stats = _export.import_spine(conn, from_dir=args.from_dir,
                                         verify_manifest=not args.no_verify)
            conn.commit()
        print(f"spine import: {stats}  (data-only; no verdicts touched)")
        return 0
    with _open_db(args.db) as conn:
        _glossary.ensure_seeded(conn)
        conn.commit()
        if args.sub == "show":
            # the spine is the alias graph: show the peer registry (defect_type
            # counts) + crosswalk edge counts, not a rebindable primary key.
            counts = _store.defect_type_counts(conn)
            n_defects = sum(r["n"] for r in counts)
            n_edges = len(_store.crosswalk_all(conn))
            print(f"spine: alias↔alias graph  ({n_defects} defect(s), {n_edges} crosswalk edge(s))")
            print("defect-type registry (peer counts):")
            if counts:
                for r in counts:
                    print(f"  {(r['defect_type'] or '-'):12} {r['n']}")
            else:
                print("  (catalog empty)")
            print(f"crosswalk edges: {n_edges}")
            return 0
    return 2


# ---------------------------------------------------------------------------
# ingestion: CVE stream (MITRE detect) + incremental refresh + catalog
# ---------------------------------------------------------------------------

def _load_devices(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"devices file not found: {p} (see README — a YAML list "
                         f"of device dicts, same shape as `posture assess` input)")
    data = yaml.safe_load(p.read_text())
    if isinstance(data, dict):  # a single device, not a list
        data = [data]
    if not isinstance(data, list):
        raise SystemExit(f"devices file must be a YAML list of device dicts: {p}")
    return data


def _cmd_stream(args) -> int:
    policy = _load_policy(args.policy)
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        stats = _stream.stream_tick(conn, repo_path=args.repo,
                                    policy_version=policy.version)
        conn.commit()
    if stats["bootstrapped"]:
        print(f"stream: bootstrapped cursor at {stats['fetched_tip']} "
              f"(first run — no skeletons produced; the daily refresh owns "
              f"the back-catalog).")
    elif stats["error"]:
        print(f"stream: no-op ({stats['error']})")
    else:
        print(f"stream: {stats['new']} new skeleton(s) · "
              f"{stats['changed_files']} changed file(s) · "
              f"{stats['skipped']} skipped · tip {stats['fetched_tip']}")
    # MITRE attribution: the stream consumes the foreign-authored MITRE map.
    line = _attr.attribution_for("mitre_cve")
    if line:
        print(f"  {line}")
    return 0


def _cmd_backfill(args) -> int:
    policy = _load_policy(args.policy)
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        stats = _stream.backfill_tick(conn, repo_path=args.repo,
                                       cap=args.cap, policy_version=policy.version)
        conn.commit()
    if stats["error"]:
        print(f"backfill: no-op ({stats['error']})")
    elif stats["done"] and not stats["upserted"]:
        print(f"backfill: done (back-catalog exhausted; {stats['upserted']} upserted this tick)")
    else:
        print(f"backfill: {stats['upserted']} skeleton(s) upserted · "
              f"{stats['skipped']} skipped · tip {stats['fetched_tip']}"
              f"{' · DONE (back-catalog exhausted)' if stats['done'] else ''}")
    line = _attr.attribution_for("mitre_cve")
    if line:
        print(f"  {line}")
    return 0


def _cmd_ingest_kev(args) -> int:
    policy = _load_policy(args.policy)
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        stats = _kev_mod.kev_ingest_tick(conn, now=_engine._now())
        conn.commit()
    if stats["error"]:
        print(f"ingest kev: no-op ({stats['error']})")
        return 1
    print(f"ingest kev: {stats['upserted']} overlay row(s) upserted · "
          f"catalog {stats['catalog_version']} ({stats['date_released']})")
    line = _attr.attribution_for("kev")
    if line:
        print(f"  {line}")
    return 0


def _cmd_ingest_apple(args) -> int:
    policy = _load_policy(args.policy)
    products = list(args.product) if args.product else list(_apple_ingest_mod.PRODUCTS)
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        for product in products:
            stats = _apple_ingest_mod.apple_ingest_tick(
                conn, product=product, history=args.history,
                now=_engine._now())
            if stats["error"]:
                print(f"ingest apple [{product}]: no-op ({stats['error']})")
                continue
            hist = ""
            if stats["history"]:
                hist = (f" · history +{stats['history_cves_added']}"
                        f"/~{stats['history_cves_earlier']}")
            print(f"ingest apple [{product}]: {stats['rows']} overlay row(s) "
                  f"(index {stats['index_cves']} cves{hist})")
        conn.commit()
    line = _attr.attribution_for("apple_advisory")
    if line:
        print(f"  {line}")
    return 0


def _cmd_ingest_debian(args) -> int:
    policy = _load_policy(args.policy)
    releases = [r.strip().lower() for r in (args.release or []) if r.strip()]
    packages = [p.strip() for p in (args.package or []) if p.strip()]
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        stats = _debian_ingest_mod.debian_ingest_tick(
            conn, releases=releases, packages=packages, now=_engine._now())
        conn.commit()
    if stats["error"]:
        print(f"ingest debian: no-op ({stats['error']})")
        return 1
    print(f"ingest debian: {stats['rows']} overlay row(s) across "
          f"{stats['sheets']} sheet(s) "
          f"({len(stats['releases'])} release(s) x {len(stats['packages'])} "
          f"package(s)) · fetched={stats['fetched']}")
    line = _attr.attribution_for("debian_tracker")
    if line:
        print(f"  {line}")
    return 0


def _cmd_ingest_ubuntu(args) -> int:
    policy = _load_policy(args.policy)
    releases = [r.strip().lower() for r in (args.release or []) if r.strip()]
    packages = [p.strip() for p in (args.package or []) if p.strip()]
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        stats = _ubuntu_ingest_mod.ubuntu_ingest_tick(
            conn, releases=releases, packages=packages, now=_engine._now())
        conn.commit()
    if stats["error"]:
        print(f"ingest ubuntu: no-op ({stats['error']})")
        return 1
    print(f"ingest ubuntu: {stats['rows']} overlay row(s) across "
          f"{stats['sheets']} sheet(s) "
          f"({len(stats['releases'])} release(s) x {len(stats['packages'])} "
          f"package(s)) · fetched={stats['fetched']}")
    line = _attr.attribution_for("ubuntu_tracker")
    if line:
        print(f"  {line}")
    return 0


def _cmd_ingest_epss(args) -> int:
    policy = _load_policy(args.policy)
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        stats = _epss_mod.epss_ingest_tick(conn, now=_engine._now())
        conn.commit()
    if stats["error"]:
        print(f"ingest epss: no-op ({stats['error']})")
        return 1
    print(f"ingest epss: {stats['rows']} overlay row(s) (daily full refresh) "
          f"· fetched={stats['fetched']}")
    line = _attr.attribution_for("epss")
    if line:
        print(f"  {line}")
    return 0


def _cmd_ingest_ghsa(args) -> int:
    policy = _load_policy(args.policy)
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        stats = _ghsa_mod.ghsa_ingest_tick(
            conn, repo_path=args.repo, cap=args.cap,
            policy_version=policy.version, now=_engine._now())
        conn.commit()
    if stats["error"]:
        print(f"ingest ghsa: no-op ({stats['error']})")
        return 1
    phase = "incremental" if stats["incremental"] else "backfill"
    print(f"ingest ghsa: {stats['upserted']} advisory(ies) upserted · "
          f"{stats['skipped']} skipped · {phase} · tip {stats['fetched_tip']}"
          f"{' · DONE (back-catalog exhausted; incremental from here)' if stats['done'] and not stats['incremental'] else ''}")
    line = _attr.attribution_for("ghsa")
    if line:
        print(f"  {line}")
    return 0


def _cmd_ingest_osv(args) -> int:
    policy = _load_policy(args.policy)
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        stats = _osv_mod.osv_ingest_tick(conn, cap=args.cap,
                                         policy_version=policy.version,
                                         now=_engine._now())
        conn.commit()
    if stats["error"]:
        print(f"ingest osv: no-op ({stats['error']})")
        return 1
    phase = "incremental" if stats["incremental"] else "backfill"
    eco = stats["fetched_ecosystem"] or "-"
    print(f"ingest osv: {stats['upserted']} record(s) upserted · "
          f"{stats['skipped']} skipped · {phase} · ecosystem {eco}"
          f"{' · all ecosystems backfilled' if stats['ecosystems_done'] else ''}"
          f"{' · DONE (no incremental changes)' if stats['done'] else ''}")
    # Best-effort per-ecosystem: a transient all.zip / modified_id.csv failure
    # for one (or some) ecosystems skips them (retried next tick) and does NOT
    # fail the ingest job — but is reported here so the outage is visible.
    failed = stats.get("failed_ecosystems") or []
    if failed:
        print(f"  warning: {len(failed)} ecosystem(s) skipped "
              f"(fetch failed, retried next tick): {', '.join(failed)}")
    line = _attr.attribution_for("osv")
    if line:
        print(f"  {line}")
    return 0


def _cmd_ingest_nvd_cpe(args) -> int:
    policy = _load_policy(args.policy)
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        stats = _refresh.nvd_cpe_ingest_tick(
            conn, cpes=args.cpe, policy_version=policy.version,
            now=_engine._now(), cap=args.cap)
        conn.commit()
    if stats["errors"]:
        print(f"ingest nvd-cpe: {stats['upserted']} row(s) upserted · "
              f"{stats['skipped']} skipped · {stats['incomplete']} incomplete")
        for e in stats["errors"][:10]:
            print(f"  {e}")
        return 1
    print(f"ingest nvd-cpe: {stats['upserted']} row(s) upserted · "
          f"{stats['skipped']} skipped across {len(stats['heads'])} CPE head(s)")
    for r in stats["results"]:
        print(f"  {r['cpe']}: {r['rows']} row(s) ({r['reason']})")
    line = _attr.attribution_for("nvd")
    if line:
        print(f"  {line}")
    return 0

def _cmd_refresh(args) -> int:
    policy = _load_policy(args.policy)
    if args.no_devices:
        # CI / catalog-only: enrich the MAP without any fleet -> the re-decide
        # loop (refresh.py:200) and vendor-override loop (refresh.py:240, guarded
        # by `if registry is not None`) both write ZERO verdicts. No device data
        # ever leaves the machine. The MAP (catalog) is enriched unchanged.
        devices = []
        reg = None
    else:
        devices = _load_devices(args.devices)
        reg = build_default_registry()
        # refresh is a LIVE run: swap the offline vendor observers (fixtures, for
        # tests) for live ones so they actually fetch tracker pages and clear NVD
        # false alarms in this tick. Mirrors the assess command's nvd->live swap.
        reg._by_id["ubuntu_tracker"] = UbuntuTrackerObserver(live=True)  # type: ignore[attr-defined]
        reg._by_id["debian_tracker"] = DebianTrackerObserver(live=True)  # type: ignore[attr-defined]
        reg._by_id["apple_advisory"] = AppleAdvisoryObserver(live=True)  # type: ignore[attr-defined]
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
        stats = _refresh.refresh_tick(conn, devices, policy_version=policy.version,
                                      cap=args.cap, live=True, registry=reg)
        conn.commit()
    print(f"refresh: enriched {stats['enriched']} · absent {stats['absent']} · "
          f"incomplete {stats['incomplete']} · verdicts upserted "
          f"{stats['verdicts_upserted']} across {stats['devices']} device(s)")
    print(f"  pending: {stats['pending_before']} -> {stats['pending_after']} "
          f"(ttl-retired {stats['ttl_retired']})")
    if stats.get("vendor_overrides"):
        print(f"  vendor overrides: {stats['vendor_overrides']} verdict(s) "
              f"(ubuntu/debian/apple cleared NVD false alarms this tick)")
    if stats["errors"]:
        print(f"  errors ({len(stats['errors'])}):")
        for e in stats["errors"][:10]:
            print(f"    {e}")
    # NVD attribution: the refresh fetches the foreign-authored NVD map.
    line = _attr.attribution_for("nvd")
    if line:
        print(f"  {line}")
    return 0


def _cmd_enrich_llm(args) -> int:
    """Source-agnostic LLM draft over thin/unscored catalog rows, behind the
    off-by-default POSTURE_LLM seam. The LLM drafts catalog MAP fields only and
    is structurally barred from trust/DEFCON decisions (drafted rows carry
    source='llm:<model>'; the assess decide path selects source='nvd' only)."""
    from . import llm_enrich
    with _open_db(args.db) as conn:
        if args.dry_run:
            ids = llm_enrich.thin_defect_ids(conn, source=args.source,
                                             limit=args.cap)
            label = f" [source={args.source}]" if args.source else " (any source)"
            print(f"{len(ids)} thin/unscored defect(s) eligible for LLM draft{label}:")
            for cid in ids:
                print(f"  {cid}")
            if not os.environ.get("POSTURE_LLM"):
                print("(POSTURE_LLM unset: dry-run only; the LLM seam is off "
                      "until the operator gates a provider)")
            return 0
        policy = _load_policy(args.policy)
        _install_policy_if_needed(conn, policy)
        stats = llm_enrich.llm_enrich_tick(
            conn, llm_enrich.default_draft_fn, model=args.model, cap=args.cap,
            source=args.source, policy_version=policy.version)
        conn.commit()
    src_label = f" [source={stats['source']}]" if stats["source"] else ""
    print(f"llm enrich: selected {stats['selected']} · drafted {stats['drafted']} · "
          f"skipped {stats['skipped']} · rejected {stats['rejected']} · "
          f"errors {stats['errors']}{src_label} (model={stats['provider']})")
    if stats["drafted"] == 0 and not os.environ.get("POSTURE_LLM"):
        print("  POSTURE_LLM unset: the LLM seam is off; drafts require the "
              "operator to gate a provider (). Use --dry-run "
              "to inspect the thin pool without drafting.")
    elif stats["errors"] and os.environ.get("POSTURE_LLM"):
        print("  POSTURE_LLM is set but no provider draft_fn is wired; pass a "
              "real draft_fn to llm_enrich_tick (the operator-gated provider).")
    if stats["rejected"]:
        print("  rejected drafts failed the deterministic validator and were "
              "not written (the provider-independent trust boundary).")
    return 0


def _cmd_source_history(args) -> int:
    """Public-infrastructure event ledger (source reliability history)."""
    ledger = _source_history.default_ledger()
    if getattr(args, "file", None):
        # .json is read as the versioned document; anything else as JSONL.
        ledger = _source_history.EventLedger.load_any(args.file)
    sub = args.sub
    if sub == "list":
        print(f"{'date':12} {'source':8} {'type':16} {'layer':12} {'status':9} id")
        print("-" * 80)
        for e in ledger.sorted_by_date():
            print(f"{e.date:12} {e.source:8} {e.event_type:16} "
                  f"{e.map_layer:12} {e.status:9} {e.id}")
        print(f"{len(ledger.events)} events ({len(ledger.active())} active)")
        if ledger.version:
            print(f"ledger version: {ledger.version}"
                  + (f" (dated {ledger.dated})" if ledger.dated else ""))
        return 0
    if sub == "show":
        e = ledger.get(args.target)
        if not e:
            print(f"{args.target}: not in ledger")
            return 1
        print(json.dumps(e.to_dict(), indent=2))
        return 0
    if sub == "source":
        rows = ledger.for_source(args.target)
        if not rows:
            print(f"{args.target}: no events")
            return 1
        for e in rows:
            print(f"{e.date}  {e.id}  [{e.status}]")
            print(f"  {e.summary}")
            if e.interpretation:
                print(f"  -> {e.interpretation}")
        return 0
    return 2


def _cmd_purge(args) -> int:
    """Bounded-growth purge: forget ancient defects that are no longer
    relevant, so the catalog on a small host stays bounded. A dry run reports
    what would go without touching the catalog."""
    with _open_db(args.db) as conn:
        stats = _store.purge_defects(
            conn,
            max_age_days=args.max_age_days,
            keep_epss_percentile=args.keep_epss_percentile,
            dry_run=args.dry_run,
        )
    cc = stats["candidate_count"]
    cd = stats["cutoff_date"]
    ma = stats["max_age_days"]
    ke = stats["keep_epss_percentile"]
    if args.dry_run:
        print(f"DRY RUN — {cc} defect(s) eligible for purge "
              f"(cutoff: {cd}, age={ma}d, keep EPSS >= {ke})")
        return 0
    print(f"purge complete — cutoff {cd} (age={ma}d, keep EPSS >= {ke})")
    print(f"  defects purged:       {stats['defects_purged']}")
    print(f"  crosswalk purged:     {stats['crosswalk_purged']}")
    print(f"  seen_defects purged:  {stats['seen_defects_purged']}")
    orphans = stats["orphan_overlays_purged"]
    print(f"  orphan kev purged:          {orphans['kev']}")
    print(f"  orphan epss purged:         {orphans['epss']}")
    print(f"  orphan debian_fixes purged: {orphans['debian_fixes']}")
    print(f"  orphan ubuntu_fixes purged: {orphans['ubuntu_fixes']}")
    print(f"  orphan apple_fixes purged:  {orphans['apple_fixes']}")
    return 0


def _cmd_catalog(args) -> int:
    with _open_db(args.db, readonly=True) as conn:
        if args.sub == "show":
            row = _store.get_defect(conn, args.defect_id)
            if not row:
                print(f"{args.defect_id}: not in catalog")
                return 1
            print(json.dumps(row, indent=2, default=str))
            first = _store.seen_first_seen(conn, args.defect_id)
            if first:
                print(f"first seen by stream: {first}")
            # emit the required attribution for whichever foreign source
            # authored this row. mitre's source maps to the mitre_cve attribution
            # id; the peer sources (ghsa/osv) + nvd map directly.
            src = row.get("source") or row.get("enrich_state") or ""
            attr_id = "mitre_cve" if src == "mitre" else src
            line = _attr.attribution_for(attr_id)
            if line:
                print(f"  {line}")
            return 0
        if args.sub == "list":
            rows = _store.catalog_list(conn, enrich_state=args.state,
                                       limit=args.limit, offset=args.offset)
            print(f"{'id':22} {'type':5} {'enrich':6} {'published':12} "
                  f"{'cvss':5} {'sev':9} src")
            print("-" * 84)
            for r in rows:
                print(f"{r['id']:22} {(r['defect_type'] or '-'):5} "
                      f"{(r['enrich_state'] or '-'):6} "
                      f"{(r['published'] or '-'):12} "
                      f"{(str(r['cvss']) if r['cvss'] is not None else '-'):5} "
                      f"{(r['severity'] or '-'):9} {r['source'] or '-'}")
            print(f"({len(rows)} row(s))")
            return 0
        if args.sub == "pending":
            ids = _store.pending_enrichment_ids(conn, limit=args.limit)
            print(f"{len(ids)} MITRE skeleton(s) awaiting NVD enrichment:")
            for cid in ids:
                print(f"  {cid}")
            return 0
    return 2


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="posture", description=__doc__.splitlines()[0] if __doc__ else "posture")
    p.add_argument("--version", action="version", version=f"posture {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def db_arg(sp): sp.add_argument("--db", default=DEFAULT_DB, help="posture DB path")
    def pol_arg(sp): sp.add_argument("--policy", default=None, help="policy YAML (default: bundled)")

    sp = sub.add_parser("demo", help="offline: 6-axis posture from the bundled fixture")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_demo)

    sp = sub.add_parser("assess", help="assess a device (YAML, Forebode devices.yaml shape)")
    sp.add_argument("device", help="path to device YAML")
    sp.add_argument("--live", action="store_true", help="real NVD pull (network + NVD_API_KEY)")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_assess)

    sp = sub.add_parser("axes", help="list the six axes"); sp.set_defaults(func=_cmd_axes)

    sp = sub.add_parser("policy", help="trust policy: show | log | validate")
    sp.add_argument("sub", choices=["show", "log", "validate"])
    sp.add_argument("file", nargs="?", default=None, help="policy YAML (validate/show)")
    db_arg(sp); sp.set_defaults(func=_cmd_policy)

    sp = sub.add_parser("observers", help="list registered observers + health state")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_observers)

    sp = sub.add_parser("health", help="source-health (operational + dossier + drift)")
    sp.add_argument("observer", nargs="?", default=None,
                    help="observer id (omit to show all)")
    sp.add_argument("--add-dossier", action="store_true",
                    help="record a dossier entry (requires --date/--claim/--citation)")
    sp.add_argument("--axis", default="vulnerability")
    sp.add_argument("--date"); sp.add_argument("--claim"); sp.add_argument("--citation")
    sp.add_argument("--direction", default="other")
    sp.add_argument("--no-source-history", action="store_true",
                    help="do not consult the public-infrastructure event ledger "
                         "for the source-reliability signal")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_health)

    sp = sub.add_parser("distrust", help="mark a observer's verdicts distrusted (retroactive)")
    sp.add_argument("observer"); sp.add_argument("--reason", default=None)
    sp.add_argument("-v", "--verbose", action="store_true")
    db_arg(sp); sp.set_defaults(func=_cmd_distrust)

    sp = sub.add_parser("audit", help="list verdicts resting on a observer")
    sp.add_argument("observer"); db_arg(sp); sp.set_defaults(func=_cmd_audit)

    sp = sub.add_parser("crosswalk", help="spine alias graph: add | show")
    sp.add_argument("sub", choices=["add", "show"])
    sp.add_argument("defect_id"); sp.add_argument("alias", nargs="?", default=None); sp.add_argument("kind", nargs="?", default="ghsa")
    db_arg(sp); sp.set_defaults(func=_cmd_crosswalk)

    sp = sub.add_parser("discover", help="horizon scan: surface candidate sources for review")
    db_arg(sp)
    sp.add_argument("--fetch", action="store_true",
                    help="live: fetch each new aggregator page (opt-in; default is an "
                         "offline delta vs already-recorded candidates). The daily "
                         "cadence runs in CI (spine.yml), not locally.")
    sp.set_defaults(func=_cmd_discover)

    # -- the growing vocabulary ------------------------------------------------
    sp = sub.add_parser("glossary", help="the vocabulary as data: list | show | add | promote | deprecate | roles")
    sp.add_argument("sub", choices=["list", "show", "add", "promote", "deprecate", "roles"])
    sp.add_argument("term", nargs="?", default=None, help="term id (show/add/promote/deprecate)")
    sp.add_argument("--status", choices=["known", "candidate", "deprecated"], default=None)
    sp.add_argument("--kind", default=None); sp.add_argument("--label", default=None)
    sp.add_argument("--roles", default=None, help="comma-separated role list")
    sp.add_argument("--citation", default=None); sp.add_argument("--successor", default=None)
    db_arg(sp); sp.set_defaults(func=_cmd_glossary)

    sp = sub.add_parser("monitor", help="vocabulary monitor: run (scan) | queue (review candidates)")
    sp.add_argument("sub", choices=["run", "queue"])
    db_arg(sp); sp.set_defaults(func=_cmd_monitor)

    sp = sub.add_parser("repair", help="self-repair proposals: list | apply <id> | reconcile (raise proposals)")
    sp.add_argument("sub", choices=["list", "apply", "reconcile"])
    sp.add_argument("proposal_id", nargs="?", default=None)
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_repair)

    sp = sub.add_parser("spine", help="spine: show | export | import | verify | publish")
    sp.add_argument("sub", choices=["show", "export", "import", "verify", "publish"])
    sp.add_argument("--out", default=".", help="export output dir (default: cwd)")
    sp.add_argument("--from", dest="from_dir", default=".", help="import source dir (default: cwd)")
    sp.add_argument("--no-verify", action="store_true", help="import: skip manifest sha256 check")
    sp.add_argument("--sign-key", dest="sign_key", default=None,
                    help="export: sign manifest.json with this ed25519 private key (PEM) -> state.sig")
    sp.add_argument("--verify-sig", dest="verify_sig", action="store_true",
                    help="verify/import: verify the manifest's ed25519 signature (state.sig) before trusting the map")
    sp.add_argument("--signature-key", dest="signature_key", default=None,
                    help="verify/import: ed25519 public key (PEM) for --verify-sig")
    sp.add_argument("--max-age-days", dest="max_age_days", type=_max_age_days,
                    default=None,
                    help="verify/import: fail when the map's manifest is older than this "
                         "many days (the daily build keeps the last good map serving, so a "
                         "stale map means the build has stopped)")
    sp.add_argument("--require-overlay", dest="require_overlay", action="append",
                    default=None, metavar="TABLE",
                    help="verify: fail when the map does not carry this overlay table's "
                         "rows (repeatable; the overlay tables are: "
                         + ", ".join(_export.OVERLAY_TABLES) + ")")
    sp.add_argument("--require-overlay-release", dest="require_overlay_release",
                    action="append", default=None,
                    metavar="TABLE:RELEASE:MIN_ROWS",
                    help="verify: fail when the map does not carry at least "
                         "MIN_ROWS rows for a release of a release-keyed overlay "
                         "table (repeatable; the release-keyed overlay tables "
                         "are: " + ", ".join(_export.RELEASE_KEYED_OVERLAY_TABLES)
                         + "; a release whose tracker feed returned nothing "
                         "leaves the table populated with the other "
                         "releases' rows, which the presence-only check "
                         "cannot see)")
    sp.add_argument("--require-overlay-max-age-days",
                    dest="require_overlay_max_age_days", type=float,
                    default=None, metavar="DAYS",
                    help="verify: fail when the newest row of a required "
                         "overlay release was fetched more than this many "
                         "days ago (a release the nightly job stopped "
                         "ingesting keeps its last-known-good rows, so only "
                         "their age shows that they went stale)")
    sp.add_argument("--require-overlay-package", dest="require_overlay_package",
                    action="append", default=None,
                    metavar="TABLE:RELEASE:PACKAGE:MIN_ROWS",
                    help="verify: fail when the map does not carry at least "
                         "MIN_ROWS rows for a source package of a release of "
                         "a release-keyed overlay table (repeatable; the "
                         "release-keyed overlay tables are: "
                         + ", ".join(_export.RELEASE_KEYED_OVERLAY_TABLES)
                         + "; a source package whose tracker feed returned "
                         "nothing leaves that release looking populated "
                         "while its fix-status rows are gone, which the "
                         "per-release floor cannot see)")
    sp.add_argument("--require-kev", dest="require_kev", type=int,
                    default=None, metavar="MIN_ROWS",
                    help="verify: fail when the map carries fewer "
                         "known-exploited (kev) rows than this (the CISA "
                         "Known Exploited Vulnerabilities set is what the "
                         "threat axis reads, and the ingest is a no-wipe "
                         "refresh, so a failed fetch leaves the "
                         "last-known-good rows serving)")
    sp.add_argument("--require-kev-max-age-days",
                    dest="require_kev_max_age_days", type=float,
                    default=None, metavar="DAYS",
                    help="verify: fail when the map's newest known-exploited "
                         "row was fetched more than this many days ago (a "
                         "known-exploited set that stopped being refreshed "
                         "still satisfies the row floor)")
    sp.add_argument("--require-apple-fixes", dest="require_apple_fixes",
                    type=int, default=None, metavar="MIN_ROWS",
                    help="verify: fail when the map carries fewer Apple fix "
                         "(apple_fixes) rows than this (Apple's own "
                         "advisories are authoritative for iOS/iPadOS/macOS "
                         "fix versions; the ingest is a per-product full "
                         "refresh that is no-wipe on the caller side, so a "
                         "failed fetch leaves the last-known-good rows "
                         "serving)")
    sp.add_argument("--require-apple-fixes-max-age-days",
                    dest="require_apple_fixes_max_age_days", type=float,
                    default=None, metavar="DAYS",
                    help="verify: fail when the map's newest Apple fix row "
                         "was fetched more than this many days ago (an "
                         "Apple fix overlay that stopped being refreshed "
                         "still satisfies the row floor)")
    sp.add_argument("--require-epss", dest="require_epss", type=int,
                    default=None, metavar="MIN_ROWS",
                    help="verify: fail when the map carries fewer EPSS "
                         "(exploitability-probability) rows than this "
                         "(FIRST.org scores every published CVE daily; "
                         "the ingest is a full refresh that is no-wipe on "
                         "the caller side, so a failed fetch leaves the "
                         "last-known-good rows serving)")
    sp.add_argument("--require-epss-max-age-days",
                    dest="require_epss_max_age_days", type=float,
                    default=None, metavar="DAYS",
                    help="verify: fail when the map's newest EPSS row was "
                         "fetched more than this many days ago (an EPSS "
                         "overlay that stopped being refreshed still "
                         "satisfies the row floor)")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_spine)

    # -- ingestion: CVE stream + incremental refresh + catalog ---------------
    sp = sub.add_parser("stream", help="one MITRE cvelistV5 stream tick (detect CVEs as published; skeletons only)")
    sp.add_argument("--repo", default=None, help="cvelistV5 clone path (default: ~/.local/share/posture/cvelist/cvelistV5)")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_stream)

    sp = sub.add_parser("backfill", help="one cvelistV5 back-catalog tick (cap-resumed; populates CVE-peer history; skeletons only)")
    sp.add_argument("--repo", default=None, help="cvelistV5 clone path (default: ~/.local/share/posture/cvelist/cvelistV5)")
    sp.add_argument("--cap", type=int, default=1000, help="max records to back-fill this tick (<=0 = unlimited)")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_backfill)

    # -- ingestion: aggregator peers (KEV overlay first; OSV/GHSA to follow) ----
    sp = sub.add_parser("ingest", help="ingest an aggregator peer / fix / exploitability overlay into the catalog (kev | osv | ghsa | apple | debian | ubuntu | epss | nvd-cpe)")
    psub = sp.add_subparsers(dest="peer", required=True)
    spk = psub.add_parser("kev", help="CISA KEV overlay refresh (exploitability_signal; CVE-keyed, full refresh)")
    db_arg(spk); pol_arg(spk); spk.set_defaults(func=_cmd_ingest_kev)
    spg = psub.add_parser("ghsa", help="GitHub Advisory Database tick (self-enriched OSV peer; cap-resumed backfill + incremental diff)")
    spg.add_argument("--repo", default=None, help="advisory-database clone path (default: ~/.local/share/posture/ghsa/advisory-database; env POSTURE_GHSA_DIR)")
    spg.add_argument("--cap", type=int, default=1000, help="max advisories to back-fill this tick (<=0 = unlimited)")
    db_arg(spg); pol_arg(spg); spg.set_defaults(func=_cmd_ingest_ghsa)
    spo = psub.add_parser("osv", help="osv.dev hub tick (self-enriched OSV peer; per-ecosystem all.zip backfill + modified_id.csv incremental)")
    spo.add_argument("--cap", type=int, default=1000, help="max records to ingest this tick (<=0 = unlimited)")
    db_arg(spo); pol_arg(spo); spo.set_defaults(func=_cmd_ingest_osv)
    spa = psub.add_parser("apple", help="Apple advisory fix-version overlay (CVE+product-keyed; per-product full refresh; optional Wayback historical recovery)")
    spa.add_argument("--product", action="append", default=None,
                     help="product slug to ingest (iphone_os|ipados|macos); repeatable, default all three")
    spa.add_argument("--history", action="store_true",
                    help="also recover pre-index CVEs from Wayback's archived HT1222/HT201222 snapshots (more fetches, rate-heavier)")
    db_arg(spa); pol_arg(spa); spa.set_defaults(func=_cmd_ingest_apple)
    spd = psub.add_parser("debian", help="Debian security-tracker status overlay (CVE+release+package-keyed; per-(release,package) full refresh; authoritative status words the OSV mirror lacks)")
    spd.add_argument("--release", action="append", default=None, required=True,
                    help="Debian release codename to ingest (trixie|bookworm|...); repeatable, REQUIRED (no default public-spine scope is wired)")
    spd.add_argument("--package", action="append", default=None, required=True,
                    help="Debian source package to ingest (linux|...); repeatable, REQUIRED (no default public-spine scope is wired)")
    db_arg(spd); pol_arg(spd); spd.set_defaults(func=_cmd_ingest_debian)
    spu = psub.add_parser("ubuntu", help="Ubuntu security-tracker status overlay (CVE+release+package-keyed; per-(release,package) full refresh; authoritative status words the OSV mirror lacks)")
    spu.add_argument("--release", action="append", default=None, required=True,
                    help="Ubuntu release codename to ingest (noble|jammy|focal|...); repeatable, REQUIRED (no default public-spine scope is wired)")
    spu.add_argument("--package", action="append", default=None, required=True,
                    help="Ubuntu source package to ingest (linux|...); repeatable, REQUIRED (no default public-spine scope is wired)")
    db_arg(spu); pol_arg(spu); spu.set_defaults(func=_cmd_ingest_ubuntu)
    spe = psub.add_parser("epss", help="FIRST.org EPSS exploitability-likelihood overlay (CVE-keyed; daily full refresh; fills the NVD-degradation gap; complementary to kev)")
    db_arg(spe); pol_arg(spe); spe.set_defaults(func=_cmd_ingest_epss)
    spn = psub.add_parser("nvd-cpe", help="NVD CPE-head ingestion: query NVD by one or more CPE heads and upsert every matching CVE into the catalog")
    spn.add_argument("--cpe", action="append", required=True,
                    help="CPE 2.3 head to query (e.g. cpe:2.3:o:linux:linux_kernel); repeatable")
    spn.add_argument("--cap", type=int, default=None,
                    help="max total rows to upsert this tick (default: no cap)")
    db_arg(spn); pol_arg(spn); spn.set_defaults(func=_cmd_ingest_nvd_cpe)

    sp = sub.add_parser("refresh", help="incremental NVD enrichment + per-CVE re-decide (wipe-proof; never a bulk re-pull)")
    sp.add_argument("--devices", default=DEFAULT_DEVICES, help="fleet YAML (list of device dicts)")
    sp.add_argument("--cap", type=int, default=_refresh.DEFAULT_CAP, help="max NVD enrichments this tick")
    sp.add_argument("--no-devices", action="store_true",
                    help="catalog-only enrichment: no fleet, no verdicts, no vendor trackers (for CI)")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_refresh)

    sp = sub.add_parser("enrich", help="LLM draft over thin/unscored catalog rows (source-agnostic; off-by-default POSTURE_LLM seam; LLM-as-map/human-as-trust)")
    epsub = sp.add_subparsers(dest="enrich_peer", required=True)
    spl = epsub.add_parser("llm", help="draft catalog map fields for thin/unscored defects with an LLM (never trust/DEFCON; drafts labeled source='llm:<model>' and barred from the assess decide path)")
    spl.add_argument("--source", default=None,
                     help="restrict the thin pool to one provenance (mitre|osv|ghsa|...); default any source")
    spl.add_argument("--cap", type=int, default=_llm_enrich.DEFAULT_CAP,
                     help="max rows drafted this tick")
    spl.add_argument("--model", default="unset",
                     help="model id stamped on source='llm:<model>' (default 'unset')")
    spl.add_argument("--dry-run", action="store_true",
                     help="list the thin/unscored pool without drafting (no provider needed)")
    db_arg(spl); pol_arg(spl); spl.set_defaults(func=_cmd_enrich_llm)

    sp = sub.add_parser("catalog", help="defect catalog: show <defect_id> | list | pending")
    sp.add_argument("sub", choices=["show", "list", "pending"])
    sp.add_argument("defect_id", nargs="?", default=None, help="defect id (show)")
    sp.add_argument("--state", choices=["mitre", "nvd", "ghsa", "osv"], default=None, help="filter list by enrich state")
    sp.add_argument("--limit", type=int, default=100)
    sp.add_argument("--offset", type=int, default=0)
    db_arg(sp); sp.set_defaults(func=_cmd_catalog)

    sp = sub.add_parser("purge",
                        help="bounded-growth: remove ancient defects no longer relevant (dry-run capable)")
    sp.add_argument("--max-age-days", type=int, default=_store.DEFAULT_PURGE_AGE_DAYS,
                    help=f"purge defects older than this many days "
                         f"(default: {_store.DEFAULT_PURGE_AGE_DAYS})")
    sp.add_argument("--keep-epss-percentile", type=float,
                    default=_store.DEFAULT_KEEP_EPSS_PERCENTILE,
                    help=f"keep CVEs with EPSS percentile >= this "
                         f"(default: {_store.DEFAULT_KEEP_EPSS_PERCENTILE})")
    sp.add_argument("--dry-run", action="store_true",
                    help="report what would be purged without deleting")
    db_arg(sp); sp.set_defaults(func=_cmd_purge)

    sp = sub.add_parser("source-history",
                        help="public-infrastructure event ledger: list | show <id> | source <src>")
    sp.add_argument("sub", choices=["list", "show", "source"])
    sp.add_argument("target", nargs="?", default=None,
                    help="event id (show) or source id (source)")
    sp.add_argument("--file", default=None,
                    help="ledger file: .json document or .jsonl stream "
                         "(default: bundled versioned seed data)")
    sp.set_defaults(func=_cmd_source_history)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except SystemExit:
        raise
    except Exception as e:
        print(f"posture: error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())