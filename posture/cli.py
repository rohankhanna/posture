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

The report footer emits NVD attribution whenever the NVD observer was actually
used (project rule: the map is foreign-authored; say so).
"""

from __future__ import annotations
import argparse
import json
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
from . import discovery as _discovery
from . import spine as _spine
from . import glossary as _glossary
from . import vocab_monitor as _vocab
from . import repair as _repair
from . import attribution as _attr
from . import stream as _stream
from . import refresh as _refresh
from . import export as _export
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
    as device INPUTS before ``assess``. The observer contract forbids DB access
    in ``assess()`` (no ``conn``), so the territory pre-loads overlays here —
    this is the "consume locally" half of "feed and enrich in CI, consume
    locally".

    Additive and never clobbers: a device that already supplies an overlay
    (explicit operator input, hermetic tests) is left untouched. No-op when the
    device declares no ``apple_product`` or the local store has no overlay rows
    for that product (the observer then falls back to its per-assess replay).

    Four overlays are consumed today:
      * ``apple_fixes`` — the Apple fix-version map (per ``apple_product``).
      * ``catalog_defects`` — the imported spine defects table keyed by CPE
        head, consumed by :class:`NvdCveObserver`'s catalog-backed fetch path
        so the vulnerability axis decides from the spine with NO network.
      * ``debian_fixes`` — the Debian security-tracker status overlay,
        reconstructed to the bulk-data dict shape ``DebianTrackerObserver``'s
        ``_decide`` consumes, so the distro axis decides from the spine with NO
        network (mirrors the NvdCveObserver catalog path).
      * ``ubuntu_fixes`` — the Ubuntu security-tracker status overlay, keyed
        per-CVE per-package, normalized at assess time by
        :class:`UbuntuTrackerObserver`'s catalog path. kev remains
        operator-supplied (``device["kev"]`` / ``kev_path``).
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
    so ``catalog_defects`` is left ABSENT and the observer falls back to its
    bundled fixture (the demo corpus), preserving ``posture demo``. Once a
    spine IS present, every nvd_cpe head is injected (empty heads -> ``[]``),
    so a head the spine doesn't cover is a COMPLETE-absent answer, NOT a
    fixture leak (the bundled sample CVEs must never surface as a real
    client's verdicts). Additive: a device that pre-supplies
    ``catalog_defects`` (operator input / hermetic test) is left untouched.
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
    shape its ``_decide`` reads, so the distro axis assesses from the spine with
    NO network path (the catalog-backed assess path, mirroring
    :class:`NvdCveObserver`).

    Only injected when the DB carries debian_fixes rows — a fresh/demo DB has
    none, so ``debian_fixes`` is left ABSENT and the observer falls back to its
    bundled fixture (preserving ``posture demo``). Once the overlay IS present,
    the bulk dict is rebuilt from the device's ``debian_release`` +
    ``debian_packages`` (an uncovered release/package yields an empty block ->
    ``_decide`` returns None -> NVD stands: a COMPLETE-absent answer, NOT a
    fixture leak). Additive: a device that pre-supplies ``debian_fixes``
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
    # Rebuild the bulk-data dict shape ``_decide`` consults:
    # {package: {cve_id: {"releases": {release: {"status", "fixed_version"}}}}}.
    # The overlay's ``fixed_in`` column maps to the tracker's ``fixed_version``.
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

    The overlay stores the RAW tracker status words (``released`` /
    ``needed`` / ``needs-triage`` / ``not-affected`` / ``DNE`` / ``ignored`` /
    ``deferred``); the observer normalizes them at assess time to the same
    ``{pkg: (status, fixed_in)}`` shape :func:`parse_cve_page` produces, so
    ``_decide`` runs UNCHANGED (one decision path, not a second one for the
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
    # to the ``found`` shape ``_decide`` consumes (mirrors parse_cve_page).
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
        for wid in observers:
            rep = _health.health_report(conn, wid, policy, now)
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


def _cmd_spine(args) -> int:
    # export is read-only over the DB and produces no trust change; it serializes
    # the catalog (the MAP) to sharded JSONL + a manifest that CI cosign-signs.
    if args.sub == "export":
        policy = _load_policy(args.policy)
        with _open_db(args.db, readonly=True) as conn:
            manifest = _export.export_spine(conn, out_dir=args.out,
                                             policy_version=policy.version)
        print(f"spine export: {manifest['counts']} -> {args.out}/{_export.SPINE_DIR}/")
        print(f"  sign it: cosign sign-blob --output-signature "
              f"{args.out}/{_export.SPINE_DIR}/state.sig "
              f"{args.out}/{_export.SPINE_DIR}/manifest.json")
        return 0
    # import is the client consumption path: load the signed spine JSONL into a
    # local DB, then run `assess` over private devices. Data-only — never touches
    # verdicts (the territory stays local + client-authored).
    if args.sub == "import":
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

    sp = sub.add_parser("spine", help="spine: show | export | import")
    sp.add_argument("sub", choices=["show", "export", "import"])
    sp.add_argument("--out", default=".", help="export output dir (default: cwd)")
    sp.add_argument("--from", dest="from_dir", default=".", help="import source dir (default: cwd)")
    sp.add_argument("--no-verify", action="store_true", help="import: skip manifest sha256 check")
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
    sp = sub.add_parser("ingest", help="ingest an aggregator peer / fix / exploitability overlay into the catalog (kev | osv | ghsa | apple | debian | ubuntu | epss)")
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

    sp = sub.add_parser("refresh", help="incremental NVD enrichment + per-CVE re-decide (wipe-proof; never a bulk re-pull)")
    sp.add_argument("--devices", default=DEFAULT_DEVICES, help="fleet YAML (list of device dicts)")
    sp.add_argument("--cap", type=int, default=_refresh.DEFAULT_CAP, help="max NVD enrichments this tick")
    sp.add_argument("--no-devices", action="store_true",
                    help="catalog-only enrichment: no fleet, no verdicts, no vendor trackers (for CI)")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_refresh)

    sp = sub.add_parser("catalog", help="defect catalog: show <defect_id> | list | pending")
    sp.add_argument("sub", choices=["show", "list", "pending"])
    sp.add_argument("defect_id", nargs="?", default=None, help="defect id (show)")
    sp.add_argument("--state", choices=["mitre", "nvd", "ghsa", "osv"], default=None, help="filter list by enrich state")
    sp.add_argument("--limit", type=int, default=100)
    sp.add_argument("--offset", type=int, default=0)
    db_arg(sp); sp.set_defaults(func=_cmd_catalog)

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