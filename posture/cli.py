"""posture CLI — argparse subparsers (mirrors forebode/cli.py's pattern).

  posture demo                    offline: full 6-axis posture from the fixture
  posture assess <device.yaml> [--live] [--db PATH]
  posture axes
  posture policy {show|log|validate} [file]
  posture witnesses
  posture health [witness] / posture health add-dossier ...
  posture distrust <witness> [--reason]
  posture audit <witness>
  posture crosswalk {add|show} ...
  posture discover

The report footer emits NVD attribution whenever the NVD witness was actually
used (AGENTS.md standing rule: the map is foreign-authored; say so).
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
from .sources.nvd_cve import NvdCveWitness
from .sources import kev as _kev_mod
from .sources import ghsa as _ghsa_mod
from .sources import osv as _osv_mod
from .sources.ubuntu_tracker import UbuntuTrackerWitness
from .sources.debian_tracker import DebianTrackerWitness
from .sources.apple_advisory import AppleAdvisoryWitness

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
        dec = f"  (decided by {ap.deciding_witness}"
        if ap.bias:
            dec += f", bias={ap.bias}"
        dec += ")" if ap.deciding_witness else ")"
        print(f"{flag} [{ap.axis}] {ap.status.upper()}"
              f"  ({len(ap.verdicts)} verdicts, complete={ap.complete}, "
              f"commit={ap.commit_state})", file=out)
        print(f"     {meta.get('desc', '')}", file=out)
        if ap.deciding_witness:
            print(f"     decided by {ap.deciding_witness}"
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
    # attribution: only for witnesses actually used that require it
    for line in _attr.all_attributions(dp.used_witnesses):
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
        dp = _engine.assess(device, reg, policy, conn=conn)
    _render_posture(dp)
    return 0


def _cmd_assess(args) -> int:
    policy = _load_policy(args.policy)
    device = _load_device(args.device)
    reg = build_default_registry()
    if args.live:
        # swap the offline NVD witness for a live one
        nvd_live = NvdCveWitness(live=True)
        # registry has the offline one at id "nvd"; replace it
        reg._by_id["nvd"] = nvd_live  # type: ignore[attr-defined]
    with _open_db(args.db) as conn:
        _install_policy_if_needed(conn, policy)
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
        print(f"OK  version={policy.version}  witnesses={len(policy.witnesses)}  "
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


def _cmd_witnesses(args) -> int:
    policy = _load_policy(args.policy)
    reg = build_default_registry()
    with _open_db(args.db, readonly=True) as conn:
        now = _engine._now()
        for w in reg.all():
            in_policy = policy.has_witness(w.id)
            deg = _health.degradation_action(conn, w.id, policy, now) if in_policy else "n/a"
            axes = ",".join(a.value for a in w.axes)
            print(f"{w.id:12} axes=[{axes:24}] bias={policy.witness_bias(w.id):12} "
                  f"weight={policy.witness_weight(w.id):7} order={policy.witness_order(w.id):3} "
                  f"policy={'yes' if in_policy else 'NO ':3} health={deg}")
    return 0


def _cmd_health(args) -> int:
    policy = _load_policy(args.policy)
    with _open_db(args.db) as conn:
        if args.add_dossier:
            if not (args.witness and args.date and args.claim and args.citation):
                raise SystemExit(
                    "health --add-dossier requires <witness> --date --claim --citation"
                )
            _health.add_dossier_entry(
                conn, args.witness, args.date, args.axis, args.claim,
                args.citation, args.direction,
            )
            conn.commit()
            print(f"recorded dossier entry for {args.witness}")
            return 0
        # default: show health report
        witness = args.witness
        if not witness:
            # show all witnesses that have any samples
            rows = conn.execute(
                "SELECT DISTINCT witness FROM health_samples ORDER BY witness"
            ).fetchall()
            witnesses = [r["witness"] for r in rows] or [w.id for w in build_default_registry().all()]
        else:
            witnesses = [witness]
        now = _engine._now()
        for wid in witnesses:
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
        affected = _prov.audit(conn, args.witness)
        n = _prov.distrust(conn, args.witness, args.reason or "(unspecified)")
        conn.commit()
        print(f"marked {n} verdict(s) resting on '{args.witness}' as distrusted "
              f"(reason: {args.reason or '(unspecified)'}).")
        print(f"({len(affected)} total verdicts audit on this witness; "
              f"records retained, not deleted.)")
        if args.verbose:
            for v in affected[:20]:
                print(f"  {v['device_id']} [{v['axis']}] {v['key']} {v['status']} "
                      f"(policy {v['policy_version']}, fetched {v['fetched_at']})")
    return 0


def _cmd_audit(args) -> int:
    with _open_db(args.db, readonly=True) as conn:
        rows = _prov.audit(conn, args.witness)
        print(f"{len(rows)} verdict(s) rest on witness '{args.witness}':")
        for v in rows:
            mark = " DISTRUSTED" if v["distrusted"] else ""
            print(f"  {v['device_id']} [{v['axis']}] {v['key']} {v['status']}"
                  f"  policy={v['policy_version']}  fetched={v['fetched_at']}{mark}")
    return 0


def _cmd_crosswalk(args) -> int:
    with _open_db(args.db) as conn:
        if args.sub == "add":
            _spine.register(conn, args.flaw_id, args.alias, args.kind)
            conn.commit()
            print(f"crosswalk: {args.flaw_id} = {args.alias} ({args.kind})")
            return 0
        if args.sub == "show":
            aliases = _spine.resolve(conn, args.flaw_id)
            if not aliases:
                print(f"{args.flaw_id}: no aliases recorded")
            else:
                print(f"{args.flaw_id}:")
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
            # the spine is the alias graph: show the peer registry (flaw_type
            # counts) + crosswalk edge counts, not a rebindable primary key.
            counts = _store.flaw_type_counts(conn)
            n_flaws = sum(r["n"] for r in counts)
            n_edges = len(_store.crosswalk_all(conn))
            print(f"spine: alias↔alias graph  ({n_flaws} flaw(s), {n_edges} crosswalk edge(s))")
            print("flaw-type registry (peer counts):")
            if counts:
                for r in counts:
                    print(f"  {(r['flaw_type'] or '-'):12} {r['n']}")
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
        # refresh is a LIVE run: swap the offline vendor witnesses (fixtures, for
        # tests) for live ones so they actually fetch tracker pages and clear NVD
        # false alarms in this tick. Mirrors the assess command's nvd->live swap.
        reg._by_id["ubuntu_tracker"] = UbuntuTrackerWitness(live=True)  # type: ignore[attr-defined]
        reg._by_id["debian_tracker"] = DebianTrackerWitness(live=True)  # type: ignore[attr-defined]
        reg._by_id["apple_advisory"] = AppleAdvisoryWitness(live=True)  # type: ignore[attr-defined]
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
            row = _store.get_flaw(conn, args.flaw_id)
            if not row:
                print(f"{args.flaw_id}: not in catalog")
                return 1
            print(json.dumps(row, indent=2, default=str))
            first = _store.seen_first_seen(conn, args.flaw_id)
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
                print(f"{r['id']:22} {(r['flaw_type'] or '-'):5} "
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

    sp = sub.add_parser("witnesses", help="list registered witnesses + health state")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_witnesses)

    sp = sub.add_parser("health", help="source-health (operational + dossier + drift)")
    sp.add_argument("witness", nargs="?", default=None,
                    help="witness id (omit to show all)")
    sp.add_argument("--add-dossier", action="store_true",
                    help="record a dossier entry (requires --date/--claim/--citation)")
    sp.add_argument("--axis", default="vulnerability")
    sp.add_argument("--date"); sp.add_argument("--claim"); sp.add_argument("--citation")
    sp.add_argument("--direction", default="other")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_health)

    sp = sub.add_parser("distrust", help="mark a witness's verdicts distrusted (retroactive)")
    sp.add_argument("witness"); sp.add_argument("--reason", default=None)
    sp.add_argument("-v", "--verbose", action="store_true")
    db_arg(sp); sp.set_defaults(func=_cmd_distrust)

    sp = sub.add_parser("audit", help="list verdicts resting on a witness")
    sp.add_argument("witness"); db_arg(sp); sp.set_defaults(func=_cmd_audit)

    sp = sub.add_parser("crosswalk", help="spine alias graph: add | show")
    sp.add_argument("sub", choices=["add", "show"])
    sp.add_argument("flaw_id"); sp.add_argument("alias", nargs="?", default=None); sp.add_argument("kind", nargs="?", default="ghsa")
    db_arg(sp); sp.set_defaults(func=_cmd_crosswalk)

    sp = sub.add_parser("discover", help="horizon scan: surface candidate sources for review")
    db_arg(sp)
    sp.add_argument("--fetch", action="store_true",
                    help="live: fetch each new aggregator page (opt-in; default is an "
                         "offline delta vs already-recorded candidates). An LLM, if wired "
                         "via POSTURE_LLM, only drafts candidates -- never decides trust. "
                         "The daily cadence runs in CI (spine.yml), not locally.")
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
    sp = sub.add_parser("ingest", help="ingest an aggregator peer into the catalog (kev | osv | ghsa)")
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

    sp = sub.add_parser("refresh", help="incremental NVD enrichment + per-CVE re-decide (wipe-proof; never a bulk re-pull)")
    sp.add_argument("--devices", default=DEFAULT_DEVICES, help="fleet YAML (list of device dicts)")
    sp.add_argument("--cap", type=int, default=_refresh.DEFAULT_CAP, help="max NVD enrichments this tick")
    sp.add_argument("--no-devices", action="store_true",
                    help="catalog-only enrichment: no fleet, no verdicts, no vendor trackers (for CI)")
    db_arg(sp); pol_arg(sp); sp.set_defaults(func=_cmd_refresh)

    sp = sub.add_parser("catalog", help="flaw catalog: show <flaw_id> | list | pending")
    sp.add_argument("sub", choices=["show", "list", "pending"])
    sp.add_argument("flaw_id", nargs="?", default=None, help="flaw id (show)")
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