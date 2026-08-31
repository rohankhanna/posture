"""Provenance tests — stamp, audit, retroactive distrust (marks, not deletes)."""
from posture.axis import Axis
from posture.observer import Verdict, Provenance
from posture import store, provenance as _prov, engine


def _conn_with_nvd_verdicts():
    conn = store.connect(":memory:")
    v = Verdict(axis="vulnerability", key="CVE-1", status="unpatched",
                detail="d", severity="HIGH", fixed_in="6.18.5",
                provenance=Provenance(observer="nvd", policy_version="2026-08-01.1",
                                       fetched_at="2026-01-01T00:00:00+00:00",
                                       complete=True, raw_ref="ref"))
    stamped = _prov.stamp([v], policy_version="2026-08-01.1",
                          fetched_at="2026-01-01T00:00:00+00:00", complete=True)
    payload = _prov.verdicts_to_commit_dicts(stamped)
    store.commit_device_verdicts(conn, "dev", "vulnerability", payload,
                                  complete=True, policy_version="2026-08-01.1",
                                  ts="2026-01-01T00:00:00+00:00")
    conn.commit()
    return conn


def test_stamp_fills_policy_version_and_ts():
    v = Verdict(axis="vulnerability", key="CVE-1", status="unpatched",
                provenance=Provenance(observer="nvd", policy_version="",
                                      fetched_at="", complete=True))
    out = _prov.stamp([v], policy_version="P1", fetched_at="T1", complete=True)
    assert out[0].provenance.policy_version == "P1"
    assert out[0].provenance.fetched_at == "T1"


def test_audit_lists_verdicts_by_observer():
    conn = _conn_with_nvd_verdicts()
    rows = _prov.audit(conn, "nvd")
    assert len(rows) == 1
    assert rows[0]["key"] == "CVE-1"
    assert rows[0]["observer"] == "nvd"


def test_distrust_marks_not_deletes():
    conn = _conn_with_nvd_verdicts()
    n = _prov.distrust(conn, "nvd", "captured")
    assert n == 1
    conn.commit()
    rows = _prov.audit(conn, "nvd")
    assert rows[0]["distrusted"] == 1            # marked
    assert rows[0]["distrust_reason"] == "captured"
    assert rows[0]["status"] == "unpatched"      # record RETAINED, not deleted


def test_distrust_log_recorded():
    conn = _conn_with_nvd_verdicts()
    _prov.distrust(conn, "nvd", "captured")
    conn.commit()
    marks = _prov.distrust_log(conn)
    assert len(marks) == 1
    assert marks[0]["observer"] == "nvd"


def test_distrust_idempotent_count():
    conn = _conn_with_nvd_verdicts()
    assert _prov.distrust(conn, "nvd", "r1") == 1
    assert _prov.distrust(conn, "nvd", "r2") == 0  # already marked

def test_stamp_preserves_evidence_fields():
    """The stamp function must preserve cvss, cvss_vector, published, cwe, and
    ref_tags on Verdict objects — these are evidence fields the assess path
    populates from the catalog, and the engine's stamp step must not drop them
    when filling in engine-controlled provenance. Regression for the bug where
    stamp() reconstructed Verdicts without copying the new evidence fields."""
    v = Verdict(
        axis="vulnerability", key="CVE-2026-1", status="unpatched",
        detail="d", severity="CRITICAL", fixed_in="6.18.5",
        cvss=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L",
        published="2026-02-01", cwe=["CWE-787"], ref_tags=["Exploit"],
        provenance=Provenance(observer="nvd", policy_version="",
                              fetched_at="", complete=True, raw_ref="ref"),
    )
    out = _prov.stamp([v], policy_version="P1", fetched_at="T1", complete=True)
    assert out[0].cvss == 9.8
    assert out[0].cvss_vector == "CVSS:3.1/AV:N/AC:L"
    assert out[0].published == "2026-02-01"
    assert out[0].cwe == ["CWE-787"]
    assert out[0].ref_tags == ["Exploit"]


def test_stamp_preserves_evidence_fields_no_provenance():
    """Same regression but for the no-provenance branch of stamp()."""
    v = Verdict(
        axis="vulnerability", key="CVE-2026-2", status="unpatched",
        detail="d", severity="HIGH", fixed_in=None,
        cvss=7.5, cvss_vector="CVSS:3.1/AV:N",
        published="2026-03-01", cwe=["CWE-89"], ref_tags=["Patch"],
        provenance=None,
    )
    out = _prov.stamp([v], policy_version="P1", fetched_at="T1", complete=True)
    assert out[0].cvss == 7.5
    assert out[0].cvss_vector == "CVSS:3.1/AV:N"
    assert out[0].published == "2026-03-01"
    assert out[0].cwe == ["CWE-89"]
    assert out[0].ref_tags == ["Patch"]


def test_engine_assess_verdicts_carry_cvss_from_catalog():
    """End-to-end: engine.assess verdicts (post-stamp, post-to_dict) carry the
    real CVSS score from the catalog — the stamp step no longer strips it.
    This is the path the weatherman shell consumes: assess verdicts with real
    evidence fields, not just status/severity."""
    import json
    import yaml
    from pathlib import Path
    from posture.refresh import _enriched_record
    from posture.policy import Policy, default_policy_path
    from posture.sources import build_default_registry
    from posture.cli import _inject_catalog_overlays

    FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
    conn = store.connect(":memory:")
    for v in json.loads((FIXTURE_DIR / "nvd_sample.json").read_text())["vulnerabilities"]:
        row = _enriched_record(v["cve"], policy_version="v", fetched_at="2026-08-22")
        store.upsert_defect(conn, row)
        store.set_enrich_state(conn, row["id"], "nvd")
    conn.commit()

    device = yaml.safe_load((FIXTURE_DIR / "sample_device.yaml").read_text())
    _inject_catalog_overlays(device, conn)
    reg = build_default_registry()
    pol = Policy.from_file(default_policy_path())
    dp = engine.assess(device, reg, pol, conn=conn, now="2026-08-22T00:00:00+00:00")
    by_axis = {a.axis: a for a in dp.axes}
    # At least one NVD-decided verdict carries a real CVSS score
    nvd_verdicts = [v for v in by_axis["vulnerability"].verdicts
                    if v.get("_observer") == "nvd" and v.get("status") == "unpatched"]
    assert nvd_verdicts, "expected at least one NVD unpatched verdict"
    has_cvss = any(v.get("cvss") is not None for v in nvd_verdicts)
    assert has_cvss, "NVD verdicts should carry real CVSS from the catalog after stamp"
