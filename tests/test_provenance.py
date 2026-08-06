"""Provenance tests — stamp, audit, retroactive distrust (marks, not deletes)."""
from posture.axis import Axis
from posture.witness import Verdict, Provenance
from posture import store, provenance as _prov, engine


def _conn_with_nvd_verdicts():
    conn = store.connect(":memory:")
    v = Verdict(axis="vulnerability", key="CVE-1", status="unpatched",
                detail="d", severity="HIGH", fixed_in="6.18.5",
                provenance=Provenance(witness="nvd", policy_version="2026-08-01.1",
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
                provenance=Provenance(witness="nvd", policy_version="",
                                      fetched_at="", complete=True))
    out = _prov.stamp([v], policy_version="P1", fetched_at="T1", complete=True)
    assert out[0].provenance.policy_version == "P1"
    assert out[0].provenance.fetched_at == "T1"


def test_audit_lists_verdicts_by_witness():
    conn = _conn_with_nvd_verdicts()
    rows = _prov.audit(conn, "nvd")
    assert len(rows) == 1
    assert rows[0]["key"] == "CVE-1"
    assert rows[0]["witness"] == "nvd"


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
    assert marks[0]["witness"] == "nvd"


def test_distrust_idempotent_count():
    conn = _conn_with_nvd_verdicts()
    assert _prov.distrust(conn, "nvd", "r1") == 1
    assert _prov.distrust(conn, "nvd", "r2") == 0  # already marked