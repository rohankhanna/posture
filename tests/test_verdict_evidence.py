"""Verdict evidence tests — CWE and ref_tags fields flow through the verdict
and persist in the store, enabling evidence-based attack-graph chaining
(node_91813484fd27).
"""

from posture import store
from posture.observer import Verdict

# --- Verdict dataclass carries the new fields -------------------------------

def test_verdict_cwe_and_ref_tags_default_none():
    v = Verdict(axis="vulnerability", key="CVE-1", status="unpatched")
    assert v.cwe is None
    assert v.ref_tags is None


def test_verdict_to_dict_includes_cwe_and_ref_tags():
    v = Verdict(
        axis="vulnerability", key="CVE-1", status="unpatched",
        cwe=["CWE-79", "CWE-78"],
        ref_tags=["Exploit", "Patch"],
    )
    d = v.to_dict()
    assert d["cwe"] == ["CWE-79", "CWE-78"]
    assert d["ref_tags"] == ["Exploit", "Patch"]


def test_verdict_to_dict_cwe_ref_tags_none_when_unset():
    v = Verdict(axis="vulnerability", key="CVE-1", status="unpatched")
    d = v.to_dict()
    assert d["cwe"] is None
    assert d["ref_tags"] is None


# --- NVD observer populates cwe and ref_tags --------------------------------

def test_nvd_observer_populates_cwe_and_ref_tags():
    """The NVD observer extracts CWE ids and reference tags from the CVE
    record and carries them through the Verdict."""
    from posture.observer import ObserverResult
    from posture.policy import Policy, default_policy_path
    from posture.sources.nvd_cve import NvdCveObserver

    # Use offline (fixture) mode — no network.
    obs = NvdCveObserver(live=False)
    policy = Policy.from_file(default_policy_path())

    # A device with a CPE that the fixture covers.
    device = {
        "id": "test-dev",
        "os": "linux",
        "os_version": "6.18",
        "matchers": [
            {"type": "nvd_cpe", "cpe": "cpe:2.3:o:linux:linux_kernel:6.18:*:*:*:*:*:*:*"},
        ],
    }
    result = obs.assess(device, policy)
    assert isinstance(result, ObserverResult)
    assert result.verdicts, "expected at least one verdict from the fixture"

    # At least one verdict should carry CWE (the fixture CVEs have weaknesses).
    has_cwe = any(v.cwe for v in result.verdicts)
    assert has_cwe, "expected at least one verdict with CWE ids from the NVD fixture"


# --- Verdict evidence persists through the store ----------------------------

def test_verdict_cwe_ref_tags_persist_in_store(tmp_path):
    """commit_device_verdicts persists cwe + ref_tags as JSON, and
    verdicts_for_device_axis restores them as Python lists."""
    conn = store.connect(str(tmp_path / "test.db"))
    ts = "2026-08-31T00:00:00+00:00"

    verdicts = [
        {
            "axis": "vulnerability",
            "key": "CVE-2026-1",
            "status": "unpatched",
            "severity": "HIGH",
            "fixed_in": "1.2.3",
            "detail": "test detail",
            "cvss": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N",
            "published": "2026-01-01",
            "cwe": ["CWE-79", "CWE-78"],
            "ref_tags": ["Exploit", "Patch"],
            "provenance": {
                "observer": "nvd",
                "policy_version": "v1",
                "fetched_at": ts,
                "complete": True,
                "raw_ref": "https://example.com",
            },
        },
    ]
    state = store.commit_device_verdicts(
        conn, "dev1", "vulnerability", verdicts,
        complete=True, policy_version="v1", ts=ts,
    )
    assert state == "swapped"

    rows = store.verdicts_for_device_axis(conn, "dev1", "vulnerability")
    assert len(rows) == 1
    r = rows[0]
    assert r["cwe"] == ["CWE-79", "CWE-78"]
    assert r["ref_tags"] == ["Exploit", "Patch"]
    conn.close()


def test_verdict_cwe_ref_tags_null_when_absent(tmp_path):
    """Verdicts without cwe/ref_tags persist as NULL, not empty strings."""
    conn = store.connect(str(tmp_path / "test2.db"))
    ts = "2026-08-31T00:00:00+00:00"

    verdicts = [
        {
            "axis": "vulnerability",
            "key": "CVE-2026-2",
            "status": "patched",
            "severity": "LOW",
            "fixed_in": "1.0.1",
            "detail": "",
            "provenance": {
                "observer": "nvd",
                "policy_version": "v1",
                "fetched_at": ts,
                "complete": True,
                "raw_ref": None,
            },
        },
    ]
    store.commit_device_verdicts(
        conn, "dev2", "vulnerability", verdicts,
        complete=True, policy_version="v1", ts=ts,
    )

    rows = store.verdicts_for_device_axis(conn, "dev2", "vulnerability")
    assert len(rows) == 1
    assert rows[0]["cwe"] is None
    assert rows[0]["ref_tags"] is None
    conn.close()


def test_upsert_verdict_persists_cwe_ref_tags(tmp_path):
    """upsert_verdict (the incremental path) also persists the new fields."""
    conn = store.connect(str(tmp_path / "test3.db"))
    ts = "2026-08-31T00:00:00+00:00"

    v = {
        "device_id": "dev3",
        "axis": "vulnerability",
        "key": "CVE-2026-3",
        "status": "unpatched",
        "severity": "CRITICAL",
        "fixed_in": None,
        "detail": "no fix",
        "cwe": ["CWE-119"],
        "ref_tags": ["Exploit", "Vendor Advisory"],
        "provenance": {
            "observer": "nvd",
            "policy_version": "v1",
            "fetched_at": ts,
            "complete": True,
            "raw_ref": "ref",
        },
    }
    store.upsert_verdict(conn, v, ts)
    conn.commit()

    rows = store.verdicts_for_device_axis(conn, "dev3", "vulnerability")
    assert len(rows) == 1
    assert rows[0]["cwe"] == ["CWE-119"]
    assert rows[0]["ref_tags"] == ["Exploit", "Vendor Advisory"]
    conn.close()
