"""End-to-end tests: the real NVD observer through the engine, the full
6-axis posture, and the audit/distrust round-trip."""
import json
from pathlib import Path

import pytest
from unittest.mock import patch
import yaml

from posture.axis import Axis
from posture.policy import default_policy_path, Policy
from posture import store, engine, provenance as _prov
from posture.sources import build_default_registry
from posture.sources.nvd_cve import NvdCveObserver

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
SAMPLE_DEVICE = FIXTURE_DIR / "sample_device.yaml"


def _sample_device():
    return yaml.safe_load(SAMPLE_DEVICE.read_text())


def test_nvd_observer_offline_fixture_produces_expected_verdicts():
    w = NvdCveObserver(live=False)
    pol = Policy.from_file(default_policy_path())
    result = w.assess(_sample_device(), pol)
    assert result.complete is True
    # 4 CVEs touch linux_kernel; the iPhone-only 99905 is filtered out
    assert len(result.verdicts) == 4
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["CVE-2026-99901"].status == "unpatched"
    assert by_key["CVE-2026-99901"].fixed_in == "6.18.5"
    assert by_key["CVE-2026-99901"].severity == "CRITICAL"
    assert by_key["CVE-2026-99902"].status == "patched"
    assert by_key["CVE-2026-99903"].status == "unpatched"
    assert by_key["CVE-2026-99903"].fixed_in == "6.18"
    assert by_key["CVE-2026-99904"].status == "not_affected"
    # provenance carries the observer + a citable raw_ref
    assert by_key["CVE-2026-99901"].provenance.observer == "nvd"
    assert by_key["CVE-2026-99901"].provenance.raw_ref


def test_full_six_axis_posture_one_real_five_unknown():
    reg = build_default_registry()
    pol = Policy.from_file(default_policy_path())
    conn = store.connect(":memory:")
    # Mock ip -j addr so the live_network_interfaces observer does not pick
    # up real system state — keeps the test deterministic.
    with patch("posture.sources.live_network_interfaces.subprocess.run",
               side_effect=FileNotFoundError("no ip binary in test")):
        dp = engine.assess(_sample_device(), reg, pol, conn=conn,
                           now="2026-08-01T00:00:00+00:00")
    by_axis = {a.axis: a for a in dp.axes}
    # the one real axis
    assert by_axis["vulnerability"].status == "unpatched"
    assert by_axis["vulnerability"].deciding_observer == "nvd"
    assert by_axis["vulnerability"].commit_state == "swapped"
    # the five stubbed axes are loud UNKNOWN
    for axis in ("configuration", "exposure", "inventory", "threat", "trust"):
        assert by_axis[axis].status == "unknown", axis
        assert by_axis[axis].gap
    # NVD attribution is emitted for the actually-used observer
    assert "nvd" in dp.used_observers


def test_audit_and_distrust_roundtrip_through_store():
    reg = build_default_registry()
    pol = Policy.from_file(default_policy_path())
    conn = store.connect(":memory:")
    with patch("posture.sources.live_network_interfaces.subprocess.run",
               side_effect=FileNotFoundError("no ip binary in test")):
        engine.assess(_sample_device(), reg, pol, conn=conn,
                      now="2026-08-01T00:00:00+00:00")
    # 4 vulnerability verdicts rest on nvd
    rows = _prov.audit(conn, "nvd")
    assert len(rows) == 4
    n = _prov.distrust(conn, "nvd", "audit test")
    conn.commit()
    assert n == 4
    # all 4 now marked, retained (not deleted)
    rows2 = _prov.audit(conn, "nvd")
    assert all(r["distrusted"] == 1 for r in rows2)
    assert len(store.verdicts_for_device_axis(conn, "demo-host", "vulnerability")) == 4


def test_nvd_observer_live_curl_mocked(monkeypatch):
    """The live fetch path works end-to-end with curl_get mocked to return a
    canned NVD page. Verifies header-only auth + totalResults completeness +
    the __HTTP__-split contract are honored (we never inspect the key in the
    URL because we mock the network; the rule is enforced structurally)."""
    page = json.loads((FIXTURE_DIR / "nvd_sample.json").read_text())
    urls: list[str] = []
    headers_seen: list[list[str]] = []

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        urls.append(url)
        headers_seen.append(list(headers or []))
        return page, 200, json.dumps(page)

    monkeypatch.setattr("posture.sources.nvd_cve.curl_get", fake_curl_get)
    monkeypatch.setenv("NVD_API_KEY", "test-secret-key")
    w = NvdCveObserver(live=True)
    pol = Policy.from_file(default_policy_path())
    result = w.assess(_sample_device(), pol)
    assert result.complete is True
    assert len(result.verdicts) == 4
    assert urls, "curl_get was called"
    # the run-#10 fleet-wipe root cause was the key in the URL query string.
    # Assert it NEVER leaks there, and IS sent as a header instead.
    assert all("apiKey=" not in u for u in urls), urls
    assert any(h.startswith("apiKey:") for hs in headers_seen for h in hs), headers_seen


def test_nvd_attribution_constant_present():
    from posture.sources.nvd_cve import NvdCveObserver
    from posture.attribution import NVD_ATTRIBUTION
    assert NvdCveObserver.attribution() == NVD_ATTRIBUTION
    assert "not endorsed or certified by the NVD" in NVD_ATTRIBUTION


def test_engine_posture_dict_serializable():
    reg = build_default_registry()
    pol = Policy.from_file(default_policy_path())
    dp = engine.assess(_sample_device(), reg, pol, conn=None,
                       now="2026-08-01T00:00:00+00:00")
    d = dp.to_dict()
    # full structure is JSON-serializable (no live objects)
    json.dumps(d)
    assert d["device_id"] == "demo-host"
    assert len(d["axes"]) == 6