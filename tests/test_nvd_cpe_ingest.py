"""NVD CPE-head ingestion tests.

The CPE-head path is the map-side complement to the per-CVE refresh: it asks
NVD for every CVE that touches a device matcher's CPE head and upserts the
result into the catalog so a self-hosted spine can cover the exact heads a
fleet actually uses.
"""
from __future__ import annotations

import pytest

from posture import refresh, store
from posture.sources import nvd_cve
from posture.sources.nvd_cve import _cpe_head


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _nvd_cve(cve_id="CVE-2026-9001",
             criteria="cpe:2.3:o:linux:linux_kernel",
             vstart="6.0", vend_excl="6.5"):
    return {
        "id": cve_id,
        "published": "2026-09-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "CPE-head ingest fixture"}],
        "metrics": {"cvssMetricV31": [{
            "baseSeverity": "HIGH",
            "cvssData": {
                "baseScore": 8.8,
                "vectorString": "CVSS:3.1/AV:N/AC:L/C:H/I:H/A:H",
            },
        }]},
        "references": [
            {"url": "https://example/advisory", "tags": ["Vendor Advisory"]},
            {"url": "https://example/patch", "tags": ["Patch"]},
        ],
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": criteria,
            "versionStartIncluding": vstart,
            "versionEndExcluding": vend_excl,
        }]}]}],
    }


def test_nvd_query_cpe_uses_header_only_api_key_and_virtual_match(monkeypatch):
    """The CPE-head query must keep the NVD key header-only and use
    ``virtualMatchString`` for the CPE, never the query-string key."""
    captured = {}

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        captured["url"] = url
        captured["headers"] = headers or []
        return ({"vulnerabilities": [], "totalResults": 0}, 200, "{}")

    monkeypatch.setattr(nvd_cve, "curl_get", fake_curl_get)
    monkeypatch.setenv("NVD_API_KEY", "SECRET-KEY-123")

    vulns, complete, _reason = nvd_cve.nvd_query_cpe(
        "cpe:2.3:o:linux:linux_kernel", throttle=False)
    assert vulns == []
    assert complete is True
    assert "apiKey" not in captured["url"]
    assert "SECRET-KEY-123" not in captured["url"]
    assert any("apiKey: SECRET-KEY-123" in h for h in captured["headers"])
    assert "virtualMatchString=cpe%3A2.3%3Ao%3Alinux%3Alinux_kernel" in captured["url"]


def test_nvd_cpe_ingest_upserts_rows_and_sets_nvd_state(conn, monkeypatch):
    cpe = "cpe:2.3:o:linux:linux_kernel"
    monkeypatch.setattr(refresh, "nvd_query_cpe",
                        lambda requested, throttle=True:
                        ([{"cve": _nvd_cve()}], True, "complete (1)"))
    stats = refresh.nvd_cpe_ingest_tick(
        conn, cpes=[cpe], policy_version="v",
        now="2026-09-30T00:00:00Z")

    assert stats["upserted"] == 1
    assert stats["skipped"] == 0
    assert stats["incomplete"] == 0
    assert stats["errors"] == []
    row = store.get_defect(conn, "CVE-2026-9001")
    assert row is not None
    assert row["source"] == "nvd"
    assert row["enrich_state"] == "nvd"
    assert row["cvss"] == 8.8
    assert row["severity"] == "HIGH"
    assert row["cwe"] == ["CWE-79"]
    assert row["ref_tags"] == ["Patch", "Vendor Advisory"]
    assert row["fixed_raw"]["source"] == "nvd"
    assert _cpe_head(cpe) in row["fixed_raw"]["cpe_heads"]

    head = _cpe_head(cpe)
    assert [r["id"] for r in store.defects_for_cpe_head(conn, head)] == \
        ["CVE-2026-9001"]


def test_nvd_cpe_ingest_incomplete_query_writes_nothing(conn, monkeypatch):
    monkeypatch.setattr(refresh, "nvd_query_cpe",
                        lambda cpe, throttle=True: ([], False, "incomplete"))
    stats = refresh.nvd_cpe_ingest_tick(
        conn, cpes=["cpe:2.3:o:linux:linux_kernel"], policy_version="v")
    assert stats["upserted"] == 0
    assert stats["incomplete"] == 1
    assert stats["errors"] == ["incomplete"]
    assert store.catalog_all(conn) == []


def test_nvd_cpe_ingest_cap_limits_total_upserts(conn, monkeypatch):
    vulns = [{"cve": _nvd_cve(f"CVE-2026-900{i}")}
             for i in range(3)]
    monkeypatch.setattr(refresh, "nvd_query_cpe",
                        lambda cpe, throttle=True:
                        (vulns, True, "complete (3)"))
    stats = refresh.nvd_cpe_ingest_tick(
        conn, cpes=["cpe:2.3:o:linux:linux_kernel"], policy_version="v",
        cap=2)
    assert stats["upserted"] == 2
    assert len(store.catalog_all(conn)) == 2
