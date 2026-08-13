"""Tests for the Ubuntu security-tracker observer — the first real VENDOR
observer on the vulnerability axis.

These pin three things:
  1. the parser maps tracker status cells to (status, fixed_in) faithfully;
  2. the observer emits honest CVE-keyed Verdicts from a device's cve_candidates
     (offline fixture), and is an honest no-op when the device gives it nothing;
  3. in the engine, the vendor observer OVERRIDES NVD on the same CVE key by
     policy order (order 5 < nvd 10 -> runs last -> wins) — the actual point:
     NVD's false-alarm unknown-fix on an Ubuntu host becomes patched.
"""
from pathlib import Path

import pytest
import yaml

from posture.axis import Axis
from posture.policy import default_policy_path, Policy
from posture import store, engine
from posture.sources import build_default_registry
from posture.sources.ubuntu_tracker import (
    UbuntuTrackerObserver, parse_cve_page, is_cve_id,
)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
SAMPLE_DEVICE = FIXTURE_DIR / "sample_device.yaml"
TRACKER_FIXTURE = FIXTURE_DIR / "ubuntu_tracker"


def _device(**extra):
    d = yaml.safe_load(SAMPLE_DEVICE.read_text())
    d.update(extra)
    return d


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def test_is_cve_id_filters_advisory_ids():
    assert is_cve_id("CVE-2026-99901")
    assert not is_cve_id("GHSA-aaaa-aaaa")
    assert not is_cve_id("PYSEC-0000-0000")
    assert not is_cve_id("")


def test_parse_cve_page_maps_status_cells():
    html = (
        '<table><tr>'
        '<th rowspan="1">linux-nvidia-6.17</th>'
        '<td>24.04 LTS <span>noble</span></td>'
        '<td class="cve-td-status">Fixed 6.17.9</td>'
        '</tr></table>'
    )
    out = parse_cve_page(html, "noble", ["linux-nvidia-6.17"])
    assert out == {"linux-nvidia-6.17": ("fixed", "6.17.9")}


def test_parse_cve_page_skips_other_release_keeps_recognized_status():
    html = (
        '<table>'
        '<tr><th rowspan="1">linux-nvidia-6.17</th>'
        '<td>22.04 LTS <span>jammy</span></td>'
        '<td class="cve-td-status">Fixed 6.17.9</td></tr>'
        '<tr><th rowspan="1">linux-nvidia-6.17</th>'
        '<td>24.04 LTS <span>noble</span></td>'
        '<td class="cve-td-status">Needs triage</td></tr>'
        '</table>'
    )
    # jammy is the wrong release -> its row is skipped; noble is 'needs', which
    # the parser DOES recognize (st[0] is not None) even though _decide won't act
    # on it. So it surfaces here; _decide later leaves the NVD verdict standing.
    assert parse_cve_page(html, "noble", ["linux-nvidia-6.17"]) == {
        "linux-nvidia-6.17": ("needs", None),
    }


# ---------------------------------------------------------------------------
# observer (offline)
# ---------------------------------------------------------------------------

def test_observer_offline_overrides_two_cves_and_skips_absent():
    w = UbuntuTrackerObserver(live=False)
    pol = Policy.from_file(default_policy_path())
    device = {
        "id": "ubuntu-host",
        "patch_level": "6.18",
        "cve_candidates": ["CVE-2026-99901", "CVE-2026-99903", "CVE-2026-99909"],
        "ubuntu_release": "noble",
        "ubuntu_packages": ["linux-nvidia-6.17"],
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    # 99909 has no fixture (absent) -> no verdict; NVD would stand in the engine
    assert sorted(by_key) == ["CVE-2026-99901", "CVE-2026-99903"]
    # NVD said unpatched (unknown-fix); Ubuntu says fixed 6.17.9, kernel 6.18 >= -> patched
    assert by_key["CVE-2026-99901"].status == "patched"
    assert by_key["CVE-2026-99901"].fixed_in == "6.17.9"
    # not affected -> patched (clears the NVD false positive), fixed_in None
    assert by_key["CVE-2026-99903"].status == "patched"
    assert by_key["CVE-2026-99903"].fixed_in is None
    for v in result.verdicts:
        assert v.provenance.observer == "ubuntu_tracker"
        assert v.provenance.raw_ref.startswith("https://ubuntu.com/security/")


def test_observer_below_fix_is_unpatched():
    w = UbuntuTrackerObserver(live=False)
    pol = Policy.from_file(default_policy_path())
    device = {
        "id": "ubuntu-host",
        "patch_level": "6.17",   # below the 6.17.9 fix
        "cve_candidates": ["CVE-2026-99901"],
        "ubuntu_release": "noble",
        "ubuntu_packages": ["linux-nvidia-6.17"],
    }
    result = w.assess(device, pol)
    assert len(result.verdicts) == 1
    assert result.verdicts[0].status == "unpatched"
    assert result.verdicts[0].fixed_in == "6.17.9"


def test_observer_no_input_is_honest_noop():
    """A non-Ubuntu host (no candidate set) gives the observer nothing to say.
    It returns ZERO verdicts (complete) so the engine keeps NVD's verdicts and
    the loud-degradation rule is unaffected — never a crash, never 'clean'."""
    w = UbuntuTrackerObserver(live=False)
    pol = Policy.from_file(default_policy_path())
    # the shipped demo device has no ubuntu_* fields and no cve_candidates
    device = yaml.safe_load(SAMPLE_DEVICE.read_text())
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no ubuntu tracker input" in result.reason


def test_observer_filters_non_cve_candidate_ids():
    """GHSA/PYSEC ids in the candidate set (from other matchers) have no tracker
    page; they are filtered out, not fetched."""
    w = UbuntuTrackerObserver(live=False)
    pol = Policy.from_file(default_policy_path())
    device = {
        "id": "ubuntu-host",
        "patch_level": "6.18",
        "cve_candidates": ["GHSA-aaaa-aaaa", "PYSEC-0000-0000", "CVE-2026-99901"],
        "ubuntu_release": "noble",
        "ubuntu_packages": ["linux-nvidia-6.17"],
    }
    result = w.assess(device, pol)
    assert [v.key for v in result.verdicts] == ["CVE-2026-99901"]


# ---------------------------------------------------------------------------
# engine: vendor overrides NVD by policy order (the actual point)
# ---------------------------------------------------------------------------

def test_vendor_observer_overrides_nvd_on_shared_cve_key():
    """NVD says CVE-2026-99901 and -99903 are unpatched (unknown-fix). With
    ubuntu_tracker registered and its policy order < nvd's, the engine runs it
    LAST and it wins on the shared CVE key — the committed verdicts carry
    observer=ubuntu_tracker and status=patched, not observer=nvd/unpatched."""
    reg = build_default_registry()
    pol = Policy.from_file(default_policy_path())
    conn = store.connect(":memory:")
    device = _device(
        cve_candidates=["CVE-2026-99901", "CVE-2026-99903"],
        ubuntu_release="noble",
        ubuntu_packages=["linux-nvidia-6.17"],
    )
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-02T00:00:00+00:00")
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "vulnerability")}
    # the two overridden CVEs now rest on the vendor, patched
    assert rows["CVE-2026-99901"]["observer"] == "ubuntu_tracker"
    assert rows["CVE-2026-99901"]["status"] == "patched"
    assert rows["CVE-2026-99903"]["observer"] == "ubuntu_tracker"
    assert rows["CVE-2026-99903"]["status"] == "patched"
    # the CVEs the vendor had nothing to say about still rest on NVD, unchanged
    assert rows["CVE-2026-99902"]["observer"] == "nvd"
    assert rows["CVE-2026-99902"]["status"] == "patched"
    assert rows["CVE-2026-99904"]["observer"] == "nvd"
    # NOTE: dp.used_observers tracks only the axis-deciding observer (here 'nvd',
    # because CVE-2026-99904's not_affected is the worst bucket present), NOT
    # every observer that produced a verdict. The override is proven by the
    # per-verdict rows above (observer=ubuntu_tracker), not by used_observers.


def test_default_demo_device_unchanged_by_new_observer():
    """The shipped demo device has no ubuntu input -> the new observer no-ops, so
    the existing vulnerability posture (unpatched, decided by NVD) is unchanged.
    Guards against the registration accidentally altering the demo's behavior."""
    reg = build_default_registry()
    pol = Policy.from_file(default_policy_path())
    conn = store.connect(":memory:")
    device = yaml.safe_load(SAMPLE_DEVICE.read_text())
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-02T00:00:00+00:00")
    vuln = {a.axis: a for a in dp.axes}["vulnerability"]
    assert vuln.status == "unpatched"
    assert vuln.deciding_observer == "nvd"
    # ubuntu_tracker ran but produced no verdicts -> not a 'used' observer
    assert "ubuntu_tracker" not in dp.used_observers


# ---------------------------------------------------------------------------
# live fetch path (mocked curl)
# ---------------------------------------------------------------------------

def test_observer_live_fetch_mocked(monkeypatch):
    """The live path parses HTML returned by curl_get (which yields
    parsed_json=None for non-JSON bodies, with the body in slot 3)."""
    html = (TRACKER_FIXTURE / "CVE-2026-99901.html").read_text()
    seen: list[str] = []

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        seen.append(url)
        return None, 200, html   # non-JSON -> data None, body in slot 3

    monkeypatch.setattr("posture.sources.ubuntu_tracker.curl_get", fake_curl_get)
    w = UbuntuTrackerObserver(live=True)
    pol = Policy.from_file(default_policy_path())
    device = {
        "id": "ubuntu-host",
        "patch_level": "6.18",
        "cve_candidates": ["CVE-2026-99901"],
        "ubuntu_release": "noble",
        "ubuntu_packages": ["linux-nvidia-6.17"],
    }
    result = w.assess(device, pol)
    assert result.complete is True
    assert len(result.verdicts) == 1
    assert result.verdicts[0].status == "patched"
    assert seen and "CVE-2026-99901" in seen[0]


def test_observer_live_404_is_absent_not_failure(monkeypatch):
    """A 404 (CVE not in the tracker) is genuine absent -> complete=True, zero
    verdicts (NVD stands in the engine). It must NOT mark the fetch incomplete
    (no-wipe: an absent tracker page is not a source failure)."""

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        return None, 404, "<html>not found</html>"

    monkeypatch.setattr("posture.sources.ubuntu_tracker.curl_get", fake_curl_get)
    w = UbuntuTrackerObserver(live=True)
    pol = Policy.from_file(default_policy_path())
    device = {
        "id": "ubuntu-host",
        "patch_level": "6.18",
        "cve_candidates": ["CVE-2026-99901"],
        "ubuntu_release": "noble",
        "ubuntu_packages": ["linux-nvidia-6.17"],
    }
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True   # absent, not incomplete