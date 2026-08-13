"""Tests for the Debian security-tracker observer — a real VENDOR observer on the
vulnerability axis.

These pin four things:
  1. the bulk-extract parser maps the tracker's per-release status fields to
     (status, fixed_in) faithfully;
  2. the observer emits honest CVE-keyed Verdicts from a device's cve_candidates
     (offline fixture), and is an honest no-op when the device gives it nothing;
  3. in the engine, the vendor observer OVERRIDES NVD on the same CVE key by
     policy order (order 5 < nvd 10 -> runs last -> wins) — the actual point:
     NVD's false-alarm unknown-fix on a Debian host becomes patched;
  4. the live fetch path (mocked curl) works, and a failed/absent fetch is a
     complete, zero-verdict no-op (no-wipe), never an engine-breaking failure.
"""
import json
from pathlib import Path

import pytest
import yaml

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.observer import ObserverRegistry
from posture.sources.nvd_cve import NvdCveObserver
from posture.sources.debian_tracker import (
    DebianTrackerObserver, bulk_extract, is_cve_id,
)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
SAMPLE_DEVICE = FIXTURE_DIR / "sample_device.yaml"
DEBIAN_FIXTURE = FIXTURE_DIR / "debian_tracker" / "data.json"

# An inline policy that authorizes nvd (order 10) + debian_tracker (order 5).
# debian_tracker's LOWER order means the engine runs it LAST and it overrides
# NVD on a shared CVE key. Built inline so the test is self-contained and needs
# NO change to the shared policy.yaml (a sibling agent wires shared files).
INLINE_POLICY = """
version: "2026-08-02.2"
supersedes: "2026-08-02.1"
dated: 2026-08-02
rationale: "inline test policy: debian_tracker overrides nvd on the CVE key"
observers:
  nvd:
    axes: [vulnerability]
    weight: high
    bias: false-alarm
    order: 10
    conditions: []
  debian_tracker:
    axes: [vulnerability]
    weight: high
    bias: false-safe
    order: 5
    conditions:
      - "Debian hosts only: device supplies cve_candidates + debian_release + debian_packages"
      - "undetermined / release absent / CVE absent -> no verdict (NVD stands)"
spine:
  primary_key: cve
  role: vulnerability_join_key
"""


def _device(**extra):
    d = yaml.safe_load(SAMPLE_DEVICE.read_text())
    d.update(extra)
    return d


def _inline_policy():
    return Policy.from_yaml(INLINE_POLICY)


def _registry():
    reg = ObserverRegistry()
    reg.register(NvdCveObserver(live=False))
    reg.register(DebianTrackerObserver(live=False))
    return reg


# ---------------------------------------------------------------------------
# parser / bulk extract
# ---------------------------------------------------------------------------

def test_is_cve_id_filters_advisory_ids():
    assert is_cve_id("CVE-2026-99901")
    assert not is_cve_id("GHSA-aaaa-aaaa")
    assert not is_cve_id("PYSEC-0000-0000")
    assert not is_cve_id("")
    assert not is_cve_id("DSA-1234-1")


def test_bulk_extract_maps_status_fields():
    data = json.loads(DEBIAN_FIXTURE.read_text())
    out = bulk_extract(data, "trixie", ["linux"])
    # resolved + real fixed_version -> (resolved, "6.18.5-1")
    assert out["CVE-2026-99901"] == ("resolved", "6.18.5-1")
    # resolved + "0" -> (resolved, "0")  [not affected]
    assert out["CVE-2026-99903"] == ("resolved", "0")
    # open -> (open, None)
    assert out["CVE-2026-99902"] == ("open", None)
    # undetermined -> (undetermined, None)  [recognized but _decide won't act]
    assert out["CVE-2026-99907"] == ("undetermined", None)


def test_bulk_extract_skips_other_release():
    data = json.loads(DEBIAN_FIXTURE.read_text())
    # bookworm only has a row for 99901 (open); trixie rows are absent here.
    out = bulk_extract(data, "bookworm", ["linux"])
    assert out == {"CVE-2026-99901": ("open", None)}


# ---------------------------------------------------------------------------
# observer (offline)
# ---------------------------------------------------------------------------

def test_observer_offline_overrides_status_mappings():
    w = DebianTrackerObserver(live=False)
    pol = _inline_policy()
    device = {
        "id": "debian-host",
        "cve_candidates": [
            "CVE-2026-99901",  # resolved + real version -> patched (fixed_in)
            "CVE-2026-99903",  # resolved + "0"         -> patched (not affected)
            "CVE-2026-99902",  # open                   -> unpatched
            "CVE-2026-99907",  # undetermined           -> NO verdict
            "CVE-2026-99909",  # absent from tracker     -> NO verdict
        ],
        "debian_release": "trixie",
        "debian_packages": ["linux"],
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    # 99907 (undetermined) and 99909 (absent) -> no verdict; NVD would stand
    assert sorted(by_key) == ["CVE-2026-99901", "CVE-2026-99902", "CVE-2026-99903"]
    # resolved + real fixed_version -> patched with fixed_in set
    assert by_key["CVE-2026-99901"].status == "patched"
    assert by_key["CVE-2026-99901"].fixed_in == "6.18.5-1"
    # resolved + "0" (not affected) -> patched, fixed_in None
    assert by_key["CVE-2026-99903"].status == "patched"
    assert by_key["CVE-2026-99903"].fixed_in is None
    # open -> unpatched
    assert by_key["CVE-2026-99902"].status == "unpatched"
    assert by_key["CVE-2026-99902"].fixed_in is None
    for v in result.verdicts:
        assert v.provenance.observer == "debian_tracker"
        assert v.provenance.raw_ref.startswith(
            "https://security-tracker.debian.org/tracker/CVE-")


def test_observer_no_input_is_honest_noop():
    """A non-Debian host (no candidate set) gives the observer nothing to say.
    It returns ZERO verdicts (complete) so the engine keeps NVD's verdicts and
    the loud-degradation rule is unaffected — never a crash, never 'clean'."""
    w = DebianTrackerObserver(live=False)
    pol = _inline_policy()
    # the shipped demo device has no debian_* fields and no cve_candidates
    device = yaml.safe_load(SAMPLE_DEVICE.read_text())
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no debian tracker input" in result.reason


def test_observer_filters_non_cve_candidate_ids():
    """GHSA/PYSEC/DSA ids in the candidate set (from other matchers) have no
    tracker row; they are filtered out, not consulted."""
    w = DebianTrackerObserver(live=False)
    pol = _inline_policy()
    device = {
        "id": "debian-host",
        "cve_candidates": ["GHSA-aaaa-aaaa", "PYSEC-0000-0000",
                           "DSA-1234-1", "CVE-2026-99901"],
        "debian_release": "trixie",
        "debian_packages": ["linux"],
    }
    result = w.assess(device, pol)
    assert [v.key for v in result.verdicts] == ["CVE-2026-99901"]


# ---------------------------------------------------------------------------
# engine: vendor overrides NVD by policy order (the actual point)
# ---------------------------------------------------------------------------

def test_vendor_observer_overrides_nvd_on_shared_cve_key():
    """NVD says CVE-2026-99901 is unpatched (unknown-fix; device 6.18 < 6.18.5).
    With debian_tracker registered and its policy order < nvd's, the engine
    runs it LAST and it wins on the shared CVE key — the committed verdict
    carries observer=debian_tracker and status=patched, not observer=nvd/
    unpatched. The override is proven at the per-verdict row level (not via
    dp.used_observers, which tracks only the axis-deciding observer)."""
    reg = _registry()
    pol = _inline_policy()
    conn = store.connect(":memory:")
    device = _device(
        cve_candidates=["CVE-2026-99901"],   # NVD unpatched; Debian resolved->patched
        debian_release="trixie",
        debian_packages=["linux"],
    )
    engine.assess(device, reg, pol, conn=conn,
                 now="2026-08-02T00:00:00+00:00")
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "vulnerability")}
    # the overridden CVE now rests on the vendor, patched
    assert rows["CVE-2026-99901"]["observer"] == "debian_tracker"
    assert rows["CVE-2026-99901"]["status"] == "patched"
    assert rows["CVE-2026-99901"]["fixed_in"] == "6.18.5-1"
    # a CVE the vendor had nothing to say about still rests on NVD, unchanged
    assert rows["CVE-2026-99902"]["observer"] == "nvd"
    assert rows["CVE-2026-99902"]["status"] == "patched"
    assert rows["CVE-2026-99904"]["observer"] == "nvd"


def test_default_demo_device_unchanged_by_new_observer():
    """The shipped demo device has no debian input -> the new observer no-ops, so
    the existing vulnerability posture (unpatched, decided by NVD) is unchanged.
    Guards against the registration accidentally altering the demo's behavior."""
    reg = _registry()
    pol = _inline_policy()
    conn = store.connect(":memory:")
    device = yaml.safe_load(SAMPLE_DEVICE.read_text())
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-02T00:00:00+00:00")
    vuln = {a.axis: a for a in dp.axes}["vulnerability"]
    assert vuln.status == "unpatched"
    assert vuln.deciding_observer == "nvd"
    # debian_tracker ran but produced no verdicts -> not a 'used' observer
    assert "debian_tracker" not in dp.used_observers


# ---------------------------------------------------------------------------
# live fetch path (mocked curl)
# ---------------------------------------------------------------------------

def test_observer_live_fetch_mocked(monkeypatch):
    """The live path reads the parsed JSON from curl_get's slot 1 (the tracker
    returns JSON, so the body is parsed there)."""
    fixture_data = json.loads(DEBIAN_FIXTURE.read_text())
    seen: list[str] = []

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        seen.append(url)
        return fixture_data, 200, json.dumps(fixture_data)

    monkeypatch.setattr("posture.sources.debian_tracker.curl_get", fake_curl_get)
    w = DebianTrackerObserver(live=True)
    pol = _inline_policy()
    device = {
        "id": "debian-host",
        "cve_candidates": ["CVE-2026-99901", "CVE-2026-99902"],
        "debian_release": "trixie",
        "debian_packages": ["linux"],
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["CVE-2026-99901"].status == "patched"
    assert by_key["CVE-2026-99902"].status == "unpatched"
    assert seen and "security-tracker.debian.org" in seen[0]


def test_observer_live_fetch_failure_is_absent_not_incomplete(monkeypatch):
    """A failed/absent bulk fetch is a complete, zero-verdict no-op (NVD stands
    in the engine). It must NOT mark the fetch incomplete (no-wipe: a failed
    download is a no-op, never a source failure that wipes stored verdicts)."""

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        return None, 0, ""   # timeout / network failure

    monkeypatch.setattr("posture.sources.debian_tracker.curl_get", fake_curl_get)
    w = DebianTrackerObserver(live=True)
    pol = _inline_policy()
    device = {
        "id": "debian-host",
        "cve_candidates": ["CVE-2026-99901"],
        "debian_release": "trixie",
        "debian_packages": ["linux"],
    }
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True   # absent, not incomplete
    assert "absent" in result.reason