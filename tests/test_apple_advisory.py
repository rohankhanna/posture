"""Tests for the Apple security-advisory witness — a real VENDOR witness on the
vulnerability axis (the Apple counterpart to ubuntu_tracker).

These pin three things:
  1. the parser maps index rows + advisory og:titles + CVE lists faithfully,
     including the earliest-version-wins rule across re-mentioned CVEs;
  2. the witness emits honest CVE-keyed Verdicts from a device's cve_candidates
     (offline fixture): patched at/above the fix, unpatched below it, no verdict
     for CVEs not in Apple's feed; and is an honest no-op when the device gives
     it nothing;
  3. in the engine, the vendor witness OVERRIDES another witness on the same
     CVE key by policy order (order 5 < 10 -> runs last -> wins) — proven at the
     per-verdict row level via store.verdicts_for_device_axis.

The NVD fixture shipped with the repo is linux-only (no Apple CVEs), so the
override proof uses a SECOND trivial inline witness (a stand-in for NVD emitting
'unpatched') with order=10 alongside AppleAdvisoryWitness at order=5; the
registry + policy are built inline so this test needs NO change to any shared
file. Live curl is monkeypatched.
"""
from pathlib import Path

import yaml

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.witness import Witness, WitnessRegistry, WitnessResult, Verdict
from posture.sources.apple_advisory import (
    AppleAdvisoryWitness, build_fix_map, is_cve_id,
    parse_advisory, parse_advisory_version, parse_index,
)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
APPLE_FIXTURE = FIXTURE_DIR / "apple_advisory"

# An inline policy that authorizes apple_advisory (order 5) and a stand-in NVD
# witness (order 10). order 5 < 10 -> the engine runs apple LAST -> apple wins
# on a shared CVE key. No shared file is touched.
_INLINE_POLICY_YAML = """
version: "2026-08-02.1"
dated: 2026-08-02
rationale: "test policy for apple_advisory witness"
witnesses:
  apple_advisory:
    axes: [vulnerability]
    weight: high
    bias: false-safe
    order: 5
    conditions: []
  stub_nvd_like:
    axes: [vulnerability]
    weight: high
    bias: false-alarm
    order: 10
    conditions: []
"""


class _StubNvdLikeWitness(Witness):
    """A trivial stand-in for NVD on the vulnerability axis: emits 'unpatched'
    on a configured CVE so the engine override can be proven without relying on
    the shipped linux-only NVD fixture. order 10 (higher than apple's 5)."""

    id = "stub_nvd_like"
    axes = (Axis.VULNERABILITY,)
    bias = "false-alarm"
    key_kind = "cve"

    def __init__(self, cve: str = "CVE-2026-99910") -> None:
        super().__init__(id=self.id, axes=self.axes, bias=self.bias)
        self._cve = cve

    def assess(self, device: dict, policy) -> WitnessResult:
        return WitnessResult(
            verdicts=[Verdict(
                axis=Axis.VULNERABILITY.value, key=self._cve,
                status="unpatched", fixed_in=None, severity="high",
                detail="stub NVD-like: thin Apple coverage -> unpatched skip",
                provenance=self._prov(complete=True, raw_ref="stub://nvd"),
            )],
            complete=True, reason="stub",
        )


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def test_is_cve_id_filters_advisory_ids():
    assert is_cve_id("CVE-2026-99910")
    assert not is_cve_id("GHSA-aaaa-aaaa")
    assert not is_cve_id("PYSEC-0000-0000")
    assert not is_cve_id("")


def test_parse_index_ios_rows_extract_url_version_id():
    html = (APPLE_FIXTURE / "index.html").read_text()
    rows = parse_index(html, "iphone_os")
    by_id = {aid: (ver, url) for ver, url, aid in rows}
    assert set(by_id) == {"HT111111", "HT222222"}
    assert by_id["HT111111"][0] == "16.7.15"
    assert by_id["HT222222"][0] == "17.1"
    assert by_id["HT111111"][1] == "https://support.apple.com/en-us/HT111111"


def test_parse_index_macos_row_extracted():
    html = (APPLE_FIXTURE / "index.html").read_text()
    rows = parse_index(html, "macos")
    assert len(rows) == 1
    ver, url, aid = rows[0]
    assert ver == "26.5"
    assert aid == "HT333333"


def test_parse_advisory_version_from_og_title():
    html = (APPLE_FIXTURE / "HT111111.html").read_text()
    assert parse_advisory_version(html, "iphone_os") == "16.7.15"
    # cross-product advisory (a macOS advisory under the iOS product) -> None
    mac_html = (APPLE_FIXTURE / "HT333333.html").read_text()
    assert parse_advisory_version(mac_html, "iphone_os") is None
    assert parse_advisory_version(mac_html, "macos") == "26.5"


def test_parse_advisory_extracts_cves_and_strips_scripts():
    html = (APPLE_FIXTURE / "HT111111.html").read_text()
    cves = parse_advisory(html)
    assert cves == ["CVE-2026-99910", "CVE-2026-99911"]  # sorted, deduped
    # the analytics-bundle leak CVE-0000-LEAK must NOT appear (script stripped)
    assert "CVE-0000-LEAK" not in cves


def test_build_fix_map_earliest_version_wins():
    """CVE-2026-99910 is re-mentioned in the 17.1 advisory AND the older 16.7.15
    advisory. The donor walks advisories oldest -> newest; the first sighting
    wins, so fixed_in must be 16.7.15 (the earliest), not 17.1."""
    index_html = (APPLE_FIXTURE / "index.html").read_text()
    advisory_dir = APPLE_FIXTURE

    def fetch(version, url, adv_id):
        return (advisory_dir / f"{adv_id}.html").read_text()

    fixed = build_fix_map(index_html, fetch)
    assert fixed["CVE-2026-99910"] == "16.7.15"   # earliest wins
    assert fixed["CVE-2026-99911"] == "16.7.15"
    assert fixed["CVE-2026-99912"] == "17.1"


# ---------------------------------------------------------------------------
# witness (offline)
# ---------------------------------------------------------------------------

def test_witness_offline_overrides_and_skips_absent():
    w = AppleAdvisoryWitness(live=False)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host",
        "os_version": "17.1",
        "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99910", "CVE-2026-99912", "CVE-2026-99999"],
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    # 99999 is not in Apple's feed -> no verdict (NVD would stand in the engine)
    assert sorted(by_key) == ["CVE-2026-99910", "CVE-2026-99912"]
    # 99910 fixed in 16.7.15, device on 17.1 (>=) -> patched
    assert by_key["CVE-2026-99910"].status == "patched"
    assert by_key["CVE-2026-99910"].fixed_in == "16.7.15"
    # 99912 fixed in 17.1, device on 17.1 (>=) -> patched
    assert by_key["CVE-2026-99912"].status == "patched"
    assert by_key["CVE-2026-99912"].fixed_in == "17.1"
    for v in result.verdicts:
        assert v.provenance.witness == "apple_advisory"
        assert v.provenance.raw_ref == "https://support.apple.com/en-us/100100"


def test_witness_below_fix_is_unpatched():
    w = AppleAdvisoryWitness(live=False)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host",
        "os_version": "16.7",   # below the 17.1 fix
        "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99912"],
    }
    result = w.assess(device, pol)
    assert len(result.verdicts) == 1
    assert result.verdicts[0].status == "unpatched"
    assert result.verdicts[0].fixed_in == "17.1"
    assert result.verdicts[0].severity == "high"


def test_witness_macos_product_path():
    w = AppleAdvisoryWitness(live=False)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "mac-host",
        "os_version": "26.5",
        "apple_product": "macos",
        "cve_candidates": ["CVE-2026-99920"],
    }
    result = w.assess(device, pol)
    assert len(result.verdicts) == 1
    assert result.verdicts[0].status == "patched"
    assert result.verdicts[0].fixed_in == "26.5"
    assert "macOS" in result.verdicts[0].detail


def test_witness_ipados_shares_ios_advisory_rows():
    """iPadOS shares the joint iOS/iPadOS advisory rows, so the ipados product
    slug resolves CVEs from the same advisories as iphone_os."""
    w = AppleAdvisoryWitness(live=False)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "ipad-host",
        "os_version": "17.1",
        "apple_product": "ipados",
        "cve_candidates": ["CVE-2026-99910"],
    }
    result = w.assess(device, pol)
    assert len(result.verdicts) == 1
    assert result.verdicts[0].status == "patched"
    assert "iPadOS" in result.verdicts[0].detail


def test_witness_no_input_is_honest_noop():
    """A non-Apple host (no candidate set / product / version) gives the witness
    nothing to say. It returns ZERO verdicts (complete) so the engine keeps NVD's
    verdicts and the loud-degradation rule is unaffected — never a crash, never
    'clean'."""
    w = AppleAdvisoryWitness(live=False)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    # no apple_* fields and no cve_candidates
    device = {"id": "linux-host"}
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no apple advisory input" in result.reason


def test_witness_unknown_product_is_honest_noop():
    """An apple_product slug not in {iphone_os, ipados, macos} is a no-op, not a
    crash."""
    w = AppleAdvisoryWitness(live=False)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "watch-host",
        "os_version": "10.4",
        "apple_product": "watchos",   # not supported by this witness
        "cve_candidates": ["CVE-2026-99910"],
    }
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no apple advisory input" in result.reason


def test_witness_filters_non_cve_candidate_ids():
    """GHSA/PYSEC ids in the candidate set (from other matchers) have no Apple
    advisory page; they are filtered out, not fetched/decided."""
    w = AppleAdvisoryWitness(live=False)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host",
        "os_version": "17.1",
        "apple_product": "iphone_os",
        "cve_candidates": ["GHSA-aaaa-aaaa", "PYSEC-0000-0000", "CVE-2026-99910"],
    }
    result = w.assess(device, pol)
    assert [v.key for v in result.verdicts] == ["CVE-2026-99910"]


# ---------------------------------------------------------------------------
# engine: vendor overrides another witness by policy order (the actual point)
# ---------------------------------------------------------------------------

def test_apple_overrides_stub_on_shared_cve_key():
    """The stub NVD-like witness says CVE-2026-99910 is unpatched (thin Apple
    coverage). With apple_advisory registered at order 5 < stub's 10, the engine
    runs apple LAST and it wins on the shared CVE key — the committed verdict
    carries witness=apple_advisory and status=patched. Proven at the per-verdict
    row level via store.verdicts_for_device_axis."""
    reg = WitnessRegistry()
    reg.register(_StubNvdLikeWitness(cve="CVE-2026-99910"))   # order 10
    reg.register(AppleAdvisoryWitness(live=False))            # order 5 -> wins
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    conn = store.connect(":memory:")
    device = {
        "id": "iphone-host",
        "os_version": "17.1",
        "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99910"],
    }
    engine.assess(device, reg, pol, conn=conn,
                  now="2026-08-02T00:00:00+00:00")
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "iphone-host", "vulnerability")}
    # the shared CVE now rests on apple_advisory, patched (overrides the stub)
    assert rows["CVE-2026-99910"]["witness"] == "apple_advisory"
    assert rows["CVE-2026-99910"]["status"] == "patched"
    assert rows["CVE-2026-99910"]["fixed_in"] == "16.7.15"


def test_apple_no_input_leaves_stub_verdict_unchanged():
    """A device with no Apple input -> the apple witness no-ops, so the stub's
    unpatched verdict stands untouched (the override must NOT fire when Apple
    has nothing to say). Guards against accidental over-clearing."""
    reg = WitnessRegistry()
    reg.register(_StubNvdLikeWitness(cve="CVE-2026-99910"))
    reg.register(AppleAdvisoryWitness(live=False))
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    conn = store.connect(":memory:")
    device = {
        "id": "iphone-host",
        # no apple_product / no cve_candidates -> apple no-ops
        "os_version": "17.1",
    }
    engine.assess(device, reg, pol, conn=conn,
                  now="2026-08-02T00:00:00+00:00")
    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "iphone-host", "vulnerability")}
    assert rows["CVE-2026-99910"]["witness"] == "stub_nvd_like"
    assert rows["CVE-2026-99910"]["status"] == "unpatched"


# ---------------------------------------------------------------------------
# live fetch path (mocked curl)
# ---------------------------------------------------------------------------

def _load_live_fixtures() -> dict:
    """Pre-load the fixture HTML the live path would fetch from the network."""
    index_html = (APPLE_FIXTURE / "index.html").read_text()
    advisories = {
        "HT111111": (APPLE_FIXTURE / "HT111111.html").read_text(),
        "HT222222": (APPLE_FIXTURE / "HT222222.html").read_text(),
        "HT333333": (APPLE_FIXTURE / "HT333333.html").read_text(),
    }
    return index_html, advisories


def test_witness_live_fetch_mocked(monkeypatch):
    """The live path parses HTML returned by curl_get (which yields
    parsed_json=None for non-JSON bodies, with the body in slot 3). The index
    plus each advisory is served from the in-memory fixture set."""
    index_html, advisories = _load_live_fixtures()
    seen: list[str] = []

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        seen.append(url)
        if "100100" in url:
            return None, 200, index_html
        adv_id = url.rstrip("/").rsplit("/", 1)[-1]
        return None, 200, advisories[adv_id]   # non-JSON -> data None, body in slot 3

    monkeypatch.setattr("posture.sources.apple_advisory.curl_get", fake_curl_get)
    w = AppleAdvisoryWitness(live=True)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host",
        "os_version": "17.1",
        "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99910", "CVE-2026-99912"],
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["CVE-2026-99910"].status == "patched"
    assert by_key["CVE-2026-99912"].status == "patched"
    # the index + two advisories were fetched over curl
    assert any("100100" in u for u in seen)
    assert any("HT111111" in u for u in seen)
    assert any("HT222222" in u for u in seen)


def test_witness_live_fetch_failure_is_absent_not_break(monkeypatch):
    """A failed/absent fetch (timeout / non-200) is best-effort: complete=True,
    zero verdicts (NVD stands). It must NOT mark the fetch incomplete and never
    break the engine (no-wipe rule). Mirrors the donor's `return []` on failure.
    """

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        return None, 0, ""   # timeout / no body

    monkeypatch.setattr("posture.sources.apple_advisory.curl_get", fake_curl_get)
    w = AppleAdvisoryWitness(live=True)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host",
        "os_version": "17.1",
        "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99910"],
    }
    result = w.assess(device, pol)
    assert result.verdicts == []
    assert result.complete is True   # absent, not incomplete
    assert "failed/absent" in result.reason


def test_witness_live_advisory_404_skipped_index_ok(monkeypatch):
    """Index ok but an advisory fetch 404s -> that advisory is skipped (best-
    effort), and the CVEs only it would have covered get no Apple verdict (NVD
    stands). CVEs covered by the still-ok advisory resolve normally."""
    index_html, advisories = _load_live_fixtures()

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        if "100100" in url:
            return None, 200, index_html
        adv_id = url.rstrip("/").rsplit("/", 1)[-1]
        if adv_id == "HT222222":
            return None, 404, "<html>not found</html>"   # 17.1 advisory absent
        return None, 200, advisories[adv_id]

    monkeypatch.setattr("posture.sources.apple_advisory.curl_get", fake_curl_get)
    w = AppleAdvisoryWitness(live=True)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host",
        "os_version": "17.1",
        "apple_product": "iphone_os",
        # 99910 is in BOTH advisories (earliest 16.7.15, still ok) -> patched
        # 99912 is ONLY in the 404'd 17.1 advisory -> no Apple verdict (NVD stands)
        "cve_candidates": ["CVE-2026-99910", "CVE-2026-99912"],
    }
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert "CVE-2026-99910" in by_key
    assert by_key["CVE-2026-99910"].status == "patched"
    assert by_key["CVE-2026-99910"].fixed_in == "16.7.15"
    assert "CVE-2026-99912" not in by_key   # only-fixed-in-17.1 -> skipped