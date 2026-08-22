"""Catalog-backed distro-assess tests — the release condition that retires the
live-curl Debian/Ubuntu tracker path at assess time.

``DebianTrackerObserver`` and ``UbuntuTrackerObserver`` read the imported
``debian_fixes`` / ``ubuntu_fixes`` spine overlays (injected by the territory
pre-pass as ``device["debian_fixes"]`` / ``device["ubuntu_fixes"]``) and decide
verdicts with NO network and NO fixture file, reusing the SAME ``_decide`` logic
as a live pull.

The load-bearing test is the PARITY property: for an identical CVE, the catalog
path and the fixture/live path emit byte-identical verdicts (status, fixed_in,
severity, detail, key). The overlay rows are built by the ingest row-builders
(``bulk_extract`` for Debian, ``extract_release`` for Ubuntu) — the exact
functions CI ingestion uses — so this pins the real round-trip, not a
hand-rolled shape.

The complete-absent property (mirror of ``test_catalog_assess.py``'s
empty-head test): a DB that HAS overlay rows but for a DIFFERENT release than
the device's yields an EMPTY injected overlay -> ``_decide`` returns None for
every candidate -> NVD stands, and the observer does NOT fall back to the
bundled fixture (reason=="catalog", zero verdicts). The bundled demo CVEs must
never leak into a real client's verdicts.

Note on the one genuine catalog/live asymmetry (Ubuntu ``needed``): the live
HTML parser ``_parse_status`` does not recognize the rendered text ``Needed``
(only ``Vulnerable`` / ``Needs triage`` / ``DNE`` / ``Ignored`` / ``Not
affected`` / ``Fixed``), so the live path returns NO verdict for a ``needed``
row. The catalog path normalizes the RAW bulk-JSON status word ``needed`` ->
``("needed", None)`` -> ``unpatched(high)``, so the catalog path is STRICTER
than the live path for the same CVE. This is the NEW signal the bulk-JSON
overlay carries that the HTML scrape loses; it is covered by a dedicated
catalog-path assertion (``test_ubuntu_catalog_needed_is_unpatched``) rather
than the byte-identical parity test.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from posture import store
from posture.policy import Policy, default_policy_path
from posture.sources.debian_tracker import (
    DebianTrackerObserver,
    bulk_extract,
)
from posture.sources.ubuntu_tracker import (
    UbuntuTrackerObserver,
    _normalize_overlay_status,
    found_from_catalog,
    parse_cve_page,
)
from posture.sources.ubuntu_ingest import extract_release
from posture.cli import _inject_catalog_overlays

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
DEBIAN_FIXTURE = FIXTURE_DIR / "debian_tracker" / "data.json"


# ---------------------------------------------------------------------------
# fixtures + helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def _policy():
    return Policy.from_file(default_policy_path())


def _debian_bulk_from_fixture() -> dict:
    """The bundled Debian bulk-tracker fixture, read as the bulk-data dict the
    observer's ``_decide`` consumes (and the ingest ``bulk_extract`` slices)."""
    return json.loads(DEBIAN_FIXTURE.read_text())


def _seed_debian(conn, bulk: dict, release: str, packages: list[str]) -> None:
    """Seed ``debian_fixes`` overlay rows the CI way: slice the bulk-data dict
    via ``bulk_extract`` (the ingest row-builder) and full-refresh each
    (release, package) sheet via ``store.replace_debian_fixes``."""
    for pkg in packages:
        sheet = bulk_extract(bulk, release, [pkg])
        rows = [{"cve_id": cid, "status": st, "fixed_in": fi}
                for cid, (st, fi) in sheet.items()]
        store.replace_debian_fixes(conn, release, pkg, rows, fetched_at="2026-08-22")
    conn.commit()


def _ubuntu_bulk_payload() -> dict:
    """A synthetic Ubuntu bulk CVE-JSON document (the shape ``ubuntu_ingest``
    fetches via ``?package=``). Covers every actionable + no-verdict raw status
    word for the noble release of the ``linux-nvidia-6.17`` source package."""
    def cve(cid, status, description=""):
        return {"id": cid, "priority": "medium", "packages": [
            {"name": "linux-nvidia-6.17", "source": f"https://ubuntu.com/security/{cid}",
             "statuses": [{"release_codename": "noble", "status": status,
                            "description": description, "component": "main",
                            "pocket": "security"}]}]}
    return {"cves": [
        cve("CVE-2026-90001", "released", "6.17.9"),       # kernel>=fix -> patched
        cve("CVE-2026-90002", "not-affected", ""),         # -> patched (not affected)
        cve("CVE-2026-90003", "needs-triage", ""),          # -> no verdict
        cve("CVE-2026-90004", "DNE", ""),                   # -> no verdict
        cve("CVE-2026-90005", "ignored", ""),               # -> no verdict
        cve("CVE-2026-90006", "released", "6.20.0-1"),     # kernel<fix -> unpatched high
        cve("CVE-2026-90007", "needed", ""),               # catalog -> unpatched high (live asymmetry)
    ], "offset": 0, "limit": 500, "total_results": 7}


def _seed_ubuntu(conn, cves: list, release: str, packages: list[str]) -> None:
    """Seed ``ubuntu_fixes`` overlay rows the CI way: slice the bulk CVE-JSON
    via ``extract_release`` (the ingest row-builder) and full-refresh each
    (release, package) sheet via ``store.replace_ubuntu_fixes``."""
    for pkg in packages:
        sheet = extract_release(cves, release, pkg)
        rows = [{"cve_id": cid, "status": st, "fixed_in": fi}
                for cid, (st, fi) in sheet.items()]
        store.replace_ubuntu_fixes(conn, release, pkg, rows, fetched_at="2026-08-22")
    conn.commit()


def _html_page(pkg: str, release: str, status_text: str) -> str:
    """A minimal Ubuntu tracker HTML page carrying ONE package row for ONE
    release, exactly the bits ``parse_cve_page`` reads (mirror of the bundled
    ``CVE-2026-99901.html`` fixture shape)."""
    return f"""<html><body>
<table class="cve-table">
  <thead><tr><th>Package</th><th>Release</th><th>Status</th></tr></thead>
  <tbody>
    <tr>
      <th rowspan="1">{pkg}</th>
      <td>24.04 LTS <span>{release}</span></td>
      <td class="cve-td-status">{status_text}</td>
    </tr>
  </tbody>
</table>
</body></html>"""


# Map a raw overlay status word to the HTML status-cell text the live tracker
# renders for the same row (so the live ``parse_cve_page`` produces the SAME
# ``found`` token as ``found_from_catalog`` for the agreeing statuses).
_LIVE_TEXT = {
    "released": "Fixed {fixed_in}",      # ("fixed", ver) on both paths
    "not-affected": "Not affected",       # ("not_affected", None) on both
    "needs-triage": "Needs triage",       # ("needs", None) on both -> no verdict
    "DNE": "DNE",                         # ("dne", None) on both -> no verdict
    "ignored": "Ignored",                  # ("ignored", None) on both -> no verdict
    # NOTE: "needed" intentionally ABSENT — live HTML "Needed" -> (None, None),
    # diverges from the catalog ("needed" -> ("needed", None) -> unpatched).
}


def _debian_device(cves, release, packages):
    return {"id": "dev", "name": "dev", "os": "linux",
            "cve_candidates": list(cves),
            "debian_release": release, "debian_packages": list(packages)}


def _ubuntu_device(cves, release, packages, kernel="6.18"):
    return {"id": "dev", "name": "dev", "os": "linux",
            "os_version": kernel, "patch_level": kernel,
            "cve_candidates": list(cves),
            "ubuntu_release": release, "ubuntu_packages": list(packages)}


def _verdict_tuple(v):
    return (v.status, v.fixed_in, v.severity, v.detail, v.key)


# ---------------------------------------------------------------------------
# Debian: parity (catalog == fixture, byte-identical)
# ---------------------------------------------------------------------------

def test_debian_catalog_assess_matches_fixture_verdict_for_verdict(conn):
    """THE Debian parity test: the catalog path (overlay injected from rows
    built by ``bulk_extract``) and the fixture path (bundled ``data.json`` read
    with NO overlay) emit identical verdicts for every actionable status.
    Debian statuses: resolved+real version -> patched(fixed_in);
    resolved+"0" -> patched(not-affected); open -> unpatched(high);
    undetermined -> no verdict (NVD stands)."""
    bulk = _debian_bulk_from_fixture()
    release, packages = "trixie", ["linux"]
    cves = ["CVE-2026-99901", "CVE-2026-99903", "CVE-2026-99902", "CVE-2026-99907"]
    _seed_debian(conn, bulk, release, packages)

    # catalog path: inject the overlay, then assess (NO network, NO fixture file)
    device_cat = _debian_device(cves, release, packages)
    _inject_catalog_overlays(device_cat, conn)
    assert "debian_fixes" in device_cat  # the territory pre-pass injected it
    pol = _policy()
    cat = DebianTrackerObserver(live=False).assess(device_cat, pol)

    # fixture path: a device with NO overlay -> observer falls back to the
    # bundled fixture (the DB is irrelevant to the observer; only the injector
    # reads it, and we do not call it for this device).
    device_fix = _debian_device(cves, release, packages)
    fix = DebianTrackerObserver(live=False).assess(device_fix, pol)

    assert cat.complete is True and fix.complete is True
    assert cat.reason == "catalog"
    assert fix.reason == "fixture"
    by_cat = {v.key: v for v in cat.verdicts}
    by_fix = {v.key: v for v in fix.verdicts}
    assert set(by_cat) == set(by_fix)
    for key in by_fix:
        assert _verdict_tuple(by_cat[key]) == _verdict_tuple(by_fix[key]), key
    # spot-check the three actionable verdicts (the 4th CVE is undetermined -> none)
    assert by_cat["CVE-2026-99901"].status == "patched"
    assert by_cat["CVE-2026-99901"].fixed_in == "6.18.5-1"
    assert by_cat["CVE-2026-99903"].status == "patched"
    assert by_cat["CVE-2026-99903"].fixed_in is None  # "0" -> not affected
    assert by_cat["CVE-2026-99902"].status == "unpatched"
    assert by_cat["CVE-2026-99902"].severity == "high"
    assert "CVE-2026-99907" not in by_cat  # undetermined -> NVD stands


# ---------------------------------------------------------------------------
# Ubuntu: parity (catalog == live, byte-identical for the agreeing statuses)
# ---------------------------------------------------------------------------

def test_ubuntu_catalog_assess_matches_live_assess_verdict_for_verdict(conn, monkeypatch):
    """THE Ubuntu parity test: the catalog path (overlay injected from rows
    built by ``extract_release``) and the live path (HTML via a monkeypatched
    ``curl_get``) emit byte-identical verdicts for every status where the two
    paths agree on the ``found`` token. Covers: released+kernel>=fix -> patched;
    released+kernel<fix -> unpatched(high); not-affected -> patched;
    needs-triage / DNE / ignored -> no verdict (NVD stands). The ``needed``
    divergence is covered by its own test below."""
    bulk = _ubuntu_bulk_payload()
    release, packages = "noble", ["linux-nvidia-6.17"]
    # every status EXCEPT needed (the catalog/live asymmetry)
    cves = ["CVE-2026-90001", "CVE-2026-90002", "CVE-2026-90003",
            "CVE-2026-90004", "CVE-2026-90005", "CVE-2026-90006"]
    _seed_ubuntu(conn, bulk["cves"], release, packages)

    # catalog path: inject the overlay, assess with live=False (NO network)
    device_cat = _ubuntu_device(cves, release, packages, kernel="6.18")
    _inject_catalog_overlays(device_cat, conn)
    assert "ubuntu_fixes" in device_cat
    pol = _policy()
    cat = UbuntuTrackerObserver(live=False).assess(device_cat, pol)

    # live path: a device with NO overlay + live=True, monkeypatched curl_get
    # returns an HTML page per CVE that parse_cve_page turns into the SAME
    # ``found`` as found_from_catalog. The overlay rows and the HTML both derive
    # from the same synthetic bulk payload -> the verdicts must match.
    by_cve = {c["id"]: c for c in bulk["cves"]}

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        # url = https://ubuntu.com/security/<CVE>
        cid = url.rsplit("/", 1)[-1]
        cve = by_cve.get(cid)
        assert cve is not None, f"unexpected live fetch for {cid}"
        st = cve["packages"][0]["statuses"][0]
        status, fixed_in = st["status"], st["description"] or None
        text = _LIVE_TEXT[status]
        text = text.format(fixed_in=fixed_in) if "{fixed_in}" in text else text
        return None, 200, _html_page(packages[0], release, text)

    monkeypatch.setattr("posture.sources.ubuntu_tracker.curl_get", fake_curl_get)
    device_live = _ubuntu_device(cves, release, packages, kernel="6.18")
    live = UbuntuTrackerObserver(live=True).assess(device_live, pol)

    assert cat.complete is True and live.complete is True
    assert cat.reason == "catalog"
    assert live.reason == "live"
    by_cat = {v.key: v for v in cat.verdicts}
    by_live = {v.key: v for v in live.verdicts}
    assert set(by_cat) == set(by_live)
    for key in by_live:
        assert _verdict_tuple(by_cat[key]) == _verdict_tuple(by_live[key]), key
    # spot-check: released+kernel>=fix -> patched; released+kernel<fix -> unpatched
    assert by_cat["CVE-2026-90001"].status == "patched"
    assert by_cat["CVE-2026-90001"].fixed_in == "6.17.9"
    assert by_cat["CVE-2026-90002"].status == "patched"
    assert by_cat["CVE-2026-90002"].fixed_in is None  # not affected
    assert by_cat["CVE-2026-90006"].status == "unpatched"
    assert by_cat["CVE-2026-90006"].severity == "high"
    # no-verdict statuses -> absent in both
    for cid in ("CVE-2026-90003", "CVE-2026-90004", "CVE-2026-90005"):
        assert cid not in by_cat
        assert cid not in by_live


def test_ubuntu_catalog_needed_is_unpatched(conn):
    """The catalog/live asymmetry: the RAW overlay word ``needed`` normalizes to
    ``("needed", None)`` -> ``_decide`` -> ``unpatched(high)``. The live HTML
    path's ``_parse_status`` does not recognize the rendered text ``Needed``
    (only ``Vulnerable``), so the live path returns NO verdict for the same
    CVE. This pins the catalog path's STRICTER behavior — the NEW signal the
    bulk-JSON overlay carries that the HTML scrape loses."""
    bulk = _ubuntu_bulk_payload()
    release, packages = "noble", ["linux-nvidia-6.17"]
    cves = ["CVE-2026-90007"]
    _seed_ubuntu(conn, bulk["cves"], release, packages)

    device = _ubuntu_device(cves, release, packages, kernel="6.18")
    _inject_catalog_overlays(device, conn)
    pol = _policy()
    cat = UbuntuTrackerObserver(live=False).assess(device, pol)
    assert cat.reason == "catalog"
    assert len(cat.verdicts) == 1
    v = cat.verdicts[0]
    assert v.key == "CVE-2026-90007"
    assert v.status == "unpatched"
    assert v.severity == "high"
    assert "needed" in v.detail


# ---------------------------------------------------------------------------
# catalog precedence over fixture
# ---------------------------------------------------------------------------

def test_debian_catalog_takes_precedence_over_fixture_when_present(conn):
    """When the overlay is present AND would differ from the bundled fixture,
    the catalog wins (reason=="catalog"). Seed an overlay where CVE-2026-99901
    is ``open`` (the fixture says ``resolved``) -> the catalog path emits
    unpatched, not the fixture's patched."""
    # synthetic bulk payload: same CVE as the fixture, DIFFERENT status
    bulk = {"linux": {"CVE-2026-99901": {"releases": {
        "trixie": {"status": "open", "fixed_version": ""}}}}}
    release, packages = "trixie", ["linux"]
    _seed_debian(conn, bulk, release, packages)

    device = _debian_device(["CVE-2026-99901"], release, packages)
    _inject_catalog_overlays(device, conn)
    pol = _policy()
    cat = DebianTrackerObserver(live=False).assess(device, pol)
    fix = DebianTrackerObserver(live=False).assess(
        _debian_device(["CVE-2026-99901"], release, packages), pol)
    assert cat.reason == "catalog"
    assert cat.verdicts[0].status == "unpatched"   # the overlay's "open"
    assert fix.verdicts[0].status == "patched"      # the fixture's "resolved"
    assert cat.verdicts[0].key == "CVE-2026-99901"


def test_ubuntu_catalog_takes_precedence_over_fixture_when_present(conn):
    """When the overlay is present AND would differ from the bundled fixture,
    the catalog wins (reason=="catalog"). Seed an overlay where CVE-2026-99901
    is ``needed`` (the fixture says ``Fixed 6.17.9``) -> the catalog path emits
    unpatched, not the fixture's patched."""
    bulk = {"cves": [{"id": "CVE-2026-99901", "packages": [
        {"name": "linux-nvidia-6.17", "source": "", "statuses": [
            {"release_codename": "noble", "status": "needed",
             "description": "", "component": "main", "pocket": "security"}]}]}],
        "total_results": 1}
    release, packages = "noble", ["linux-nvidia-6.17"]
    _seed_ubuntu(conn, bulk["cves"], release, packages)

    device = _ubuntu_device(["CVE-2026-99901"], release, packages, kernel="6.18")
    _inject_catalog_overlays(device, conn)
    pol = _policy()
    cat = UbuntuTrackerObserver(live=False).assess(device, pol)
    assert cat.reason == "catalog"
    assert cat.verdicts[0].status == "unpatched"   # the overlay's "needed"
    assert cat.verdicts[0].key == "CVE-2026-99901"


# ---------------------------------------------------------------------------
# live wins over catalog
# ---------------------------------------------------------------------------

def test_debian_live_wins_over_catalog(conn, monkeypatch):
    """An explicit ``live=True`` pull wins even when a catalog is injected —
    the operator asked for the network. Mocked curl so no real network; asserts
    the catalog is NOT consulted."""
    _seed_debian(conn, _debian_bulk_from_fixture(), "trixie", ["linux"])
    calls = []

    live_bulk = {"linux": {"CVE-2026-99901": {"releases": {
        "trixie": {"status": "open", "fixed_version": ""}}}}}

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        calls.append(url)
        return live_bulk, 200, json.dumps(live_bulk)

    monkeypatch.setattr("posture.sources.debian_tracker.curl_get", fake_curl_get)
    device = _debian_device(["CVE-2026-99901"], "trixie", ["linux"])
    _inject_catalog_overlays(device, conn)
    assert "debian_fixes" in device  # catalog IS present, but live must win
    pol = _policy()
    result = DebianTrackerObserver(live=True).assess(device, pol)
    assert result.complete is True
    assert result.reason == "live"
    assert result.verdicts[0].status == "unpatched"  # the LIVE "open", not the catalog's "resolved"
    assert calls, "live curl_get was called (catalog was NOT used)"


def test_ubuntu_live_wins_over_catalog(conn, monkeypatch):
    """An explicit ``live=True`` pull wins even when a catalog is injected —
    the operator asked for the network. Mocked curl so no real network; asserts
    the catalog is NOT consulted (use_catalog is False on the live branch)."""
    _seed_ubuntu(conn, _ubuntu_bulk_payload()["cves"], "noble", ["linux-nvidia-6.17"])
    calls = []

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        calls.append(url)
        cid = url.rsplit("/", 1)[-1]
        # live says "Not affected" for CVE-2026-90001 (catalog says released -> patched)
        text = "Not affected" if cid == "CVE-2026-90001" else "Fixed 6.17.9"
        return None, 200, _html_page("linux-nvidia-6.17", "noble", text)

    monkeypatch.setattr("posture.sources.ubuntu_tracker.curl_get", fake_curl_get)
    device = _ubuntu_device(["CVE-2026-90001"], "noble", ["linux-nvidia-6.17"], kernel="6.18")
    _inject_catalog_overlays(device, conn)
    assert "ubuntu_fixes" in device  # catalog IS present, but live must win
    pol = _policy()
    result = UbuntuTrackerObserver(live=True).assess(device, pol)
    assert result.complete is True
    assert result.reason == "live"
    # live said "Not affected" -> patched with fixed_in=None; catalog said released -> patched with 6.17.9
    assert result.verdicts[0].status == "patched"
    assert result.verdicts[0].fixed_in is None  # the LIVE verdict, not the catalog's 6.17.9
    assert calls, "live curl_get was called (catalog was NOT used)"


# ---------------------------------------------------------------------------
# fresh-DB fixture fallback (preserves posture demo)
# ---------------------------------------------------------------------------

def test_debian_fresh_db_falls_back_to_fixture(conn):
    """A fresh/demo DB (no debian_fixes rows) -> ``_inject_*`` leaves
    ``debian_fixes`` ABSENT -> the observer falls back to the bundled fixture
    (reason=="fixture"); the ``posture demo`` path is preserved."""
    device = _debian_device(["CVE-2026-99901"], "trixie", ["linux"])
    _inject_catalog_overlays(device, conn)
    assert "debian_fixes" not in device
    pol = _policy()
    result = DebianTrackerObserver(live=False).assess(device, pol)
    assert result.reason == "fixture"
    # the fixture's CVE-2026-99901 (trixie resolved 6.18.5-1) -> patched
    assert any(v.key == "CVE-2026-99901" and v.status == "patched"
               for v in result.verdicts)


def test_ubuntu_fresh_db_falls_back_to_fixture(conn):
    """A fresh/demo DB (no ubuntu_fixes rows) -> ``_inject_*`` leaves
    ``ubuntu_fixes`` ABSENT -> the observer falls back to the bundled fixture
    (reason=="fixture"); the ``posture demo`` path is preserved."""
    device = _ubuntu_device(["CVE-2026-99901"], "noble", ["linux-nvidia-6.17"], kernel="6.18")
    _inject_catalog_overlays(device, conn)
    assert "ubuntu_fixes" not in device
    pol = _policy()
    result = UbuntuTrackerObserver(live=False).assess(device, pol)
    assert result.reason == "fixture"
    # the fixture's CVE-2026-99901 (noble Fixed 6.17.9, kernel 6.18>=fix) -> patched
    assert any(v.key == "CVE-2026-99901" and v.status == "patched"
               for v in result.verdicts)


# ---------------------------------------------------------------------------
# no-clobber
# ---------------------------------------------------------------------------

def test_debian_injector_does_not_clobber_operator_input(conn):
    """A device that pre-supplies ``debian_fixes`` (operator/hermetic override)
    is left untouched by the injector, even when the DB carries overlay rows."""
    _seed_debian(conn, _debian_bulk_from_fixture(), "trixie", ["linux"])
    preset = {"linux": {"CVE-X": {"releases": {"trixie": {
        "status": "open", "fixed_version": ""}}}}}
    device = _debian_device(["CVE-X"], "trixie", ["linux"])
    device["debian_fixes"] = preset
    _inject_catalog_overlays(device, conn)
    assert device["debian_fixes"] is preset


def test_ubuntu_injector_does_not_clobber_operator_input(conn):
    """A device that pre-supplies ``ubuntu_fixes`` (operator/hermetic override)
    is left untouched by the injector, even when the DB carries overlay rows."""
    _seed_ubuntu(conn, _ubuntu_bulk_payload()["cves"], "noble", ["linux-nvidia-6.17"])
    preset = {"CVE-X": {"linux-nvidia-6.17": ("needed", None)}}
    device = _ubuntu_device(["CVE-X"], "noble", ["linux-nvidia-6.17"], kernel="6.18")
    device["ubuntu_fixes"] = preset
    _inject_catalog_overlays(device, conn)
    assert device["ubuntu_fixes"] is preset


# ---------------------------------------------------------------------------
# uncovered-release complete-absent (NOT a fixture leak)
# ---------------------------------------------------------------------------

def test_debian_uncovered_release_is_complete_absent_not_fixture_leak(conn):
    """THE complete-absent property: the DB HAS debian_fixes rows (so the guard
    passes and the overlay IS injected) but for a DIFFERENT release than the
    device's. The injected overlay is empty for the device's release/package
    -> ``_decide`` returns None for every candidate -> NVD stands, and the
    observer does NOT fall back to the bundled fixture (reason=="catalog",
    zero verdicts). The bundled demo CVEs must never surface as a real
    client's verdicts for a release the spine simply doesn't list."""
    # seed rows for bookworm; the device runs trixie
    _seed_debian(conn, _debian_bulk_from_fixture(), "bookworm", ["linux"])
    # confirm the DB does carry rows (the guard will pass)
    assert conn.execute("SELECT 1 FROM debian_fixes LIMIT 1").fetchone()

    device = _debian_device(["CVE-2026-99901"], "trixie", ["linux"])
    _inject_catalog_overlays(device, conn)
    # overlay IS injected (guard passed) but empty for trixie
    assert "debian_fixes" in device
    assert device["debian_fixes"] == {}  # no rows for the device's release
    pol = _policy()
    result = DebianTrackerObserver(live=False).assess(device, pol)
    assert result.complete is True
    assert result.reason == "catalog"  # NOT "fixture" — no leak
    assert result.verdicts == []        # complete-absent, NVD stands


def test_ubuntu_uncovered_release_is_complete_absent_not_fixture_leak(conn):
    """THE complete-absent property (Ubuntu): the DB HAS ubuntu_fixes rows (so
    the guard passes and the overlay IS injected) but for a DIFFERENT release
    than the device's. The injected overlay is empty for the device's
    release/package -> ``_decide`` returns None for every candidate -> NVD
    stands, and the observer does NOT fall back to the bundled fixture
    (reason=="catalog", zero verdicts)."""
    # seed rows for jammy; the device runs noble
    bulk = {"cves": [{"id": "CVE-2026-99901", "packages": [
        {"name": "linux-nvidia-6.17", "source": "", "statuses": [
            {"release_codename": "jammy", "status": "released",
             "description": "5.15.0-1011", "component": "main", "pocket": "security"}]}]}],
        "total_results": 1}
    _seed_ubuntu(conn, bulk["cves"], "jammy", ["linux-nvidia-6.17"])
    assert conn.execute("SELECT 1 FROM ubuntu_fixes LIMIT 1").fetchone()

    device = _ubuntu_device(["CVE-2026-99901"], "noble", ["linux-nvidia-6.17"], kernel="6.18")
    _inject_catalog_overlays(device, conn)
    assert "ubuntu_fixes" in device
    assert device["ubuntu_fixes"] == {}  # no rows for the device's release
    pol = _policy()
    result = UbuntuTrackerObserver(live=False).assess(device, pol)
    assert result.complete is True
    assert result.reason == "catalog"  # NOT "fixture" — no leak
    assert result.verdicts == []        # complete-absent, NVD stands


# ---------------------------------------------------------------------------
# unit tests: the ubuntu overlay normalizer
# ---------------------------------------------------------------------------

def test_normalize_overlay_status_maps_each_raw_word():
    """Each raw ``ubuntu_fixes`` overlay status word -> the ``_decide`` token
    the live ``_parse_status`` would produce for the matching HTML text. Words
    with no actionable mapping (pending / deferred / unknown) -> ``(None, None)``
    -> NVD stands, the same outcome as an unrecognized live status cell."""
    cases = [
        ("released", "6.17.9", ("fixed", "6.17.9")),
        ("released", None, ("fixed", None)),       # released with no version note
        ("not-affected", None, ("not_affected", None)),
        ("needed", None, ("needed", None)),
        ("needs-triage", None, ("needs", None)),
        ("DNE", None, ("dne", None)),
        ("ignored", None, ("ignored", None)),
        ("pending", None, (None, None)),           # no actionable mapping
        ("deferred", None, (None, None)),
        ("", None, (None, None)),                   # absent/blank
        (None, None, (None, None)),
        ("Released", "6.17.9", ("fixed", "6.17.9")),  # case-insensitive
    ]
    for status, fixed_in, expected in cases:
        assert _normalize_overlay_status(status, fixed_in) == expected, \
            f"{status!r}, {fixed_in!r} -> {_normalize_overlay_status(status, fixed_in)} (want {expected})"


def test_found_from_catalog_absent_cve_is_empty():
    """A CVE absent from the catalog -> ``{}`` (a COMPLETE-absent answer:
    ``_decide`` returns None -> NVD stands — no fallback to the demo fixture)."""
    assert found_from_catalog("CVE-2026-99999", {}) == {}
    assert found_from_catalog("CVE-2026-99999",
                              {"CVE-2026-99901": {"linux": ("released", "1.0")}}) == {}


def test_found_from_catalog_normalizes_each_package():
    """The per-CVE overlay block -> the ``{package: (normalized_status,
    fixed_in)}`` shape ``parse_cve_page`` returns, so ``_decide`` runs
    UNCHANGED on the catalog path."""
    catalog = {"CVE-2026-1": {
        "linux": ("released", "6.17.9"),
        "linux-nvidia-6.17": ("not-affected", ""),
    }}
    found = found_from_catalog("CVE-2026-1", catalog)
    assert found == {"linux": ("fixed", "6.17.9"),
                     "linux-nvidia-6.17": ("not_affected", None)}