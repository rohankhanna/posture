"""Tests for the Apple-advisory historical-recovery path — the port of the
donor's ``backfill()`` / ``discover_urls()`` / ``discover_historical_urls()``
mechanisms that recover pre-index CVEs (those
aged off Apple's rolling security-releases index 100100) from two sources:

  1. NVD reference URLs (``discover_urls_from_refs``) — a CVE's NVD refs link
     the Apple advisory that fixed it; each referenced advisory lists every CVE
     fixed in that version.
  2. the Wayback Machine's archived yearly snapshots of Apple's cumulative
     security-updates index (HT1222 + successor HT201222) — ``discover_historical_urls``
     -> ``parse_index_links`` enumerates the historical advisory article IDs,
     and ``backfill_fix_map`` live-fetches each, merging into the ``cve -> fixed_in``
     map with earliest-fix-version-wins.

These pin five things:
  1. the small parsers (``advisory_id_of`` / ``parse_index_links`` /
     ``discover_urls_from_refs``) map URLs faithfully, deduping locale variants
     and dropping self/non-article links;
  2. ``backfill_fix_map`` adds new pre-index CVEs, replaces an index sighting
     with a strictly-earlier historical sighting (earliest-fix-version-wins),
     skips already-covered / cross-product advisories, and is best-effort on
     fetch failure (never a hard fail);
  3. the Wayback CDX snapshot enumerator (``_ht1222_snapshot_urls``) parses the
     CDX JSON array and degrades to ``[]`` on any malformation/failure;
  4. ``discover_historical_urls`` unions advisory URLs across yearly snapshots
     of both index articles (HT1222 + HT201222), best-effort per snapshot;
  5. the observer, in ``live=True`` + ``history=True`` mode, recovers a pre-index
     CVE the live index alone misses (decides patched/unpatched instead of NVD's
     silent skip), while ``history=False`` (the default) stays byte-identical to
     the index-only path (no regression) and the earliest-wins merge replaces an
     index fix version with an earlier historical one.

All offline: live curl is monkeypatched; no real Apple / Wayback / NVD fetch;
NVD_API_KEY never touched. Fixtures under posture/fixtures/apple_advisory/.
"""
from pathlib import Path

import pytest

from posture.policy import Policy
from posture.sources.apple_advisory import (
    AppleAdvisoryObserver, advisory_id_of, backfill_fix_map,
    discover_historical_urls, discover_urls_from_refs, parse_index_links,
    _ht1222_snapshot_urls,
)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
APPLE = FIXTURE_DIR / "apple_advisory"
INDEX_HTML = (APPLE / "index.html").read_text()
SNAPSHOT_HTML = (APPLE / "ht1222_snapshot.html").read_text()
ADV = {a: (APPLE / f"{a}.html").read_text()
       for a in ("HT111111", "HT222222", "HT333333", "HT444444", "HT555555")}

_INLINE_POLICY_YAML = """
version: "2026-08-08.1"
dated: 2026-08-08
rationale: "test policy for apple_advisory historical recovery"
observers:
  apple_advisory:
    axes: [vulnerability]
    weight: high
    bias: false-safe
    order: 5
    conditions: []
"""


# ---------------------------------------------------------------------------
# small parsers
# ---------------------------------------------------------------------------

def test_advisory_id_of_extracts_upper_article_id():
    assert advisory_id_of("https://support.apple.com/en-us/HT444444") == "HT444444"
    assert advisory_id_of("https://support.apple.com/en-us/101682/") == "101682"
    assert advisory_id_of("https://support.apple.com/en-gb/HT1222") == "HT1222"


def test_parse_index_links_dedups_locale_drops_self_and_nonarticle():
    urls = parse_index_links(SNAPSHOT_HTML)
    # HT444444 appears once (en-gb locale variant normalized+deduped to en-us);
    # HT555555 present; HT111111 present (not dropped here — covered-adv-id skip
    # happens in backfill, not in the link enumeration); HT1222 self-link dropped;
    # the non-article "foo" link dropped.
    assert urls == [
        "https://support.apple.com/en-us/HT111111",
        "https://support.apple.com/en-us/HT444444",
        "https://support.apple.com/en-us/HT555555",
    ]


def test_discover_urls_from_refs_picks_apple_canonical_only():
    # Faithful to the donor: the locale path is preserved (Apple serves the same
    # content regardless of locale, and backfill dedups locale variants by
    # advisory_id via its covered set). Non-apple refs are dropped; the URL
    # fragment and trailing slash are stripped.
    refs = [
        "https://support.apple.com/en-us/HT444444",
        "https://support.apple.com/en-gb/HT444444#extra",   # locale kept; frag stripped
        "https://nvd.nist.gov/vuln/detail/CVE-2026-99920",    # non-apple, dropped
        "https://support.apple.com/en-us/HT555555/",
    ]
    assert discover_urls_from_refs(refs) == [
        "https://support.apple.com/en-gb/HT444444",
        "https://support.apple.com/en-us/HT444444",
        "https://support.apple.com/en-us/HT555555",
    ]
    assert discover_urls_from_refs(None) == []
    assert discover_urls_from_refs([]) == []


# ---------------------------------------------------------------------------
# backfill_fix_map
# ---------------------------------------------------------------------------

def _fetch(adv_html=ADV):
    """Advisory-page getter keyed by URL article id (offline fixtures)."""
    def f(url):
        return adv_html.get(advisory_id_of(url))
    return f


def test_backfill_adds_new_pre_index_cves():
    merged, stats = backfill_fix_map(
        ["https://support.apple.com/en-us/HT444444"], _fetch(), "iphone_os")
    # 99920 is fixed only in the pre-index 15.7.1 advisory -> added
    assert merged["CVE-2026-99920"] == "15.7.1"
    assert stats["cves_added"] >= 1
    assert stats["fetched"] == 1
    assert stats["advisories"] == 1
    assert stats["fetch_failed"] == 0


def test_backfill_earliest_wins_replaces_index_sighting():
    # The live index already recorded 99910 at 16.7.15; the pre-index advisory
    # re-mentions it at 15.7.1 (strictly earlier) -> REPLACE.
    base = {"CVE-2026-99910": "16.7.15"}
    merged, stats = backfill_fix_map(
        ["https://support.apple.com/en-us/HT444444"], _fetch(), "iphone_os",
        base=base)
    assert merged["CVE-2026-99910"] == "15.7.1"
    assert stats["cves_earlier"] == 1
    # 99910 was not "added" (it existed); 99920 was.
    assert merged["CVE-2026-99920"] == "15.7.1"


def test_backfill_does_not_replace_with_a_later_sighting():
    # If the historical advisory were LATER than the base, earliest-wins must
    # keep the existing (earlier) base entry. Synthesize a base earlier than
    # 15.7.1; backfill must NOT overwrite it.
    base = {"CVE-2026-99910": "15.0"}   # strictly earlier than 15.7.1
    merged, stats = backfill_fix_map(
        ["https://support.apple.com/en-us/HT444444"], _fetch(), "iphone_os",
        base=base)
    assert merged["CVE-2026-99910"] == "15.0"
    assert stats["cves_earlier"] == 0


def test_backfill_skips_covered_advisory_ids():
    # HT111111 already covered by the index pass -> skipped, never re-fetched.
    merged, stats = backfill_fix_map(
        ["https://support.apple.com/en-us/HT111111",
         "https://support.apple.com/en-us/HT444444"],
        _fetch(), "iphone_os", covered_adv_ids={"HT111111"})
    # 99911 (only in HT111111) must NOT appear — HT111111 was skipped
    assert "CVE-2026-99911" not in merged
    assert "CVE-2026-99920" in merged   # HT444444 was fetched
    assert stats["skipped_existing"] == 1
    assert stats["fetched"] == 1


def test_backfill_skips_cross_product_advisory():
    # HT555555 is a Safari advisory; for iphone_os parse_advisory_version is
    # None -> skipped, and its CVE-2026-99930 must never enter the iOS map.
    merged, stats = backfill_fix_map(
        ["https://support.apple.com/en-us/HT555555"], _fetch(), "iphone_os")
    assert "CVE-2026-99930" not in merged
    # cross-product skip happens after fetch, before the advisory count
    assert stats["fetched"] == 0
    assert stats["advisories"] == 0


def test_backfill_best_effort_on_fetch_failure():
    merged, stats = backfill_fix_map(
        ["https://support.apple.com/en-us/HT404404"], lambda u: None, "iphone_os",
        base={"CVE-2026-99910": "16.7.15"})
    # failed fetch leaves the base map intact; never a hard fail
    assert merged == {"CVE-2026-99910": "16.7.15"}
    assert stats["fetch_failed"] == 1
    assert stats["fetched"] == 0


def test_backfill_dedups_within_batch():
    url = "https://support.apple.com/en-us/HT444444"
    merged, stats = backfill_fix_map([url, url], _fetch(), "iphone_os")
    assert merged["CVE-2026-99920"] == "15.7.1"
    # second occurrence counted as skipped_existing (seen set), not a re-fetch
    assert stats["skipped_existing"] == 1
    assert stats["fetched"] == 1


# ---------------------------------------------------------------------------
# Wayback CDX snapshot enumeration
# ---------------------------------------------------------------------------

def test_ht1222_snapshot_urls_parses_cdx_json(monkeypatch):
    # The CDX response is a JSON array whose FIRST row is the field-name header;
    # _ht1222_snapshot_urls skips it (rows[1:]) and reads row[1] = timestamp.
    cdx_rows = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
        ["support.apple.com/en-us/HT1222", "20200115000000",
         "https://support.apple.com/en-us/HT1222", "text/html", "200", "abc", "1234"],
        ["support.apple.com/en-us/HT1222", "20210620000000",
         "https://support.apple.com/en-us/HT1222", "text/html", "200", "def", "5678"],
    ]
    monkeypatch.setattr(
        "posture.sources.apple_advisory.curl_get",
        lambda url, headers=None, max_time=60, extra=None: (cdx_rows, 200, "[]"))
    urls = _ht1222_snapshot_urls("HT1222")
    assert urls == [
        "http://web.archive.org/web/20200115000000id_/https://support.apple.com/en-us/HT1222",
        "http://web.archive.org/web/20210620000000id_/https://support.apple.com/en-us/HT1222",
    ]


@pytest.mark.parametrize("bad", [
    None,                       # no JSON (non-JSON body -> curl_get returns None)
    "not-a-list",               # wrong type
    [["only", "one", "row"]],   # header only, no data rows
    [["hdr"], ["row-no-ts"]],   # row without a timestamp string
    [["hdr"], [123, 456]],      # non-list row
])
def test_ht1222_snapshot_urls_degrades_on_malformation(monkeypatch, bad):
    monkeypatch.setattr(
        "posture.sources.apple_advisory.curl_get",
        lambda url, headers=None, max_time=60, extra=None: (bad, 200, "x"))
    assert _ht1222_snapshot_urls("HT1222") == []


def test_discover_historical_urls_unions_across_snapshots(monkeypatch):
    # Two yearly snapshots, both serving the same fixture -> union is the
    # fixture's link set (deduped). Best-effort: a None snapshot is skipped.
    monkeypatch.setattr(
        "posture.sources.apple_advisory._ht1222_snapshot_urls",
        lambda article: [f"http://web.archive.org/web/{article}-snap1",
                         f"http://web.archive.org/web/{article}-snap2"])
    snaps = {"snap1": SNAPSHOT_HTML, "snap2": None}   # snap2 "fails"
    urls = discover_historical_urls(
        articles=("HT1222",),
        fetch_snapshot=lambda u: snaps.get(u.rsplit("-", 1)[-1]))
    assert urls == [
        "https://support.apple.com/en-us/HT111111",
        "https://support.apple.com/en-us/HT444444",
        "https://support.apple.com/en-us/HT555555",
    ]


def test_discover_historical_urls_covers_both_index_articles(monkeypatch):
    # Confirm HT201222 is enumerated too (not just HT1222).
    seen_articles = []
    monkeypatch.setattr(
        "posture.sources.apple_advisory._ht1222_snapshot_urls",
        lambda article: seen_articles.append(article) or [])
    discover_historical_urls()   # default articles = (HT1222, HT201222)
    assert seen_articles == ["HT1222", "HT201222"]


# ---------------------------------------------------------------------------
# observer integration: history=True recovers pre-index CVEs; history=False
# stays byte-identical to the index-only path (no regression)
# ---------------------------------------------------------------------------

def _history_curl(monkeypatch, cdx_rows=None, snapshot=SNAPSHOT_HTML,
                  index_html=INDEX_HTML, advisories=ADV):
    """Monkeypatch curl_get for the live+history path. Serves the index, the
    CDX JSON, Wayback snapshot pages, and per-advisory pages from fixtures."""
    if cdx_rows is None:
        cdx_rows = [["h", "20200101000000"], ["h", "20210601000000"]]

    def fake_curl_get(url, headers=None, max_time=60, extra=None):
        if "web.archive.org/cdx" in url:
            return cdx_rows, 200, "[]"
        if "web.archive.org/web/" in url:
            return None, 200, snapshot
        if "100100" in url:
            return None, 200, index_html
        return None, 200, advisories[advisory_id_of(url)]
    monkeypatch.setattr("posture.sources.apple_advisory.curl_get", fake_curl_get)


def test_observer_history_recovers_pre_index_cve(monkeypatch):
    """live+history: CVE-2026-99920 (fixed only in the pre-index 15.7.1
    advisory) is recovered and decided, instead of NVD's silent skip."""
    _history_curl(monkeypatch)
    w = AppleAdvisoryObserver(live=True, history=True)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host", "os_version": "17.1", "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99920"],
    }
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert "CVE-2026-99920" in by_key
    assert by_key["CVE-2026-99920"].status == "patched"
    assert by_key["CVE-2026-99920"].fixed_in == "15.7.1"


def test_observer_history_false_does_not_recover_pre_index_cve(monkeypatch):
    """history=False (default): the same pre-index CVE gets NO Apple verdict
    (the live index does not cover it) — byte-identical to the index-only path.
    This is the no-regression proof."""
    _history_curl(monkeypatch)
    w = AppleAdvisoryObserver(live=True, history=False)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host", "os_version": "17.1", "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99920"],
    }
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert "CVE-2026-99920" not in by_key   # index does not cover it -> NVD stands


def test_observer_history_earliest_wins_replaces_index_fix_version(monkeypatch):
    """live+history: CVE-2026-99910 is on the index at 16.7.15 but re-mentioned
    in the pre-index advisory at 15.7.1; earliest-wins must report 15.7.1."""
    _history_curl(monkeypatch)
    w = AppleAdvisoryObserver(live=True, history=True)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host", "os_version": "17.1", "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99910"],
    }
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["CVE-2026-99910"].fixed_in == "15.7.1"
    assert by_key["CVE-2026-99910"].status == "patched"   # 17.1 >= 15.7.1


def test_observer_history_false_keeps_index_fix_version(monkeypatch):
    """history=False: CVE-2026-99910 keeps the index's 16.7.15 (the historical
    15.7.1 sighting is NOT merged) — confirms the default path is untouched."""
    _history_curl(monkeypatch)
    w = AppleAdvisoryObserver(live=True, history=False)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host", "os_version": "17.1", "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99910"],
    }
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["CVE-2026-99910"].fixed_in == "16.7.15"


def test_observer_history_nvd_refs_recover_when_wayback_down(monkeypatch):
    """If the Wayback CDX is down (returns no snapshots), the NVD-ref path
    (device['apple_ref_urls']) still recovers the pre-index advisory."""
    _history_curl(monkeypatch, cdx_rows=[["hdr"]])   # header only -> no snapshots
    w = AppleAdvisoryObserver(live=True, history=True)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host", "os_version": "17.1", "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99920"],
        "apple_ref_urls": ["https://support.apple.com/en-us/HT444444",
                           "https://nvd.nist.gov/vuln/detail/CVE-2026-99920"],
    }
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["CVE-2026-99920"].fixed_in == "15.7.1"   # recovered via NVD ref


def test_observer_history_skips_cross_product_advisory(monkeypatch):
    """The Safari advisory's CVE-2026-99930 must never get an iOS verdict, even
    with history on (cross-product skip in backfill)."""
    _history_curl(monkeypatch)
    w = AppleAdvisoryObserver(live=True, history=True)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host", "os_version": "17.1", "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99930"],
    }
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert "CVE-2026-99930" not in by_key


def test_observer_history_best_effort_when_wayback_down_and_no_refs(monkeypatch):
    """Wayback is down (CDX returns no snapshots) and the device supplies no
    NVD refs -> backfill gets no URLs, so the index map stands and an index-
    covered CVE still decides correctly with complete=True (best-effort: a
    historical outage never breaks the index-only decision / no-wipe)."""
    _history_curl(monkeypatch, cdx_rows=[["hdr"]])   # header only -> no snapshots
    w = AppleAdvisoryObserver(live=True, history=True)
    pol = Policy.from_yaml(_INLINE_POLICY_YAML)
    device = {
        "id": "iphone-host", "os_version": "17.1", "apple_product": "iphone_os",
        "cve_candidates": ["CVE-2026-99910"],   # index covers it at 16.7.15
        # no apple_ref_urls -> no NVD-ref recovery path either
    }
    result = w.assess(device, pol)
    assert result.complete is True
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["CVE-2026-99910"].fixed_in == "16.7.15"   # index map intact