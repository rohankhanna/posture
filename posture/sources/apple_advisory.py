"""Apple security advisories — the Apple vendor witness on the vulnerability
axis.

Why this witness exists (the gap it closes): NVD's iOS/iPadOS/macOS coverage is
thin. It associates CVEs with ``cpe:2.3:o:apple:iphone_os`` but frequently records
NO version range, so posture's NVD witness *silently skips* most Apple CVEs (the
device reads a falsely clean "0 unpatched"). Apple's own security advisories are
authoritative — each advisory lists the CVE-IDs fixed *in a given iOS/macOS
version*. This witness fetches Apple's security-releases index
(https://support.apple.com/en-us/100100), parses the per-product advisory rows
+ their fix versions, fetches each advisory page, extracts the CVE-IDs, and
builds a ``cve -> fixed_in`` map (the EARLIEST version wins — advisories are
walked oldest -> newest and the first sighting wins). At decision time it
compares the device's version against Apple's fixed version:

  ``device_version >= fixed_in`` -> patched (overrides NVD's skip/unknown-fix
    with Apple's authoritative "you have the fix").
  ``device_version <  fixed_in``  -> unpatched (Apple shipped a fix the device
    hasn't installed — the catch for a device behind the latest).
  CVE not in Apple's feed         -> NO verdict (the NVD verdict stands).

The override is by POLICY ORDER, not code: this witness's policy ``order`` is
lower than NVD's, so the engine runs it LAST and it wins on a shared CVE key.
That is the posture port of Forebode's hardcoded vendor-override call order —
here it is one YAML number.

Contract difference from Forebode: Forebode's ``apple_advisory`` fetched the
whole catalog into a ``apple_fixes`` table and decided from it (sequential, db
backed). Posture's witnesses run in a pure fan-out and cannot share state across
runs, so the candidate CVE set + the device's product/version are DEVICE INPUTS
(``device["cve_candidates"]``, ``device["apple_product"]``, version via
``os_version``/``patch_level``), and the index+advisory fetch is replayed per
assess(). The parser + decision logic are faithful to Forebode's ground truth
(forebode/sources/apple_advisory.py); only the input channel + the absence of a
persistent fixes table changed.

Offline mode (default) reads bundled HTML fixtures (an index page + one or more
advisory pages) under ``posture/fixtures/apple_advisory/`` so the tests run
deterministically with no network. Live mode
(``AppleAdvisoryWitness(live=True)``) fetches the real index + each advisory via
curl (HTML -> body straight from ``curl_get``'s third return value; its JSON
parser yields ``None`` for non-JSON bodies).

Simplifications vs. the donor (documented): the donor's ``backfill()`` /
``discover_urls()`` / Wayback-Machine historical-index paths are OUT OF SCOPE
here — they exist to recover pre-index CVEs from NVD refs + archived HT1222
snapshots, which is a db-backed catalog-maintenance job, not a per-device
decision. The decision path (index -> advisories -> cve->fixed_in -> decide) is
faithful. The live path fetches the live index + each advisory with polite
spacing via ``curl_get``; it does NOT retry or fall back to Wayback (a future
note). A failed/absent fetch is best-effort (mirrors the donor's ``return []``):
``complete=True`` + zero verdicts so the NVD verdict stands and the engine's
no-wipe rule is never tripped by an Apple-side outage.
"""

from __future__ import annotations

import re
from pathlib import Path

from packaging.version import InvalidVersion, Version

from ..axis import Axis
from ..witness import Witness, WitnessResult, Verdict
from ._net import curl_get

INDEX_URL = "https://support.apple.com/en-us/100100"
TIMEOUT = 60
# Apple's support pages are JS-rendered but the CVE list and the og:title
# (which carries the product + version) are present in the raw HTML. A normal
# browser UA avoids the occasional generic-bot block.
_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/120 Safari/537.36")
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "apple_advisory"

# Forebode product slug -> the label prefix used in the index rows + og:titles.
# iOS and iPadOS share one advisory per release ("iOS X and iPadOS X"), so both
# products read the same joint rows. macOS rows are their own ("macOS <Name> X").
PRODUCTS = {"iphone_os": "iOS", "ipados": "iPadOS", "macos": "macOS"}

# A device's candidate set may carry OSV/PyPI advisory ids (GHSA-*, PYSEC-*) from
# other matchers; Apple's advisories are keyed by CVE-ID, so only real CVE ids
# are eligible. Same door-filter as ubuntu_tracker.
_CVE_ID = re.compile(r"^CVE-\d{4}-\d+$", re.I)

# Index rows on the security-releases page (100100). iOS/iPadOS share a joint
# row ("iOS 26.5.2 and iPadOS 26.5.2"); macOS rows carry a marketing name before
# the version ("macOS Tahoe 26.5.2", "macOS Big Sur 11.7.10" — name is one or two
# words). Each captures the advisory URL + the fix version. (Donor verbatim.)
_INDEX_ROW_IOS = re.compile(
    r'href="(https://support\.apple\.com/[^"]+)"[^>]*>\s*'
    r'iOS\s+([0-9][0-9.]*)\s+and\s+iPadOS\b',
    re.IGNORECASE,
)
_INDEX_ROW_MACOS = re.compile(
    r'href="(https://support\.apple\.com/[^"]+)"[^>]*>\s*'
    r'macOS\s+[A-Za-z]+(?:\s+[A-Za-z]+)?\s+([0-9][0-9.]*)',
    re.IGNORECASE,
)
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_SCRIPT_STYLE = re.compile(r"<(script|style)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
# Apple's advisory pages carry the product + version in an og:title meta:
# "About the security content of iOS 17.1 and iPadOS 17.1 - Apple Support".
# macOS: "About the security content of macOS Tahoe 26.5.2 - Apple Support"
# (older: "OS X El Capitan 10.11.6"). A non-matching product's advisory (Safari
# for iOS backfill, iOS for macOS backfill) gives no fix version -> skipped, so
# one product's backfill never contaminates the other's fixed-version table.
_OG_TITLE = re.compile(r'<meta\s+property="og:title"\s+content="([^"]*)"',
                       re.IGNORECASE)
_IOS_VER = re.compile(r"\biOS\s+([0-9][0-9.]*)")
# macOS / OS X: a marketing name (one or two words) sits between the product
# token and the numeric version. "macOS Tahoe 26.5.2", "macOS Big Sur 11.7.10",
# "OS X El Capitan 10.11.6", "OS X Mountain Lion 10.8.5".
_MACOS_VER = re.compile(
    r"\b(?:macOS|OS\s+X)\s+[A-Za-z]+(?:\s+[A-Za-z]+)?\s+([0-9][0-9.]*)",
    re.IGNORECASE)


def is_cve_id(cid: str) -> bool:
    """True for real CVE ids (``CVE-YYYY-NNNN``), False for GHSA/PYSEC/etc.
    Reused from ubuntu_tracker (same door-filter, same shape)."""
    return bool(cid) and _CVE_ID.match(cid) is not None


def _strip(html: str) -> str:
    """Drop <script>/<style> blocks so CVE-IDs in analytics bundles don't leak
    into the advisory's CVE list. (Donor verbatim.)"""
    return _SCRIPT_STYLE.sub(" ", html)


def _version_regex(product: str) -> re.Pattern:
    return _MACOS_VER if product == "macos" else _IOS_VER


def parse_advisory_version(html: str, product: str = "iphone_os") -> str | None:
    """The fix version an advisory page states for ``product``, or ``None``
    when the advisory is for a different product (Safari/macOS for an iOS
    ``product``, iOS for a macOS ``product``) — those don't give a fix version
    in this product's space, so backfill must ignore them.

    Pulled from the page's ``og:title`` (the only place the version survives in
    the raw HTML; the visible heading is JS-rendered). (Donor verbatim.)
    """
    m = _OG_TITLE.search(html)
    if not m:
        return None
    mv = _version_regex(product).search(m.group(1))
    return mv.group(1) if mv else None


def parse_index(html: str, product: str = "iphone_os") -> list[tuple[str, str, str]]:
    """Extract (version, advisory_url, advisory_id) for every advisory listed
    on the security-releases index for ``product``. Deduped by URL.
    (Donor verbatim.)"""
    rx = _INDEX_ROW_MACOS if product == "macos" else _INDEX_ROW_IOS
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for url, version in rx.findall(html):
        if url in seen:
            continue
        seen.add(url)
        adv_id = url.rstrip("/").rsplit("/", 1)[-1]
        out.append((version, url, adv_id))
    return out


def parse_advisory(html: str) -> list[str]:
    """Return the unique CVE-IDs listed on one advisory page. Scripts/styles
    are stripped first so CVE-IDs in analytics bundles don't leak in.
    (Donor verbatim.)"""
    return sorted(set(_CVE.findall(_strip(html))))


def _ver_key(v: str):
    """Sort key for advisory versions — valid packaging Versions sort before
    unparseable strings; the two classes never compare (tuple-tagged)."""
    try:
        return (0, Version(v))
    except (InvalidVersion, TypeError):
        return (1, v)


def _ge(installed: str, fixed: str) -> bool:
    """True if installed >= fixed. Mirrors ubuntu_tracker._kge /
    nvd_cve.compare_versions: never raises, lex fallback for unparseable."""
    try:
        return Version(installed) >= Version(fixed)
    except (InvalidVersion, TypeError):
        return installed >= fixed


def build_fix_map(index_html: str, fetch_advisory_html,
                  product: str = "iphone_os") -> dict[str, str]:
    """Build ``{cve_id: fixed_in}`` for ``product``.

    ``fetch_advisory_html(version, url, adv_id) -> html_str | None`` is the
    advisory-page getter (offline reads a fixture; live curl_gets). The map
    keeps the EARLIEST version where Apple fixed a CVE: advisories are
    processed oldest -> newest and the first sighting wins (a CVE can be
    re-mentioned in later backport notes). Faithful to the donor's ``fetch``.

    The product filter is applied twice: at the index (``parse_index`` picks
    the product's row regex — iOS/iPadOS share the joint rows, macOS has its
    own) and at each advisory page via ``parse_advisory_version`` — an advisory
    whose og:title carries a different product's version (a Safari/iOS advisory
    hit during a macOS pass) yields ``None`` and is skipped, so one product's
    backfill never contaminates the other's fixed-version table.
    """
    rows = parse_index(index_html, product)
    # Oldest first so the first sighting of a CVE is its earliest fix version.
    rows.sort(key=lambda t: _ver_key(t[0]))

    fixed: dict[str, str] = {}
    for version, url, adv_id in rows:
        html = fetch_advisory_html(version, url, adv_id)
        if not html:
            continue  # best-effort; a failed advisory never breaks the build
        # confirm this advisory actually carries a fix version for this
        # product (og:title gate); skip cross-product advisories.
        page_ver = parse_advisory_version(html, product)
        if not page_ver:
            continue
        for cid in parse_advisory(html):
            if cid in fixed:
                continue  # earliest fix already recorded
            fixed[cid] = page_ver
    return fixed


class AppleAdvisoryWitness(Witness):
    """The Apple security-advisory vendor witness on the vulnerability axis.

    Overrides NVD's false-clean skip on Apple CVEs (NVD records the CVE against
    ``cpe:2.3:o:apple:iphone_os`` with no version range -> NVD silently skips it)
    by fetching Apple's authoritative advisories and emitting CVE-keyed Verdicts
    (patched / unpatched) so the engine's per-key override (policy order) lets
    it win over NVD on the same CVE without any code change.
    """

    id = "apple_advisory"
    axes = (Axis.VULNERABILITY,)
    bias = "false-safe"   # vendor authoritative; tends to clear NVD's false-clean skips
    key_kind = "cve"      # emits CVE ids -> the vocab monitor sees a known kind

    def __init__(self, live: bool = False, fixture_dir: Path | str | None = None) -> None:
        super().__init__(id=self.id, axes=self.axes, bias=self.bias,
                         key_kind=self.key_kind)
        self.live = live
        self.fixture_dir = Path(fixture_dir) if fixture_dir else FIXTURE_DIR

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> WitnessResult:
        cves = [c for c in (device.get("cve_candidates") or []) if is_cve_id(c)]
        product = str(device.get("apple_product") or "").strip().lower()
        version = str(device.get("os_version") or device.get("patch_level") or "").strip()
        # No candidate set / product / version -> honest zero verdicts. The
        # engine keeps NVD's verdicts (this witness adds no keys to override);
        # the loud-degradation rule is unaffected. A non-Apple host simply has
        # nothing for this witness to say.
        if not cves or not product or not version or product not in PRODUCTS:
            return WitnessResult(
                verdicts=[], complete=True,
                reason="no apple advisory input "
                        "(device lacks cve_candidates/apple_product/os_version "
                        "or apple_product not in {iphone_os,ipados,macos})",
            )

        index_html, ok = self._fetch_index()
        # Best-effort: a failed/absent index fetch -> complete=True, zero
        # verdicts (NVD stands). Never a fetch failure that breaks the engine
        # (no-wipe rule). Mirrors the donor's `return []` on fetch failure.
        if not ok or not index_html:
            return WitnessResult(
                verdicts=[], complete=True,
                reason="apple advisory index fetch failed/absent (NVD stands)",
            )

        fixed = build_fix_map(index_html, self._fetch_advisory_html, product)

        verdicts: list[Verdict] = []
        for cid in cves:
            v = self._decide(cid, fixed, version, product)
            if v is not None:
                verdicts.append(v)

        return WitnessResult(
            verdicts=verdicts, complete=True,
            reason="fixture" if not self.live else "live",
        )

    # -- decide one CVE -> a Verdict (or None: NVD stands) ---------------------

    def _decide(self, cve_id: str, fixed: dict[str, str],
                device_version: str, product: str) -> Verdict | None:
        """Authoritative Apple patch status for one CVE on one device.

        Returns ``None`` when Apple has no advisory for this CVE (Apple silent
        -> the NVD verdict stands). When Apple *does* cover the CVE it is
        authoritative: patched if the device is at/above the fix, unpatched if
        below. Faithful to forebode/sources/apple_advisory.decide.
        """
        fixed_in = fixed.get(cve_id)
        if not fixed_in:
            return None  # Apple silent — let the NVD verdict stand
        label = PRODUCTS.get(product, product)
        # The advisory URL is the citable per-CVE ref; we point at the index
        # (the catalog the cve->fixed_in map was built from) as raw_ref.
        url = INDEX_URL
        if _ge(device_version, fixed_in):
            return Verdict(
                axis=Axis.VULNERABILITY.value, key=cve_id,
                status="patched", fixed_in=fixed_in,
                detail=f"Apple advisory: fixed in {label} {fixed_in}, "
                       f"device on {device_version} (at/above fix) — "
                       "overrides NVD's thin Apple coverage",
                provenance=self._prov(complete=True, raw_ref=url),
            )
        return Verdict(
            axis=Axis.VULNERABILITY.value, key=cve_id,
            status="unpatched", fixed_in=fixed_in,
            severity="high",
            detail=f"Apple advisory: fixed in {label} {fixed_in}, "
                   f"device on {device_version} (below fix — update available)",
            provenance=self._prov(complete=True, raw_ref=url),
        )

    # -- fetch (live curl or offline fixture) --------------------------------

    def _fetch_index(self) -> tuple[str, bool]:
        if not self.live:
            return self._read_fixture("index.html"), True
        return self._fetch_live(INDEX_URL)

    def _fetch_advisory_html(self, version: str, url: str, adv_id: str) -> str | None:
        if not self.live:
            p = self.fixture_dir / f"{adv_id}.html"
            try:
                return p.read_text()
            except FileNotFoundError:
                return None  # genuine absent -> skip this advisory
        html, ok = self._fetch_live(url)
        return html if ok else None

    def _read_fixture(self, name: str) -> str:
        p = self.fixture_dir / name
        try:
            return p.read_text()
        except FileNotFoundError:
            return ""

    def _fetch_live(self, url: str) -> tuple[str, bool]:
        """Real page pull via curl. Apple's pages return HTML (not JSON), so we
        take the body straight from curl_get's third return value (its JSON
        parser yields None for non-JSON bodies)."""
        _data, code, body = curl_get(
            url, headers=[f"User-Agent: {_UA}"], max_time=TIMEOUT)
        if code == 200 and body:
            return body, True
        # Any non-200 / timeout / empty body = best-effort absent (donor returns
        # [] on failure). The caller treats absent as skip; never a hard fail.
        return "", False