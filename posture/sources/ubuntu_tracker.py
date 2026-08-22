"""Ubuntu security tracker — the first real VENDOR observer on the
vulnerability axis.

Why this observer exists (the gap it closes): NVD records Ubuntu kernel CVEs
against ``cpe:2.3:o:canonical:ubuntu_linux`` with NO fix boundary ("24.04
affected, no fix recorded"), so posture's NVD observer over-reports
*unknown-fix* on an Ubuntu host — a brand-new kernel ends up flagged for CVEs
Ubuntu fixed long ago in the running flavor. Ubuntu's own security tracker
(``ubuntu.com/security/<CVE>``) is authoritative: each per-CVE page lists, per
release + source package, the status — ``Fixed <dpkg-version>``, ``Not
affected``, ``Vulnerable``, ``Needs triage``, ``DNE`` … This observer fetches
the page for the device's candidate CVEs only and overrides NVD's verdict on
the SAME CVE key:

  ``Fixed <ver>``         -> patched if running kernel >= ver, else unpatched
  ``Not affected``        -> patched (clears the NVD false positive)
  ``Vulnerable``/``needed`` -> unpatched (Ubuntu confirms open)
  ``Needs triage`` / ``DNE`` / ``Not in release`` / absent -> NO verdict
                             (the NVD unknown-fix stands; the tracker has
                             nothing usable to say)

The override is by POLICY ORDER, not code: this observer's policy ``order`` is
lower than NVD's, so the engine runs it LAST and it wins on a shared CVE key.
That is the posture port of Forebode's hardcoded vendor-override call order —
here it is one YAML number.

Contract difference from Forebode: Forebode's ``ubuntu_tracker`` fetched the
unknown-fix CVE set PRODUCED BY the NVD pass (sequential). Posture's observers
run in a pure fan-out and cannot see each other's verdicts (the 5-step core is
invariant), so the candidate CVE set is a DEVICE INPUT — ``device["cve_candidates"]``
— populated in a real run from a prior NVD pass or the OS package CVE list. The
parser + status mapping are faithful to Forebode's ground truth
(forebode/sources/ubuntu_tracker.py); only the input channel changed.

Offline mode (default) reads a bundled HTML fixture per CVE so the tests run
deterministically with no network. Live mode (``UbuntuTrackerObserver(live=True)``)
fetches ``ubuntu.com/security/<CVE>`` via curl.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..axis import Axis
from .. import debver
from ..observer import Observer, ObserverResult, Verdict
from ._net import curl_get

TRACKER_URL = "https://ubuntu.com/security/{cve}"
TIMEOUT = 30
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "ubuntu_tracker"

# The tracker is keyed by CVE id (https://ubuntu.com/security/CVE-…). A device's
# candidate set may also carry OSV/PyPI advisory ids (GHSA-*, PYSEC-*) from other
# matchers; those have no tracker page and 404 every run. Only real CVE ids are
# fetchable, so filter at the door.
_CVE_ID = re.compile(r"^CVE-\d{4}-\d+$", re.I)

# A package group header: <th rowspan="N">linux-nvidia-6.17</th>
_PKG_TH = re.compile(r'<th[^>]*rowspan="(\d+)"[^>]*>\s*([^<]+?)\s*</th>', re.I)
# A release cell: <td ...> 24.04 LTS <span ...>noble</span> </td>
_REL_CELL = re.compile(
    r'<td[^>]*>\s*(\d+\.\d+(?:\.\d+)?)\s*(?:LTS)?\s*'
    r'<span[^>]*>\s*([a-z][a-z0-9-]*)\s*</span>\s*</td>',
    re.I,
)
# The status cell that follows a release cell (class includes cve-td-status).
_STATUS_CELL = re.compile(
    r'<td[^>]*cve-td-status[^>]*>(.*?)</td>', re.I | re.DOTALL)
_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def is_cve_id(cid: str) -> bool:
    """True for real CVE ids (``CVE-YYYY-NNNN``), False for GHSA/PYSEC/etc."""
    return bool(cid) and _CVE_ID.match(cid) is not None


def _clean(cell_html: str) -> str:
    return _WS.sub(" ", _TAG.sub(" ", cell_html)).strip()


def _parse_status(text: str) -> tuple[str | None, str | None]:
    """Map a tracker status-cell text -> (status, fixed_in). status is None for
    anything we don't act on (caller treats None as 'no override' -> NVD stands).
    Faithful to forebode/sources/ubuntu_tracker._parse_status."""
    t = text.lower()
    if t.startswith("fixed"):
        rest = text[len("fixed"):].strip()
        ver = rest.split()[0] if rest else None
        return ("fixed", ver)
    if "not affected" in t:
        return ("not_affected", None)
    if "not in release" in t:
        return ("not_in_release", None)
    if t.startswith("needs") or "needs triage" in t or "needs evaluation" in t:
        return ("needs", None)
    if "vulnerable" in t:
        return ("vulnerable", None)
    if "dne" in t or "does not exist" in t:
        return ("dne", None)
    if "ignored" in t:
        return ("ignored", None)
    return (None, None)


def parse_cve_page(html: str, release: str,
                   packages: list[str]) -> dict[str, tuple[str | None, str | None]]:
    """Extract the status for ``release`` (codename, e.g. 'noble') of every
    package in ``packages`` that appears on the page.

    Returns ``{package: (status, fixed_in)}`` (only packages with a recognized
    status for the release). Empty if none of the candidate packages have a row
    for the release (the CVE isn't tracked for the host's flavor).
    """
    out: dict[str, tuple[str | None, str | None]] = {}
    ths = list(_PKG_TH.finditer(html))
    for i, m in enumerate(ths):
        pkg = m.group(2).strip()
        if pkg not in packages:
            continue
        start = m.end()
        end = ths[i + 1].start() if i + 1 < len(ths) else len(html)
        block = html[start:end]
        for rm in _REL_CELL.finditer(block):
            if rm.group(2).lower() != release:
                continue
            sm = _STATUS_CELL.search(block[rm.end():])
            if not sm:
                continue
            st = _parse_status(_clean(sm.group(1)))
            if st[0] is not None:
                out[pkg] = st
            break  # this package's row for the release
    return out


def _normalize_overlay_status(status: str | None,
                              fixed_in: str | None) -> tuple[str | None, str | None]:
    """Map a RAW ``ubuntu_fixes`` overlay status word to the ``(status,
    fixed_in)`` token :func:`_decide` acts on — the bulk-JSON counterpart of
    :func:`_parse_status`'s HTML-text mapping. The overlay stores the raw
    tracker words (``released`` / ``needed`` / ``needs-triage`` /
    ``not-affected`` / ``DNE`` / ``ignored`` / ``deferred`` / ``pending``);
    this normalizes them to the same tokens the live/fixture path produces so
    ``_decide`` runs UNCHANGED. ``(None, None)`` means 'no override' (needs
    triage / DNE / ignored / deferred / pending / unknown) -> NVD stands, the
    same outcome as a ``_parse_status`` it doesn't recognize."""
    s = (status or "").strip().lower()
    if s == "released":
        return ("fixed", fixed_in)
    if s == "not-affected":
        return ("not_affected", None)
    if s == "needed":
        return ("needed", None)
    if s == "needs-triage":
        return ("needs", None)
    if s == "dne":
        return ("dne", None)
    if s == "ignored":
        return ("ignored", None)
    # pending / deferred / anything else -> no actionable mapping (NVD stands)
    return (None, None)


def found_from_catalog(
    cve_id: str, catalog: dict
) -> dict[str, tuple[str | None, str | None]]:
    """Normalize the territory-injected ``ubuntu_fixes`` overlay rows for ONE
    CVE to the same ``{package: (status, fixed_in)}`` shape :func:`parse_cve_page`
    returns, so :meth:`UbuntuTrackerObserver._decide` runs UNCHANGED (one
    decision path, not a second one for the catalog). A CVE absent from the
    catalog -> ``{}`` (a COMPLETE absent answer: ``_decide`` returns None -> NVD
    stands — no fallback to the demo fixture)."""
    raw = catalog.get(cve_id, {})
    return {pkg: _normalize_overlay_status(status, fixed_in)
            for pkg, (status, fixed_in) in raw.items()}


def _kge(installed: str, fixed: str) -> bool:
    """True if installed >= fixed, using dpkg version semantics.

    Real Ubuntu tracker fixed versions are dpkg versions (e.g.
    ``6.17.9-6.17.0+signed``, ``1.0~rc1``) that ``packaging.version`` cannot
    compare correctly — it raises ``InvalidVersion`` and the old lex fallback
    gave the WRONG answer (a tilde pre-release like ``1.0~rc1`` lex-compares
    ``>= 1.0`` but dpkg orders ``1.0~rc1 < 1.0``, so the fallback would declare
    a vulnerable kernel patched). dpkg semantics via :mod:`posture.debver` is
    the correct comparator. Never raises (pure-string algorithm)."""
    return debver.ge(installed, fixed)


class UbuntuTrackerObserver(Observer):
    """The Ubuntu security-tracker vendor observer on the vulnerability axis.

    Overrides NVD's false-alarm unknown-fix on Ubuntu kernel CVEs by fetching
    Ubuntu's authoritative per-CVE tracker page. Emits CVE-keyed Verdicts
    (patched / unpatched) so the engine's per-key override (policy order) lets
    it win over NVD on the same CVE without any code change.
    """

    id = "ubuntu_tracker"
    axes = (Axis.VULNERABILITY,)
    bias = "false-safe"   # vendor authoritative; tends to clear NVD false positives
    key_kind = "cve"      # emits CVE ids -> the vocab monitor sees a known kind

    def __init__(self, live: bool = False, fixture_dir: Path | str | None = None) -> None:
        super().__init__(id=self.id, axes=self.axes, bias=self.bias,
                         key_kind=self.key_kind)
        self.live = live
        self.fixture_dir = Path(fixture_dir) if fixture_dir else FIXTURE_DIR

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> ObserverResult:
        cves = [c for c in (device.get("cve_candidates") or []) if is_cve_id(c)]
        release = str(device.get("ubuntu_release") or "").strip().lower()
        packages = [p for p in (device.get("ubuntu_packages") or []) if p]
        # No candidate set / release / packages -> honest zero verdicts. The
        # engine keeps NVD's verdicts (this observer adds no keys to override);
        # the loud-degradation rule is unaffected. A non-Ubuntu host simply has
        # nothing for this observer to say.
        if not cves or not release or not packages:
            return ObserverResult(
                verdicts=[], complete=True,
                reason="no ubuntu tracker input "
                        "(device lacks cve_candidates/ubuntu_release/ubuntu_packages)",
            )

        kernel = str(device.get("patch_level") or device.get("os_version") or "")
        # The territory pre-pass (cli._inject_catalog_overlays) loads the
        # imported ubuntu_fixes overlay into ``device["ubuntu_fixes"]`` BEFORE
        # assess — keyed per-CVE per-package with RAW tracker status words.
        # When present and not live, _decide consumes the normalized overlay
        # with NO network (the catalog-backed assess path, mirroring
        # NvdCveObserver). Absent -> fall back to live/fixture.
        # Live > catalog > fixture.
        catalog = device.get("ubuntu_fixes")
        use_catalog = not self.live and catalog is not None

        verdicts: list[Verdict] = []
        complete = True
        reasons: list[str] = []

        for cid in cves:
            if use_catalog:
                found = found_from_catalog(cid, catalog)
            else:
                html, ok, reason = self._fetch(cid)
                if not ok:
                    complete = False
                    reasons.append(reason or f"{cid} incomplete")
                    continue
                found = parse_cve_page(html, release, packages)
            v = self._decide(cid, found, kernel, release)
            if v is not None:
                verdicts.append(v)

        if reasons:
            out_reason = "; ".join(reasons)
        elif use_catalog:
            out_reason = "catalog"
        else:
            out_reason = "fixture" if not self.live else "live"
        return ObserverResult(verdicts=verdicts, complete=complete, reason=out_reason)

    # -- decide one CVE -> a Verdict (or None: NVD stands) ---------------------

    def _decide(self, cve_id: str,
                found: dict[str, tuple[str | None, str | None]],
                kernel: str, release: str) -> Verdict | None:
        """First actionable status across the candidate packages (in the order
        the device declared them). Returns None when the tracker has no usable
        verdict for this CVE -> the NVD verdict stands."""
        url = TRACKER_URL.format(cve=cve_id)
        for pkg, (status, fixed_in) in found.items():
            if status == "fixed" and fixed_in:
                if kernel and _kge(kernel, fixed_in):
                    return Verdict(
                        axis=Axis.VULNERABILITY.value, key=cve_id,
                        status="patched", fixed_in=fixed_in,
                        severity="medium",
                        detail=f"Ubuntu tracker: fixed in {fixed_in} ({pkg}, {release}); "
                               f"kernel {kernel} at/above fix — clears NVD unknown-fix",
                        provenance=self._prov(complete=True, raw_ref=url),
                    )
                return Verdict(
                    axis=Axis.VULNERABILITY.value, key=cve_id,
                    status="unpatched", fixed_in=fixed_in,
                    severity="high",
                    detail=f"Ubuntu tracker: fixed in {fixed_in} ({pkg}, {release}); "
                           f"kernel {kernel} below fix — update available",
                    provenance=self._prov(complete=True, raw_ref=url),
                )
            if status == "not_affected":
                return Verdict(
                    axis=Axis.VULNERABILITY.value, key=cve_id,
                    status="patched", fixed_in=None,
                    detail=f"Ubuntu tracker: not affected ({pkg}, {release}) — "
                           "clears NVD false positive",
                    provenance=self._prov(complete=True, raw_ref=url),
                )
            if status in ("vulnerable", "needed"):
                return Verdict(
                    axis=Axis.VULNERABILITY.value, key=cve_id,
                    status="unpatched", fixed_in=None,
                    severity="high",
                    detail=f"Ubuntu tracker: {status} ({pkg}, {release}) — "
                           "Ubuntu confirms open",
                    provenance=self._prov(complete=True, raw_ref=url),
                )
            # needs / not_in_release / dne / ignored -> try the next package
        return None

    # -- fetch (live curl or offline fixture) --------------------------------

    def _fetch(self, cve: str) -> tuple[str, bool, str]:
        if not self.live:
            return self._fetch_fixture(cve)
        return self._fetch_live(cve)

    def _fetch_fixture(self, cve: str) -> tuple[str, bool, str]:
        p = self.fixture_dir / f"{cve}.html"
        try:
            return p.read_text(), True, "fixture"
        except FileNotFoundError:
            # genuine absent — complete + zero (NVD stands), not a failure
            return "", True, f"{cve}: no fixture (absent)"

    def _fetch_live(self, cve: str) -> tuple[str, bool, str]:
        """Real per-CVE tracker pull via curl. The tracker returns HTML (not
        JSON), so we take the body straight from curl_get's third return value
        (its JSON parser yields None for non-JSON bodies)."""
        url = TRACKER_URL.format(cve=cve)
        _data, code, body = curl_get(
            url, headers=["User-Agent: posture/1.0"], max_time=TIMEOUT)
        if code == 200 and body:
            return body, True, f"{cve}: live"
        if code == 404:
            return "", True, f"{cve}: absent (404)"   # genuine absent -> NVD stands
        return "", False, f"{cve}: incomplete (http {code or 'timeout'})"