"""The CVE spine observer — NVD, the one real observer today.

Faithful to Forebode's hard-won NVD rules (forebode/sources/nvd.py ground
truth):

  - `curl`, NOT python `requests` (requests hangs on NVD's CDN).
  - API key in a HEADER (`apiKey: <key>`), NEVER the query string. Putting it
    in the query string triggers NVD's "404-masquerade" — the actual root cause
    of Forebode's run-#10 fleet wipe (every authenticated broad-CPE pull came
    back empty -> DELETE+INSERT wiped the fleet). Header-only is the fix.
  - `__HTTP__%{http_code}` sentinel splits status from body; 404-twice =
    genuine absent (complete=True, zero); retry give-up = complete=False
    (no-wipe); `totalResults` reached = complete.
  - Emits the NVD attribution string in its output (attribution rule).

Offline mode (default) reads a bundled NVD-shaped fixture so `posture demo`
and the tests run deterministically with no network and no key. Live mode
(`NvdCveObserver(live=True)`) does the real per-CPE pull. The engine treats
both identically — the completeness gate, provenance, and health sampling
don't care whether the fetch was a fixture or a CDN.
"""

from __future__ import annotations
import json
import os
import time
import urllib.parse
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from ..axis import Axis
from ..observer import Observer, ObserverResult, Verdict, Provenance
from ..attribution import NVD_ATTRIBUTION
from ._net import curl_get

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 500          # small pages = reliable on anonymous NVD (Forebode rule)
MAX_RESULTS = 20000      # runaway net, NOT a completeness ceiling
FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nvd_sample.json"
# Per-CVE NVD rate limit: 0.6s with an API key, 6s anonymous (50/30s vs 5/30s).
CVE_THROTTLE_KEYED = 0.6
CVE_THROTTLE_ANON = 6.0


def _pad_cpe(cpe: str) -> str:
    """Pad a CPE 2.3 URI to 13 components with `:*` so a versionless vendor CPE
    (e.g. cpe:2.3:o:apple:iphone_os) is valid for virtualMatchString."""
    parts = cpe.split(":")
    while len(parts) < 13:
        parts.append("*")
    return ":".join(parts)


def _cpe_head(cpe: str) -> str:
    """The first 5 components (part:vendor:product), lowercased — the match key
    for 'does this range apply to this device's CPE?'"""
    return ":".join(cpe.split(":")[:5]).lower()


def _criteria_version(cpe: str) -> str:
    """The version component (index 5) of a CPE 2.3 criteria string, or '*' if
    absent. A short/malformed criteria must never crash the range decision."""
    parts = cpe.split(":")
    return parts[5] if len(parts) > 5 and parts[5] else "*"


def compare_versions(a: str, b: str) -> int:
    """-1/0/1, never raises (mirrors Forebode match.compare_versions)."""
    if a == b:
        return 0
    try:
        return -1 if Version(a) < Version(b) else (1 if Version(a) > Version(b) else 0)
    except (InvalidVersion, TypeError):
        pass
    # fallback: naive string compare so a non-parseable version never crashes
    return -1 if a < b else (1 if a > b else 0)


def _metrics(cve: dict) -> tuple[float | None, str | None, str | None]:
    """(cvss, severity, vectorString) preferring CVSS 3.1 -> 3.0 -> 2."""
    m = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in m and m[key]:
            e = m[key][0]
            data = e.get("cvssData", {})
            score = data.get("baseScore")
            sev = e.get("baseSeverity") or _sev(score)
            vec = data.get("vectorString")
            if score is not None:
                return score, (sev or "").upper() or None, vec
    return None, None, None


def _sev(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def _desc(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            return (d.get("value") or "").replace("\n", " ")[:300]
    return ""


def _refs(cve: dict) -> list[str]:
    return [r.get("url") for r in (cve.get("references") or []) if r.get("url")]


def _cwes(cve: dict) -> list[str]:
    """CWE ids the CVE maps to (the foothold/weakness-class signal).

    NVD nests these under ``weaknesses[].description[].value`` as bare ids
    like ``"CWE-79"`` (sometimes a prose line; we keep only the id-shaped
    values and de-dup, sorted)."""
    out: set[str] = set()
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = (d.get("value") or "").strip()
            if v.startswith("CWE-"):
                out.add(v)
    return sorted(out)


def _ref_tags(cve: dict) -> list[str]:
    """Reference tags across all references (the arming/patch-availability
    signal — e.g. ``"Patch"``, ``"Vendor Advisory"``, ``"Exploit"``).

    De-duped and sorted; a flat union, NOT url-keyed, so a row can be filtered
    on ``"Exploit" in ref_tags`` cheaply."""
    out: set[str] = set()
    for r in cve.get("references") or []:
        for t in r.get("tags") or []:
            if t:
                out.add(t)
    return sorted(out)


def _ranges_for_cve(cve: dict, matcher_cpe: str) -> list[dict]:
    """Vulnerable cpeMatch entries whose criteria head matches the matcher's
    CPE head. Each carries the boundary fields used to decide affectedness +
    fixed_in (mirrors Forebode match._nvd_range_affected)."""
    head = _cpe_head(matcher_cpe)
    out: list[dict] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                if not cm.get("vulnerable"):
                    continue
                if _cpe_head(cm.get("criteria", "")) != head:
                    continue
                out.append({
                    "criteria": cm.get("criteria"),
                    "vstart_incl": cm.get("versionStartIncluding"),
                    "vstart_excl": cm.get("versionStartExcluding"),
                    "vend_incl": cm.get("versionEndIncluding"),
                    "vend_excl": cm.get("versionEndExcluding"),
                    "crit_ver": _criteria_version(cm.get("criteria", "")),
                })
    return out


def _decide_range(device_ver: str, rng: dict) -> tuple[str | None, str | None]:
    """Return (status, fixed_in): 'unpatched' | 'patched' | 'not_affected',
    and fixed_in (a version or None for unknown-fix). Mirrors Forebode
    match._nvd_range_affected."""
    vstart_incl = rng.get("vstart_incl")
    vstart_excl = rng.get("vstart_excl")
    vend_incl = rng.get("vend_incl")
    vend_excl = rng.get("vend_excl")
    crit_ver = rng.get("crit_ver") or "*"

    # lower bound
    if vstart_incl and compare_versions(device_ver, vstart_incl) < 0:
        return "not_affected", None
    if vstart_excl and compare_versions(device_ver, vstart_excl) <= 0:
        return "not_affected", None

    # upper bound
    if vend_excl:
        if compare_versions(device_ver, vend_excl) < 0:
            return "unpatched", vend_excl
        return "patched", vend_excl
    if vend_incl:
        if compare_versions(device_ver, vend_incl) <= 0:
            return "unpatched", vend_incl
        return "patched", vend_incl
    # concrete version on the criteria (not '*'): point match
    if crit_ver and crit_ver != "*":
        if compare_versions(device_ver, crit_ver) == 0:
            return "unpatched", None
        return "not_affected", None
    # no upper bound, device >= lower bound -> affected, unknown fix
    return "unpatched", None


def decide_cve_for_device(cve: dict, device_ver: str, cpe: str) -> tuple[str | None, str | None, str | None, str | None, list[dict]]:
    """Re-decide ONE NVD CVE against ONE device CPE + version. Returns
    ``(status, fixed_in, severity, detail, ranges)`` where status is
    'unpatched' | 'patched' | 'not_affected', or None when the CVE doesn't
    touch this device's CPE (no comparable range -> skip, no verdict).

    Shared by :meth:`NvdCveObserver._interpret` (the per-CPE pull path) and the
    incremental refresh (per-CVE enrichment -> re-decide). Keeping the decision
    in one place means a skeleton promoted by the refresh and a CVE pulled by
    ``assess`` are decided by the exact same logic.
    """
    ranges = _ranges_for_cve(cve, cpe)
    if not ranges:
        return None, None, None, None, ranges  # CVE doesn't touch this CPE -> skip
    status = "not_affected"
    fixed_in: str | None = None
    for rng in ranges:
        s, fi = _decide_range(str(device_ver), rng)
        if s == "unpatched":
            status = "unpatched"
            fixed_in = fi
            break
        if s == "patched" and status != "unpatched":
            status = "patched"
            fixed_in = fi
    score, sev, _vec = _metrics(cve)
    return status, fixed_in, (sev or "unknown"), _desc(cve), ranges


def nvd_query_cve(cve_id: str, throttle: bool = True) -> tuple[dict | None, bool, str]:
    """Per-CVE NVD fetch via **curl**, header-only ``apiKey`` (NEVER the query
    string — putting the key in the query string is Forebode's run-#10 fleet-
    wipe root cause). Returns ``(cve_obj, complete, reason)``:

      * cve_obj = the NVD ``vulnerabilities[0].cve`` dict, or None.
      * complete=True, cve_obj=None  -> NVD proved the id genuinely absent
        (404 twice / zero results). The refresh leaves the skeleton pending
        rather than wiping anything; absence is not "this CVE doesn't exist,"
        only "NVD hasn't enriched it yet."
      * complete=False, cve_obj=None -> the fetch was NOT provably whole
        (timeout / non-404 error / empty page mid-stream). The refresh treats
        this as no-wipe: the skeleton stays pending, retried next tick.

    Uses the shared :func:`._net.curl_get` (subprocess curl, ``--max-time 60``,
    the ``__HTTP__%{http_code}`` status split) — not python ``requests``, which
    hangs on NVD's CDN. Honors ``NVD_API_KEY`` in the ``apiKey`` HEADER.
    """
    api_key = os.environ.get("NVD_API_KEY")
    headers = ["Accept: application/json"]
    if api_key:
        # HEADER-ONLY. The key NEVER goes in the URL/query string.
        headers.append(f"apiKey: {api_key}")
    if throttle:
        time.sleep(CVE_THROTTLE_KEYED if api_key else CVE_THROTTLE_ANON)
    params = {"cveId": cve_id}
    url = NVD_URL + "?" + urllib.parse.urlencode(params)
    data, code, _body = curl_get(url, headers=headers)
    if data is None:
        if code == 404:
            # could be a rate-limit masquerade; one retry, then genuine absent
            time.sleep(10)
            data, code, _ = curl_get(url, headers=headers)
            if data is None and code == 404:
                return None, True, f"{cve_id}: absent (404 twice)"
        if data is None:
            return None, False, f"{cve_id}: incomplete (http {code or 'timeout'})"
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None, True, f"{cve_id}: zero (absent)"  # genuinely zero
    return vulns[0].get("cve", vulns[0]), True, f"{cve_id}: enriched"


class NvdCveObserver(Observer):
    """The CVE spine. Queries NVD per device CPE and emits vulnerability
    Verdicts (unpatched/patched/not_affected) with CVSS + fixed_in."""

    id = "nvd"
    axes = (Axis.VULNERABILITY,)
    bias = "false-alarm"
    key_kind = "cve"   # emits CVE ids -> the vocab monitor sees a known kind

    def __init__(self, live: bool = False, fixture: Path | str | None = None) -> None:
        super().__init__(id=self.id, axes=self.axes, bias=self.bias,
                         key_kind=self.key_kind)
        self.live = live
        self.fixture = Path(fixture) if fixture else FIXTURE

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> ObserverResult:
        matchers = [m for m in device.get("matchers", [])
                    if m.get("type") == "nvd_cpe" and m.get("cpe")]
        if not matchers:
            return ObserverResult(verdicts=[], complete=True,
                                  reason="device has no nvd_cpe matchers")

        # The territory pre-pass (cli._inject_catalog_overlays) loads the
        # imported spine defects table into ``device["catalog_defects"]`` keyed
        # by CPE head BEFORE assess — the "consume locally" half of "feed and
        # enrich in CI, consume locally". When present, _fetch reads the catalog
        # (NO network, NO fixture file); the observer contract still forbids DB
        # access in assess (no conn). Absent -> fall back to fixture/live.
        catalog = device.get("catalog_defects")

        verdicts: list[Verdict] = []
        complete = True
        reasons: list[str] = []
        for m in matchers:
            cpe = m["cpe"]
            device_ver = m.get("version") or device.get("os_version") or device.get("patch_level") or "*"
            records, ok, reason = self._fetch(cpe, catalog)
            if not ok:
                complete = False
                reasons.append(reason or f"{cpe} incomplete")
            for rec in records:
                v = self._interpret(rec, device_ver, cpe)
                if v is not None:
                    verdicts.append(v)
        if reasons:
            out_reason = "; ".join(reasons)
        elif catalog is not None:
            out_reason = "catalog"
        else:
            out_reason = "fixture" if not self.live else "live"
        return ObserverResult(verdicts=verdicts, complete=complete, reason=out_reason)

    # -- fetch (live curl, offline fixture, or offline catalog) ---------------

    def _fetch(self, cpe: str, catalog: dict | None = None) -> tuple[list[dict], bool, str]:
        # precedence: an explicit --live operator pull wins (the operator asked
        # for the network); then the territory-injected catalog (the imported
        # spine, no network); then the bundled fixture (the demo/hermetic
        # corpus). Live > catalog > fixture.
        if self.live:
            return self._fetch_live(cpe)
        if catalog is not None:
            return self._fetch_catalog(cpe, catalog)
        return self._fetch_fixture(cpe)

    def _fetch_fixture(self, cpe: str) -> tuple[list[dict], bool, str]:
        try:
            data = json.loads(self.fixture.read_text())
        except FileNotFoundError:
            return [], False, f"fixture missing: {self.fixture}"
        # the fixture is a single NVD-shaped page; filter vulnerabilities whose
        # configurations reference this CPE head (so one fixture serves many CPEs)
        head = _cpe_head(cpe)
        vulns = [v for v in data.get("vulnerabilities", [])
                 if self._cve_touches_cpe(v.get("cve", {}), head)]
        return vulns, True, "fixture"

    @staticmethod
    def _cve_touches_cpe(cve: dict, head: str) -> bool:
        for cfg in cve.get("configurations") or []:
            for node in cfg.get("nodes") or []:
                for cm in node.get("cpeMatch") or []:
                    if _cpe_head(cm.get("criteria", "")) == head:
                        return True
        return False

    def _fetch_catalog(self, cpe: str, catalog: dict) -> tuple[list[dict], bool, str]:
        """Read pre-injected catalog defects for this CPE — NO network, NO
        fixture file. ``catalog`` is the device input the territory pre-pass
        loaded from the imported spine defects table (``{cpe_head: [defect_row,
        ...]}`` of NVD-sourced rows). Each row is reconstructed to the NVD
        vuln shape so :meth:`_interpret` decides it through the SAME
        :func:`decide_cve_for_device` logic as a live pull — there is ONE
        decision path, not a second one for the catalog.

        A head present in the catalog with zero rows is a COMPLETE absent
        answer (the spine is the whole corpus; absence in the spine IS
        absence — no fallback to the demo fixture, which would leak the
        bundled sample CVEs into a real client's verdicts)."""
        head = _cpe_head(cpe)
        rows = catalog.get(head, [])
        vulns = [self._defect_row_to_vuln(r) for r in rows]
        return vulns, True, f"catalog:{head} ({len(vulns)})"

    @staticmethod
    def _defect_row_to_vuln(row: dict) -> dict:
        """Reconstruct the minimal NVD ``{"cve": {...}}`` shape the live/
        fixture paths consume from one parsed catalog defect row, so the
        catalog-backed assess reuses :meth:`_interpret` /
        :func:`decide_cve_for_device` UNCHANGED. The catalog row is a faithful
        projection of these fields (built by :func:`refresh._enriched_record`
        from the live cve), so nothing the decision + provenance read is lost:
        configurations (the cpeMatch ranges), metrics, descriptions,
        references, and the id. ``decide_cve_for_device`` re-filters the
        reconstructed cpeMatch by the device's CPE head, exactly as it does for
        a live-pulled cve."""
        fr = row.get("fixed_raw") or {}
        cpe_match = [{
            "vulnerable": True,
            "criteria": rng.get("criteria"),
            "versionStartIncluding": rng.get("vstart_incl"),
            "versionStartExcluding": rng.get("vstart_excl"),
            "versionEndIncluding": rng.get("vend_incl"),
            "versionEndExcluding": rng.get("vend_excl"),
        } for rng in (fr.get("ranges") or []) if rng.get("criteria")]
        cve: dict = {
            "id": row.get("id"),
            "configurations": [{"nodes": [{"cpeMatch": cpe_match}]}] if cpe_match else [],
            "descriptions": [{"lang": "en", "value": row.get("description") or ""}],
            "references": [{"url": u} for u in (row.get("refs") or [])],
        }
        # metrics: only when the row carries a score or a vector. _metrics
        # returns (None, None, None) when baseScore is None -> severity falls
        # to "unknown" downstream, the same as a live CVE with no CVSS.
        if row.get("cvss") is not None or row.get("cvss_vector"):
            cve["metrics"] = {"cvssMetricV31": [{"cvssData": {
                "baseScore": row.get("cvss"),
                "vectorString": row.get("cvss_vector")},
                "baseSeverity": row.get("severity")}]}
        return {"cve": cve}

    def _fetch_live(self, cpe: str) -> tuple[list[dict], bool, str]:
        """Real NVD per-CPE pull, paginated, header-only apiKey."""
        api_key = os.environ.get("NVD_API_KEY")
        headers = ["Accept: application/json"]
        if api_key:
            headers.append(f"apiKey: {api_key}")   # HEADER-ONLY (never query string)
        out: list[dict] = []
        start = 0
        reached_total = False
        label = _cpe_head(cpe)
        while start < MAX_RESULTS:
            params = {
                "virtualMatchString": _pad_cpe(cpe),
                "resultsPerPage": PAGE_SIZE,
                "startIndex": start,
            }
            url = NVD_URL + "?" + urllib.parse.urlencode(params)
            data, code, _body = curl_get(url, headers=headers)
            if data is None:
                if code == 404:
                    # could be a rate-limit masquerade; one retry, then absent
                    time.sleep(10)
                    data, code, _ = curl_get(url, headers=headers)
                    if data is None and code == 404:
                        return [], True, f"{label}: absent (404 twice)"  # genuine absent
                if data is None:
                    return out, False, f"{label}: incomplete (http {code or 'timeout'})"
            vulns = data.get("vulnerabilities") or []
            total = data.get("totalResults", 0)
            if not vulns and start == 0:
                return [], True, f"{label}: zero (absent)"  # genuinely zero
            if not vulns:
                return out, False, f"{label}: empty page mid-stream"
            out.extend(vulns)
            start += len(vulns)
            if start >= total:
                reached_total = True
                break
            time.sleep(1.2 if api_key else 8.0)   # throttle: 50/30s keyed, 5/30s anon
        if not reached_total and start >= MAX_RESULTS:
            return out, False, f"{label}: hit MAX_RESULTS cap"
        return out, True, f"{label}: complete ({len(out)})"

    # -- interpret one NVD vuln into a Verdict (or None) ----------------------

    def _interpret(self, vuln: dict, device_ver: str, cpe: str) -> Verdict | None:
        cve = vuln.get("cve", vuln)
        cid = cve.get("id")
        if not cid:
            return None
        status, fixed_in, severity, detail, ranges = decide_cve_for_device(
            cve, device_ver, cpe)
        if status is None:
            return None  # CVE doesn't touch this device's CPE -> skip
        ref = next((u for u in _refs(cve)
                    if "nvd.nist.gov/vuln/detail" in u), None) or f"{NVD_URL}?cveId={cid}"
        return Verdict(
            axis=Axis.VULNERABILITY.value,
            key=cid,
            status=status,
            detail=detail,
            severity=severity,
            fixed_in=fixed_in,
            provenance=Provenance(
                observer=self.id, policy_version="", fetched_at="",
                complete=True, raw_ref=ref,
            ),
        )

    # -- attribution (the required NVD notice) ---------------------

    @staticmethod
    def attribution() -> str:
        return NVD_ATTRIBUTION