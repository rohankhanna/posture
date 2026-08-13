"""Debian security tracker — a real VENDOR observer on the vulnerability axis.

Why this observer exists (the gap it closes): NVD records upstream
``linux_kernel`` CVEs against ``cpe:2.3:o:linux:linux_kernel`` with NO fix
boundary ("affected, no fix recorded"), so posture's NVD observer over-reports
*unknown-fix* on a Debian-based host — a fully-updated Raspberry Pi OS (Debian
13 "trixie") ends up flagged for CVEs Debian fixed long ago. Debian's own
security tracker (``security-tracker.debian.org``) is authoritative: its bulk
``/tracker/data/json`` lists, per source package + per release, each CVE's
status — ``resolved`` (with a fixed dpkg version, or ``"0"`` = not affected),
``open`` (vulnerable), ``undetermined`` (needs triage). This observer downloads
that one bulk document, filters it to the device's candidate CVEs, and
overrides NVD's verdict on the SAME CVE key:

  ``resolved`` + ``fixed_version`` ``"0"``  -> patched  (Debian: not affected)
  ``resolved`` + real ``fixed_version``      -> patched  (fix is in the release)
  ``open``                                    -> unpatched (Debian confirms open)
  ``undetermined`` / release absent / CVE absent -> NO verdict (NVD stands)

The override is by POLICY ORDER, not code: this observer's policy ``order`` is
lower than NVD's, so the engine runs it LAST and it wins on a shared CVE key.
That is the posture port of Forebode's hardcoded vendor-override call order —
here it is one YAML number.

Contract difference from Forebode: Forebode's ``debian_tracker`` fetched the
bulk JSON once per refresh, cached per (cve, release, package) in a DB table,
and the override read it offline (sequential). Posture's observers run in a
pure fan-out and cannot see each other's verdicts (the 5-step core is
invariant), so the candidate CVE set is a DEVICE INPUT —
``device["cve_candidates"]`` — populated in a real run from a prior NVD pass or
the OS package CVE list. The bulk fetch + status mapping are faithful to
Forebode's ground truth (forebode/sources/debian_tracker.py); only the input
channel and the cache layer changed (no DB; the parsed dict is held in memory
for the one assess() call).

DEVICE-ASSUMED-FULLY-UPDATED-LATEST assumption (inherited from the donor): the
device is assumed to run the latest release (fully updated — versions supplied
by hand, no dpkg probe). The verdict is therefore a STATUS MAPPING, not an
installed-vs-fixed version compare: a ``resolved`` row means the fix is in the
release and a fully-updated device has it (-> patched); it does NOT compare the
device's installed kernel version against ``fixed_version``. This is deliberate
and documented; it differs from ``ubuntu_tracker`` which DOES compare.

Device inputs (read from the device dict, follow the ubuntu_tracker convention):
  - ``cve_candidates`` : list of CVE ids to override (filtered to real CVE ids;
    GHSA/PYSEC/etc. have no tracker row and are dropped at the door).
  - ``debian_release`` : Debian release codename, e.g. "trixie" (lowercased).
  - ``debian_packages`` : Debian source packages to consult, e.g. ["linux"]
    (iterated in declared order; first actionable status wins).

Offline mode (default) reads a bundled JSON fixture
(``posture/fixtures/debian_tracker/data.json``) shaped exactly like the bulk
tracker endpoint, so the tests run deterministically with no network. Live mode
(``DebianTrackerObserver(live=True)``) fetches the bulk JSON via curl; the
tracker returns JSON, so curl_get's parsed slot carries the data. A failed or
absent fetch is a complete, zero-verdict no-op (NVD stands) — NEVER a fetch
failure that breaks the engine (no-wipe rule), mirroring the donor's "a failed
download leaves the override a no-op — the run never fails".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..axis import Axis
from ..observer import Observer, ObserverResult, Verdict
from ._net import curl_get

TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
CVE_PAGE_URL = "https://security-tracker.debian.org/tracker/{cve}"
TIMEOUT = 120
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "debian_tracker"
FIXTURE_FILE = "data.json"

# The tracker is keyed by CVE id. A device's candidate set may also carry
# OSV/PyPI advisory ids (GHSA-*, PYSEC-*) from other matchers; those have no
# tracker row. Only real CVE ids are consultable, so filter at the door.
_CVE_ID = re.compile(r"^CVE-\d{4}-\d+$", re.I)


def is_cve_id(cid: str) -> bool:
    """True for real CVE ids (``CVE-YYYY-NNNN``), False for GHSA/PYSEC/etc."""
    return bool(cid) and _CVE_ID.match(cid) is not None


def bulk_extract(
    data: dict, release: str, packages: list[str]
) -> dict[str, tuple[str, str | None]]:
    """Extract ``{cve_id: (status, fixed_in)}`` for ``release`` (codename, e.g.
    'trixie') across ``packages`` (source packages, e.g. ['linux']) from the
    bulk Debian tracker JSON.

    Faithful to forebode/sources/debian_tracker.fetch's row extraction (without
    the DB write): for each package block, each CVE's per-release sub-object is
    read; a CVE with no ``status`` for the release is skipped (not tracked for
    this release). Returns only CVEs that have a status for the release.
    """
    out: dict[str, tuple[str, str | None]] = {}
    for pkg in packages:
        pblock = data.get(pkg) or {}
        for cid, info in pblock.items():
            rel = (info.get("releases") or {}).get(release) or {}
            status = rel.get("status")
            if not status:
                continue  # CVE not tracked for this release
            fix = rel.get("fixed_version") or None
            out[cid] = (status, fix)
    return out


class DebianTrackerObserver(Observer):
    """The Debian security-tracker vendor observer on the vulnerability axis.

    Overrides NVD's false-alarm unknown-fix on Debian-based hosts by fetching
    Debian's authoritative bulk tracker JSON. Emits CVE-keyed Verdicts
    (patched / unpatched) so the engine's per-key override (policy order) lets
    it win over NVD on the same CVE without any code change.

    Bulk, not per-CVE: the Debian endpoint has no small per-CVE JSON, and the
    unknown-fix set is large, so one download serves all candidates (mirrors
    the donor's one-download design).
    """

    id = "debian_tracker"
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
        release = str(device.get("debian_release") or "").strip().lower()
        packages = [p for p in (device.get("debian_packages") or []) if p]
        # No candidate set / release / packages -> honest zero verdicts. The
        # engine keeps NVD's verdicts (this observer adds no keys to override);
        # the loud-degradation rule is unaffected. A non-Debian host simply has
        # nothing for this observer to say.
        if not cves or not release or not packages:
            return ObserverResult(
                verdicts=[], complete=True,
                reason="no debian tracker input "
                        "(device lacks cve_candidates/debian_release/debian_packages)",
            )

        data, reason = self._fetch()
        if data is None:
            # Failed / absent bulk fetch -> complete + zero verdicts (NVD
            # stands). NEVER a fetch failure that breaks the engine (no-wipe).
            return ObserverResult(verdicts=[], complete=True, reason=reason)

        verdicts: list[Verdict] = []
        for cid in cves:
            v = self._decide(cid, release, packages, data)
            if v is not None:
                verdicts.append(v)

        out_reason = reason or ("live" if self.live else "fixture")
        return ObserverResult(verdicts=verdicts, complete=True, reason=out_reason)

    # -- decide one CVE -> a Verdict (or None: NVD stands) ---------------------

    def _decide(
        self, cve_id: str, release: str, packages: list[str], data: dict
    ) -> Verdict | None:
        """First actionable status across the candidate packages (in the order
        the device declared them). Returns None when the tracker has no usable
        verdict for this CVE -> the NVD verdict stands. Faithful to
        forebode/sources/debian_tracker.decide (without the DB read)."""
        ref = CVE_PAGE_URL.format(cve=cve_id)
        for pkg in packages:
            pblock = data.get(pkg) or {}
            info = pblock.get(cve_id) or {}
            rel = (info.get("releases") or {}).get(release) or {}
            status = rel.get("status")
            if not status:
                continue  # CVE not tracked for this release in this package
            fix = rel.get("fixed_version") or None
            if status == "resolved":
                if fix and fix != "0":
                    return Verdict(
                        axis=Axis.VULNERABILITY.value, key=cve_id,
                        status="patched", fixed_in=fix,
                        detail=f"Debian tracker: fixed in {pkg} {fix} ({release}) "
                               f"— device assumed on latest {release}",
                        provenance=self._prov(complete=True, raw_ref=ref),
                    )
                # fixed_version "0" (or empty) -> Debian: not affected
                return Verdict(
                    axis=Axis.VULNERABILITY.value, key=cve_id,
                    status="patched", fixed_in=None,
                    detail=f"Debian tracker: not affected ({pkg}, {release}) "
                           "— clears NVD false positive",
                    provenance=self._prov(complete=True, raw_ref=ref),
                )
            if status == "open":
                return Verdict(
                    axis=Axis.VULNERABILITY.value, key=cve_id,
                    status="unpatched", fixed_in=None,
                    severity="high",
                    detail=f"Debian tracker: open in {release} ({pkg}) "
                           "— Debian confirms vulnerable",
                    provenance=self._prov(complete=True, raw_ref=ref),
                )
            # undetermined / anything else -> try next package, else None
        return None

    # -- fetch (live curl or offline fixture) --------------------------------

    def _fetch(self) -> tuple[dict | None, str]:
        """Return (parsed_bulk_data_or_None, reason). None means absent/failed —
        the caller treats it as a complete, zero-verdict no-op (no-wipe)."""
        if not self.live:
            return self._fetch_fixture()
        return self._fetch_live()

    def _fetch_fixture(self) -> tuple[dict | None, str]:
        import json
        p = self.fixture_dir / FIXTURE_FILE
        try:
            return json.loads(p.read_text()), "fixture"
        except FileNotFoundError:
            # genuine absent — complete + zero (NVD stands), not a failure
            return None, "no fixture (absent)"
        except (ValueError, OSError) as exc:
            # a corrupt fixture is still a no-op, never an engine failure
            return None, f"fixture unreadable ({type(exc).__name__})"

    def _fetch_live(self) -> tuple[dict | None, str]:
        """Real bulk tracker pull via curl. The tracker returns JSON, so
        curl_get's parsed slot (1) carries the data; the body (slot 3) is only
        needed when JSON parsing fails. A non-200 / timeout / parse failure is
        a complete, zero-verdict no-op (NVD stands) — never an incomplete fetch
        (no-wipe), mirroring the donor's "failed download -> stale -> no-op"."""
        data, code, _body = curl_get(
            TRACKER_URL,
            headers=["User-Agent: posture/1.0", "Accept-Encoding: gzip, deflate"],
            max_time=TIMEOUT,
        )
        if code == 200 and data is not None:
            return data, "live"
        # failed / absent / unparseable -> no-op (complete, zero verdicts)
        return None, f"fetch absent (http {code or 'timeout'})"