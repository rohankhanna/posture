"""Attribution registry — required attribution strings for consumed sources.

Project rule: any NVD-sourced output must emit
`This product uses the NVD API but is not endorsed or certified by the NVD.`
The map is foreign-authored; say so. posture generalizes this to a registry so
each foreign source can carry its own required notice.
"""

from __future__ import annotations

# The NVD ToU-required attribution string (Forebode: forebode/corpus.py:NVD_ATTRIBUTION).
NVD_ATTRIBUTION = "This product uses the NVD API but is not endorsed or certified by the NVD."

# registry: witness id -> required attribution line (empty string = none required)
ATTRIBUTIONS: dict[str, str] = {
    "nvd": NVD_ATTRIBUTION,
    # mitre_cve: MITRE's CVE program is US-gov-funded; no formal ToU attribution
    # required for the ids themselves, but noting sponsorship is honest.
    "mitre_cve": "CVE ids are assigned under the MITRE CVE program (US CISA-sponsored).",
    # kev: CISA's Known Exploited Vulnerabilities catalog — public domain US-gov
    # data; no formal ToU attribution required, but noting the source is honest.
    "kev": "KEV overlay data from the CISA Known Exploited Vulnerabilities catalog.",
    # ghsa: GitHub Advisory Database — CC-BY 4.0; attribution per the license.
    "ghsa": "Advisory data from the GitHub Advisory Database (CC-BY 4.0).",
    # osv: OSV.dev / GCS export — aggregate of many ecosystem DBs; the hub itself
    # is CC-BY 4.0 (OSV.dev), with per-ecosystem licenses varying.
    "osv": "Vulnerability data from OSV.dev (aggregated ecosystem advisories).",
    # apple_advisory: Apple security advisories are public; no formal ToU
    # attribution required, but noting the source is honest.
    "apple_advisory": "Apple fix-version data from Apple security advisories (support.apple.com).",
}


def attribution_for(witness_id: str) -> str:
    """Return the required attribution line for a witness, or '' if none."""
    return ATTRIBUTIONS.get(witness_id, "")


def all_attributions(used_witnesses: list[str]) -> list[str]:
    """Distinct, order-preserving attribution lines for the witnesses actually
    used in a run (so reports only emit attributions for sources they touched)."""
    seen: list[str] = []
    for w in used_witnesses:
        line = attribution_for(w)
        if line and line not in seen:
            seen.append(line)
    return seen