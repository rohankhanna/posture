"""Attribution registry — required attribution strings for consumed sources.

Forebode's AGENTS.md standing rule: any NVD-sourced output must emit
`This product uses the NVD API but is not endorsed or certified by the NVD.`
The map is foreign-authored; say so. posture inherits that rule and generalizes
it to a registry so each foreign source can carry its own required notice.
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