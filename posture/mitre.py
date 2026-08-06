"""MITRE cvelistV5 — the CVE-id naming authority as a stream source.

MITRE's CVE program is the naming authority (Axiom 1 in Forebode's axiom
stack): a CVE id refers to a discretely real, bounded thing, and the same id
in NVD and MITRE is the same point on the map. The cvelistV5 git repo
(``github.com/CVEProject/cvelistV5``) is the authoritative CVE record corpus —
CNAs publish to MITRE's CVE Services and the repo updates within minutes, rate-
limit-free. This module is posture's self-contained port of Forebode's
``corpus`` MITRE pieces (``MITRE_REPO``, ``mitre_repo_path``, ``_mitre_record``,
``_vec_fields``): the record normalizer + the on-disk clone path the stream
ticks.

**The map is not the territory.** A MITRE record is a point on the foreign-
authored map (US CISA-sponsored), not a fact about a machine. A skeleton built
from it says "MITRE published this; NVD has not yet enriched it" — never "this
device is vulnerable." No verdict is claimed until NVD ranges arrive (the
incremental refresh). CVE ids themselves carry no formal ToU attribution, but
the program's sponsorship is disclosed honestly (see ``attribution.ATTRIBUTIONS
['mitre_cve']``).

posture keeps its OWN blobless clone (default ``~/.local/share/posture/cvelist/
cvelistV5``), independent of the Forebode repo; set ``POSTURE_CVELIST_DIR`` to
reuse an existing clone directory (e.g. the Forebode one) without re-cloning.
"""

from __future__ import annotations
import os
import re
from pathlib import Path

MITRE_REPO = "https://github.com/CVEProject/cvelistV5.git"


def mitre_repo_path(cache_dir: str | os.PathLike | None = None) -> Path:
    """On-disk path of posture's cvelistV5 clone. Defaults to
    ``~/.local/share/posture/cvelist/cvelistV5``; the ``POSTURE_CVELIST_DIR``
    env var overrides the parent directory (so an existing clone, e.g. the
    Forebode one, can be reused without re-cloning). Creates the parent dir so a
    first-run clone has a home."""
    base = Path(cache_dir) if cache_dir else \
        Path(os.environ.get(
            "POSTURE_CVELIST_DIR",
            os.path.expanduser("~/.local/share/posture/cvelist")))
    base.mkdir(parents=True, exist_ok=True)
    return base / "cvelistV5"


def vec_fields(vector: str | None) -> dict:
    """Parse AV and C/I/A from a CVSS vector string by splitting on the metric
    separator ('/'). A single-letter regex collides ('C:' matches inside
    'AC:'), so we split 'KEY:VALUE' pairs instead. (Ported from Forebode
    ``corpus._vec_fields``.)"""
    out: dict[str, str | None] = {"av": None, "c": None, "i": None, "a": None}
    if not vector:
        return out
    m: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            m[k] = v
    out["av"] = m.get("AV")
    out["c"] = m.get("C")
    out["i"] = m.get("I")
    out["a"] = m.get("A")
    return out


def mitre_record(rec: dict) -> dict:
    """Normalize a MITRE CVE JSON 5.0 record (the shape found at
    ``cves/<year>/<prefix>/<CVEID>.json`` in cvelistV5). Returns the fields the
    stream skeleton + later NVD enrichment need: id, published, description,
    cwes, cvss vector (if the CNA carried one), and the AV/CIA split. (Ported
    from Forebode ``corpus._mitre_record``.)

    CVE 5.0 ``cna.metrics`` is a LIST of objects each holding a CVSS-version
    key (e.g. ``{"cvssV3_1": {...}}``), NOT a dict — handled tolerantly.
    """
    meta = rec.get("cveMetadata", {}) or {}
    cna = (rec.get("containers", {}) or {}).get("cna", {}) or {}
    descs = [d.get("value", "") for d in cna.get("descriptions", [])
             if d.get("lang") == "en"]
    desc = descs[0].strip() if descs else ""
    cwes: list[str] = []
    for pt in cna.get("problemTypes", []):
        for d in pt.get("descriptions", []):
            cid = d.get("cweId") or ""
            if cid.startswith("CWE-") and cid not in cwes:
                cwes.append(cid)
    # CVSS from CNA metrics (list of {cvssVx_y: {...}}).
    vector: str | None = None
    metrics = cna.get("metrics", []) or []
    if isinstance(metrics, dict):  # tolerant of either shape
        metrics = [metrics]
    for m in metrics:
        if not isinstance(m, dict):
            continue
        for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2"):
            if m.get(k) and isinstance(m[k], dict):
                vector = m[k].get("vectorString")
                if vector:
                    break
        if vector:
            break
    vf = vec_fields(vector)
    return {
        "id": meta.get("cveId", "") or rec.get("cveId", ""),
        "source": "mitre",
        "published": (meta.get("datePublished") or "")[:10] or None,
        "description": desc,
        "cwes": cwes,
        "vector": vector,
        "av": vf["av"], "c": vf["c"], "i": vf["i"], "a": vf["a"],
    }


def mitre_refs(rec: dict) -> list[str]:
    """Reference URLs from a MITRE CVE 5.0 record (``containers.cna.references``).
    Kept separate from :func:`mitre_record` (which exposes exploit/patch booleans
    in Forebode, not the URLs) so the skeleton's ``refs`` — which NVD later
    overwrites — can be extracted here."""
    cna = (rec.get("containers") or {}).get("cna") or {}
    return [r.get("url") for r in cna.get("references", []) if r.get("url")]