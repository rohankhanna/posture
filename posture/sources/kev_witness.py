"""CISA KEV overlay witness — the first REAL witness on the threat axis.

The threat axis answers "what is being
exploited in the wild". This witness overlays a device's own CVE candidates
against the CISA Known Exploited Vulnerabilities (KEV) catalog and emits one
threat-axis ``Verdict`` per CVE, keyed on the CVE id (key_kind "cve"), with
status ``targeted`` / ``clear``:

  - the CVE is in the KEV set -> ``targeted`` (HIGH; exploited in the wild).
  - the CVE is not in the KEV set -> ``clear``.

The engine's per-axis loud-degradation rule turns "no verdicts" into UNKNOWN
(never "clean"), and any KEV-listed CVE drives the threat axis to
``targeted`` (worst present); none listed drives it to ``clear``.

This is the DEVICE-ASSESSMENT (territory) half of posture's KEV use, and is
deliberately distinct from the CI INGEST overlay ``posture/sources/kev.py``
(``kev_ingest_tick`` -> the ``store.kev`` table, never writes verdicts). They
share the "kev" name but live in different namespaces: that module populates
the signed spine's KEV map in CI; THIS module consumes a KEV set as device
input and emits territory verdicts locally. A client imports the spine's
``kev.jsonl`` into its ``store.kev`` and supplies the KEV cve_id set to this
witness via ``device["kev"]`` (inline) or ``device["kev_path"]`` (local JSON
file). ``assess`` gets no DB connection, so it consumes only device input —
no peeking at the local ``store.kev`` table.

False-safe no-op decisions (bias "false-safe"):

  - no ``cve_candidates`` supplied -> honest no-op (nothing to score).
  - ``cve_candidates`` supplied but NO KEV overlay supplied (neither
    ``device["kev"]`` nor ``device["kev_path"]``) -> honest no-op, reason
    "no KEV overlay supplied". We do NOT claim ``clear`` for CVEs we could not
    check against the KEV catalog — that would be a false-safe failure (a
    missing overlay is not "nothing is exploited").
  - an explicitly-EMPTY KEV set (supplied ``[]``) -> all ``clear``. This IS
    honest: "we have the catalog, and nothing matches" is a real answer,
    distinct from "we have no catalog at all".

Contract mirrors cyclonedx_sbom: inline ``device["kev"]`` takes precedence;
a bare/relative ``kev_path`` filename is also tried in the bundled fixture
dir (offline tests); a missing file is an honest no-op (complete=True, zero)
— a local missing file is no input, not a source failure, so it must NOT
trip the no-wipe gate.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..axis import Axis
from ..witness import Witness, WitnessResult, Verdict

# Bundled offline fixture dir. Tests point device["kev_path"] here (or rely on
# the fixture-dir fallback in _read_file) for deterministic, network-free runs.
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "kev"


class KevThreatWitness(Witness):
    """CISA KEV overlay on the threat axis.

    Reads the device's ``cve_candidates`` + a KEV cve_id set (inline list or
    local JSON file) and emits one ``targeted`` / ``clear`` Verdict per CVE,
    keyed on the CVE id. Honest no-op (zero verdicts, complete=True) when the
    device gives no candidates or no KEV overlay — the axis falls to UNKNOWN
    via loud degradation, never silently 'clear'. Local only: no network, no
    live mode, no DB access.
    """

    id = "kev"
    axes = (Axis.THREAT,)
    bias = "false-safe"   # a missing KEV overlay is no-op, never all-clear
    # Declares the identifier kind this witness emits, so the vocab monitor
    # records CVE keys under a known kind ("cve") cleanly instead of surfacing
    # them as an unknown scheme.
    key_kind = "cve"

    def __init__(self, fixture_dir: Path | str | None = None) -> None:
        # `Witness` is a dataclass; pass the identity fields (incl. key_kind)
        # up so they are stamped on the INSTANCE, not just the class — the
        # dataclass-generated __init__ would otherwise shadow the class-level
        # key_kind with None.
        super().__init__(
            id=self.id, axes=self.axes, bias=self.bias, key_kind=self.key_kind,
        )
        self.fixture_dir = Path(fixture_dir) if fixture_dir else FIXTURE_DIR

    # -- the uniform contract ------------------------------------------------

    def assess(self, device: dict, policy) -> WitnessResult:
        candidates = device.get("cve_candidates")
        if not candidates:
            # No CVEs to score -> honest no-op. The engine keeps the threat
            # axis UNKNOWN (loud), never silently 'clear'.
            return WitnessResult(
                verdicts=[], complete=True, reason="no cve candidates supplied",
            )

        # Resolve the KEV overlay set. Inline takes precedence; a path is read
        # (with fixture-dir fallback); a missing file is an honest no-op.
        kev = device.get("kev")
        if kev is None:
            path = device.get("kev_path")
            if path:
                kev = self._read_file(path)
                if kev is None:
                    return WitnessResult(
                        verdicts=[], complete=True, reason="kev path not found",
                    )
            else:
                # Candidates present but NO overlay at all -> false-safe no-op.
                # Do not claim `clear` for CVEs we could not check against KEV.
                return WitnessResult(
                    verdicts=[], complete=True, reason="no KEV overlay supplied",
                )

        # An explicitly-empty KEV set is a real "nothing is exploited" answer
        # (distinct from "no overlay supplied"); all candidates are clear.
        kev_set = set(str(c) for c in kev) if isinstance(kev, list) else set()

        verdicts: list[Verdict] = []
        for cve in candidates:
            cve = str(cve)
            if cve in kev_set:
                verdicts.append(Verdict(
                    axis=Axis.THREAT.value,
                    key=cve,
                    status="targeted",
                    severity="HIGH",
                    detail="in CISA KEV (exploited in the wild)",
                    provenance=self._prov(complete=True, raw_ref=f"kev:{cve}"),
                ))
            else:
                verdicts.append(Verdict(
                    axis=Axis.THREAT.value,
                    key=cve,
                    status="clear",
                    detail="not in CISA KEV",
                    provenance=self._prov(complete=True, raw_ref=f"kev:{cve}"),
                ))

        return WitnessResult(
            verdicts=verdicts, complete=True,
            reason=f"kev overlay: {len(verdicts)} cve(s) scored",
        )

    # -- helpers -------------------------------------------------------------

    def _read_file(self, path: str | Path) -> list | None:
        """Read a JSON file holding a list of KEV cve_ids. Try the literal
        path first, then fall back to the bundled fixture dir (offline tests).
        Returns the list (possibly empty) on success, or None if the file is
        not found in either place."""
        p = Path(path)
        candidates: list[Path] = [p]
        if not p.is_absolute():
            candidates.append(self.fixture_dir / p.name)
        for c in candidates:
            try:
                data = json.loads(c.read_text())
            except (OSError, ValueError):
                continue
            return data if isinstance(data, list) else []
        return None