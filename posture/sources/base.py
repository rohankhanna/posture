"""Witness base + standard-format adapter scaffolding + the registry builder.

The bet on standard formats is the hedge against domain expansion: anything
that speaks STIX 2.x, CSAF, OSV-schema, or CycloneDX can be ingested by a
generic adapter rather than a per-source parser. A new source that adopts a
standard costs ~zero to add. `StandardFormatWitness` is the scaffolding for
those adapters — the parse hook is left to subclasses; the fetch/provenance/
health plumbing is shared.
"""

from __future__ import annotations
from abc import abstractmethod

from ..axis import Axis
from ..witness import Witness, WitnessResult, Verdict, WitnessRegistry, Provenance
from .nvd_cve import NvdCveWitness
from .ubuntu_tracker import UbuntuTrackerWitness
from .debian_tracker import DebianTrackerWitness
from .apple_advisory import AppleAdvisoryWitness
from .cis_checker import CisCheckerWitness

# curl helper lives in _net.py (kept dependency-free to avoid an import cycle).
from ._net import curl_get  # noqa: F401  (re-exported for witnesses/subclasses)


class StandardFormatWitness(Witness):
    """Base for witnesses that ingest a STANDARD format (CSAF/OSV/STIX/
    CycloneDX). Subclasses implement `parse(records, device, policy)` to turn
    parsed standard docs into Verdicts; fetch + provenance + health are shared.

    This is deliberately a thin scaffold: the point is the uniform socket, not
    a half-implemented adapter. Each standard gets a concrete subclass when
    that axis is wired (out of scope for this skeleton build).
    """

    fmt: str = "abstract"   # e.g. "csaf" / "osv" / "cyclonedx"

    @abstractmethod
    def fetch(self, device: dict, policy) -> tuple[list[dict], bool, str]:
        """Return (parsed_docs, complete, reason). Subclasses decide where to
        fetch from and how to parse the standard format into list[dict]."""
        raise NotImplementedError

    @abstractmethod
    def parse(self, docs: list[dict], device: dict, policy) -> list[Verdict]:
        """Turn parsed standard docs into Verdicts on this witness's axes."""
        raise NotImplementedError

    def assess(self, device: dict, policy) -> WitnessResult:
        docs, complete, reason = self.fetch(device, policy)
        verdicts = self.parse(docs, device, policy) if complete or docs else []
        # stamp the witness id into provenance; engine fills the rest
        for v in verdicts:
            if v.provenance is None:
                v.provenance = Provenance(witness=self.id, policy_version="",
                                          fetched_at="", complete=complete)
            else:
                v.provenance = Provenance(
                    witness=self.id, policy_version=v.provenance.policy_version,
                    fetched_at=v.provenance.fetched_at,
                    complete=v.provenance.complete, raw_ref=v.provenance.raw_ref,
                )
        return WitnessResult(verdicts=verdicts, complete=complete, reason=reason)


def default_registry(fresh: bool = False) -> WitnessRegistry:
    """The shipped registry: a real witness on every axis. vulnerability
    (nvd + the three vendor trackers), inventory (cyclonedx_sbom),
    configuration (cis_checker), exposure (local_exposure), threat (kev),
    trust (sigverify). `fresh=True` forces a new instance (tests want
    isolation)."""
    reg = WitnessRegistry()
    reg.register(NvdCveWitness())
    reg.register(UbuntuTrackerWitness())   # vendor witnesses (vuln axis) —
    reg.register(DebianTrackerWitness())   # override NVD on the same CVE key
    reg.register(AppleAdvisoryWitness())    # by policy order (< nvd's 10)
    # CyclonedxSbomWitness subclasses StandardFormatWitness (defined in THIS
    # module), so import it lazily inside the builder to avoid a top-level
    # circular import (base <-> cyclonedx_sbom). By the time this function
    # runs, StandardFormatWitness is fully defined.
    from .cyclonedx_sbom import CyclonedxSbomWitness
    reg.register(CyclonedxSbomWitness())     # first real witness on inventory
    reg.register(CisCheckerWitness())       # first real witness on configuration
    # The remaining three axes are now wired with real witnesses too (lazy
    # imports keep top-level import cycles out: each module imports Witness
    # + WitnessResult/Verdict from ..witness, not from this base module).
    from .local_exposure import LocalExposureWitness
    from .kev_witness import KevThreatWitness
    from .sigverify import SigVerifyWitness
    reg.register(LocalExposureWitness())     # exposure: local surface reader
    reg.register(KevThreatWitness())         # threat: CISA KEV overlay
    reg.register(SigVerifyWitness())         # trust: signature verification
    return reg