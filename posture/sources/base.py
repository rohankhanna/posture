"""Observer base + standard-format adapter scaffolding + the registry builder.

The bet on standard formats is the hedge against domain expansion: anything
that speaks STIX 2.x, CSAF, OSV-schema, or CycloneDX can be ingested by a
generic adapter rather than a per-source parser. A new source that adopts a
standard costs ~zero to add. `StandardFormatObserver` is the scaffolding for
those adapters — the parse hook is left to subclasses; the fetch/provenance/
health plumbing is shared.
"""

from __future__ import annotations
from abc import abstractmethod

from ..axis import Axis
from ..observer import Observer, ObserverResult, Verdict, ObserverRegistry, Provenance
from .nvd_cve import NvdCveObserver
from .ubuntu_tracker import UbuntuTrackerObserver
from .debian_tracker import DebianTrackerObserver
from .apple_advisory import AppleAdvisoryObserver
from .cis_checker import CisCheckerObserver

# curl helper lives in _net.py (kept dependency-free to avoid an import cycle).
from ._net import curl_get  # noqa: F401  (re-exported for observers/subclasses)


class StandardFormatObserver(Observer):
    """Base for observers that ingest a STANDARD format (CSAF/OSV/STIX/
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
        """Turn parsed standard docs into Verdicts on this observer's axes."""
        raise NotImplementedError

    def assess(self, device: dict, policy) -> ObserverResult:
        docs, complete, reason = self.fetch(device, policy)
        verdicts = self.parse(docs, device, policy) if complete or docs else []
        # stamp the observer id into provenance; engine fills the rest
        for v in verdicts:
            if v.provenance is None:
                v.provenance = Provenance(observer=self.id, policy_version="",
                                          fetched_at="", complete=complete)
            else:
                v.provenance = Provenance(
                    observer=self.id, policy_version=v.provenance.policy_version,
                    fetched_at=v.provenance.fetched_at,
                    complete=v.provenance.complete, raw_ref=v.provenance.raw_ref,
                )
        return ObserverResult(verdicts=verdicts, complete=complete, reason=reason)


def default_registry(fresh: bool = False) -> ObserverRegistry:
    """The shipped registry: a real observer on every axis. vulnerability
    (nvd + the three vendor trackers), inventory (cyclonedx_sbom),
    configuration (cis_checker), exposure (local_exposure), threat (kev),
    trust (sigverify). `fresh=True` forces a new instance (tests want
    isolation)."""
    reg = ObserverRegistry()
    reg.register(NvdCveObserver())
    reg.register(UbuntuTrackerObserver())   # vendor observers (vuln axis) —
    reg.register(DebianTrackerObserver())   # override NVD on the same CVE key
    reg.register(AppleAdvisoryObserver())    # by policy order (< nvd's 10)
    # CyclonedxSbomObserver subclasses StandardFormatObserver (defined in THIS
    # module), so import it lazily inside the builder to avoid a top-level
    # circular import (base <-> cyclonedx_sbom). By the time this function
    # runs, StandardFormatObserver is fully defined.
    from .cyclonedx_sbom import CyclonedxSbomObserver
    reg.register(CyclonedxSbomObserver())     # first real observer on inventory
    reg.register(CisCheckerObserver())       # first real observer on configuration
    # The remaining three axes are now wired with real observers too (lazy
    # imports keep top-level import cycles out: each module imports Observer
    # + ObserverResult/Verdict from ..observer, not from this base module).
    from .local_exposure import LocalExposureObserver
    from .firewall import FirewallObserver
    from .network_interfaces import NetworkInterfacesObserver
    from .live_network_interfaces import LiveNetworkInterfacesObserver
    from .kev_observer import KevThreatObserver
    from .sigverify import SigVerifyObserver
    reg.register(LocalExposureObserver())     # exposure: local surface reader
    reg.register(FirewallObserver())           # exposure: firewall-state grounding probe
    reg.register(NetworkInterfacesObserver())  # exposure: interface grounding (device snapshot)
    reg.register(LiveNetworkInterfacesObserver())  # exposure: interface grounding (live ip -j addr, overrides snapshot)
    reg.register(KevThreatObserver())         # threat: CISA KEV overlay
    reg.register(SigVerifyObserver())         # trust: signature verification
    return reg