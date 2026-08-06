"""Source layer — witnesses that plug into the engine's uniform socket.

Adding a source = writing one module implementing Witness + a policy entry.
The engine never imports a source by name; it asks the registry. This package
ships a REAL witness on EVERY axis: vulnerability (nvd_cve + the three vendor
trackers), inventory (cyclonedx_sbom), configuration (cis_checker), exposure
(local_exposure), threat (kev_witness), and trust (sigverify). An axis with no
verdicts still reports loud UNKNOWN via the engine's loud-degradation rule, but
no axis is left at a stub.
"""

from .base import StandardFormatWitness, default_registry  # noqa: F401
from .nvd_cve import NvdCveWitness  # noqa: F401
from .ubuntu_tracker import UbuntuTrackerWitness  # noqa: F401
from .debian_tracker import DebianTrackerWitness  # noqa: F401
from .apple_advisory import AppleAdvisoryWitness  # noqa: F401
from .cyclonedx_sbom import CyclonedxSbomWitness  # noqa: F401
from .cis_checker import CisCheckerWitness  # noqa: F401
from .local_exposure import LocalExposureWitness  # noqa: F401
from .kev_witness import KevThreatWitness  # noqa: F401
from .sigverify import SigVerifyWitness  # noqa: F401


def build_default_registry() -> "StandardFormatWitness.__class__":  # type: ignore
    """Construct and return a WitnessRegistry with every shipped witness
    registered (real + stubs)."""
    from .base import default_registry as _dr
    return _dr(fresh=True)