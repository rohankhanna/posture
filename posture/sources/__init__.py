"""Source layer — witnesses that plug into the engine's uniform socket.

Adding a source = writing one module implementing Witness + a policy entry.
The engine never imports a source by name; it asks the registry. This package
ships REAL witnesses on the vulnerability axis (nvd_cve + the three vendor
trackers), inventory (cyclonedx_sbom), and configuration (cis_checker), plus
THREE STUB witnesses (exposure/threat/trust) that report loud UNKNOWN until
each of those axes is wired.
"""

from .base import StandardFormatWitness, default_registry  # noqa: F401
from .nvd_cve import NvdCveWitness  # noqa: F401
from .ubuntu_tracker import UbuntuTrackerWitness  # noqa: F401
from .debian_tracker import DebianTrackerWitness  # noqa: F401
from .apple_advisory import AppleAdvisoryWitness  # noqa: F401
from .cyclonedx_sbom import CyclonedxSbomWitness  # noqa: F401
from .cis_checker import CisCheckerWitness  # noqa: F401
from .stubs import (  # noqa: F401
    ExposureStub,
    ThreatStub,
    TrustStub,
)


def build_default_registry() -> "StandardFormatWitness.__class__":  # type: ignore
    """Construct and return a WitnessRegistry with every shipped witness
    registered (real + stubs)."""
    from .base import default_registry as _dr
    return _dr(fresh=True)