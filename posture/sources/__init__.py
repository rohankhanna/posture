"""Source layer — observers that plug into the engine's uniform socket.

Adding a source = writing one module implementing Observer + a policy entry.
The engine never imports a source by name; it asks the registry. This package
ships a REAL observer on EVERY axis: vulnerability (nvd_cve + the three vendor
trackers), inventory (cyclonedx_sbom), configuration (cis_checker), exposure
(local_exposure), threat (kev_observer), and trust (sigverify). An axis with no
verdicts still reports loud UNKNOWN via the engine's loud-degradation rule, but
no axis is left at a stub.
"""

from .base import StandardFormatObserver, default_registry  # noqa: F401
from .nvd_cve import NvdCveObserver  # noqa: F401
from .ubuntu_tracker import UbuntuTrackerObserver  # noqa: F401
from .debian_tracker import DebianTrackerObserver  # noqa: F401
from .apple_advisory import AppleAdvisoryObserver  # noqa: F401
from .cyclonedx_sbom import CyclonedxSbomObserver  # noqa: F401
from .cis_checker import CisCheckerObserver  # noqa: F401
from .local_exposure import LocalExposureObserver  # noqa: F401
from .firewall import FirewallObserver  # noqa: F401
from .network_interfaces import NetworkInterfacesObserver  # noqa: F401
from .live_network_interfaces import LiveNetworkInterfacesObserver, parse_ip_addr_json  # noqa: F401
from .kev_observer import KevThreatObserver  # noqa: F401
from .sigverify import SigVerifyObserver  # noqa: F401


def build_default_registry() -> "StandardFormatObserver.__class__":  # type: ignore
    """Construct and return a ObserverRegistry with every shipped observer
    registered (real + stubs)."""
    from .base import default_registry as _dr
    return _dr(fresh=True)