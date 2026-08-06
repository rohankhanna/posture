"""posture — a source-agnostic, axis-based posture pillar with monitored trust.

Fundamental design:
  CVEs are the spine today; the body is the six axes; the resilience is the
  skeleton/flesh split; and the trust in the spine itself has to be monitored
  as a living thing, because it already nearly broke once.

See README.md and the plan at ~/.claude/plans/linked-popping-alpaca.md.
"""

__version__ = "0.1.0"

# Re-export the core contract for convenience.
from .axis import Axis, AXES, AXIS_META  # noqa: F401
from .witness import (  # noqa: F401
    FetchResult,
    Verdict,
    Provenance,
    WitnessResult,
    Witness,
)