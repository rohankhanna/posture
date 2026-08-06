"""The three stub witnesses — one per still-unwired non-vulnerability axis.

The inventory and configuration axes are now wired with REAL witnesses
(cyclonedx_sbom and cis_checker respectively), so their stubs were pruned.
What remains here covers the three axes that still have no real witness:
exposure, threat, and trust.

Each stub is an HONEST placeholder: it declares which axis it would serve and
returns no verdicts with a loud reason. The engine's loud-degradation rule
turns "no verdicts" into axis status UNKNOWN — never silently "clean". This
is the honest "the map is blank here" signal AND the exact extension point:
to wire a real witness for an axis, you replace the stub with a real module
implementing the same Witness contract and add a policy entry. Nothing else
in the engine changes.

These stubs are deliberately registered so the policy's intended authority +
bias for each axis is visible (posture witnesses / posture policy show), and
so the engine reports UNKNOWN (not "clean") for every un-wired axis.
"""

from __future__ import annotations
from ..axis import Axis
from ..witness import Witness, WitnessResult


class _Stub(Witness):
    """Common stub behaviour. Subclasses set id, axes, bias."""
    not_implemented_msg = "no witness implemented for {axis}"

    def assess(self, device: dict, policy) -> WitnessResult:
        axis = self.axes[0].value
        return WitnessResult(
            verdicts=[],
            complete=True,
            reason=self.not_implemented_msg.format(axis=axis),
        )


class ExposureStub(_Stub):
    def __init__(self) -> None:
        super().__init__(id="shodan", axes=(Axis.EXPOSURE,), bias="neutral")


class ThreatStub(_Stub):
    def __init__(self) -> None:
        super().__init__(id="kev", axes=(Axis.THREAT,), bias="false-safe")


class TrustStub(_Stub):
    def __init__(self) -> None:
        super().__init__(id="slsa", axes=(Axis.TRUST,), bias="neutral")