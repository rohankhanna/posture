"""The uniform witness contract — the heart of the skeleton/flesh split.

Every source (NVD, a future CIS checker, a Shodan feed, an SBOM reader) is
one module implementing `Witness`. The engine is source-agnostic: it never
imports a source by name, it asks the registry for the witnesses a policy
authorizes and calls `assess()` on each. Adding a source = writing one module
+ a policy entry. The 5-step core never changes.

This mirrors Forebode's `FetchResult` contract (forebode/sources/__init__.py)
and its verdict shape (forebode/match.py:decide -> {id, status, fixed_in,
reason}), generalized from "device_cve" to "any axis's keyed verdict".
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from typing import Iterable

from .axis import Axis


# ---------------------------------------------------------------------------
# FetchResult — the load-bearing completeness gate (mirrors Forebode)
# ---------------------------------------------------------------------------

@dataclass
class FetchResult:
    """A source fetch: the records gathered + whether the fetch is *provably*
    whole.

    `complete=True` ONLY when the fetch reached the source's end-of-results
    signal (e.g. NVD `totalResults`) or proved the thing genuinely absent.
    `complete=False` on truncation (rate-limit give-up, network error
    mid-stream, cap hit). The engine treats `complete=False` as "do not
    replace stored verdicts" (no-wipe) — fragile remote ends must never delete
    last-known-good state by failing. (Forebode's run-#10 fleet wipe root
    cause: an empty/incomplete pull deleting ~14000 rows.)
    """

    records: list[dict]
    complete: bool
    reason: str = ""

    @classmethod
    def absent(cls) -> "FetchResult":
        """A complete answer of zero records (the source proved absence)."""
        return cls([], complete=True, reason="genuinely absent")


# ---------------------------------------------------------------------------
# Provenance — stamped on every verdict so trust can be unwound retroactively
# ---------------------------------------------------------------------------

@dataclass
class Provenance:
    """Who said this, under which policy, when, and how completely.

    This is the mechanism for retroactive distrust: when a source is later
    found captured/defunded, `provenance.witness` lets you query every verdict
    that rests on it and re-evaluate — without deleting the record (you keep
    the fact that you no longer trust it, auditable).
    """

    witness: str                 # source id, e.g. "nvd"
    policy_version: str           # the trust policy version that authorized this
    fetched_at: str               # ISO-8601 timestamp of the fetch
    complete: bool                # was the underlying fetch provably whole?
    raw_ref: str | None = None    # a citable pointer (URL, record id) to the source datum

    def to_dict(self) -> dict:
        return {
            "witness": self.witness,
            "policy_version": self.policy_version,
            "fetched_at": self.fetched_at,
            "complete": self.complete,
            "raw_ref": self.raw_ref,
        }


# ---------------------------------------------------------------------------
# Verdict — one keyed posture finding on one axis for one device
# ---------------------------------------------------------------------------

@dataclass
class Verdict:
    """One posture finding. `key` is the join key WITHIN the axis:

      - vulnerability -> the CVE id (the spine)
      - configuration  -> a check id (e.g. "CIS-1.1.1")
      - exposure       -> a port / service id
      - inventory      -> package name + version
      - threat         -> an indicator / cve id
      - trust          -> an artifact id

    `status` is axis-appropriate (see axis.AXIS_META[*]["status_set"]). An
    axis with NO verdicts is UNKNOWN (the engine's loud-degradation rule),
    so a Verdict is only ever created when a witness actually had something to
    say — never as a placeholder "all clear".
    """

    axis: str
    key: str
    status: str
    detail: str = ""
    severity: str | None = None
    fixed_in: str | None = None
    provenance: Provenance | None = None

    def to_dict(self) -> dict:
        d = {
            "axis": self.axis,
            "key": self.key,
            "status": self.status,
            "detail": self.detail,
            "severity": self.severity,
            "fixed_in": self.fixed_in,
        }
        if self.provenance is not None:
            d["provenance"] = self.provenance.to_dict()
        return d


# ---------------------------------------------------------------------------
# WitnessResult — what a witness returns from assess()
# ---------------------------------------------------------------------------

@dataclass
class WitnessResult:
    """The output of one witness's assessment of one device.

    `verdicts` carry their witness id in provenance (the engine fills
    policy_version/fetched_at/complete if the witness left them partial).
    `complete` mirrors FetchResult.completeness and gates the no-wipe commit.
    `latency_ms` feeds the source-health operational monitor.
    """

    verdicts: list[Verdict]
    complete: bool
    reason: str = ""
    latency_ms: int = 0


# ---------------------------------------------------------------------------
# Witness — the uniform contract every source implements
# ---------------------------------------------------------------------------

@dataclass
class Witness(ABC):
    """A source of posture signal for one or more axes.

    Subclasses set `id`, `axes`, and a default `bias` (the direction this
    source tends to err — "false-alarm" | "false-safe" | "neutral"). The
    active policy may override `bias`, `weight`, and `order` per-witness.

    `assess(device, policy)` fetches + interprets for one device and returns a
    WitnessResult. The engine times the call (for health), stamps provenance,
    records a health sample, and commits through the completeness gate — so a
    witness implementation only needs to: fetch -> decide per record -> emit
    Verdicts with provenance.witness set.
    """

    id: str
    axes: tuple[Axis, ...]
    bias: str = "neutral"  # default; policy may override
    key_kind: str | None = None  # the identifier kind this witness emits (e.g. "cve")

    @abstractmethod
    def assess(self, device: dict, policy) -> WitnessResult:
        """Assess one device. Return Verdicts on this witness's axes.

        The implementation should set `verdict.provenance.witness = self.id`
        and may set `raw_ref`. The engine fills policy_version / fetched_at /
        complete (from the fetch) if the witness leaves them unset.

        `key_kind` (class-level) declares the identifier kind of the keys this
        witness emits, so the vocab monitor can surface a NEW kind as a
        candidate term (auto) without crashing. Leave None if the witness
        emits no joinable identifier.
        """
        raise NotImplementedError

    # convenience for subclasses: stamp a partial provenance with this witness
    def _prov(self, complete: bool, raw_ref: str | None = None) -> Provenance:
        return Provenance(
            witness=self.id,
            policy_version="",   # filled by the engine
            fetched_at="",        # filled by the engine
            complete=complete,
            raw_ref=raw_ref,
        )


# ---------------------------------------------------------------------------
# WitnessRegistry — the uniform socket sources plug into
# ---------------------------------------------------------------------------

@dataclass
class WitnessRegistry:
    """The set of witnesses available to the engine, keyed by id.

    The engine asks `for_axis(axis, policy)` for the witnesses a policy
    authorizes for an axis, in policy order. A source not in the registry (or
    not in the policy) is simply not consulted — adding a source is
    `registry.register(W)` + a policy entry, nothing else.
    """

    _by_id: dict[str, Witness] = field(default_factory=dict)

    def register(self, w: Witness) -> None:
        if w.id in self._by_id:
            raise ValueError(f"witness already registered: {w.id}")
        self._by_id[w.id] = w

    def get(self, witness_id: str) -> Witness | None:
        return self._by_id.get(witness_id)

    def all(self) -> list[Witness]:
        return list(self._by_id.values())

    def for_axis(self, axis, policy) -> list[Witness]:
        """Witnesses authorized by the policy for `axis`, in authority order:
        LOWER `order` = HIGHER authority, so the lowest-order witness runs LAST
        and overrides the others (priority 1 is the top authority). Ties broken
        by witness id for determinism.

        Axes match by string VALUE, so a promoted non-seed axis (a string, not
        an Axis enum) still matches a witness that declares it — the dimension
        set grows without the enum being the law.
        """
        ax = axis.value if isinstance(axis, Axis) else str(axis)
        authorized: list[Witness] = []
        for w in self._by_id.values():
            w_axes = [a.value if isinstance(a, Axis) else str(a) for a in w.axes]
            if ax not in w_axes:
                continue
            if not policy.has_witness(w.id):
                continue
            authorized.append(w)
        order_of = lambda wid: policy.witness_order(wid)
        # sort by -order ascending => highest order first, lowest order LAST
        return sorted(authorized, key=lambda w: (-order_of(w.id), w.id))

    def used_in(self, verdicts: Iterable[Verdict]) -> list[str]:
        """Distinct witness ids that actually produced a verdict — for
        attribution (only attribute sources that were actually consulted)."""
        seen: list[str] = []
        for v in verdicts:
            wid = v.provenance.witness if v.provenance else ""
            if wid and wid not in seen:
                seen.append(wid)
        return seen