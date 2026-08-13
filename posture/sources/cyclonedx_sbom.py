"""CycloneDX SBOM reader — the first REAL witness on the inventory axis.

A CycloneDX SBOM is the *measured floor* of what is
installed on a device — the ground truth under the other axes (you can't be
vulnerable for a package you didn't install; you can't trust what isn't
there). This witness reads one (inline via ``device["sbom"]`` or a local JSON
file via ``device["sbom_path"]``) and emits one ``present`` Verdict per
component, keyed ``<name>@<version>``. The inventory axis is never 'clear'
when an SBOM is supplied: ``present`` is the honest non-clean status (an axis
with packages on it is a map with marks on it, not a green field). With no SBOM
the witness is an HONEST NO-OP — zero verdicts, ``complete=True`` — so the
engine's loud-degradation rule makes the axis UNKNOWN (loud), never silently
'clean'. A missing ``sbom_path`` file is treated the same way (complete=True,
zero) — a local missing file is no input, not a source failure, so it must
NOT trip the no-wipe gate.

This is a LOCAL witness: it reads an SBOM the device supplies. NO network,
NO ``curl_get``, NO live mode. It subclasses ``StandardFormatWitness`` (the
scaffolding left in sources/base.py explicitly for CycloneDX) and implements
the two hook methods ``fetch`` + ``parse``; provenance and the ``assess``
flow are shared by the base (do not override ``assess``).

Device input fields introduced:
  - ``device["sbom"]``      — an inline CycloneDX-shaped dict with a
                              ``components`` list of ``{name, version, ...}``.
  - ``device["sbom_path"]`` — path to a CycloneDX JSON file on disk. For
                              offline tests, point this at the bundled fixture
                              ``posture/fixtures/sbom/sample.json``. If the
                              literal path is missing, the bundled fixture dir
                              is tried as a fallback before reporting
                              'sbom path not found'.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..axis import Axis
from ..witness import Verdict
from .base import StandardFormatWitness

# Bundled offline fixture dir. Tests point device["sbom_path"] here (or rely
# on the fallback in _read_file) for deterministic, network-free runs.
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "sbom"


class CyclonedxSbomWitness(StandardFormatWitness):
    """CycloneDX SBOM reader on the inventory axis.

    Reads a CycloneDX SBOM the device supplies (inline dict or local JSON file)
    and emits one ``present`` Verdict per named component, keyed
    ``<name>@<version>``. Honest no-op (zero verdicts, complete=True) when the
    device gives no SBOM — the axis falls to UNKNOWN via loud degradation,
    never silently 'clear'. Local only: no network, no live mode.
    """

    id = "cyclonedx_sbom"
    axes = (Axis.INVENTORY,)
    bias = "neutral"
    fmt = "cyclonedx"
    # Declares the identifier kind this witness emits, so the vocab monitor
    # records "<name>@<version>" keys under a known kind ("package") cleanly
    # instead of surfacing them as an unknown scheme.
    key_kind = "package"

    def __init__(self, fixture_dir: Path | str | None = None) -> None:
        # `Witness` is a dataclass; pass the identity fields (incl. key_kind)
        # up so they are stamped on the INSTANCE, not just the class — the
        # dataclass-generated __init__ would otherwise shadow the class-level
        # key_kind with None.
        super().__init__(
            id=self.id, axes=self.axes, bias=self.bias, key_kind=self.key_kind,
        )
        self.fixture_dir = Path(fixture_dir) if fixture_dir else FIXTURE_DIR

    # -- fetch: read the SBOM (inline dict or local file) ---------------------

    def fetch(self, device: dict, policy) -> tuple[list[dict], bool, str]:
        """Return ``(components, complete, reason)``. Never raises.

        - ``device["sbom"]`` (a CycloneDX-shaped dict with a ``components``
          list) -> use it directly.
        - ``device["sbom_path"]`` (path to a CycloneDX JSON file). The literal
          path is tried first; if missing, the bundled fixture dir is tried as
          a fallback (offline tests). Still missing -> complete=True, zero
          ("sbom path not found") — a local missing file is no input, not a
          source failure, so it must NOT trip the no-wipe gate.
        - Neither supplied -> complete=True, zero, "no sbom supplied" (honest
          no-op; the axis falls to UNKNOWN via loud degradation, not 'clear').
        """
        sbom = device.get("sbom")
        if isinstance(sbom, dict):
            comps = sbom.get("components")
            if not isinstance(comps, list):
                comps = []
            return comps, True, "inline sbom"

        path = device.get("sbom_path")
        if path:
            comps = self._read_file(path)
            if comps is None:
                return [], True, "sbom path not found"
            return comps, True, f"sbom file: {path}"

        return [], True, "no sbom supplied"

    def _read_file(self, path: str | Path) -> list[dict] | None:
        """Read a CycloneDX JSON file. Try the literal path first, then fall
        back to the bundled fixture dir (offline tests). Returns the
        ``components`` list (possibly empty) on success, or None if the file
        is not found in either place."""
        p = Path(path)
        candidates: list[Path] = [p]
        # A bare/relative filename may name a bundled fixture — try it in the
        # fixture dir too. (An absolute path is taken literally; a missing one
        # genuinely is missing.)
        if not p.is_absolute():
            candidates.append(self.fixture_dir / p.name)
        for c in candidates:
            try:
                data = json.loads(c.read_text())
            except (OSError, ValueError):
                continue
            comps = data.get("components") if isinstance(data, dict) else None
            return comps if isinstance(comps, list) else []
        return None

    # -- parse: components -> present Verdicts --------------------------------

    def parse(self, components: list[dict], device: dict,
              policy) -> list[Verdict]:
        """One ``present`` Verdict per named component, keyed ``<name>@<version>``.

        Components without a name are skipped (no key to join on within the
        inventory axis). ``version`` defaults to "" if absent — the key still
        uniquely identifies the package line as "this name, this version (or
        unversioned)". Provenance is stamped with the witness id + a citable
        raw_ref to the SBOM source (the base ``assess`` re-stamps the witness
        id and the engine fills policy_version/fetched_at/complete).
        """
        raw_ref = self._source_ref(device)
        out: list[Verdict] = []
        for c in components:
            if not isinstance(c, dict):
                continue
            name = c.get("name")
            if not name:
                continue   # no name -> no join key within the inventory axis
            version = str(c.get("version") or "")
            # collapse the empty-version case to "libc installed (SBOM)" rather
            # than "libc  installed (SBOM)" (the naive f-string leaves a double
            # space when version is "").
            label = f"{name} {version}".strip()
            detail = f"{label} installed (SBOM)"
            out.append(Verdict(
                axis=Axis.INVENTORY.value,
                key=f"{name}@{version}",
                status="present",
                detail=detail,
                provenance=self._prov(complete=True, raw_ref=raw_ref),
            ))
        return out

    # -- helpers -------------------------------------------------------------

    def _source_ref(self, device: dict) -> str:
        """A citable pointer to the SBOM the device supplied (raw_ref on
        provenance). For an inline dict, an inline: pseudo-ref; for a file,
        the path."""
        if device.get("sbom_path"):
            return str(device["sbom_path"])
        return "inline:device.sbom"