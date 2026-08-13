"""Pure-python signature verification — the first REAL witness on the trust axis.

The trust axis answers "can you trust
what is installed". This witness verifies a supplied signature against a
supplied public key for each artifact the device names, using the
``cryptography`` library (ed25519 by default; rsa-pss also supported). It
emits one trust-axis ``Verdict`` per artifact, keyed on the artifact id
(key_kind "artifact"), with status ``trusted`` / ``untrusted``:

  - the signature verifies under the public key for the payload -> ``trusted``.
  - the signature is invalid, OR any required field (payload / signature /
    public key) is missing, OR the algorithm is unsupported -> ``untrusted``
    (HIGH). This is the false-safe direction: an artifact we cannot verify is
    treated as untrusted and flagged loudly — we never silently skip it or
    call it trusted on absence of evidence.

The engine's per-axis loud-degradation rule turns "no verdicts" into UNKNOWN
(never "clean"), and any untrusted artifact drives the trust axis to
``untrusted`` (worst present); all verified drives it to ``trusted``.

This is a LOCAL witness — it verifies signatures over data the device supplies.
NO network, NO curl_get, NO live mode. The artifact descriptors are a DEVICE
INPUT (``device["artifacts"]`` inline or ``device["artifacts_path"]`` to a
local JSON file), so the fan-out stays pure and the witness stays offline +
deterministic.

The deferred heavier variant is SLSA / cosign keyless attestation (in-toto
DSSE + Fulcio/Rekor) — a future, separately-id'd ``slsa`` witness in the
credentialed lane. This first cut is honest GENERIC signature verification,
which is the core of the trust axis and needs no external service.

Artifact descriptor shape::

    {
      "id":         "artifact id",            # the trust-axis key
      "payload":     "<str or bytes>",        # the signed data; OR payload_path
      "signature":   "<hex or base64>",       # the signature; OR signature_path
      "public_key":  "<PEM or raw>",           # the verifier key; OR public_key_path
      "algorithm":   "ed25519" | "rsa-pss"     # default ed25519
    }

ed25519 public keys may be PEM (SubjectPublicKeyInfo) or raw 32 bytes (hex /
base64); rsa-pss keys must be PEM. Signatures are raw bytes, hex or base64.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from ..axis import Axis
from ..witness import Witness, WitnessResult, Verdict

# cryptography is a declared dependency (pyproject). The guard keeps the
# module importable + registerable even if the wheel is somehow absent in a
# minimal environment (CI does not run pytest, but import must never break
# the engine): in that case every artifact is reported untrusted (false-safe).
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - cryptography is a declared dep
    _HAS_CRYPTO = False
    InvalidSignature = Exception

# Bundled offline fixture dir (tests may point artifacts_path here).
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "artifacts"


# ---------------------------------------------------------------------------
# field resolution + decode helpers (never raise; None => missing)
# ---------------------------------------------------------------------------

def _payload_bytes(a: dict) -> bytes | None:
    val = a.get("payload")
    if val is None:
        path = a.get("payload_path")
        if path:
            try:
                return Path(path).read_bytes()
            except OSError:
                return None
        return None
    if isinstance(val, bytes):
        return val
    return str(val).encode("utf-8")


def _decode_sig(s) -> bytes | None:
    """A signature is raw bytes; if given as a string, hex then base64."""
    if isinstance(s, bytes):
        return s
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        pass
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return None


def _signature_bytes(a: dict) -> bytes | None:
    val = a.get("signature")
    if val is None:
        path = a.get("signature_path")
        if path:
            try:
                return Path(path).read_bytes()
            except OSError:
                return None
        return None
    return _decode_sig(val)


def _public_key_bytes(a: dict) -> bytes | None:
    val = a.get("public_key")
    if val is None:
        path = a.get("public_key_path")
        if path:
            try:
                return Path(path).read_bytes()
            except OSError:
                return None
        return None
    if isinstance(val, bytes):
        return val
    return str(val).encode("utf-8")


def _load_ed25519(pub_bytes: bytes):
    """Load an ed25519 public key from PEM, or from raw 32 bytes (the bytes
    as-is, or hex/base64-decoded). Raises if none load."""
    if b"BEGIN" in pub_bytes:
        return serialization.load_pem_public_key(pub_bytes)
    candidates: list[bytes] = [pub_bytes]
    try:
        candidates.append(bytes.fromhex(pub_bytes.decode("ascii")))
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        candidates.append(base64.b64decode(pub_bytes, validate=True))
    except Exception:
        pass
    last_err: Exception | None = None
    for c in candidates:
        try:
            return ed25519.Ed25519PublicKey.from_public_bytes(c)
        except Exception as e:  # not 32 raw bytes / wrong material
            last_err = e
    raise ValueError(f"could not load ed25519 public key: {last_err}")


def _verify(a: dict, algorithm: str | None) -> tuple[bool, str]:
    """Return (ok, reason). reason is the algorithm name on success, or a
    short failure detail on failure. Never raises."""
    payload = _payload_bytes(a)
    sig = _signature_bytes(a)
    pub = _public_key_bytes(a)
    if payload is None:
        return False, "no payload"
    if sig is None:
        return False, "no signature"
    if pub is None:
        return False, "no public key"
    algo = (algorithm or "ed25519").strip().lower()
    try:
        if algo == "ed25519":
            key = _load_ed25519(pub)
            if not isinstance(key, ed25519.Ed25519PublicKey):
                # a PEM key that isn't ed25519 -> wrong key type for algo
                return False, "key is not an ed25519 public key"
            key.verify(sig, payload)
            return True, "ed25519"
        if algo == "rsa-pss":
            key = serialization.load_pem_public_key(pub)
            if not isinstance(key, rsa.RSAPublicKey):
                return False, "key is not an RSA public key"
            key.verify(
                sig, payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                             salt_length=padding.PSS.DIGEST_LENGTH),
                hashes.SHA256(),
            )
            return True, "rsa-pss"
        return False, f"unsupported algorithm: {algo}"
    except InvalidSignature:
        return False, "signature invalid"
    except Exception as e:
        return False, f"verify error: {type(e).__name__}"


# ---------------------------------------------------------------------------
# the witness
# ---------------------------------------------------------------------------

class SigVerifyWitness(Witness):
    """Pure-python signature verification on the trust axis.

    Reads artifact descriptors the device supplies (inline list or local JSON
    file) and emits one ``trusted`` / ``untrusted`` Verdict per artifact, keyed
    on the artifact id. Honest no-op (zero verdicts, complete=True) when the
    device gives no artifacts — the axis falls to UNKNOWN via loud degradation,
    never silently 'trusted'. Local only: no network, no live mode.
    """

    id = "sigverify"
    axes = (Axis.TRUST,)
    bias = "false-safe"   # unverifiable artifact -> untrusted, never skipped
    # Declares the identifier kind this witness emits, so the vocab monitor
    # records artifact-id keys under a known kind ("artifact") cleanly instead
    # of surfacing them as an unknown scheme.
    key_kind = "artifact"

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
        artifacts = device.get("artifacts")
        if isinstance(artifacts, list):
            arts = artifacts
        else:
            path = device.get("artifacts_path")
            if path:
                arts = self._read_file(path)
                if arts is None:
                    return WitnessResult(
                        verdicts=[], complete=True, reason="artifacts path not found",
                    )
            else:
                # No artifacts supplied -> honest no-op. Zero verdicts,
                # complete=True so the engine keeps the trust axis UNKNOWN
                # (loud), never silently 'trusted' — and never crashes.
                return WitnessResult(
                    verdicts=[], complete=True, reason="no artifacts supplied",
                )

        verdicts: list[Verdict] = []
        for a in arts:
            if not isinstance(a, dict):
                continue
            aid = a.get("id")
            if not aid:
                continue   # no join key within the trust axis
            key = str(aid)

            if not _HAS_CRYPTO:  # pragma: no cover - declared dep
                verdicts.append(Verdict(
                    axis=Axis.TRUST.value, key=key, status="untrusted",
                    severity="HIGH", detail="untrusted: cryptography library unavailable",
                    provenance=self._prov(complete=True, raw_ref=f"sigverify:{key}"),
                ))
                continue

            ok, reason = _verify(a, a.get("algorithm"))
            if ok:
                verdicts.append(Verdict(
                    axis=Axis.TRUST.value,
                    key=key,
                    status="trusted",
                    detail=f"signature verified ({reason})",
                    provenance=self._prov(complete=True, raw_ref=f"sigverify:{key}"),
                ))
            else:
                verdicts.append(Verdict(
                    axis=Axis.TRUST.value,
                    key=key,
                    status="untrusted",
                    severity="HIGH",
                    detail=f"untrusted: {reason}",
                    provenance=self._prov(complete=True, raw_ref=f"sigverify:{key}"),
                ))

        return WitnessResult(
            verdicts=verdicts, complete=True,
            reason=f"sigverify: {len(verdicts)} artifact(s) checked",
        )

    # -- helpers -------------------------------------------------------------

    def _read_file(self, path: str | Path) -> list | None:
        """Read a JSON file holding the artifact list. Try the literal path
        first, then fall back to the bundled fixture dir (offline tests).
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