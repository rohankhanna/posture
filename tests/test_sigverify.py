"""Tests for the sigverify trust observer — the first REAL observer on the
trust axis.

These pin four things:
  1. a valid signature under the supplied public key -> ``trusted``; an invalid
     signature, a tampered payload, a wrong key, or any missing required field
     -> ``untrusted`` (HIGH; the false-safe direction — never silently skip);
  2. both supported algorithms work: ed25519 (default, PEM or raw key, hex/
     base64 signature) and rsa-pss (PEM key);
  3. the observer is an honest no-op (zero verdicts, complete=True) when the
     device gives no artifacts and when an ``artifacts_path`` file is missing —
     never a crash, never 'trusted';
  4. in the engine, the trust axis becomes REAL: ``trusted`` when all
     artifacts verify, ``untrusted`` when any fails, ``unknown`` when the
     observer no-ops, and the committed per-verdict rows attribute to observer
     "sigverify".

Keys are generated IN-PROCESS by the test (cryptography lib) — no fixture
files, no network, fully hermetic + sovereign.

SELF-CONTAINED: builds its own ObserverRegistry + Policy inline (no reliance on
the shared default registry / policy file). Mirrors test_cyclonedx_sbom.py's
style.
"""
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from posture.axis import Axis
from posture.policy import Policy
from posture import store, engine
from posture.observer import ObserverRegistry
from posture.sources.sigverify import SigVerifyObserver

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "posture" / "fixtures"
SAMPLE_DEVICE = FIXTURE_DIR / "sample_device.yaml"


_INLINE_POLICY_YAML = """
version: "2026-08-06.3"
supersedes: "2026-08-06.2"
dated: 2026-08-06
rationale: |
  test policy for the sigverify trust observer (self-contained test).
observers:
  sigverify:
    axes: [trust]
    weight: high
    bias: false-safe
    order: 10
    conditions: []
"""


def _policy() -> Policy:
    return Policy.from_yaml(_INLINE_POLICY_YAML)


def _registry() -> ObserverRegistry:
    reg = ObserverRegistry()
    reg.register(SigVerifyObserver())
    return reg


# ---------------------------------------------------------------------------
# in-process key fixtures
# ---------------------------------------------------------------------------

def _ed25519_pair():
    """Return (pub_pem_str, sign_fn) for a fresh ed25519 keypair."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return pub_pem, priv.sign


def _rsa_pair():
    """Return (pub_pem_str, sign_fn) for a fresh rsa keypair (PSS/SHA256)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    def sign(payload: bytes) -> bytes:
        return priv.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )

    return pub_pem, sign


# ---------------------------------------------------------------------------
# observer (offline): trusted / untrusted / no-op
# ---------------------------------------------------------------------------

def test_observer_valid_ed25519_signature_is_trusted():
    w = SigVerifyObserver()
    pol = _policy()
    pub_pem, sign = _ed25519_pair()
    sig_hex = sign(b"payload").hex()
    device = {"id": "host", "artifacts": [
        {"id": "pkgA", "payload": "payload", "signature": sig_hex,
         "public_key": pub_pem},
    ]}
    result = w.assess(device, pol)
    assert result.complete is True
    assert len(result.verdicts) == 1
    v = result.verdicts[0]
    assert v.axis == Axis.TRUST.value
    assert v.key == "pkgA"
    assert v.status == "trusted"
    assert v.severity is None
    assert "ed25519" in v.detail
    assert v.provenance.observer == "sigverify"
    assert v.provenance.raw_ref == "sigverify:pkgA"


def test_observer_ed25519_default_algorithm_when_field_absent():
    pub_pem, sign = _ed25519_pair()
    w = SigVerifyObserver()
    pol = _policy()
    device = {"id": "host", "artifacts": [
        {"id": "pkgA", "payload": "payload", "signature": sign(b"payload").hex(),
         "public_key": pub_pem},   # no "algorithm" -> defaults to ed25519
    ]}
    result = w.assess(device, pol)
    assert result.verdicts[0].status == "trusted"


def test_observer_tampered_payload_is_untrusted():
    w = SigVerifyObserver()
    pol = _policy()
    pub_pem, sign = _ed25519_pair()
    sig_hex = sign(b"payload").hex()
    device = {"id": "host", "artifacts": [
        {"id": "pkgA", "payload": "TAMPERED", "signature": sig_hex,
         "public_key": pub_pem},
    ]}
    result = w.assess(device, pol)
    assert result.verdicts[0].status == "untrusted"
    assert result.verdicts[0].severity == "HIGH"
    assert "signature invalid" in result.verdicts[0].detail


def test_observer_wrong_key_is_untrusted():
    w = SigVerifyObserver()
    pol = _policy()
    _pub_pem_a, sign_a = _ed25519_pair()
    pub_pem_b, _sign_b = _ed25519_pair()   # a different keypair
    sig_hex = sign_a(b"payload").hex()
    device = {"id": "host", "artifacts": [
        {"id": "pkgA", "payload": "payload", "signature": sig_hex,
         "public_key": pub_pem_b},   # signed by A, verified against B
    ]}
    result = w.assess(device, pol)
    assert result.verdicts[0].status == "untrusted"


def test_observer_missing_signature_is_untrusted_false_safe():
    w = SigVerifyObserver()
    pol = _policy()
    pub_pem, _ = _ed25519_pair()
    device = {"id": "host", "artifacts": [
        {"id": "pkgA", "payload": "payload", "public_key": pub_pem},  # no sig
    ]}
    result = w.assess(device, pol)
    assert result.verdicts[0].status == "untrusted"
    assert "no signature" in result.verdicts[0].detail


def test_observer_missing_public_key_is_untrusted():
    pub_pem, sign = _ed25519_pair()
    w = SigVerifyObserver()
    pol = _policy()
    device = {"id": "host", "artifacts": [
        {"id": "pkgA", "payload": "payload", "signature": sign(b"payload").hex()},
        # no public_key
    ]}
    result = w.assess(device, pol)
    assert result.verdicts[0].status == "untrusted"
    assert "no public key" in result.verdicts[0].detail


def test_observer_missing_payload_is_untrusted():
    pub_pem, sign = _ed25519_pair()
    w = SigVerifyObserver()
    pol = _policy()
    device = {"id": "host", "artifacts": [
        {"id": "pkgA", "signature": sign(b"payload").hex(), "public_key": pub_pem},
        # no payload
    ]}
    result = w.assess(device, pol)
    assert result.verdicts[0].status == "untrusted"
    assert "no payload" in result.verdicts[0].detail


def test_observer_unsupported_algorithm_is_untrusted():
    pub_pem, sign = _ed25519_pair()
    w = SigVerifyObserver()
    pol = _policy()
    device = {"id": "host", "artifacts": [
        {"id": "pkgA", "payload": "payload", "signature": sign(b"payload").hex(),
         "public_key": pub_pem, "algorithm": "hmac"},   # unsupported
    ]}
    result = w.assess(device, pol)
    assert result.verdicts[0].status == "untrusted"
    assert "unsupported algorithm" in result.verdicts[0].detail


def test_observer_valid_rsa_pss_signature_is_trusted():
    w = SigVerifyObserver()
    pol = _policy()
    pub_pem, sign = _rsa_pair()
    sig_hex = sign(b"payload").hex()
    device = {"id": "host", "artifacts": [
        {"id": "pkgA", "payload": "payload", "signature": sig_hex,
         "public_key": pub_pem, "algorithm": "rsa-pss"},
    ]}
    result = w.assess(device, pol)
    assert result.verdicts[0].status == "trusted"
    assert "rsa-pss" in result.verdicts[0].detail


def test_observer_base64_signature_decodes():
    """A base64 (not hex) signature is accepted — the decoder tries hex then
    base64."""
    import base64 as _b64
    pub_pem, sign = _ed25519_pair()
    sig_b64 = _b64.b64encode(sign(b"payload")).decode()
    w = SigVerifyObserver()
    pol = _policy()
    device = {"id": "host", "artifacts": [
        {"id": "pkgA", "payload": "payload", "signature": sig_b64,
         "public_key": pub_pem},
    ]}
    result = w.assess(device, pol)
    assert result.verdicts[0].status == "trusted"


def test_observer_multiple_artifacts_mixed_trust():
    w = SigVerifyObserver()
    pol = _policy()
    pub_pem_a, sign_a = _ed25519_pair()
    good = sign_a(b"payload").hex()
    device = {"id": "host", "artifacts": [
        {"id": "good", "payload": "payload", "signature": good, "public_key": pub_pem_a},
        {"id": "bad", "payload": "payload", "signature": good, "public_key": "wrong"},
        {"id": "ugly", "payload": "payload", "public_key": pub_pem_a},  # no sig
    ]}
    result = w.assess(device, pol)
    by_key = {v.key: v for v in result.verdicts}
    assert by_key["good"].status == "trusted"
    assert by_key["bad"].status == "untrusted"
    assert by_key["ugly"].status == "untrusted"


def test_observer_no_artifacts_is_honest_noop():
    w = SigVerifyObserver()
    pol = _policy()
    result = w.assess({"id": "host"}, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "no artifacts supplied" in result.reason


def test_observer_missing_artifacts_path_is_complete_zero_not_failure():
    w = SigVerifyObserver()
    pol = _policy()
    result = w.assess({"id": "host", "artifacts_path": "/no/such/artifacts.json"}, pol)
    assert result.verdicts == []
    assert result.complete is True
    assert "artifacts path not found" in result.reason


def test_observer_artifacts_path_reads_inline_file(tmp_path):
    pub_pem, sign = _ed25519_pair()
    sig_hex = sign(b"payload").hex()
    import json
    p = tmp_path / "arts.json"
    p.write_text(json.dumps([
        {"id": "pkgA", "payload": "payload", "signature": sig_hex, "public_key": pub_pem},
    ]))
    w = SigVerifyObserver()
    pol = _policy()
    result = w.assess({"id": "host", "artifacts_path": str(p)}, pol)
    assert result.verdicts[0].status == "trusted"
    assert result.verdicts[0].provenance.raw_ref == "sigverify:pkgA"


def test_observer_skips_artifacts_without_id():
    pub_pem, sign = _ed25519_pair()
    w = SigVerifyObserver()
    pol = _policy()
    device = {"id": "host", "artifacts": [
        {"payload": "payload", "signature": sign(b"payload").hex(), "public_key": pub_pem},  # no id
        {"id": "pkgA", "payload": "payload", "signature": sign(b"payload").hex(), "public_key": pub_pem},
        "not-a-dict",
    ]}
    result = w.assess(device, pol)
    assert [v.key for v in result.verdicts] == ["pkgA"]


# ---------------------------------------------------------------------------
# engine: trust axis becomes REAL (trusted/untrusted) with input, UNKNOWN
# without
# ---------------------------------------------------------------------------

def test_engine_trust_axis_trusted_when_all_verify_and_attributed_rows():
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    pub_pem, sign = _ed25519_pair()
    device = {"id": "demo-host", "artifacts": [
        {"id": "pkgA", "payload": "payload", "signature": sign(b"payload").hex(),
         "public_key": pub_pem},
        {"id": "pkgB", "payload": "payload2", "signature": sign(b"payload2").hex(),
         "public_key": pub_pem},
    ]}
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")

    rows = {r["key"]: r for r in
            store.verdicts_for_device_axis(conn, "demo-host", "trust")}
    assert sorted(rows) == ["pkgA", "pkgB"]
    for r in rows.values():
        assert r["observer"] == "sigverify"
        assert r["status"] == "trusted"
        assert r["complete"] == 1

    tru = {a.axis: a for a in dp.axes}["trust"]
    assert tru.status == "trusted"
    assert tru.deciding_observer == "sigverify"
    assert "sigverify" in dp.used_observers

    ap = store.axis_posture(conn, "demo-host", "trust")
    assert ap["status"] == "trusted"


def test_engine_trust_axis_untrusted_when_any_fails():
    """An untrusted artifact is the worst status on the trust axis and drives
    the axis to 'untrusted' even if other artifacts verify."""
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    pub_pem, sign = _ed25519_pair()
    device = {"id": "demo-host", "artifacts": [
        {"id": "good", "payload": "payload", "signature": sign(b"payload").hex(),
         "public_key": pub_pem},
        {"id": "bad", "payload": "TAMPERED", "signature": sign(b"payload").hex(),
         "public_key": pub_pem},
    ]}
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")
    tru = {a.axis: a for a in dp.axes}["trust"]
    assert tru.status == "untrusted"                  # worst present wins


def test_engine_trust_axis_unknown_without_artifacts():
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    dp = engine.assess({"id": "demo-host"}, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")
    tru = {a.axis: a for a in dp.axes}["trust"]
    assert tru.status == "unknown"
    assert tru.verdicts == []
    assert tru.gap is not None
    assert store.verdicts_for_device_axis(conn, "demo-host", "trust") == []
    assert "sigverify" not in dp.used_observers


def test_engine_default_demo_device_trust_stays_unknown():
    reg = _registry()
    pol = _policy()
    conn = store.connect(":memory:")
    device = yaml.safe_load(SAMPLE_DEVICE.read_text())
    dp = engine.assess(device, reg, pol, conn=conn,
                       now="2026-08-06T00:00:00+00:00")
    tru = {a.axis: a for a in dp.axes}["trust"]
    assert tru.status == "unknown"
    assert tru.verdicts == []