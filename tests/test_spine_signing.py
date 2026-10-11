"""Tests for spine manifest signing and verification — the cryptographic trust
anchor over the spine manifest.

These pin five things:
  1. ``generate_signing_keypair`` produces a valid ed25519 keypair in PEM files;
  2. ``sign_manifest`` writes a hex-encoded ed25519 signature to ``state.sig``
     over the exact bytes of ``manifest.json``;
  3. ``verify_manifest_signature`` succeeds on a valid signature and fails
     loudly (ValueError) on a tampered manifest, wrong key, missing signature,
     or non-hex signature;
  4. the signature is independent of the sha256 manifest-internal consistency
     check — a tampered shard is caught by ``verify_spine`` (sha256), while a
     tampered manifest is caught by ``verify_manifest_signature`` (ed25519);
  5. the CLI round-trip (export --sign-key, import --verify-sig) works end to
     end.

Keys are generated IN-PROCESS by the test (cryptography lib) — no fixture
files, no network, fully hermetic.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from posture import store, export


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _seed(conn) -> None:
    store.upsert_defect(conn, {
        "id": "CVE-2026-5001", "published": "2026-07-04", "cvss": 9.9,
        "severity": "CRITICAL", "description": "test defect",
        "fixed_raw": None, "refs": [], "cwe": [], "ref_tags": [],
        "source": "nvd", "fetched_at": "t1", "policy_version": "v",
        "complete": 1,
    })
    store.set_enrich_state(conn, "CVE-2026-5001", "nvd")
    conn.commit()


def _gen_keypair(tmp_path):
    """Generate a keypair using the export module's own generator."""
    priv = tmp_path / "signing_key.pem"
    pub = tmp_path / "signing_pub.pem"
    export.generate_signing_keypair(priv, pub)
    return priv, pub


# ---------------------------------------------------------------------------
# keypair generation
# ---------------------------------------------------------------------------

def test_generate_keypair_produces_valid_ed25519(tmp_path):
    priv, pub = _gen_keypair(tmp_path)
    assert priv.exists()
    assert pub.exists()
    # private key loads as ed25519
    priv_key = serialization.load_pem_private_key(priv.read_bytes(), password=None)
    assert isinstance(priv_key, ed25519.Ed25519PrivateKey)
    # public key loads as ed25519
    pub_key = serialization.load_pem_public_key(pub.read_bytes())
    assert isinstance(pub_key, ed25519.Ed25519PublicKey)
    # keys match (pub is the public half of priv)
    priv_pub_pem = priv_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert priv_pub_pem == pub.read_bytes()


# ---------------------------------------------------------------------------
# sign + verify round trip
# ---------------------------------------------------------------------------

def test_sign_and_verify_round_trip(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    priv, pub = _gen_keypair(tmp_path)

    sig = export.sign_manifest(out, priv)
    assert isinstance(sig, str)
    sig_file = out / "spine" / "state.sig"
    assert sig_file.exists()
    assert sig_file.read_text().strip() == sig

    # verification succeeds
    export.verify_manifest_signature(out, pub)  # no raise


# ---------------------------------------------------------------------------
# tamper detection
# ---------------------------------------------------------------------------

def test_verify_fails_on_tampered_manifest(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    priv, pub = _gen_keypair(tmp_path)
    export.sign_manifest(out, priv)

    # tamper the manifest
    manifest_path = out / "spine" / "manifest.json"
    m = json.loads(manifest_path.read_text())
    m["counts"]["defects"] = 999
    manifest_path.write_text(json.dumps(m, sort_keys=True, indent=2) + "\n")

    with pytest.raises(ValueError, match="signature verification FAILED"):
        export.verify_manifest_signature(out, pub)


def test_verify_fails_with_wrong_key(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    priv_a, pub_a = _gen_keypair(tmp_path)
    # generate a SECOND keypair
    priv_b = tmp_path / "signing_key_b.pem"
    pub_b = tmp_path / "signing_pub_b.pem"
    export.generate_signing_keypair(priv_b, pub_b)

    export.sign_manifest(out, priv_a)

    # verifying with the wrong public key fails
    with pytest.raises(ValueError, match="signature verification FAILED"):
        export.verify_manifest_signature(out, pub_b)


def test_verify_fails_on_missing_signature(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    _, pub = _gen_keypair(tmp_path)

    # no state.sig written
    with pytest.raises(ValueError, match="signature missing"):
        export.verify_manifest_signature(out, pub)


def test_verify_fails_on_non_hex_signature(conn, tmp_path):
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    priv, pub = _gen_keypair(tmp_path)
    export.sign_manifest(out, priv)

    # corrupt the signature file
    (out / "spine" / "state.sig").write_text("NOT-HEX-AT-ALL\n")

    with pytest.raises(ValueError, match="not valid hex"):
        export.verify_manifest_signature(out, pub)


def test_sign_fails_on_missing_manifest(tmp_path):
    priv, _ = _gen_keypair(tmp_path)
    out = tmp_path / "nonexistent"
    with pytest.raises(ValueError, match="manifest not found"):
        export.sign_manifest(out, priv)


def test_sign_rejects_non_ed25519_key(conn, tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")

    # generate an RSA key instead
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = rsa_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    priv_path = tmp_path / "rsa_key.pem"
    priv_path.write_bytes(rsa_pem)

    with pytest.raises(ValueError, match="not ed25519"):
        export.sign_manifest(out, priv_path)


# ---------------------------------------------------------------------------
# signature vs sha256: they catch different tamper classes
# ---------------------------------------------------------------------------

def test_sha256_catches_shard_tamper_signature_catches_manifest_tamper(conn, tmp_path):
    """The ed25519 signature is over manifest.json; the sha256 checks are over
    each shard. A shard tamper is caught by verify_spine (sha256) but NOT by
    verify_manifest_signature (the manifest itself is unchanged). A manifest
    tamper is caught by verify_manifest_signature but NOT by verify_spine (the
    shards are unchanged, but the manifest no longer matches them — actually
    verify_spine reads the manifest to get the expected sha256, so a manifest
    tamper that changes the sha256 field would also be caught by verify_spine;
    the key point is that the SIGNATURE catches a manifest swap that sha256
    alone cannot, because sha256 is self-referential: the manifest declares its
    own expected hashes)."""
    _seed(conn)
    out = tmp_path / "out"
    export.export_spine(conn, out_dir=out, policy_version="v")
    priv, pub = _gen_keypair(tmp_path)
    export.sign_manifest(out, priv)

    # Case 1: shard tamper — signature still verifies (manifest unchanged),
    # but verify_spine raises
    shard = out / "spine" / "defects" / "2026-07.jsonl"
    shard.write_text(shard.read_text() + '{"id":"EVIL"}\n')
    export.verify_manifest_signature(out, pub)  # still verifies — manifest intact
    with pytest.raises(ValueError, match="sha256 mismatch"):
        export.verify_spine(out)


# ---------------------------------------------------------------------------
# CLI round trip (export --sign-key, import --verify-sig)
# ---------------------------------------------------------------------------

def test_cli_export_sign_and_import_verify(conn, tmp_path):
    from posture import cli
    import argparse, sys

    _seed(conn)
    db = tmp_path / "test.db"
    # dump conn to a file db
    file_conn = store.connect(str(db))
    for row in store.catalog_all(conn):
        store.upsert_defect(file_conn, row)
        store.set_enrich_state(file_conn, row["id"], "nvd")
    file_conn.commit()
    file_conn.close()

    out = tmp_path / "out"
    priv, pub = _gen_keypair(tmp_path)

    # export with signing
    export_args = argparse.Namespace(
        sub="export", out=str(out), from_dir=".", no_verify=False,
        sign_key=str(priv), verify_sig=False, signature_key=None,
        db=str(db), policy=None,
    )
    rc = cli._cmd_spine(export_args)
    assert rc == 0
    assert (out / "spine" / "state.sig").exists()

    # import with signature verification
    import_db = tmp_path / "import.db"
    import_args = argparse.Namespace(
        sub="import", out=".", from_dir=str(out), no_verify=False,
        sign_key=None, verify_sig=True, signature_key=str(pub),
        db=str(import_db), policy=None,
    )
    rc = cli._cmd_spine(import_args)
    assert rc == 0

    # verify data landed
    imp_conn = store.connect(str(import_db))
    defects = store.catalog_all(imp_conn)
    assert len(defects) == 1
    assert defects[0]["id"] == "CVE-2026-5001"
    imp_conn.close()


def test_cli_import_verify_sig_fails_on_tampered(conn, tmp_path):
    from posture import cli
    import argparse

    _seed(conn)
    db = tmp_path / "test.db"
    file_conn = store.connect(str(db))
    for row in store.catalog_all(conn):
        store.upsert_defect(file_conn, row)
        store.set_enrich_state(file_conn, row["id"], "nvd")
    file_conn.commit()
    file_conn.close()

    out = tmp_path / "out"
    priv, pub = _gen_keypair(tmp_path)

    # export with signing
    export_args = argparse.Namespace(
        sub="export", out=str(out), from_dir=".", no_verify=False,
        sign_key=str(priv), verify_sig=False, signature_key=None,
        db=str(db), policy=None,
    )
    cli._cmd_spine(export_args)

    # tamper the manifest
    manifest_path = out / "spine" / "manifest.json"
    m = json.loads(manifest_path.read_text())
    m["counts"]["defects"] = 999
    manifest_path.write_text(json.dumps(m, sort_keys=True, indent=2) + "\n")

    # import with signature verification should fail
    import_db = tmp_path / "import.db"
    import_args = argparse.Namespace(
        sub="import", out=".", from_dir=str(out), no_verify=False,
        sign_key=None, verify_sig=True, signature_key=str(pub),
        db=str(import_db), policy=None,
    )
    with pytest.raises(ValueError, match="signature verification FAILED"):
        cli._cmd_spine(import_args)
