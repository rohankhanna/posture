"""Atomic, verified publication of the served spine.

The deployment line serves the spine directory straight to clients, so the
directory must never be observed half-written. These tests pin the publishing
contract:

  1. publish_spine writes a map that verifies against its own manifest
     (every shard's sha256 + row count);
  2. publishing replaces the previous map completely \u2014 no stale shard from the
     previous format survives beside the new one;
  3. a failed export or a failed verification leaves the previously published
     map EXACTLY as it was (the served map is never half-written), and the
     staging directory is cleaned up;
  4. the optional manifest signature is produced before the swap, so the
     published map carries it;
  5. the CLI exposes spine verify (a loud, non-zero failure on a tampered
     shard) and spine publish;
  6. the daily job script publishes through that verified path (it must not
     export straight into the served directory).

Offline and hermetic: no network, no fixtures on disk, keys generated
in-process.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from posture import export, store
from posture.cli import main

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def conn():
    return store.connect(":memory:")


def _seed(conn) -> None:
    store.upsert_defect(conn, {
        "id": "CVE-2026-7001", "published": "2026-07-04", "cvss": 9.9,
        "severity": "CRITICAL", "description": "published defect",
        "fixed_raw": {"source": "nvd", "ranges": []}, "refs": [],
        "source": "nvd", "fetched_at": "t1", "policy_version": "v", "complete": 1,
    })
    store.set_enrich_state(conn, "CVE-2026-7001", "nvd")
    store.upsert_defect(conn, {
        "id": "CVE-2026-7002", "published": "2026-06-15",
        "description": "skeleton", "fixed_raw": {"source": "mitre"},
        "refs": [], "source": "mitre", "fetched_at": "t2",
        "policy_version": "v", "complete": 1,
    })
    store.set_enrich_state(conn, "CVE-2026-7002", "mitre")


def _write_keypair(tmp_path: Path) -> tuple[Path, Path]:
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_path / "signing_key.pem"
    pub_path = tmp_path / "signing_key.pub.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


# ---------------------------------------------------------------------------
# publish_spine
# ---------------------------------------------------------------------------

def test_publish_writes_a_map_that_verifies(conn, tmp_path):
    _seed(conn)
    manifest = export.publish_spine(conn, out_dir=tmp_path, policy_version="v-test")

    assert (tmp_path / "spine" / "manifest.json").exists()
    # the published map verifies against its own manifest
    verified = export.verify_spine(tmp_path)
    assert verified["counts"]["defects"] == 2
    assert manifest["counts"]["defects"] == 2
    # and the staging/previous directories are gone
    assert not (tmp_path / export.STAGING_DIR_NAME).exists()
    assert not (tmp_path / export.PREVIOUS_DIR_NAME).exists()


def test_publish_replaces_the_previous_map_completely(conn, tmp_path):
    _seed(conn)
    # a previous map with a shard in the OLD format, plus a stale manifest
    published = tmp_path / "spine"
    (published / "flaws").mkdir(parents=True)
    (published / "flaws" / "cves.jsonl").write_text('{"id": "CVE-OLD"}\n')
    (published / "manifest.json").write_text('{"manifest_version": "1"}\n')

    export.publish_spine(conn, out_dir=tmp_path, policy_version="v-test")

    # the stale shard is gone: the served directory holds exactly the new map
    assert not (published / "flaws").exists()
    assert not (published / "flaws" / "cves.jsonl").exists()
    export.verify_spine(tmp_path)


def test_a_failed_verification_leaves_the_previous_map_intact(conn, tmp_path, monkeypatch):
    _seed(conn)
    export.publish_spine(conn, out_dir=tmp_path, policy_version="v-test")
    before = (tmp_path / "spine" / "manifest.json").read_bytes()
    before_shards = sorted(p.name for p in (tmp_path / "spine").rglob("*.jsonl"))

    def _boom(_from_dir):
        raise ValueError("shard tampered (sha256 mismatch): spine/defects/2026-07.jsonl")

    monkeypatch.setattr(export, "verify_spine", _boom)
    with pytest.raises(ValueError):
        export.publish_spine(conn, out_dir=tmp_path, policy_version="v-test")

    # the served map is untouched and still the previously published one
    assert (tmp_path / "spine" / "manifest.json").read_bytes() == before
    assert sorted(p.name for p in (tmp_path / "spine").rglob("*.jsonl")) == before_shards
    # nothing half-written is left behind
    assert not (tmp_path / export.STAGING_DIR_NAME).exists()
    assert not (tmp_path / export.PREVIOUS_DIR_NAME).exists()


def test_a_failed_export_leaves_the_previous_map_intact(conn, tmp_path, monkeypatch):
    _seed(conn)
    export.publish_spine(conn, out_dir=tmp_path, policy_version="v-test")
    before = (tmp_path / "spine" / "manifest.json").read_bytes()

    def _boom(*_args, **_kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(export, "export_spine", _boom)
    with pytest.raises(RuntimeError):
        export.publish_spine(conn, out_dir=tmp_path, policy_version="v-test")

    assert (tmp_path / "spine" / "manifest.json").read_bytes() == before
    assert not (tmp_path / export.STAGING_DIR_NAME).exists()


def test_publish_signs_the_manifest_before_the_swap(conn, tmp_path):
    _seed(conn)
    priv_path, pub_path = _write_keypair(tmp_path)

    export.publish_spine(conn, out_dir=tmp_path, policy_version="v-test",
                         sign_key=priv_path)

    sig = tmp_path / "spine" / "state.sig"
    assert sig.exists()
    # the published manifest is the one that was signed
    export.verify_manifest_signature(tmp_path, pub_path)


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------

def test_cli_verify_accepts_a_good_map_and_rejects_a_tampered_one(conn, tmp_path):
    _seed(conn)
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")

    assert main(["spine", "verify", "--from", str(tmp_path)]) == 0

    shard = next((tmp_path / "spine" / "defects").glob("*.jsonl"))
    shard.write_text(shard.read_text() + '{"id": "CVE-INJECTED"}\n')

    assert main(["spine", "verify", "--from", str(tmp_path)]) == 1


def test_cli_publish_writes_a_verifiable_map(tmp_path):
    db = tmp_path / "posture.db"
    conn = store.connect(str(db))
    _seed(conn)
    conn.commit()
    conn.close()

    out = tmp_path / "served"
    assert main(["spine", "publish", "--db", str(db), "--out", str(out)]) == 0
    assert (out / "spine" / "manifest.json").exists()
    export.verify_spine(out)


# ---------------------------------------------------------------------------
# spine verify --verify-sig (the operator's signature check on the served map)
# ---------------------------------------------------------------------------

def test_cli_verify_with_signature_accepts_a_signed_map(conn, tmp_path, capsys):
    # The operator's confirmation of a signed served map is the same trust
    # check a client makes: the manifest's ed25519 signature verifies against
    # the public key before the manifest's internal consistency is trusted.
    _seed(conn)
    priv, pub = _write_keypair(tmp_path)
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")
    export.sign_manifest(tmp_path, priv)

    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--verify-sig", "--signature-key", str(pub)]) == 0
    out = capsys.readouterr().out
    assert "signature verified" in out, out


def test_cli_verify_with_signature_rejects_a_tampered_manifest(
        conn, tmp_path, capsys):
    _seed(conn)
    priv, pub = _write_keypair(tmp_path)
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")
    export.sign_manifest(tmp_path, priv)
    # tamper the signed manifest so its signature no longer matches
    manifest = tmp_path / "spine" / "manifest.json"
    data = json.loads(manifest.read_text())
    data["counts"]["defects"] = 999
    manifest.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")

    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--verify-sig", "--signature-key", str(pub)]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_cli_verify_with_signature_rejects_the_wrong_key(
        conn, tmp_path, capsys):
    _seed(conn)
    priv_a, _ = _write_keypair(tmp_path)
    # a second, unrelated keypair (in its own directory so it does not
    # overwrite the first) the runbook did not sign with
    other = tmp_path / "other"
    other.mkdir()
    priv_b = other / "signing_key.pem"
    pub_b = other / "signing_key.pub.pem"
    export.generate_signing_keypair(priv_b, pub_b)
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")
    export.sign_manifest(tmp_path, priv_a)

    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--verify-sig", "--signature-key", str(pub_b)]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_cli_verify_sig_without_a_signature_key_fails(
        conn, tmp_path, capsys):
    # --verify-sig without --signature-key cannot verify anything, so the
    # command fails loudly rather than silently degrading to an unsigned
    # verification.
    _seed(conn)
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")

    assert main(["spine", "verify", "--from", str(tmp_path),
                 "--verify-sig"]) == 1
    assert "--signature-key" in capsys.readouterr().out


def test_cli_verify_without_verify_sig_is_unchanged(conn, tmp_path, capsys):
    # An unsigned verification must not require a signature or claim one.
    _seed(conn)
    export.export_spine(conn, out_dir=tmp_path, policy_version="v-test")

    assert main(["spine", "verify", "--from", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "signature" not in out, out


# ---------------------------------------------------------------------------
# the daily job script
# ---------------------------------------------------------------------------

def _run_daily_job(tmp_path: Path) -> list[str]:
    """Run scripts/vps_spine.sh against a stub `posture` binary and return the
    recorded invocations (one argv line per call, space-joined)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "posture-calls.log"
    stub = bin_dir / "posture"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{log}"\n'
        "exit 0\n"
    )
    stub.chmod(0o755)

    state = tmp_path / "state"
    state.mkdir()
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["POSTURE_STATE_DIR"] = str(state)
    env["POSTURE_EXPORT_DIR"] = str(state)
    env["POSTURE_CVELIST_DIR"] = str(state / "cvelist")
    env["POSTURE_GHSA_DIR"] = str(state / "ghsa")
    env["POSTURE_DB_PATH"] = str(state / "posture.db")

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "vps_spine.sh")],
        env=env, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return [line for line in log.read_text().splitlines() if line]


def test_the_daily_job_publishes_through_the_verified_path(tmp_path):
    calls = _run_daily_job(tmp_path)

    publishes = [c for c in calls if c.startswith("spine publish")]
    assert len(publishes) == 1, calls
    assert "--out" in publishes[0]
    # the job must not export straight into the served directory any more
    assert not [c for c in calls if c.startswith("spine export")], calls
    # publishing is the LAST step: it is the thing that hands the map over
    assert calls[-1].startswith("spine publish"), calls
    # the map is published after the data plane and the overlays
    assert any(c.startswith("ingest ubuntu") for c in calls), calls
    assert any(c.startswith("ingest debian") for c in calls), calls
