#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify deterministic key derivation, purpose binding, and app isolation."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

from eth_keys import keys
from nacl.signing import SigningKey as Ed25519SigningKey

CASE_ID = "tc-gos-attestatio-003"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def rpc(url: str, method: str, body: dict[str, Any]) -> dict[str, Any]:
    """Make a bounded JSON RPC request with readiness retries."""
    for attempt in range(1, 11):
        request = urllib.request.Request(
            url.replace("{method}", method),
            data=json.dumps(body, separators=(",", ":")).encode(),
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                value = json.load(response)
            break
        except urllib.error.HTTPError:
            raise
        except (ConnectionError, OSError, TimeoutError, urllib.error.URLError):
            if attempt == 10:
                raise
            time.sleep(2)
    if not isinstance(value, dict):
        raise AssertionError(f"{method} returned non-object JSON")
    return value


def rejected(url: str, body: dict[str, Any]) -> dict[str, Any]:
    """Require GetKey to reject an invalid input."""
    request = urllib.request.Request(
        url.replace("{method}", "GetKey"),
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            payload = response.read()
            raise AssertionError(
                f"GetKey accepted invalid input with HTTP {response.status}: {len(payload)} bytes"
            )
    except urllib.error.HTTPError as error:
        payload = error.read()
        return {
            "http_status": error.code,
            "diagnostic_present": bool(payload),
            "diagnostic_sha256": hashlib.sha256(payload).hexdigest(),
        }


def public_key(seed: bytes, algorithm: str) -> bytes:
    """Interpret one 32-byte seed using the requested algorithm."""
    if len(seed) != 32:
        raise AssertionError(f"{algorithm} seed length was {len(seed)}, not 32")
    if algorithm == "ed25519":
        return bytes(Ed25519SigningKey(seed).verify_key)
    if algorithm == "secp256k1":
        return keys.PrivateKey(seed).public_key.to_compressed_bytes()
    raise AssertionError(f"unsupported local algorithm: {algorithm}")


def derive(
    url: str, path: str, purpose: str, algorithm: str
) -> tuple[bytes, bytes, bytes, bytes, dict[str, Any]]:
    """Derive a key and cryptographically validate its purpose-bound chain head."""
    value = rpc(
        url,
        "GetKey",
        {"path": path, "purpose": purpose, "algorithm": algorithm},
    )
    seed = bytes.fromhex(str(value["key"]))
    chain_value = value.get("signature_chain")
    if not isinstance(chain_value, list) or len(chain_value) != 2:
        raise AssertionError(f"{algorithm} signature chain did not contain two entries")
    chain = [bytes.fromhex(str(item)) for item in chain_value]
    if len(chain[0]) != 65:
        raise AssertionError(f"{algorithm} chain-head signature length was invalid")
    derived_public = public_key(seed, algorithm)
    message = f"{purpose}:{derived_public.hex()}".encode()
    signature = keys.Signature(signature_bytes=chain[0])
    recovered = signature.recover_public_key_from_msg(message)
    if not recovered.verify_msg(message, signature):
        raise AssertionError(f"{algorithm} purpose-bound signature did not verify")
    root = recovered.to_compressed_bytes()
    observation = {
        "algorithm": algorithm,
        "path_sha256": hashlib.sha256(path.encode()).hexdigest(),
        "purpose_sha256": hashlib.sha256(purpose.encode()).hexdigest(),
        "seed_sha256": hashlib.sha256(seed).hexdigest(),
        "public_key_sha256": hashlib.sha256(derived_public).hexdigest(),
        "public_key_length": len(derived_public),
        "chain_entries": len(chain),
        "chain_head_verified": True,
        "chain_head_signature_sha256": hashlib.sha256(chain[0]).hexdigest(),
        "app_root_sha256": hashlib.sha256(root).hexdigest(),
        "kms_signature_present": bool(chain[1]),
        "kms_signature_sha256": (
            hashlib.sha256(chain[1]).hexdigest() if chain[1] else None
        ),
    }
    return seed, derived_public, root, chain[1], observation


def validate_kms_chain(
    signature_bytes: bytes,
    app_id_hex: str,
    app_root: bytes,
    expected_root: keys.PublicKey | None = None,
) -> tuple[keys.PublicKey, dict[str, bool]]:
    """Verify one KMS-issued app-root signature and reject three mutations."""
    if len(signature_bytes) != 65:
        raise AssertionError("KMS app-root signature length was invalid")
    app_id = bytes.fromhex(app_id_hex)
    if not app_id:
        raise AssertionError("app identity was empty")
    message = b"dstack-kms-issued:" + app_id + app_root
    signature = keys.Signature(signature_bytes=signature_bytes)
    recovered = signature.recover_public_key_from_msg(message)
    if not recovered.verify_msg(message, signature):
        raise AssertionError("KMS app-root signature did not verify")
    if expected_root is not None and recovered != expected_root:
        raise AssertionError("signature chain recovered a different KMS root")
    trusted_root = expected_root or recovered

    tampered_signature = bytearray(signature_bytes)
    tampered_signature[0] ^= 1
    try:
        tampered_signature_rejected = not trusted_root.verify_msg(
            message, keys.Signature(signature_bytes=bytes(tampered_signature))
        )
    except ValueError:
        tampered_signature_rejected = True
    tampered_app_id = bytearray(app_id)
    tampered_app_id[0] ^= 1
    app_id_mutation_rejected = not trusted_root.verify_msg(
        b"dstack-kms-issued:" + bytes(tampered_app_id) + app_root, signature
    )
    tampered_root = bytearray(app_root)
    tampered_root[0] ^= 1
    app_root_mutation_rejected = not trusted_root.verify_msg(
        b"dstack-kms-issued:" + app_id + bytes(tampered_root), signature
    )
    mutations = {
        "signature_mutation_rejected": tampered_signature_rejected,
        "app_id_mutation_rejected": app_id_mutation_rejected,
        "app_root_mutation_rejected": app_root_mutation_rejected,
    }
    if not all(mutations.values()):
        raise AssertionError("KMS chain mutation did not fail closed")
    return trusted_root, mutations


def main() -> int:
    """Run deterministic key derivation and purpose separation acceptance."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    values = manifest.get("values", {})
    services = values.get("services", {})
    primary = services.get("DstackGuest") if isinstance(services, dict) else None
    peer = values.get("key_derivation_peer")
    status = "PASS"
    summary = (
        "Key determinism, path, algorithm, purpose, and app separation were verified."
    )
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    stage = "capability"
    try:
        capable = (
            isinstance(primary, dict)
            and isinstance(primary.get("url"), str)
            and isinstance(peer, dict)
            and peer.get("app_relation") == "different-compose-and-app-id"
            and isinstance(peer.get("dstack_guest_url"), str)
        )
        if not capable:
            status = "BLOCKED"
            summary = "fixture lacks different-app DstackGuest key derivation peers"
            observations["missing_capability"] = "key-derivation-app-isolation-peer"
        else:
            primary_url = str(primary["url"])
            peer_url = str(peer["dstack_guest_url"])
            stage = "health-before"
            info_before = rpc(primary_url, "Info", {})
            peer_info = rpc(peer_url, "Info", {})
            if not info_before.get("app_id") or not peer_info.get("app_id"):
                raise AssertionError("primary or peer app identity was absent")
            if info_before["app_id"] == peer_info["app_id"]:
                raise AssertionError("fixture peers had the same app identity")
            run_hash = hashlib.sha256(
                os.environ["DSTACK_TEST_RUN_ID"].encode()
            ).hexdigest()
            path_a = f"acceptance/{run_hash[:16]}"
            path_b = f"acceptance/{run_hash[16:32]}"
            purpose_a = "acceptance-a"
            purpose_b = "acceptance-b"
            stage = "primary-repeat"
            seed_a, pub_a, root_a, kms_a, row_a = derive(
                primary_url, path_a, purpose_a, "secp256k1"
            )
            seed_repeat, pub_repeat, root_repeat, kms_repeat, row_repeat = derive(
                primary_url, path_a, purpose_a, "secp256k1"
            )
            if (seed_a, pub_a, root_a) != (seed_repeat, pub_repeat, root_repeat):
                raise AssertionError("same app/path derivation was not deterministic")
            stage = "purpose-separation"
            seed_purpose, pub_purpose, root_purpose, kms_purpose, row_purpose = derive(
                primary_url, path_a, purpose_b, "secp256k1"
            )
            if seed_purpose != seed_a or pub_purpose != pub_a or root_purpose != root_a:
                raise AssertionError(
                    "purpose unexpectedly changed seed, key, or app root"
                )
            if row_purpose["kms_signature_sha256"] != row_a["kms_signature_sha256"]:
                raise AssertionError(
                    "purpose changed the stable KMS app-root signature"
                )
            if (
                row_purpose["chain_head_signature_sha256"]
                == row_a["chain_head_signature_sha256"]
            ):
                raise AssertionError("purpose did not change the chain-head signature")
            stage = "algorithm-separation"
            seed_ed, pub_ed, root_ed, kms_ed, row_ed = derive(
                primary_url, path_a, purpose_a, "ed25519"
            )
            if seed_ed != seed_a:
                raise AssertionError("algorithm unexpectedly changed the derived seed")
            if pub_ed == pub_a or root_ed != root_a:
                raise AssertionError(
                    "algorithm public-key or app-root separation failed"
                )
            stage = "path-separation"
            seed_path, _, root_path, kms_path, row_path = derive(
                primary_url, path_b, purpose_a, "secp256k1"
            )
            if seed_path == seed_a or root_path != root_a:
                raise AssertionError("different path seed or app-root relation failed")
            stage = "app-separation"
            seed_peer, _, root_peer, kms_peer, row_peer = derive(
                peer_url, path_a, purpose_a, "secp256k1"
            )
            if seed_peer == seed_a or root_peer == root_a:
                raise AssertionError("different app did not isolate seed and app root")
            kms_root, mutations = validate_kms_chain(
                kms_a, str(info_before["app_id"]), root_a
            )
            kms_rows = (
                (kms_repeat, str(info_before["app_id"]), root_repeat, row_repeat),
                (kms_purpose, str(info_before["app_id"]), root_purpose, row_purpose),
                (kms_ed, str(info_before["app_id"]), root_ed, row_ed),
                (kms_path, str(info_before["app_id"]), root_path, row_path),
                (kms_peer, str(peer_info["app_id"]), root_peer, row_peer),
            )
            for kms_signature, app_id, app_root, row in kms_rows:
                validate_kms_chain(kms_signature, app_id, app_root, kms_root)
                row["kms_chain_verified"] = True
            row_a["kms_chain_verified"] = True
            row_a["kms_mutations"] = mutations
            observations["kms_root_sha256"] = hashlib.sha256(
                kms_root.to_compressed_bytes()
            ).hexdigest()
            observations["kms_chain_mutations"] = mutations
            kms_chain_present = bool(
                row_a["kms_signature_present"]
                and row_repeat["kms_signature_present"]
                and row_purpose["kms_signature_present"]
                and row_ed["kms_signature_present"]
                and row_path["kms_signature_present"]
                and row_peer["kms_signature_present"]
            )
            if (
                kms_chain_present
                and row_peer["kms_signature_sha256"] == row_a["kms_signature_sha256"]
            ):
                raise AssertionError("different app reused the KMS app-root signature")
            stage = "invalid-algorithm"
            invalid = rejected(
                primary_url,
                {"path": path_a, "purpose": purpose_a, "algorithm": "rsa2048"},
            )
            stage = "health-after"
            info_after = rpc(primary_url, "Info", {})
            if info_after.get("app_id") != info_before.get("app_id") or info_after.get(
                "instance_id"
            ) != info_before.get("instance_id"):
                raise AssertionError("primary identity changed during key matrix")
            if not kms_chain_present:
                status = "BLOCKED"
                summary = "fixture lacks KMS-signed app-root signature chains"
                observations["missing_capability"] = "kms-signed-app-root-chain"
            observations.update(
                {
                    "primary_repeat": [row_a, row_repeat],
                    "purpose": row_purpose,
                    "algorithm": row_ed,
                    "path": row_path,
                    "peer": row_peer,
                    "invalid": invalid,
                    "same_app_path_seed_stable": True,
                    "purpose_seed_stable": True,
                    "purpose_signature_binding_changed": row_purpose[
                        "chain_head_signature_sha256"
                    ]
                    != row_a["chain_head_signature_sha256"],
                    "algorithm_seed_stable": True,
                    "algorithm_public_key_separated": True,
                    "path_seed_separated": True,
                    "app_seed_and_root_separated": True,
                    "service_healthy_after": True,
                }
            )
    except (
        AssertionError,
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        urllib.error.URLError,
    ) as error:
        status = "FAIL"
        summary = f"{stage}: {error}"
        observations["failure"] = str(error)
        observations["failure_stage"] = stage
    artifact = {
        "path": "artifacts/key-derivation-purpose.json",
        "step_id": f"{case_id}-step-01",
        "name": "Key derivation and purpose separation",
        "description": "Key, public-key, root, chain, path, and purpose hashes without secret seed bytes.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "Primary and different-app peer identities and DstackGuest listeners were checked.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Repeated, purpose, algorithm, path, and peer derivations were exercised with cryptographic chain-head recovery.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Invalid algorithm rejection, identity stability, and redacted seed/root separation were verified.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Derived secret bytes are compared in memory only; artifacts retain one-way hashes and public-key lengths.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
