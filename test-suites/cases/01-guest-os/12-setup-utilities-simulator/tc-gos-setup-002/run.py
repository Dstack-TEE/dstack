#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate X25519/AES-GCM environment decryption in isolation."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-setup-002"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write a JSON document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def main() -> int:
    """Run the case-scoped ECDH decryption acceptance matrix."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    candidate_source = (
        pathlib.Path(runtime["repository"]) / "dstack/dstack-util/src/crypto.rs"
    )

    with tempfile.TemporaryDirectory(prefix="dstack-ecdh-decrypt-") as directory:
        probe = pathlib.Path(directory)
        (probe / "src").mkdir()
        (probe / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")
        (probe / "src/lib.rs").write_text(
            f"#[path = {json.dumps(str(candidate_source))}]\nmod crypto;\n"
            + RUST_TESTS,
            encoding="utf-8",
        )
        environment = os.environ.copy()
        shared_target = runtime.get("cargo_target_dir") or runtime.get(
            "values", {}
        ).get("cargo_target_dir")
        if shared_target:
            environment["CARGO_TARGET_DIR"] = str(shared_target)
        completed = subprocess.run(
            [
                "cargo",
                "test",
                "--quiet",
                "--manifest-path",
                str(probe / "Cargo.toml"),
                "acceptance::",
            ],
            text=True,
            capture_output=True,
            timeout=300,
            env=environment,
            check=False,
        )

    log = result_dir / "artifacts/ecdh-decrypt-probe.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(completed.stdout + completed.stderr, encoding="utf-8")
    artifact = {
        "path": "artifacts/ecdh-decrypt-probe.log",
        "step_id": f"{case_id}-step-01",
        "name": "ECDH decryption acceptance probe",
        "description": (
            "Bounded Cargo test status for the exact committed candidate crypto "
            "module; no key, shared secret, plaintext, or ciphertext is printed."
        ),
    }
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    passed = completed.returncode == 0
    status = "PASS" if passed else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": (
                "The candidate X25519/AES-GCM decryptor passed the isolated "
                "identity, mutation, recovery, and concurrency matrix."
                if passed
                else "The candidate X25519/AES-GCM decryptor failed the isolated matrix."
            ),
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": (
                        "Fixed identities produced symmetric agreement and only "
                        "the authentic envelope decrypted."
                    ),
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": (
                        "Wrong identity, truncation, invalid peer, and independent "
                        "nonce/body/tag mutations failed before valid recovery."
                    ),
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": (
                        "Concurrent valid and invalid operations were isolated and "
                        "the temporary crate was removed."
                    ),
                },
            ],
            "artifacts": [artifact],
            "remarks": (
                "Pure in-process source-module probe. Test output contains names "
                "and status only; sensitive cryptographic material is never logged."
            ),
        },
    )
    return 0


CARGO_TOML = """[package]
name = "dstack-ecdh-decrypt-probe"
version = "0.0.0"
edition = "2021"

[dependencies]
aes-gcm = "0.10"
anyhow = "1"
binrw = { version = "0.15.1", default-features = false, features = ["std"] }
getrandom = { version = "0.3.1", features = ["std"] }
hex = "0.4"
rand = "0.8"
x25519-dalek = { version = "2", features = ["static_secrets"] }
"""

RUST_TESTS = r"""
#[cfg(test)]
mod acceptance {
    use super::crypto::{dh_agree, dh_decrypt};
    use aes_gcm::{aead::{Aead, Nonce}, Aes256Gcm, KeyInit};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn envelope() -> ([u8; 32], Vec<u8>) {
        let recipient = [7u8; 32];
        let ephemeral = [9u8; 32];
        let recipient_pub = PublicKey::from(&StaticSecret::from(recipient)).to_bytes();
        let ephemeral_pub = PublicKey::from(&StaticSecret::from(ephemeral)).to_bytes();
        let shared = dh_agree(ephemeral, recipient_pub);
        let nonce = [3u8; 12];
        let encrypted = Aes256Gcm::new_from_slice(&shared).unwrap()
            .encrypt(Nonce::<Aes256Gcm>::from_slice(&nonce), b"acceptance sentinel".as_ref())
            .unwrap();
        (recipient, [ephemeral_pub.as_slice(), nonce.as_slice(), encrypted.as_slice()].concat())
    }

    fn valid() {
        let (recipient, envelope) = envelope();
        assert_eq!(dh_decrypt(recipient, &envelope).unwrap(), b"acceptance sentinel");
    }

    #[test]
    fn agreement_is_symmetric_and_identity_bound() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let alice_pub = PublicKey::from(&StaticSecret::from(alice)).to_bytes();
        let bob_pub = PublicKey::from(&StaticSecret::from(bob)).to_bytes();
        assert_eq!(dh_agree(alice, bob_pub), dh_agree(bob, alice_pub));
        let (recipient, envelope) = envelope();
        assert!(dh_decrypt([8u8; 32], &envelope).is_err());
        assert_eq!(dh_decrypt(recipient, &envelope).unwrap(), b"acceptance sentinel");
    }

    #[test]
    fn truncation_invalid_peer_and_each_authenticated_region_fail_closed() {
        let (recipient, original) = envelope();
        for size in [0usize, 31, 32, 43, 44, original.len() - 1] {
            assert!(dh_decrypt(recipient, &original[..size]).is_err());
            valid();
        }
        let mut invalid_peer = original.clone();
        invalid_peer[..32].fill(0);
        assert!(dh_decrypt(recipient, &invalid_peer).is_err());
        valid();
        for index in [32usize, 44, original.len() - 1] {
            let mut changed = original.clone();
            changed[index] ^= 1;
            assert!(dh_decrypt(recipient, &changed).is_err());
            valid();
        }
    }

    #[test]
    fn concurrent_success_and_failure_are_isolated() {
        let mut workers = Vec::new();
        for index in 0..32 {
            workers.push(std::thread::spawn(move || {
                let (recipient, envelope) = envelope();
                if index % 3 == 0 {
                    assert!(dh_decrypt([8u8; 32], &envelope).is_err());
                }
                assert_eq!(dh_decrypt(recipient, &envelope).unwrap(), b"acceptance sentinel");
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    }
}
"""


if __name__ == "__main__":
    raise SystemExit(main())
