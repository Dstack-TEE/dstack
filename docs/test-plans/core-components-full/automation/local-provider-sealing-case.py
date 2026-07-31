#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate physical TDX quote sealing against the SGX local key provider."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

from nacl.public import PrivateKey, SealedBox

CASE_ID = "tc-gos-platform-002"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Atomically write one JSON evidence document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")
        temporary = pathlib.Path(f.name)
    temporary.replace(path)


def rpc(url: str, method: str, body: dict[str, Any]) -> dict[str, Any]:
    """Call one JSON guest RPC without retaining sensitive response data."""
    request = urllib.request.Request(
        url.replace("{method}", method),
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError("guest RPC returned a non-object")
    return value


def provider_request(host: str, port: int, quote: bytes) -> dict[str, Any]:
    """Send one framed in-memory quote to the lease-visible provider."""
    payload = json.dumps({"quote": list(quote)}, separators=(",", ":")).encode()
    with socket.create_connection((host, port), timeout=90) as stream:
        stream.settimeout(90)
        stream.sendall(struct.pack(">I", len(payload)) + payload)
        header = stream.recv(4)
        if len(header) != 4:
            raise RuntimeError("provider closed before response header")
        expected = struct.unpack(">I", header)[0]
        response = bytearray()
        while len(response) < expected:
            part = stream.recv(expected - len(response))
            if not part:
                raise RuntimeError("provider closed before complete response")
            response.extend(part)
    value = json.loads(response)
    if not isinstance(value, dict):
        raise RuntimeError("provider returned a non-object")
    return value


def derive(tappd_url: str, host: str, port: int) -> tuple[bytes, dict[str, Any]]:
    """Derive a key in memory and return it with non-sensitive observations."""
    private_key = PrivateKey.generate()
    report_data = bytes(private_key.public_key) + bytes(32)
    quote_attempts = 0
    while True:
        quote_attempts += 1
        try:
            quote_value = rpc(tappd_url, "RawQuote", {"report_data": report_data.hex()})
            break
        except (ConnectionError, OSError, TimeoutError, urllib.error.URLError):
            if quote_attempts >= 15:
                raise
            time.sleep(2)
    quote = bytes.fromhex(str(quote_value["quote"]))
    attempts = 0
    while True:
        attempts += 1
        try:
            response = provider_request(host, port, quote)
            break
        except (ConnectionResetError, ConnectionAbortedError, TimeoutError):
            if attempts >= 3:
                raise
            time.sleep(attempts)
    ciphertext = bytes(response["encrypted_key"])
    provider_quote = bytes(response["provider_quote"])
    plaintext = SealedBox(private_key).decrypt(ciphertext)
    observation = {
        "tdx_quote_length": len(quote),
        "encrypted_key_length": len(ciphertext),
        "provider_quote_length": len(provider_quote),
        "provider_quote_present": bool(provider_quote),
        "decryption_succeeded": len(plaintext) == 32,
        "quote_rpc_attempts": quote_attempts,
        "provider_request_attempts": attempts,
    }
    return plaintext, observation


def main() -> int:
    """Run the physical local-provider sealing and isolation matrix."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise RuntimeError(f"unsupported case id: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    primary_url = values["services"]["Tappd"]["url"]
    provider = values["services"]["LocalKeyProvider"]
    peer = values["local_provider_peer"]
    host, port = str(provider["host"]), int(provider["port"])
    observations: dict[str, Any] = {}
    failures: list[str] = []
    stage = "primary_first"

    try:
        primary_key_1, observations["primary_first"] = derive(primary_url, host, port)
        stage = "primary_repeat"
        primary_key_2, observations["primary_repeat"] = derive(primary_url, host, port)
        stage = "peer_identity"
        peer_key, observations["peer"] = derive(peer["tappd_url"], host, port)
        observations["same_identity_stable"] = primary_key_1 == primary_key_2
        observations["peer_identity_isolated"] = primary_key_1 != peer_key
        if primary_key_1 != primary_key_2:
            failures.append(
                "primary derived key changed across equivalent valid quotes"
            )
        if primary_key_1 == peer_key:
            failures.append("different app identities derived the same key")

        # Alter one byte in a fresh valid quote and prove that no response key is returned.
        stage = "tampered_quote"
        private_key = PrivateKey.generate()
        report_data = bytes(private_key.public_key) + bytes(32)
        quote = bytearray(
            bytes.fromhex(
                str(
                    rpc(primary_url, "RawQuote", {"report_data": report_data.hex()})[
                        "quote"
                    ]
                )
            )
        )
        quote[len(quote) // 2] ^= 1
        stage = "invalid_frame"
        try:
            tampered = provider_request(host, port, bytes(quote))
            observations["tampered_quote_rejected"] = not bool(
                tampered.get("encrypted_key")
            )
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
            observations["tampered_quote_rejected"] = True
        if not observations["tampered_quote_rejected"]:
            failures.append("tampered quote returned encrypted key material")

        # Invalid frame length must be bounded; a subsequent valid request proves recovery.
        try:
            with socket.create_connection((host, port), timeout=10) as stream:
                stream.sendall(struct.pack(">I", 0))
                stream.shutdown(socket.SHUT_WR)
                invalid_reply = stream.recv(32)
            observations["invalid_frame_rejected"] = len(invalid_reply) == 0
        except OSError:
            observations["invalid_frame_rejected"] = True
        if not observations["invalid_frame_rejected"]:
            failures.append("invalid zero-length frame was not rejected")
        stage = "post_error_recovery"
        recovered_key, observations["post_error_recovery"] = derive(
            primary_url, host, port
        )
        observations["post_error_key_stable"] = recovered_key == primary_key_1
        if recovered_key != primary_key_1:
            failures.append(
                "valid request after invalid input did not recover stable key"
            )

        # Restart only the lease-owned primary VM, never the host/provider.
        stage = "vm_restart"
        cli = [str(item) for item in values["vmm_cli_argv"]]
        vm_id = str(values["vm_id"])
        subprocess.run(
            [*cli, "stop", vm_id],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
        subprocess.run(
            [*cli, "start", vm_id],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
        for _ in range(120):
            status = subprocess.run(
                [*cli, "info", "--json", vm_id],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            info = json.loads(status.stdout)
            if info.get("boot_progress") == "done" and info.get("status") == "running":
                break
            time.sleep(5)
        else:
            raise RuntimeError(
                "lease-owned primary VM did not become ready after restart"
            )
        stage = "after_vm_restart"
        restarted_key, observations["after_vm_restart"] = derive(
            primary_url, host, port
        )
        observations["restart_key_stable"] = restarted_key == primary_key_1
        if restarted_key != primary_key_1:
            failures.append("derived key changed after lease-owned VM restart")
    except (
        Exception
    ) as error:  # Result captures only the error class/message, never key material.
        failures.append(f"{stage}: {type(error).__name__}: {error}")
        observations["failed_stage"] = stage

    artifact = {
        "path": "artifacts/local-provider-sealing-observations.json",
        "step_id": f"{case_id}-step-02",
        "name": "Local provider sealing observations",
        "description": "Lengths and boolean assertions proving physical quote acceptance, same-identity stability, cross-identity isolation, invalid-input rejection, recovery, and VM-restart persistence without retaining quotes or key material.",
    }
    observations["sensitive_values_persisted"] = False
    observations["observation_sha256"] = hashlib.sha256(
        json.dumps(observations, sort_keys=True).encode()
    ).hexdigest()
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts" / "manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    steps = [
        {
            "id": f"{case_id}-step-01",
            "status": status,
            "observed": "Lease-owned primary and peer hardware guests plus the configured SGX local-key-provider endpoint were available."
            if not failures
            else "Fixture or baseline operation failed; see redacted summary.",
        },
        {
            "id": f"{case_id}-step-02",
            "status": status,
            "observed": "Same-identity stability, peer identity isolation, sealed-box recipient binding, and tamper rejection passed."
            if not failures
            else "One or more sealing or identity assertions failed.",
        },
        {
            "id": f"{case_id}-step-03",
            "status": status,
            "observed": "Invalid framing and tampered evidence failed closed; the next valid request recovered."
            if not failures
            else "Failure/recovery assertions did not all pass.",
        },
        {
            "id": f"{case_id}-step-04",
            "status": status,
            "observed": "Lease-owned VM restart preserved the identity-scoped derived key and peer isolation."
            if not failures
            else "Restart/isolation assertions did not all pass.",
        },
    ]
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "Physical SGX local-key-provider sealing, identity isolation, rejection, recovery, and lease-owned VM restart checks passed."
            if not failures
            else "; ".join(failures)[:800],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "No quote, private key, decrypted key, ciphertext, or credential was persisted. The physical host and shared provider were not restarted.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
