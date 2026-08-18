#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic hardware regressions promoted from confirmed Agent cases."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import tempfile
from typing import Any


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON so a reader never observes a partial document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def ssh(target: dict[str, Any], command: str) -> str:
    """Run one command inside the guest and return its stdout."""
    argv = target.get("ssh_argv")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) for item in argv)
    ):
        raise RuntimeError("fixture target has no safe ssh_argv")
    process = subprocess.run(
        [*argv, command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if process.returncode:
        # ssh writes its own warnings to stderr, so reporting stderr alone can
        # surface a known-hosts notice while hiding which guest command failed
        # and what it printed.
        raise RuntimeError(
            f"guest command failed with {process.returncode}: {command!r}\n"
            f"stdout: {process.stdout[-600:]!r}\nstderr: {process.stderr[-600:]!r}"
        )
    return process.stdout


def rpc(target: dict[str, Any], method: str, request: dict[str, Any]) -> dict[str, Any]:
    """Issue one guest RPC and return the decoded response."""
    body = json.dumps(request, separators=(",", ":"))
    command = (
        "curl --silent --show-error --fail-with-body "
        "--unix-socket /run/dstack.sock --header 'Content-Type: application/json' "
        f"--data-binary {shlex.quote(body)} http://localhost/{shlex.quote(method)}"
    )
    value = json.loads(ssh(target, command))
    if not isinstance(value, dict):
        raise RuntimeError(f"{method} returned a non-object")
    return value


def target_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Resolve the guest access details this lease provisioned."""
    values = manifest.get("values", {})
    for candidate in (values.get("target"), values.get("hardware_guest"), values):
        if isinstance(candidate, dict) and isinstance(candidate.get("ssh_argv"), list):
            return candidate
    raise RuntimeError("fixture manifest does not contain a case-owned hardware target")


def boot_case(
    case_id: str, target: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run a boot and identity case against the live guest."""
    print(f"STEP {case_id}-step-01 START", flush=True)
    units = ssh(
        target,
        "systemctl show dstack-prepare.service docker.service app-compose.service "
        "dstack-guest-agent.service --property=Id,ActiveState,Result,ExecMainStartTimestampMonotonic "
        "--no-pager",
    )
    blocks = [block for block in units.strip().split("\n\n") if block]
    if len(blocks) != 4 or any(
        "ActiveState=active" not in block or "Result=success" not in block
        for block in blocks
    ):
        raise AssertionError("required guest services were not active and successful")
    timestamps = {}
    for block in blocks:
        values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        timestamps[values["Id"]] = int(values["ExecMainStartTimestampMonotonic"])
    prepare = timestamps["dstack-prepare.service"]
    if (
        not prepare < timestamps["docker.service"]
        or not prepare < timestamps["app-compose.service"]
    ):
        raise AssertionError(
            "dstack preparation did not precede Docker and app-compose"
        )
    # Probe each path separately. A combined test only reports that something
    # was unreadable, which cannot distinguish a guest-agent defect from a
    # platform that exposes no TDX event log.
    required_paths = (
        "/dstack/.host-shared/.instance_info",
        "/dstack/.host-shared/.sys-config.json",
        "/sys/firmware/acpi/tables/CCEL",
    )
    probe = "; ".join(
        f'test -r {path} && echo "ok {path}" || echo "missing {path}"'
        for path in required_paths
    )
    identity = ssh(target, probe).strip()
    unreadable = [
        line.split(" ", 1)[1]
        for line in identity.splitlines()
        if line.startswith("missing ")
    ]
    if unreadable:
        raise AssertionError("unreadable guest paths: " + ", ".join(unreadable))
    print(
        f"EVIDENCE {case_id}-step-01 - Proves required services and measured-boot inputs are healthy.",
        flush=True,
    )
    print(
        json.dumps({"units": sorted(timestamps), "identity_and_ccel": True}), flush=True
    )
    print(f"STEP {case_id}-step-01 END - PASS", flush=True)
    print(f"STEP {case_id}-step-02 START", flush=True)
    if not (
        prepare < timestamps["docker.service"]
        and prepare < timestamps["app-compose.service"]
    ):
        raise AssertionError("monotonic ordering changed")
    print(
        f"EVIDENCE {case_id}-step-02 - Proves prepare completed before its Docker and compose consumers.",
        flush=True,
    )
    print(json.dumps({"start_monotonic": timestamps}, sort_keys=True), flush=True)
    print(f"STEP {case_id}-step-02 END - PASS", flush=True)
    print(f"STEP {case_id}-step-03 START", flush=True)
    after = ssh(
        target,
        "systemctl is-active dstack-prepare.service docker.service app-compose.service dstack-guest-agent.service",
    )
    if after.split() != ["active"] * 4:
        raise AssertionError("service availability was not preserved")
    print(
        f"EVIDENCE {case_id}-step-03 - Proves all services remained available without rebooting the physical host.",
        flush=True,
    )
    print("all required units remained active", flush=True)
    print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    steps = [
        {
            "id": f"{case_id}-step-01",
            "status": "PASS",
            "observed": "The case-owned TDX guest, required services, identity files, and CCEL were healthy.",
        },
        {
            "id": f"{case_id}-step-02",
            "status": "PASS",
            "observed": "Systemd monotonic timestamps proved prepare completed before Docker and app-compose.",
        },
        {
            "id": f"{case_id}-step-03",
            "status": "PASS",
            "observed": "All required services remained active; no physical-host reboot was performed.",
        },
    ]
    return steps, {
        "environment": "HARDWARE",
        "start_monotonic": timestamps,
        "identity_and_ccel": True,
    }


def signing_case(
    case_id: str, target: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run a key derivation and signing case against the live guest."""
    print(f"STEP {case_id}-step-01 START", flush=True)
    info = rpc(target, "Info", {})
    if not info.get("app_id") or not info.get("instance_id"):
        raise AssertionError("DstackGuest.Info did not return guest identity")
    print(
        f"EVIDENCE {case_id}-step-01 - Proves the case-owned hardware guest identity and DstackGuest listener are healthy.",
        flush=True,
    )
    print(
        json.dumps({"info_fields": sorted(info), "identity_present": True}), flush=True
    )
    print(f"STEP {case_id}-step-01 END - PASS", flush=True)
    print(f"STEP {case_id}-step-02 START", flush=True)
    rows = []
    for algorithm in ("ed25519", "secp256k1", "k256", "secp256k1_prehashed"):
        data = hashlib.sha256(f"{case_id}:{algorithm}".encode()).hexdigest()
        signed = rpc(target, "Sign", {"algorithm": algorithm, "data": data})
        required = {"signature", "signature_chain", "public_key"}
        if (
            not required.issubset(signed)
            or not signed["signature"]
            or not signed["public_key"]
        ):
            raise AssertionError(f"{algorithm} returned an incomplete signature")
        verified = rpc(
            target,
            "Verify",
            {
                "algorithm": algorithm,
                "data": data,
                "signature": signed["signature"],
                "public_key": signed["public_key"],
            },
        )
        if verified.get("valid") is not True:
            raise AssertionError(f"{algorithm} signature did not verify")
        negative = rpc(
            target,
            "Verify",
            {
                "algorithm": algorithm,
                "data": hashlib.sha256((data + "changed").encode()).hexdigest(),
                "signature": signed["signature"],
                "public_key": signed["public_key"],
            },
        )
        if negative.get("valid") is not False:
            raise AssertionError(f"{algorithm} accepted changed data")
        rows.append(
            {
                "algorithm": algorithm,
                "signature_bytes": len(signed["signature"]) // 2,
                "public_key_bytes": len(signed["public_key"]) // 2,
                "chain_entries": len(signed["signature_chain"]),
                "valid": True,
                "changed_data_valid": False,
            }
        )
    print(
        f"EVIDENCE {case_id}-step-02 - Proves all documented algorithms sign, verify, and reject changed data.",
        flush=True,
    )
    print(json.dumps(rows, sort_keys=True), flush=True)
    print(f"STEP {case_id}-step-02 END - PASS", flush=True)
    print(f"STEP {case_id}-step-03 START", flush=True)
    repeat_data = hashlib.sha256(f"{case_id}:repeat".encode()).hexdigest()
    first = rpc(target, "Sign", {"algorithm": "ed25519", "data": repeat_data})
    second = rpc(target, "Sign", {"algorithm": "ed25519", "data": repeat_data})
    if first["signature"] != second["signature"]:
        raise AssertionError("Ed25519 repeat signature was not deterministic")
    post = rpc(target, "Info", {})
    if post.get("app_id") != info.get("app_id") or post.get("instance_id") != info.get(
        "instance_id"
    ):
        raise AssertionError("public identity changed during signing")
    print(
        f"EVIDENCE {case_id}-step-03 - Proves deterministic repeat signing and post-negative service availability.",
        flush=True,
    )
    print(
        json.dumps({"repeat_deterministic": True, "identity_unchanged": True}),
        flush=True,
    )
    print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    steps = [
        {
            "id": f"{case_id}-step-01",
            "status": "PASS",
            "observed": "The case-owned hardware guest identity and DstackGuest endpoint were healthy.",
        },
        {
            "id": f"{case_id}-step-02",
            "status": "PASS",
            "observed": "All four documented algorithms signed and verified valid data and rejected changed data.",
        },
        {
            "id": f"{case_id}-step-03",
            "status": "PASS",
            "observed": "Repeated Ed25519 signing was deterministic and guest identity and availability were preserved.",
        },
    ]
    return steps, {
        "environment": "HARDWARE",
        "algorithms": rows,
        "secret_material_persisted": False,
    }


def main() -> int:
    """Run the hardware case selected by the environment."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    status = "PASS"
    failure = None
    steps = []
    evidence: dict[str, Any] = {}
    try:
        target = target_from_manifest(manifest)
        if target.get("destructive_actions_allowed") is not True:
            raise RuntimeError(
                "hardware fixture is not case-owned for destructive test operations"
            )
        if case_id == "tc-gos-boot-and-i-001":
            steps, evidence = boot_case(case_id, target)
        elif case_id == "tc-gos-attestatio-005":
            steps, evidence = signing_case(case_id, target)
        else:
            raise RuntimeError(f"unsupported promoted hardware case: {case_id}")
    except Exception as error:
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
        completed = {step["id"] for step in steps}
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id not in completed:
                steps.append({"id": step_id, "status": "FAIL", "observed": failure})
        print(failure, flush=True)
    evidence["status"] = status
    evidence["failure"] = failure
    evidence_path = artifacts / "hardware-regression-matrix.json"
    atomic_json(evidence_path, evidence)
    artifact = {
        "name": "Hardware regression matrix",
        "path": "artifacts/hardware-regression-matrix.json",
        "step_id": f"{case_id}-step-02",
        "description": "Records bounded hardware observations and proves the expected ordering or cryptographic matrix without storing private key material.",
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "Promoted hardware regression passed."
            if status == "PASS"
            else failure,
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "HARDWARE: no physical-host reboot was performed.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
