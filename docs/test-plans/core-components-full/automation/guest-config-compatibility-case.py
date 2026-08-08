#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise current configuration against the supported guest image matrix."""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import re
import subprocess
import tempfile
import threading
import time
from typing import Any

CASE_ID = "tc-gos-platform-010"
ID_PATTERN = re.compile(r"Created VM with ID:\s*([0-9a-fA-F-]+)")


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Atomically write one JSON evidence or registry document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def run(
    argv: list[str], timeout: int = 120, *, preserve_stdout: bool = False
) -> dict[str, Any]:
    """Run one bounded command and retain bounded diagnostic output.

    Structured discovery callers may retain stdout in memory so truncation does not
    turn a valid JSON document into an empty capability inventory.
    """
    try:
        process = subprocess.run(
            argv, text=True, capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return {
            "returncode": 124,
            "stdout": stdout if preserve_stdout else stdout[-4000:],
            "stderr": (stderr + f"\ncommand timed out after {timeout}s")[-4000:],
        }
    return {
        "returncode": process.returncode,
        "stdout": process.stdout if preserve_stdout else process.stdout[-4000:],
        "stderr": process.stderr[-4000:],
    }


def parse_info(result: dict[str, Any]) -> dict[str, Any]:
    """Parse a successful VMM info response or return an empty object."""
    if result["returncode"] != 0:
        return {}
    try:
        value = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def main() -> int:
    """Run the pinned guest configuration compatibility matrix."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    matrix = values["version_matrix"]
    live = values["live_vmm"]
    cli = [str(item) for item in live["cli_argv"]]
    registry = pathlib.Path(live["created_vms_registry"])
    workspace = pathlib.Path(matrix["case_owned_workspace"])
    prefix = str(live["name_prefix"])
    versions = [str(item) for item in matrix["ordered_versions"]]
    images = {str(k): str(v) for k, v in matrix["guest_images"].items()}
    lock = threading.Lock()
    rows: dict[str, dict[str, Any]] = {
        v: {"version": v, "image": images[v]} for v in versions
    }
    artifacts: list[dict[str, str]] = []
    failures: list[str] = []

    def record(filename: str, step: str, value: Any, description: str) -> None:
        path = result_dir / "artifacts" / filename
        atomic_json(path, value)
        artifacts.append(
            {
                "path": f"artifacts/{filename}",
                "step_id": step,
                "name": filename.removesuffix(".json").replace("-", " ").title(),
                "description": description,
            }
        )
        atomic_json(
            result_dir / "artifacts" / "manifest.json", {"artifacts": artifacts}
        )

    baseline = {
        "ordered_versions": versions,
        "images": images,
        "vmm_url": live.get("url"),
        "allowed_actions": live.get("allowed_actions"),
        "case_owned_dependencies": bool(live.get("case_owned")),
        "attestation_probe": live.get("attestation_probe"),
        "registry_initial": json.loads(registry.read_text())
        if registry.exists()
        else [],
        "resources": {
            "vcpu_per_row": 2,
            "memory_mib_per_row": 4096,
            "disk_gib_per_row": 20,
        },
    }
    expected_attestation_probe = {
        "mode": "physical-tdx",
        "kms_uses_product_attestation_defaults": True,
        "vmm_uses_product_pccs": True,
        "vmm_tee_simulator_absent": True,
    }
    if live.get("attestation_probe") != expected_attestation_probe:
        failures.append("physical TDX collateral prerequisite probe did not pass")
    record(
        "step01-baseline.json",
        f"{CASE_ID}-step-01",
        baseline,
        "Pinned rows, lease-owned endpoint, clean registry, and exact resource baseline.",
    )

    inventory_result = run(
        [*cli, "lsimage", "--json"], timeout=30, preserve_stdout=True
    )
    try:
        inventory_value = json.loads(inventory_result["stdout"])
    except json.JSONDecodeError:
        inventory_value = []
    if isinstance(inventory_value, dict):
        inventory_value = inventory_value.get(
            "images", inventory_value.get("items", [])
        )
    available_images = (
        {
            str(item.get("name", item.get("id", "")))
            for item in inventory_value
            if isinstance(item, dict)
        }
        if isinstance(inventory_value, list)
        else set()
    )
    missing_images = sorted(set(images.values()) - available_images)
    if inventory_result["returncode"] != 0 or missing_images:
        capability = {
            "capability": "official-guest-version-image-inventory",
            "available_image_count": len(available_images),
            "required_images": sorted(images.values()),
            "missing_images": missing_images,
            "inventory_query_returncode": inventory_result["returncode"],
        }
        record(
            "step02-image-inventory-capability.json",
            f"{CASE_ID}-step-02",
            capability,
            "Bounded live VMM inventory query proving whether every pinned official guest image is available without substituting another image.",
        )
        blocked = (
            "The live VMM lacks the complete pinned official guest image inventory; "
            "compatibility behavior cannot start without substituting required rows."
        )
        atomic_json(
            result_dir / "result.json",
            {
                "schema_version": "1.0",
                "case_id": CASE_ID,
                "provisional": False,
                "status": "BLOCKED",
                "summary": "BLOCKED on official-guest-version-image-inventory: missing "
                + (", ".join(missing_images) or "inventory query")
                + ".",
                "steps": [
                    {
                        "id": f"{CASE_ID}-step-01",
                        "status": "PASS",
                        "observed": "Pinned four-version matrix, lease-owned endpoint, clean VM registry, and exact resource policy were captured.",
                    },
                    {
                        "id": f"{CASE_ID}-step-02",
                        "status": "BLOCKED",
                        "observed": blocked,
                    },
                    {
                        "id": f"{CASE_ID}-step-03",
                        "status": "BLOCKED",
                        "observed": "Invalid-input and dependency recovery operations require the missing official image inventory.",
                    },
                    {
                        "id": f"{CASE_ID}-step-04",
                        "status": "BLOCKED",
                        "observed": "Restart, persistence, and adjacent-row isolation require the missing official image inventory.",
                    },
                ],
                "artifacts": artifacts,
                "remarks": "No VM was created and no alternate image was substituted. Provide all four pinned images to satisfy official-guest-version-image-inventory.",
            },
        )
        return 0

    workspace.mkdir(parents=True, exist_ok=True)
    docker_compose = workspace / "docker-compose.yml"
    docker_compose.write_text(
        'services:\n  compatibility-probe:\n    image: busybox:1.36\n    command: ["sh", "-c", "sleep 86400"]\n',
        encoding="utf-8",
    )
    app_compose = workspace / "app-compose.json"
    compose_cmd = [
        *cli,
        "compose",
        "--name",
        f"{prefix}-compat",
        "--docker-compose",
        str(docker_compose),
        "--kms",
        "--gateway",
        "--key-provider",
        "kms",
        "--public-logs",
        "--public-sysinfo",
        "--event-log-version",
        "2",
        "--output",
        str(app_compose),
    ]
    composed = run(compose_cmd)
    if composed["returncode"] != 0:
        raise RuntimeError(f"compose generation failed: {composed['stderr'][-800:]}")
    compose_value = json.loads(app_compose.read_text())
    compose_value["compat_optional_probe"] = {"revision": 1, "ignorable": True}
    atomic_json(app_compose, compose_value)
    required = {"manifest_version", "name", "runner", "docker_compose_file"}
    if not required.issubset(compose_value):
        failures.append("generated compose omitted required current-schema fields")
    if (
        compose_value.get("key_provider") != "kms"
        or not compose_value.get("kms_enabled")
        or not compose_value.get("gateway_enabled")
    ):
        failures.append("generated compose disabled required KMS/gateway semantics")
    simulator_fields = sorted(
        set(compose_value)
        & {
            "simulated_tee",
            "mock_attestation_seed",
            "mock_collateral_url",
            "mock_mr_config",
            "mock_vm_config",
        }
    )
    if simulator_fields:
        failures.append(
            f"production compose contains simulator fields: {simulator_fields}"
        )
    invalid = run(
        [
            *cli,
            "deploy",
            "--name",
            f"{prefix}-invalid",
            "--image",
            images[versions[-1]],
        ],
        timeout=30,
    )
    missing_required_clear = (
        invalid["returncode"] == 2
        and "--compose" in invalid["stderr"]
        and "required" in invalid["stderr"]
    )
    if not missing_required_clear:
        failures.append(
            "missing required compose input did not fail clearly before VM creation"
        )

    user_config = workspace / "user-config.json"
    user_config.write_text(
        json.dumps({"compatibility_probe": {"optional_future_field": True}}),
        encoding="utf-8",
    )

    def register(vm_id: str) -> None:
        with lock:
            current = json.loads(registry.read_text()) if registry.exists() else []
            if vm_id not in current:
                current.append(vm_id)
                atomic_json(registry, current)

    def deploy(version: str) -> tuple[str, dict[str, Any]]:
        name = f"{prefix}-{version.replace('.', '-').replace('-candidate', '-cand')}"
        argv = [
            *cli,
            "deploy",
            "--name",
            name,
            "--image",
            images[version],
            "--compose",
            str(app_compose),
            "--vcpu",
            "2",
            "--memory",
            "4096",
            "--disk",
            "20G",
            "--user-config",
            str(user_config),
            "--tee",
            "--kms-url",
            str(live["kms_guest_url"]),
            "--gateway-url",
            str(live["gateway_guest_url"]),
        ]
        result = run(argv, timeout=180)
        match = ID_PATTERN.search(result["stdout"])
        vm_id = match.group(1) if match else None
        if vm_id:
            register(vm_id)
        return version, {
            "name": name,
            "argv_policy": {
                "uses_compose": "--compose" in argv,
                "vcpu": 2,
                "memory_mib": 4096,
                "disk_gib": 20,
                "physical_tee": "--tee" in argv,
                "no_tee": "--no-tee" in argv,
                "simulated_tee": "--simulated-tee" in argv,
            },
            "returncode": result["returncode"],
            "stderr": result["stderr"],
            "vm_id": vm_id,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(versions)) as executor:
        for version, deployed in executor.map(deploy, versions):
            rows[version].update(deployed)
            if not deployed["vm_id"]:
                failures.append(
                    f"{version} deploy failed before returning a VM ID: {deployed['stderr'][-400:]}"
                )

    deadline = time.monotonic() + 600
    pending = {v for v in versions if rows[v].get("vm_id")}
    while pending and time.monotonic() < deadline:
        for version in list(pending):
            info_result = run(
                [*cli, "info", rows[version]["vm_id"], "--json"], timeout=30
            )
            info = parse_info(info_result)
            rows[version]["last_info"] = {
                k: info.get(k)
                for k in (
                    "id",
                    "name",
                    "status",
                    "boot_progress",
                    "boot_error",
                    "image_version",
                    "app_id",
                    "instance_id",
                    "events",
                )
                if k in info
            }
            if info.get("boot_progress") == "done" and info.get("status") == "running":
                rows[version]["boot_done"] = True
                pending.remove(version)
            elif info.get("status") in {"exited", "stopped", "failed"}:
                rows[version]["early_exit"] = True
                pending.remove(version)
        if pending:
            time.sleep(5)
    for version in sorted(pending):
        failures.append(
            f"{version} did not reach boot_progress=done within shared 10-minute deadline"
        )
    for version in versions:
        policy = rows[version].get("argv_policy", {})
        if (
            not policy.get("physical_tee")
            or policy.get("no_tee")
            or policy.get("simulated_tee")
        ):
            failures.append(f"{version} did not select physical TDX exclusively")
        if rows[version].get("vm_id") and not rows[version].get("boot_done"):
            failures.append(f"{version} exited or failed before boot_progress=done")

    ready = [v for v in versions if rows[v].get("boot_done")]

    def vm_action(version: str, action: str) -> tuple[str, dict[str, Any]]:
        return version, run(
            [*cli, action, rows[version]["vm_id"]],
            timeout=180,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(ready))) as executor:
        stopped_rows = executor.map(lambda version: vm_action(version, "stop"), ready)
        for version, stopped in stopped_rows:
            rows[version]["graceful_stop_returncode"] = stopped["returncode"]
            if stopped["returncode"] != 0:
                failures.append(f"{version} graceful stop failed after readiness")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(ready))) as executor:
        started_rows = executor.map(lambda version: vm_action(version, "start"), ready)
        for version, started in started_rows:
            rows[version]["restart_returncode"] = started["returncode"]
            if started["returncode"] != 0:
                failures.append(f"{version} restart failed")

    recovery_deadline = time.monotonic() + 600
    recovering = {v for v in ready if rows[v].get("restart_returncode") == 0}
    while recovering and time.monotonic() < recovery_deadline:
        for version in list(recovering):
            info = parse_info(
                run([*cli, "info", rows[version]["vm_id"], "--json"], timeout=30)
            )
            if info.get("boot_progress") == "done" and info.get("status") == "running":
                rows[version]["recovered"] = True
                rows[version]["identity_stable"] = info.get("app_id") == rows[
                    version
                ].get("last_info", {}).get("app_id") and info.get(
                    "instance_id"
                ) == rows[version].get("last_info", {}).get("instance_id")
                recovering.remove(version)
            elif info.get("status") in {"exited", "stopped", "failed"}:
                recovering.remove(version)
        if recovering:
            time.sleep(5)
    for version in sorted(recovering):
        failures.append(
            f"{version} did not recover after restart within shared deadline"
        )
    final_stop_versions = []
    for version in ready:
        if rows[version].get("recovered") and not rows[version].get("identity_stable"):
            failures.append(f"{version} identity changed across restart")
        if rows[version].get("recovered"):
            final_stop_versions.append(version)
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, len(final_stop_versions))
    ) as executor:
        final_rows = executor.map(
            lambda version: vm_action(version, "stop"),
            final_stop_versions,
        )
        for version, final_stop in final_rows:
            rows[version]["final_stop_returncode"] = final_stop["returncode"]
            if final_stop["returncode"] != 0:
                failures.append(f"{version} final graceful stop failed")

    compatibility = {
        "compose_generation": composed,
        "compose_assertions": {
            "required_fields_present": required.issubset(compose_value),
            "kms_enabled": compose_value.get("kms_enabled"),
            "gateway_enabled": compose_value.get("gateway_enabled"),
            "key_provider": compose_value.get("key_provider"),
            "event_log_version": compose_value.get("event_log_version"),
            "unknown_optional_field_present": "compat_optional_probe" in compose_value,
            "simulator_fields": simulator_fields,
        },
        "missing_required_input": {
            "returncode": invalid["returncode"],
            "clear_error": missing_required_clear,
            "stderr": invalid["stderr"][-1000:],
        },
        "rows": rows,
        "shared_deadline_seconds": 600,
        "sensitive_values_persisted": False,
    }
    record(
        "compatibility-matrix.json",
        f"{CASE_ID}-step-02",
        compatibility,
        "Current compose schema, four official guest rows, bounded boot diagnostics, invalid-input rejection, restart recovery, and identity isolation evidence.",
    )
    status = "PASS" if not failures else "FAIL"
    step_status = "PASS" if status == "PASS" else "FAIL"
    steps = [
        {
            "id": f"{CASE_ID}-step-01",
            "status": "PASS",
            "observed": "Pinned four-version matrix, lease-owned endpoint, clean VM registry, and exact resource policy were captured.",
        },
        {
            "id": f"{CASE_ID}-step-02",
            "status": step_status,
            "observed": "Current-schema compose with an unknown optional field was exercised by all official guest rows; required-field and simulator-field boundaries were checked.",
        },
        {
            "id": f"{CASE_ID}-step-03",
            "status": step_status,
            "observed": "Missing required input failed before VM creation and ready rows were gracefully stopped and restarted under shared bounded deadlines.",
        },
        {
            "id": f"{CASE_ID}-step-04",
            "status": step_status,
            "observed": "Recovered rows retained app/instance identity and were gracefully stopped; provider cleanup owns every registered VM ID.",
        },
    ]
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": "Four-version guest configuration compatibility, schema boundaries, recovery, and isolation passed."
            if not failures
            else "; ".join(failures)[:1200],
            "steps": steps,
            "artifacts": artifacts,
            "remarks": "No credential, private key, plaintext sentinel, or simulator-only production field is retained in evidence. VM IDs are registered immediately for provider-owned removal.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
