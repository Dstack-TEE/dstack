#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Prepare immutable pinned source inputs for mixed-version tests."""
# ruff: noqa: D103

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import compatibility_stack

STATE_ROOT = Path(
    os.environ.get("DSTACK_TEST_STATE_ROOT", "").strip()
    or str(Path.home() / ".cache/dstack-test/runtime-state")
)
ROOT = STATE_ROOT / "version-fixtures"
CACHE = STATE_ROOT / "version-cache"
PINNED = ("v0.5.4", "v0.5.8", "v0.5.11")


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def request() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        fail(f"invalid provider request: {error}")
    if not isinstance(value, dict):
        fail("provider request must be an object")
    return value


def run(command: list[str], *, cwd: Path | None = None) -> str:
    process = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
        check=False,
    )
    if process.returncode:
        fail(f"command failed: {' '.join(command)}: {process.stderr[-2000:]}")
    return process.stdout.strip()


def ensure_source(repository: Path, version: str) -> dict[str, str]:
    tag = f"refs/tags/{version}"
    probe = subprocess.run(
        ["git", "rev-parse", "--verify", f"{tag}^{{commit}}"],
        cwd=repository,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if probe.returncode:
        # Test worktrees may intentionally be created without tags. Fetch only
        # the immutable requested tag instead of refreshing branches or all
        # remote refs, then resolve the peeled commit locally.
        run(["git", "fetch", "--no-tags", "origin", f"{tag}:{tag}"], cwd=repository)
    commit = run(["git", "rev-parse", "--verify", f"{tag}^{{commit}}"], cwd=repository)
    source = CACHE / "sources" / version
    if source.is_dir():
        observed = run(["git", "rev-parse", "HEAD"], cwd=source)
        if observed != commit:
            fail(f"cached source mismatch for {version}: {observed} != {commit}")
    else:
        source.parent.mkdir(parents=True, exist_ok=True)
        run(
            ["git", "worktree", "add", "--force", "--detach", str(source), commit],
            cwd=repository,
        )
    target = CACHE / "targets" / version
    target.mkdir(parents=True, exist_ok=True)
    return {
        "version": version.removeprefix("v"),
        "ref": version,
        "commit": commit,
        "source": str(source),
        "cargo_target_dir": str(target),
    }


def prepare(value: dict[str, Any]) -> dict[str, Any]:
    lease = value.get("lease", {})
    requested = value.get("request", {})
    lease_id = str(lease.get("lease_id", ""))
    if not lease_id.startswith("lease-"):
        fail("lease identity is missing")
    runtime_path = Path(str(requested.get("_runtime_manifest", ""))).resolve()
    if not runtime_path.is_file():
        fail("runtime manifest is unavailable")
    runtime = json.loads(runtime_path.read_text())
    repository = Path(str(runtime.get("repository", ""))).resolve()
    if not (repository / ".git").exists() and not run(
        ["git", "rev-parse", "--is-inside-work-tree"], cwd=repository
    ):
        fail("candidate repository is not a git worktree")
    workspace = ROOT / lease_id
    workspace.mkdir(parents=True, exist_ok=False)
    CACHE.mkdir(parents=True, exist_ok=True)
    lock_path = CACHE / ".lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        historical = [ensure_source(repository, version) for version in PINNED]
    candidate = {
        "version": "0.6.0-candidate",
        "ref": "candidate",
        "commit": str(runtime.get("candidate_commit", "")),
        "source": str(repository),
        "cargo_target_dir": str(runtime.get("cargo_target_dir", "")),
        "prepared_binaries": runtime.get("prepared_binaries", {}),
    }
    matrix = {
        "candidate": candidate,
        "historical": historical,
        "ordered_versions": ["0.5.4", "0.5.8", "0.5.11", "0.6.0-candidate"],
        "guest_images": {
            "0.5.4": os.environ.get("DSTACK_TEST_IMAGE_0_5_4", "dstack-dev-0.5.4"),
            "0.5.8": os.environ.get("DSTACK_TEST_IMAGE_0_5_8", "dstack-0.5.8"),
            "0.5.11": os.environ.get("DSTACK_TEST_IMAGE_0_5_11", "dstack-0.5.11"),
            "0.6.0-candidate": os.environ.get(
                "DSTACK_TEST_GUEST_IMAGE", "dstack-0.6.0"
            ),
        },
        "build_cache_shared": True,
        "case_owned_workspace": str(workspace),
    }
    vmm_cli = repository / "dstack" / "vmm" / "src" / "vmm-cli.py"
    try:
        stack = compatibility_stack.start(
            workspace,
            lease_id,
            runtime,
            runtime_path,
            list(matrix["guest_images"].values()),
        )
    except BaseException:
        shutil.rmtree(workspace, ignore_errors=True)
        raise
    vmm_url = str(stack["vmm_url"])
    created_vms = workspace / "created-vms.json"
    created_vms.write_text("[]\n", encoding="utf-8")
    return {
        "values": {
            "version_matrix": matrix,
            "live_vmm": {
                "url": vmm_url,
                "cli_argv": [sys.executable, str(vmm_cli), "--url", vmm_url],
                "pid": int(stack["handle"]["pids"][0]),
                "config": str(stack["handle"]["config"]),
                "log": str(stack["handle"]["log"]),
                "candidate_image": os.environ.get(
                    "DSTACK_TEST_GUEST_IMAGE", "dstack-0.6.0"
                ),
                "development_image": os.environ.get(
                    "DSTACK_TEST_NO_TEE_GUEST_IMAGE", "dstack-dev-0.6.0"
                ),
                "name_prefix": f"dtest-{lease_id[-12:]}",
                "created_vms_registry": str(created_vms),
                "kms_guest_url": stack["kms_guest_url"],
                "gateway_guest_url": stack["gateway_guest_url"],
                "dependency_logs": stack["logs"],
                "image_archive_guest_url": stack["image_archive_guest_url"],
                "image_archive_digest": stack["image_archive_digest"],
                "kms_upgrade_policy_guest_urls": stack["kms_upgrade_policy_guest_urls"],
                "kms_upgrade_policy_path": stack["kms_upgrade_policy_path"],
                "kms_upgrade_proxies": stack["kms_upgrade_proxies"],
                "kms_upgrade_policy_observations": stack[
                    "kms_upgrade_policy_observations"
                ],
                "image_archive_path": stack["image_archive_path"],
                "port_mapping": stack["port_mapping"],
                "case_owned": True,
                "allowed_actions": ["deploy", "start", "stop", "restart", "remove"],
            },
            "destructive_actions_allowed": True,
        },
        "cleanup_handle": {
            "state_root": str(STATE_ROOT.resolve()),
            "workspace": str(workspace),
            "vmm_url": vmm_url,
            "vmm_cli": str(vmm_cli),
            "stack_handle": stack["handle"],
        },
    }


def verify(value: dict[str, Any]) -> dict[str, Any]:
    matrix = value.get("prepared", {}).get("values", {}).get("version_matrix", {})
    historical = matrix.get("historical", [])
    ok = (
        matrix.get("ordered_versions")
        == ["0.5.4", "0.5.8", "0.5.11", "0.6.0-candidate"]
        and isinstance(historical, list)
        and len(historical) == 3
        and all(Path(str(item.get("source", ""))).is_dir() for item in historical)
    )
    return {
        "ok": ok,
        "expected": {"versions": ["0.5.4", "0.5.8", "0.5.11", "0.6.0-candidate"]},
        "observed": {"versions": matrix.get("ordered_versions", [])},
        "error": None if ok else "pinned version source matrix is incomplete",
    }


def cleanup_upgrade_registries(workspace: Path) -> None:
    """Remove case-owned upgrade registries and their unique local image tags."""
    for path in sorted(workspace.glob("upgrade-registry*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            fail(f"invalid upgrade registry handle: {error}")
        container = str(value.get("registry_container", ""))
        host = str(value.get("registry_host", ""))
        guest = str(value.get("registry_guest", ""))
        if (
            not container.startswith("dstack-upgrade-registry-")
            or not host
            or not guest
        ):
            fail(f"unsafe upgrade registry handle: {path}")
        images = []
        image_keys = ["bridge_image", "candidate_image"]
        if value.get("candidate_gateway_image"):
            image_keys.append("candidate_gateway_image")
        for key in image_keys:
            image = str(value.get(key, ""))
            if not image.startswith(f"{guest}/"):
                fail(f"unsafe upgrade image handle: {image}")
            images.append(f"{host}/{image.removeprefix(f'{guest}/')}")
        completed = subprocess.run(
            ["sudo", "su", "kvin", "-c", f"docker rm -f {container}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        if completed.returncode and "No such container" not in completed.stderr:
            fail(
                f"failed to remove upgrade registry {container}: {completed.stderr[-500:]}"
            )
        for image in images:
            completed = subprocess.run(
                ["sudo", "su", "kvin", "-c", f"docker image rm {image}"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
                check=False,
            )
            if completed.returncode and "No such image" not in completed.stderr:
                fail(
                    f"failed to remove upgrade image {image}: {completed.stderr[-500:]}"
                )


def destroy(value: dict[str, Any]) -> dict[str, Any]:
    for resource in value.get("resources", []):
        handle = resource.get("cleanup", {}).get("handle", {})
        text = str(handle.get("workspace", ""))
        if not text:
            continue
        workspace = Path(text).resolve()
        state_root_text = str(handle.get("state_root", ""))
        state_root = (
            Path(state_root_text).resolve() if state_root_text else ROOT.resolve()
        )
        if (
            workspace.parent != state_root / "version-fixtures"
            or not workspace.name.startswith("lease-")
        ):
            fail(f"refusing unsafe version workspace cleanup: {workspace}")
        registry = workspace / "created-vms.json"
        if registry.is_file():
            try:
                vm_ids = json.loads(registry.read_text(encoding="utf-8"))
            except json.JSONDecodeError as error:
                fail(f"invalid created VM registry: {error}")
            if isinstance(vm_ids, dict):
                vm_ids = vm_ids.get("created_vms", [])
            if not isinstance(vm_ids, list):
                fail("created VM registry must be an array")
            normalized_ids = [
                item.get("id") if isinstance(item, dict) else item for item in vm_ids
            ]
            if not all(isinstance(vm_id, str) and vm_id for vm_id in normalized_ids):
                fail("created VM registry entries must contain VM IDs")
            cli = [
                sys.executable,
                str(handle.get("vmm_cli", "")),
                "--url",
                str(handle.get("vmm_url", "")),
            ]
            for vm_id in normalized_ids:
                subprocess.run(
                    [*cli, "remove", vm_id],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=120,
                    check=False,
                )
        cleanup_upgrade_registries(workspace)
        stack_handle = handle.get("stack_handle")
        if isinstance(stack_handle, dict):
            compatibility_stack.stop(workspace, stack_handle)
        shutil.rmtree(workspace, ignore_errors=True)
    return {"released": True}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "verify", "destroy"}:
        fail("usage: version-matrix.py prepare|verify|destroy")
    value = request()
    result = {"prepare": prepare, "verify": verify, "destroy": destroy}[sys.argv[1]](
        value
    )
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
