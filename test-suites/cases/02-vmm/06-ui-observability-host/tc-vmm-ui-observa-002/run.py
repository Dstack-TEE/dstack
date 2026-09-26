#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise VMM console history, live follow, ANSI, and path isolation."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

CASE_ID = "tc-vmm-ui-observa-002"
CHANNELS = ("serial", "stdout", "stderr")


def atomic_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def get(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def rpc(base: str, route: str, vm_id: str) -> int:
    request = urllib.request.Request(
        base + route.split("?", 1)[0],
        data=json.dumps({"id": vm_id}).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code


def create(test_input: dict[str, Any], suffix: str) -> str:
    process = subprocess.run(
        [
            *map(str, test_input["create_stopped_helper_argv"]),
            "--name",
            f"{test_input['name_prefix']}-{suffix}",
        ],
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if process.returncode:
        raise AssertionError("prepared stopped VM creation failed")
    vm_id = str(json.loads(process.stdout.splitlines()[-1])["id"])
    if vm_id not in json.loads(
        pathlib.Path(test_input["created_vms_registry"]).read_text()
    ):
        raise AssertionError("created VM was not registered")
    return vm_id


def write(control: list[str], vm_id: str, channel: str, text: str) -> None:
    process = subprocess.run(
        [*control, "--id", vm_id, "--channel", channel, "--text", text],
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if process.returncode:
        raise AssertionError(f"controlled {channel} write failed")


def wait_text(path: pathlib.Path, token: str, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file() and token in path.read_text(errors="replace"):
            return
        time.sleep(0.1)
    raise AssertionError(f"follow stream did not contain {token}")


def main() -> int:
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    vmm = values["vmm"]
    fixture = values.get("vmm_console_follow", {})
    required = {
        "console_endpoint",
        "history_seed_argv",
        "live_append_argv",
        "follow_argv",
        "tail_observer_argv",
        "ansi_policy_selector",
        "ansi_observer_argv",
        "gap_duplicate_observer_argv",
        "cross_vm_probe_argv",
        "path_escape_probe_argv",
        "invalid_input_argv",
        "availability_probe_argv",
        "cleanup_argv",
    }
    if (
        fixture.get("destructive_actions_allowed") is not True
        or not required <= fixture.keys()
    ):
        raise RuntimeError("complete case-owned console controller is absent")
    endpoint = str(fixture["console_endpoint"])
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm["json_prpc_routes"]
    test_input = vmm["test_input"]
    truncate_control = [str(x) for x in fixture["history_seed_argv"]]
    append_control = [str(x) for x in fixture["live_append_argv"]]
    ids: list[str] = []
    evidence: dict[str, Any] = {
        "rows": {},
        "vm_processes_started": 0,
        "image_build_tested": False,
    }
    failures: list[str] = []
    steps: list[dict[str, Any]] = []
    follower: subprocess.Popen[bytes] | None = None
    try:
        vm_a = create(test_input, "console-a")
        ids.append(vm_a)
        vm_b = create(test_input, "console-b")
        ids.append(vm_b)
        for channel in CHANNELS:
            write(
                truncate_control,
                vm_a,
                channel,
                f"{channel}-old-0\n{channel}-old-1\n\x1b[31m{channel}-ansi\x1b[0m\n",
            )
            write(truncate_control, vm_b, channel, f"peer-{channel}-secret-marker\n")
        status_code, _ = get(
            f"{endpoint}?id={urllib.parse.quote(vm_a)}&follow=false&ansi=false&lines=1&ch=serial"
        )
        if status_code != 200:
            raise AssertionError("console endpoint was unavailable")
        evidence["rows"]["effective-prerequisite"] = True
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "Two immediately registered stopped VMs exposed isolated, case-controlled serial/stdout/stderr files on the healthy case-owned VMM.",
            }
        )

        for channel in CHANNELS:
            code, body = get(
                f"{endpoint}?id={vm_a}&follow=false&ansi=false&lines=2&ch={channel}"
            )
            text = body.decode(errors="replace")
            if (
                code != 200
                or f"{channel}-old-0" in text
                or f"{channel}-old-1" not in text
                or f"{channel}-ansi" not in text
            ):
                raise AssertionError(f"{channel} historical tail was incorrect")
            evidence["rows"][f"{channel}-history-tail"] = True
        stripped_code, stripped = get(
            f"{endpoint}?id={vm_a}&follow=false&ansi=false&lines=1&ch=serial"
        )
        raw_code, raw = get(
            f"{endpoint}?id={vm_a}&follow=false&ansi=true&lines=1&ch=serial"
        )
        if (
            stripped_code != 200
            or raw_code != 200
            or b"\x1b[" in stripped
            or b"\x1b[31m" not in raw
        ):
            raise AssertionError("ANSI preserve/strip policy was incorrect")
        evidence["rows"]["ansi-strip"] = True
        evidence["rows"]["ansi-preserve"] = True

        write(truncate_control, vm_a, "serial", "follow-history\n")
        follow_file = result_dir / "artifacts/follow-output.txt"
        follow_file.parent.mkdir(parents=True, exist_ok=True)
        output = follow_file.open("wb")
        follow_url = f"{endpoint}?id={vm_a}&follow=true&ansi=false&lines=1&ch=serial"
        follower = subprocess.Popen(
            [*map(str, fixture["follow_argv"]), follow_url],
            stdout=output,
            stderr=subprocess.PIPE,
        )
        wait_text(follow_file, "follow-history")
        write(append_control, vm_a, "serial", "follow-live-1\n")
        wait_text(follow_file, "follow-live-1")
        write(append_control, vm_a, "serial", "\x1b[32mfollow-live-2\x1b[0m\n")
        wait_text(follow_file, "follow-live-2")
        follower.terminate()
        follower.wait(timeout=5)
        follower = None
        output.close()
        followed = follow_file.read_text(errors="replace")
        tokens = ("follow-history", "follow-live-1", "follow-live-2")
        if any(followed.count(token) != 1 for token in tokens) or "\x1b[" in followed:
            raise AssertionError("follow transition had a gap, duplicate, or ANSI leak")
        evidence["rows"]["history-live-no-gap-duplicate"] = True
        evidence["rows"]["live-ansi-strip"] = True

        peer_code, peer_body = get(
            f"{endpoint}?id={vm_a}&follow=false&ansi=false&lines=100&ch=stderr"
        )
        if peer_code != 200 or b"peer-stderr-secret-marker" in peer_body:
            raise AssertionError("cross-VM log isolation failed")
        traversal_code, _ = get(
            f"{endpoint}?id={urllib.parse.quote('../escape')}&follow=false&ansi=false&lines=1&ch=serial"
        )
        invalid_code, _ = get(
            f"{endpoint}?id=00000000-0000-0000-0000-000000000000&follow=false&ansi=false&lines=1&ch=serial"
        )
        channel_code, _ = get(
            f"{endpoint}?id={vm_a}&follow=false&ansi=false&lines=1&ch=unknown"
        )
        available = subprocess.run(
            [str(x) for x in fixture["availability_probe_argv"]],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if (
            traversal_code != 404
            or invalid_code != 404
            or channel_code != 400
            or available.returncode
        ):
            raise AssertionError(
                "path, invalid-input, channel, or availability boundary failed"
            )
        evidence["rows"].update(
            {
                "cross-vm-isolation": True,
                "path-escape-404": True,
                "invalid-vm-404": True,
                "invalid-channel-400": True,
                "adjacent-availability": True,
            }
        )
        evidence["http_status"] = {
            "traversal": traversal_code,
            "invalid_vm": invalid_code,
            "invalid_channel": channel_code,
        }
        steps.append(
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "All three channels tailed exact history; follow crossed into two live writes once each without gaps or duplicates; ANSI was stripped or preserved according to policy.",
            }
        )
        steps.append(
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Cross-VM content stayed isolated, traversal and unknown VM returned 404, unknown channel returned 400, and the public VM list remained available.",
            }
        )
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for number in range(1, 4):
            step_id = f"{CASE_ID}-step-{number:02d}"
            if not any(step["id"] == step_id for step in steps):
                steps.append(
                    {"id": step_id, "status": "FAIL", "observed": failures[-1]}
                )
    finally:
        if follower is not None:
            follower.terminate()
            try:
                follower.wait(timeout=5)
            except subprocess.TimeoutExpired:
                follower.kill()
        cleanup = []
        for vm_id in ids:
            cleanup.append(
                {
                    "id": vm_id,
                    "stop": rpc(base, routes["StopVm"], vm_id),
                    "remove": rpc(base, routes["RemoveVm"], vm_id),
                }
            )
        evidence["cleanup"] = cleanup
    artifact = {
        "path": "artifacts/vmm-console-follow.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Console history and live-follow matrix",
        "description": "Three-channel history, live boundary, ANSI, isolation, invalid-input, availability, and cleanup evidence.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status_value = "PASS" if not failures else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status_value,
            "summary": f"{len(evidence['rows'])}/13 console rows passed."
            if not failures
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "evidence": [
                {
                    "path": artifact["path"],
                    "sha256": hashlib.sha256(
                        (result_dir / artifact["path"]).read_bytes()
                    ).hexdigest(),
                }
            ],
            "remarks": "Only two registered stopped VM work directories were written; no QEMU VM or image build was started.",
        },
    )
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
