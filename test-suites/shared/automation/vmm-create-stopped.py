#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Create and register one stopped VM from the prepared case fixture."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
from pathlib import Path

VM_ID = re.compile(r"^Created VM with ID:\s*([0-9a-f-]{36})$", re.MULTILINE)


def fail(message: str) -> None:
    """Exit with one concise setup error."""
    print(message, file=sys.stderr)
    raise SystemExit(1)


def parse_args() -> argparse.Namespace:
    """Parse the bounded VM configuration overrides used by lifecycle cases."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--name")
    parser.add_argument("--image")
    parser.add_argument("--compose")
    parser.add_argument("--vcpu", type=int)
    parser.add_argument("--memory", type=int)
    parser.add_argument("--disk-size", type=int)
    parser.add_argument("--hugepages", action="store_true")
    parser.add_argument("--pin-numa", action="store_true")
    parser.add_argument("--registry")
    parser.add_argument("--url")
    parser.add_argument("--stopped", action="store_true")
    parser.add_argument("--no-tee", action="store_true")
    parser.add_argument("--simulated-tee")
    parser.add_argument("subcommand", nargs="?")
    # Older case harnesses used `--` before the prepared mode flags. These are
    # still helper options, not a child command, so accept the delimiter without
    # silently discarding the following values.
    return parser.parse_args([value for value in sys.argv[1:] if value != "--"])


def apply_overrides(command: list[str], args: argparse.Namespace) -> list[str]:
    """Replace prepared scalar options and append explicitly requested flags."""
    resolved = list(command)
    scalar = {
        "--name": args.name,
        "--image": args.image,
        "--compose": args.compose,
        "--vcpu": args.vcpu,
        "--memory": args.memory,
        "--disk-size": args.disk_size,
    }
    for option, value in scalar.items():
        if value is None:
            continue
        if option in resolved:
            index = resolved.index(option)
            if index + 1 >= len(resolved):
                fail(f"prepared command has no value for {option}")
            resolved[index + 1] = str(value)
        else:
            resolved.extend([option, str(value)])
    for option, enabled in (
        ("--hugepages", args.hugepages),
        ("--pin-numa", args.pin_numa),
    ):
        if enabled and option not in resolved:
            resolved.append(option)
    return resolved


def main() -> None:
    """Create the prepared stopped VM and register its returned ID."""
    args = parse_args()
    manifest_path = Path(os.environ.get("DSTACK_TEST_CASE_MANIFEST", "")).resolve()
    if not manifest_path.is_file():
        fail("DSTACK_TEST_CASE_MANIFEST is unavailable")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    vmm = manifest.get("values", {}).get("vmm", {})
    test_input = vmm.get("test_input", {})
    command = test_input.get("create_stopped_argv")
    registry = Path(str(test_input.get("created_vms_registry", ""))).resolve()
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(item, str) for item in command)
    ):
        fail("prepared create_stopped_argv is invalid")
    if not registry.is_file():
        fail("prepared created VM registry is unavailable")
    if args.registry and Path(args.registry).resolve() != registry:
        fail("registry override does not match the prepared VM registry")
    if args.url and args.url != vmm.get("rpc_url"):
        fail("URL override does not match the prepared VMM endpoint")
    if args.subcommand not in (None, "deploy"):
        fail("only the prepared deploy operation is supported")
    prepared_flags = set(test_input.get("create_stopped_args", []))
    requested_flags = {
        flag
        for flag, enabled in (("--stopped", args.stopped), ("--no-tee", args.no_tee))
        if enabled
    }
    if not requested_flags.issubset(prepared_flags):
        fail("requested VM mode is not part of the prepared fixture")
    if args.simulated_tee:
        expected = None
        flags = list(test_input.get("create_stopped_args", []))
        if "--simulated-tee" in flags:
            index = flags.index("--simulated-tee")
            if index + 1 < len(flags):
                expected = flags[index + 1]
        if args.simulated_tee != expected:
            fail("simulated TEE override does not match the prepared fixture")
    command = apply_overrides(command, args)
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if completed.returncode:
        fail(f"VMM create command failed: {completed.stderr[-1000:]}")
    match = VM_ID.search(completed.stdout)
    if not match:
        fail("VMM create command did not return a VM ID")
    vm_id = match.group(1)
    with registry.open("r+", encoding="utf-8") as output:
        fcntl.flock(output, fcntl.LOCK_EX)
        current = json.load(output)
        if not isinstance(current, list):
            fail("created VM registry must contain an array")
        if vm_id not in current:
            current.append(vm_id)
        output.seek(0)
        json.dump(current, output, separators=(",", ":"))
        output.write("\n")
        output.truncate()
    print(json.dumps({"id": vm_id}, separators=(",", ":")))


if __name__ == "__main__":
    main()
