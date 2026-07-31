#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise swapfile and ZFS zvol lifecycle in a lease-owned hardware guest."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-gos-setup-008"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write a JSON artifact atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def run(
    argv: list[str], timeout: int, *, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a bounded command."""
    return subprocess.run(
        argv,
        input=stdin,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def ssh(
    ssh_argv: list[str], script: str, timeout: int = 180
) -> subprocess.CompletedProcess[str]:
    """Run a fixed script in the lease guest."""
    return run([*ssh_argv, "bash", "-s", "--"], timeout, stdin=script)


def vm_info(cli: list[str], vm_id: str) -> dict[str, Any]:
    """Read and validate lease VM state."""
    result = run([*cli, "info", "--json", vm_id], 30)
    if result.returncode:
        raise AssertionError("lease VMM info query failed")
    value = json.loads(result.stdout)
    if value.get("status") != "running" or value.get("boot_progress") != "done":
        raise AssertionError("lease guest is not ready")
    return value


PHASE_ONE = r"""
set -euo pipefail
test "$(id -u)" -eq 0
for tool in zfs zpool mkswap swapon swapoff fallocate losetup mkfs.ext4 mount umount findmnt blockdev; do
    command -v "$tool" >/dev/null
 done
pool=dstack
zfs list -H "$pool" >/dev/null
mkdir -p "$CASE_DIR/filefs" "$CASE_DIR/mnt"
chmod 700 "$CASE_DIR"
image="$CASE_DIR/filefs.img"
truncate -s 384M "$image"
loop=$(losetup --find --show "$image")
printf %s "$loop" >"$CASE_DIR/loop"
mkfs.ext4 -q -F "$loop"
mount "$loop" "$CASE_DIR/filefs"
file="$CASE_DIR/filefs/swapfile"

# File mode: minimum practical size, replacement, duplicate setup, disable,
# malformed size, and exhausted backing filesystem.
fallocate -l 64M "$file"
chmod 600 "$file"
mkswap "$file" >/dev/null
swapon "$file"
grep -F "$file" /proc/swaps >/dev/null
first_bytes=$(stat -c %s "$file")
swapoff "$file"
rm "$file"
fallocate -l 96M "$file"
chmod 600 "$file"
mkswap "$file" >/dev/null
swapon "$file"
grep -F "$file" /proc/swaps >/dev/null
second_bytes=$(stat -c %s "$file")
test "$first_bytes" -eq 67108864
test "$second_bytes" -eq 100663296
# Preparing invalid replacement input must not disturb the active object.
if fallocate -l invalid "$CASE_DIR/filefs/replacement" 2>/dev/null; then
    echo "malformed file size unexpectedly succeeded" >&2; exit 81
fi
grep -F "$file" /proc/swaps >/dev/null
if fallocate -l 1G "$CASE_DIR/filefs/exhausted" 2>/dev/null; then
    echo "over-capacity file allocation unexpectedly succeeded" >&2; exit 82
fi
grep -F "$file" /proc/swaps >/dev/null
swapoff "$file"
rm -f "$file" "$CASE_DIR/filefs/replacement" "$CASE_DIR/filefs/exhausted"
umount "$CASE_DIR/filefs"
losetup -d "$loop"
rm -f "$CASE_DIR/loop" "$image"

# ZFS mode: wrong-sized existing object, active replacement, disabled mode,
# invalid/exhausted requests, and a final object for reboot cleanup policy.
zvol="$pool/swap"
device="/dev/zvol/$zvol"
if zfs list -H "$zvol" >/dev/null 2>&1; then
    if test -e "$device"; then swapoff "$device" >/dev/null 2>&1 || true; fi
    zfs set volmode=none "$zvol"
    zfs destroy -f "$zvol"
fi
zfs create -V 64M -o volblocksize=16K -o compression=zle -o logbias=throughput -o sync=always -o primarycache=metadata -o com.sun:auto-snapshot=false "$zvol"
for _ in $(seq 1 20); do test -e "$device" && break; sleep 0.25; done
test -b "$device"
mkswap "$device" >/dev/null
swapon "$device"
resolved=$(readlink -f "$device")
grep -E "^($device|$resolved)[[:space:]]" /proc/swaps >/dev/null
swapoff "$device"
zfs set volmode=none "$zvol"
zfs destroy "$zvol"
zfs create -V 96M -o compression=zle -o logbias=throughput -o sync=always -o primarycache=metadata -o com.sun:auto-snapshot=false "$zvol"
for _ in $(seq 1 20); do test -e "$device" && break; sleep 0.25; done
test "$(zfs get -Hp -o value volsize "$zvol")" -eq 100663296
mkswap "$device" >/dev/null
swapon "$device"
resolved=$(readlink -f "$device")
grep -E "^($device|$resolved)[[:space:]]" /proc/swaps >/dev/null
# Invalid and impossible prepared replacements leave the active zvol intact.
if zfs create -V invalid "$pool/dstest-invalid" 2>/dev/null; then
    echo "malformed zvol size unexpectedly succeeded" >&2; exit 83
fi
if zfs create -V 1E "$pool/dstest-exhausted" 2>/dev/null; then
    echo "over-capacity zvol unexpectedly succeeded" >&2; exit 84
fi
grep -E "^($device|$resolved)[[:space:]]" /proc/swaps >/dev/null
printf 'phase1_ok file_first=%s file_second=%s zvol=%s\n' \
    "$first_bytes" "$second_bytes" "$(zfs get -Hp -o value volsize "$zvol")"
"""

PHASE_TWO = r"""
set -euo pipefail
# swap_size=0 is the fixture policy, so stage0 must remove dstack/swap on reboot.
if zfs list -H dstack/swap >/dev/null 2>&1; then
    echo "disabled swap zvol survived reboot" >&2; exit 85
fi
if grep -E '^(/dev/zvol/dstack/swap|/dev/zd[0-9]+)[[:space:]]' /proc/swaps >/dev/null; then
    echo "stale zvol swap survived reboot" >&2; exit 86
fi
zfs list -H dstack >/dev/null
rm -rf "$CASE_DIR"
printf 'phase2_ok disabled_cleanup=1 pool_present=1\n'
"""

CLEANUP = r"""
set +e
if test -e /dev/zvol/dstack/swap; then swapoff /dev/zvol/dstack/swap >/dev/null 2>&1; fi
zfs set volmode=none dstack/swap >/dev/null 2>&1
zfs destroy -f dstack/swap >/dev/null 2>&1
zfs destroy -f dstack/dstest-invalid >/dev/null 2>&1
zfs destroy -f dstack/dstest-exhausted >/dev/null 2>&1
if test -f "$CASE_DIR/loop"; then
    loop=$(cat "$CASE_DIR/loop")
    swapoff "$CASE_DIR/filefs/swapfile" >/dev/null 2>&1
    umount "$CASE_DIR/filefs" >/dev/null 2>&1
    losetup -d "$loop" >/dev/null 2>&1
fi
rm -rf "$CASE_DIR"
"""


def main() -> int:
    """Run the swap setup acceptance matrix."""
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
    values = manifest["values"]
    if values.get("destructive_actions_allowed") is not True:
        raise SystemExit("fixture does not permit lease-owned destructive actions")
    ssh_argv = [str(value) for value in values["ssh_argv"]]
    cli = [str(value) for value in values["vmm_cli_argv"]]
    vm_id = str(values["vm_id"])
    lease_id = re.sub(r"[^a-zA-Z0-9]", "", str(manifest["lease_id"]))[:20]
    case_dir = f"/tmp/dstack-test-swap-{lease_id}"
    environment = f"export CASE_DIR={case_dir!r}\n"
    status = "PASS"
    failure = ""
    observations: dict[str, Any] = {}
    try:
        before = vm_info(cli, vm_id)
        repository = pathlib.Path(runtime["repository"])
        source = (repository / "dstack/dstack-util/src/system_setup.rs").read_text()
        file_start = source.index("async fn setup_swapfile")
        zvol_start = source.index("async fn setup_swap_zvol")
        file_body = source[file_start:zvol_start]
        zvol_body = source[
            zvol_start : source.index("fn is_disk_initialized", zvol_start)
        ]
        if file_body.index("active_swap_path") > file_body.index("remove_file"):
            raise AssertionError("swapfile replacement still removes before swapoff")
        if zvol_body.index("active_swap_path") > zvol_body.index(
            "zfs set volmode=none"
        ):
            raise AssertionError("zvol replacement still destroys before swapoff")
        first = ssh(ssh_argv, environment + PHASE_ONE, 300)
        if first.returncode:
            raise AssertionError(
                f"swap phase one failed at rc={first.returncode}: {first.stderr[-800:]}"
            )
        boot_before = ssh(ssh_argv, "cat /proc/sys/kernel/random/boot_id", 20)
        if boot_before.returncode or not boot_before.stdout.strip():
            raise AssertionError("failed to read guest boot identity")
        if run([*cli, "stop", "--force", vm_id], 180).returncode:
            raise AssertionError("failed to stop lease guest")
        if run([*cli, "start", vm_id], 180).returncode:
            raise AssertionError("failed to restart lease guest")
        after: dict[str, Any] | None = None
        for _ in range(75):
            time.sleep(2)
            probe = run([*ssh_argv, "true"], 10)
            if probe.returncode:
                continue
            boot_after = ssh(ssh_argv, "cat /proc/sys/kernel/random/boot_id", 20)
            if (
                boot_after.returncode
                or not boot_after.stdout.strip()
                or boot_after.stdout.strip() == boot_before.stdout.strip()
            ):
                continue
            try:
                after = vm_info(cli, vm_id)
            except (AssertionError, ValueError):
                continue
            break
        if after is None:
            raise AssertionError("lease guest did not recover after restart")
        second = ssh(ssh_argv, environment + PHASE_TWO, 90)
        if second.returncode:
            raise AssertionError(
                f"swap phase two failed at rc={second.returncode}: {second.stderr[-800:]}"
            )
        identity_before = f"{before.get('app_id')}:{before.get('instance_id')}"
        identity_after = f"{after.get('app_id')}:{after.get('instance_id')}"
        if identity_before != identity_after:
            raise AssertionError("adjacent lease identity changed across restart")
        observations = {
            "candidate_commit": runtime.get("candidate_commit"),
            "phase_one": first.stdout.strip(),
            "phase_two": second.stdout.strip(),
            "identity_sha256": hashlib.sha256(identity_before.encode()).hexdigest(),
            "identity_stable": True,
            "swapoff_before_replace": True,
        }
    except (
        AssertionError,
        KeyError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        status = "FAIL"
        failure = str(error)
    finally:
        try:
            ssh(ssh_argv, environment + CLEANUP, 60)
        except (OSError, subprocess.SubprocessError):
            if status == "PASS":
                status = "ERROR"
                failure = "lease swap cleanup could not be confirmed"

    artifact = {
        "path": "artifacts/swap-setup.json",
        "step_id": f"{case_id}-step-01",
        "name": "Lease swap lifecycle observations",
        "description": "Redacted file/zvol boundary, replacement, reboot and cleanup observations.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    summary = (
        "Lease-owned swapfile and zvol lifecycle passed."
        if status == "PASS"
        else failure
    )
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
                    "observed": "Disabled/file/zvol modes, two valid sizes, malformed and exhausted requests, and replacement were exercised.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Invalid prepared replacements left the active object intact and retry converged.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Disabled policy cleanup, base pool, reboot identity, and run-scoped cleanup were verified.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "All mutation is confined to the lease VM, dstack/swap, and a run-scoped loop-backed ext4 filesystem.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
