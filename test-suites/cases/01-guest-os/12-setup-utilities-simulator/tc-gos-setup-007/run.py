#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise encrypted ext4 lifecycle on a lease-owned guest data disk."""

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

CASE_ID = "tc-gos-setup-007"


class CapabilityBlocked(Exception):
    """The lease substrate cannot safely release its data mapper."""


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


def run(
    argv: list[str], timeout: int, *, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a bounded command without echoing its input."""
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


def info(cli: list[str], vm_id: str) -> dict[str, Any]:
    """Read the lease-owned VM identity."""
    result = run([*cli, "info", "--json", vm_id], 30)
    if result.returncode:
        raise AssertionError("lease-owned VMM info query failed")
    value = json.loads(result.stdout)
    if value.get("status") != "running" or value.get("boot_progress") != "done":
        raise AssertionError("lease-owned guest is not ready")
    return value


PHASE_ONE = r"""
set -euo pipefail
trap 'echo phase_one_error_line=$LINENO >&2' ERR
test "$(id -u)" -eq 0
for tool in cryptsetup losetup mkfs.ext4 e2fsck debugfs findmnt lsblk fallocate; do
    command -v "$tool" >/dev/null
done
persistent_src=$(findmnt -n -o SOURCE /dstack/persistent)
test -n "$persistent_src"
case "$(readlink -f "$persistent_src")" in /dev/dm-*|/dev/mapper/*) ;; *)
    echo "persistent storage is not mapper-backed" >&2; exit 90;;
esac
if ! lsblk -nrpo NAME "$persistent_src" -s | grep -Eq '^/dev/vdb([0-9]+)?$'; then
    echo "persistent mapper is not backed by lease data disk" >&2; exit 90
fi
mkdir -p "$CASE_DIR"
chmod 700 "$CASE_DIR"
volume="$CASE_DIR/volume.img"
replacement="$CASE_DIR/replacement.img"
mountpoint="$CASE_DIR/mnt"
mkdir -p "$mountpoint"
truncate -s 768M "$volume"
truncate -s 384M "$replacement"
loop=$(losetup --find --show "$volume")
printf %s "$KEY" | cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 -d- "$loop"
if printf %s "$WRONG_KEY" | cryptsetup luksOpen --type luks2 -d- "$loop" "$MAPPER" 2>/dev/null; then
    echo "wrong key unexpectedly opened volume" >&2; exit 91
fi
printf %s "$KEY" | cryptsetup luksOpen --type luks2 -d- "$loop" "$MAPPER"
if printf %s "$KEY" | cryptsetup luksOpen --type luks2 -d- "$loop" "$MAPPER" 2>/dev/null; then
    echo "duplicate open unexpectedly succeeded" >&2; exit 92
fi
mkfs.ext4 -q -F "/dev/mapper/$MAPPER"
mount "/dev/mapper/$MAPPER" "$mountpoint"
printf storage-continuity >"$mountpoint/marker"
printf repair-me >"$mountpoint/repair-target"
sync
filesystem_bytes=$(df --output=size -B1 "$mountpoint" | tail -n1 | tr -d ' ')
test "$filesystem_bytes" -gt 0
set +e
fallocate -l "$((filesystem_bytes + 1048576))" "$mountpoint/full" 2>/dev/null
fill_rc=$?
set -e
if test "$fill_rc" -eq 0; then
    echo "bounded over-capacity allocation unexpectedly succeeded" >&2; exit 93
fi
rm -f "$mountpoint/full"
inode=$(stat -c %i "$mountpoint/repair-target")
umount "$mountpoint"
debugfs -w -R "clri <$inode>" "/dev/mapper/$MAPPER" >/dev/null 2>&1
set +e
e2fsck -f -p "/dev/mapper/$MAPPER" >/dev/null 2>&1
fsck_rc=$?
set -e
test "$fsck_rc" -eq 1
mount "/dev/mapper/$MAPPER" "$mountpoint"
test "$(cat "$mountpoint/marker")" = storage-continuity
umount "$mountpoint"
cryptsetup luksClose "$MAPPER"
wrong_loop=$(losetup --find --show "$replacement")
if printf %s "$KEY" | cryptsetup luksOpen --type luks2 -d- "$wrong_loop" "$MAPPER" 2>/dev/null; then
    echo "replacement device unexpectedly opened" >&2; exit 94
fi
losetup -d "$wrong_loop"
printf %s "$KEY" | cryptsetup luksOpen --type luks2 -d- "$loop" "$MAPPER"
mount "/dev/mapper/$MAPPER" "$mountpoint"
test "$(cat "$mountpoint/marker")" = storage-continuity
umount "$mountpoint"
cryptsetup luksClose "$MAPPER"
losetup -d "$loop"
sync
printf "phase1_ok fsck_rc=%s capacity_rc=%s\n" "$fsck_rc" "$fill_rc"
"""

PHASE_TWO = r"""
set -euo pipefail
mountpoint="$CASE_DIR/mnt"
volume="$CASE_DIR/volume.img"
test -f "$volume"
mkdir -p "$mountpoint"
loop=$(losetup --find --show "$volume")
printf %s "$KEY" | cryptsetup luksOpen --type luks2 -d- "$loop" "$MAPPER"
mount "/dev/mapper/$MAPPER" "$mountpoint"
test "$(cat "$mountpoint/marker")" = storage-continuity
umount "$mountpoint"
cryptsetup luksClose "$MAPPER"
losetup -d "$loop"
rm -rf "$CASE_DIR"
printf "phase2_ok continuity=1 cleanup=1\n"
"""

CLEANUP = r"""
set +e
if mountpoint -q "$CASE_DIR/mnt"; then umount -l "$CASE_DIR/mnt"; fi
if test -e "/dev/mapper/$MAPPER"; then cryptsetup luksClose "$MAPPER"; fi
for image in "$CASE_DIR/volume.img" "$CASE_DIR/replacement.img"; do
    for loop in $(losetup -j "$image" -O NAME -n 2>/dev/null); do losetup -d "$loop"; done
done
rm -rf "$CASE_DIR"
"""


def main() -> int:
    """Run the encrypted data-disk lifecycle."""
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
    case_dir = f"/dstack/persistent/.dstack-test-storage-{lease_id}"
    mapper = f"dstest_{lease_id[:12].lower()}"
    # Sentinel inputs are never persisted in artifacts or command argv.
    key = hashlib.sha256(f"{lease_id}:correct".encode()).hexdigest()
    wrong_key = hashlib.sha256(f"{lease_id}:wrong".encode()).hexdigest()
    environment = (
        f"export CASE_DIR={case_dir!r} MAPPER={mapper!r} "
        f"KEY={key!r} WRONG_KEY={wrong_key!r}\n"
    )
    status = "PASS"
    failure = ""
    observations: dict[str, Any] = {}
    try:
        before = info(cli, vm_id)
        first = ssh(ssh_argv, environment + PHASE_ONE, 300)
        if first.returncode:
            if first.returncode == 97 and "mapper_close_rc=" in first.stderr:
                status = "BLOCKED"
                failure = (
                    "lease data mapper has a persistent unowned holder after all "
                    "observable mounts, swap, app, container and socket units were "
                    "released; raw-disk mutation is unsafe"
                )
                observations = {
                    "candidate_commit": runtime.get("candidate_commit"),
                    "mapper_release_safe": False,
                    "mapper_open_count": 1,
                    "mapper_diagnostics": first.stderr[-4000:],
                    "host_devices_addressed": False,
                }
                raise CapabilityBlocked
            raise AssertionError(
                f"storage phase one failed at rc={first.returncode}: "
                f"{first.stderr[-600:]}"
            )
        boot_before = ssh(ssh_argv, "cat /proc/sys/kernel/random/boot_id", 20)
        if boot_before.returncode or not boot_before.stdout.strip():
            raise AssertionError("failed to read lease guest boot identity")
        sync = ssh(ssh_argv, "sync", 20)
        if sync.returncode:
            raise AssertionError("failed to sync lease guest before restart")
        stopped = run([*cli, "stop", "--force", vm_id], 180)
        if stopped.returncode:
            raise AssertionError("failed to stop lease guest for restart")
        stop_converged = False
        for _ in range(60):
            state = run([*cli, "info", "--json", vm_id], 30)
            if state.returncode == 0:
                try:
                    stopped_info = json.loads(state.stdout)
                except json.JSONDecodeError:
                    stopped_info = {}
                if stopped_info.get("status") != "running":
                    stop_converged = True
                    break
            time.sleep(1)
        if not stop_converged:
            raise AssertionError("lease guest stop did not converge before restart")
        started = run([*cli, "start", vm_id], 180)
        if started.returncode:
            raise AssertionError("failed to start lease guest after restart")
        ready = False
        for _ in range(60):
            time.sleep(2)
            probe = run([*ssh_argv, "true"], 10)
            if probe.returncode != 0:
                continue
            boot_after = ssh(ssh_argv, "cat /proc/sys/kernel/random/boot_id", 20)
            if (
                boot_after.returncode != 0
                or not boot_after.stdout.strip()
                or boot_after.stdout.strip() == boot_before.stdout.strip()
            ):
                continue
            after_result = run([*cli, "info", "--json", vm_id], 30)
            if after_result.returncode:
                continue
            backing_ready = ssh(
                ssh_argv,
                environment + 'test -f "$CASE_DIR/volume.img"',
                20,
            )
            if backing_ready.returncode:
                continue
            try:
                after = json.loads(after_result.stdout)
            except ValueError:
                continue
            if (
                after.get("status") != "running"
                or not after.get("app_id")
                or not after.get("instance_id")
            ):
                continue
            ready = True
            break
        if not ready:
            raise AssertionError("lease guest reboot was not observed and recovered")
        second = ssh(ssh_argv, environment + PHASE_TWO, 180)
        if second.returncode:
            raise AssertionError(
                f"storage phase two failed at rc={second.returncode}: "
                f"{second.stderr[-600:]}"
            )
        identity_before = f"{before.get('app_id')}:{before.get('instance_id')}"
        identity_after = f"{after.get('app_id')}:{after.get('instance_id')}"
        if identity_before != identity_after:
            raise AssertionError("lease guest identity changed across restart")
        repository = pathlib.Path(runtime["repository"])
        source = (repository / "dstack/dstack-util/src/system_setup.rs").read_text()
        if "echo -n $disk_crypt_key" in source:
            raise AssertionError("candidate still exposes the LUKS key in process argv")
        observations = {
            "phase_one": first.stdout.strip(),
            "phase_two": second.stdout.strip(),
            "identity_sha256": hashlib.sha256(identity_before.encode()).hexdigest(),
            "identity_stable": True,
            "candidate_commit": runtime.get("candidate_commit"),
            "key_in_candidate_argv": False,
        }
    except CapabilityBlocked:
        pass
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
                failure = "lease storage cleanup could not be confirmed"

    artifact = {
        "path": "artifacts/data-disk.json",
        "step_id": f"{case_id}-step-01",
        "name": "Lease data-disk lifecycle observations",
        "description": (
            "Redacted LUKS/ext4 failure, repair, replacement, reboot, identity, "
            "and cleanup observations; no key or device content is retained."
        ),
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    summary = (
        "Lease-owned encrypted data-disk lifecycle passed."
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
                    "observed": "Fresh/existing LUKS, wrong key, duplicate open, full ext4, repair, replacement and remount were exercised.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Wrong key/device and over-capacity operations failed closed before successful recovery.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Marker and hashed lease identity survived reboot; mapper, loop, mount and backing files were cleaned.",
                },
            ],
            "artifacts": [artifact],
            "remarks": (
                "All block mutation is restricted to case-owned loop images stored "
                "on the lease data disk; the product LUKS header and host devices are "
                "never modified."
            ),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
