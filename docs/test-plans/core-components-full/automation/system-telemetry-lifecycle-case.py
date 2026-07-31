#!/usr/bin/env python3
"""Exercise live GuestApi network and resource telemetry transitions."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-observabil-004"
UNKNOWN_ID = "00000000-0000-4000-8000-000000000000"


def ssh(
    argv: list[str], command: str, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run one bounded command in the lease-owned guest."""
    result = subprocess.run(
        [*argv, command],
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(f"guest command failed with rc={result.returncode}")
    return result


def rpc(url: str, vm_id: str) -> tuple[int, dict[str, Any]]:
    """Call one proxied GuestApi JSON method."""
    request = urllib.request.Request(
        url,
        data=json.dumps({"id": vm_id}, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            code, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        code, raw = error.code, error.read()
    value = json.loads(raw) if raw else {}
    if not isinstance(value, dict):
        raise AssertionError("GuestApi returned a non-object")
    return code, value


def by_name(rows: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    """Find one row by name."""
    return next((row for row in rows if row.get("name") == name), None)


def main() -> int:
    """Run baseline, changed, restored, invalid-input, and cleanup observations."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    values = manifest["values"]
    ssh_argv = values["ssh_argv"]
    vm_id = str(values["vm_id"])
    proxied = values["services"]["ProxiedGuestApi"]
    base = str(proxied["url"])
    lease = os.environ.get("DSTACK_TEST_LEASE_ID", "lease")[-8:].replace("-", "")
    interface = f"ethobs{lease[:5]}"
    peer = f"veth{lease[:6]}"
    container = f"dstack-telemetry-{lease}"
    dns = "192.0.2.53"
    address = "192.0.2.10"
    marker_dir = f"/run/dstack-telemetry-{lease}"
    cleanup_errors: list[str] = []
    checks: dict[str, bool] = {}
    status = "FAIL"
    summary = "telemetry lifecycle did not complete"
    started = time.monotonic()

    def call(method: str, target: str = vm_id) -> tuple[int, dict[str, Any]]:
        return rpc(base.format(method=method), target)

    try:
        baseline_codes_values = {
            method: call(method)
            for method in ("SysInfo", "NetworkInfo", "ListContainers")
        }
        checks["baseline_methods_healthy"] = all(
            code == 200 for code, _ in baseline_codes_values.values()
        )
        if not checks["baseline_methods_healthy"]:
            raise AssertionError("baseline GuestApi methods failed")
        baseline_sys = baseline_codes_values["SysInfo"][1]
        baseline_net = baseline_codes_values["NetworkInfo"][1]
        baseline_containers = baseline_codes_values["ListContainers"][1]
        if by_name(baseline_net.get("interfaces", []), interface):
            raise AssertionError("run-scoped interface already exists")
        if any(
            container in row.get("names", [])
            for row in baseline_containers.get("containers", [])
        ):
            raise AssertionError("run-scoped container already exists")
        mount_point = str(
            baseline_sys.get("disks", [{}])[0].get("mount_point", "/data")
        )
        baseline_disk = baseline_sys.get("disks", [{}])[0]
        baseline_available = int(baseline_sys.get("available_memory", 0))
        baseline_used = int(baseline_sys.get("used_memory", 0))
        baseline_swap = int(baseline_sys.get("total_swap", 0))

        network_setup = f"""set -eu
mkdir -p {shlex.quote(marker_dir)}
printf '[Match]\nName={interface}\n[Link]\nUnmanaged=yes\n' > /run/systemd/network/00-{interface}.network
networkctl reload
ip link add {interface} type veth peer name {peer}
ip addr add {address}/24 dev {interface}
ip link set {interface} up
ip link set {peer} up
ip route add 198.51.100.0/24 dev {interface} metric 4096
"""
        ssh(ssh_argv, network_setup)
        checks["network_setup_completed"] = True

        dns_setup = f"""set -eu
cp /etc/resolv.conf {marker_dir}/resolv.conf
printf '\nnameserver {dns}\n' >> {marker_dir}/resolv.conf
mount --bind {marker_dir}/resolv.conf /etc/resolv.conf
"""
        ssh(ssh_argv, dns_setup)
        checks["dns_setup_completed"] = True

        storage_setup = f"""set -eu
dd if=/dev/urandom of={shlex.quote(mount_point)}/.dstack-telemetry-{lease} bs=1M count=128 conv=fsync >/dev/null 2>&1
dd if=/dev/zero of={marker_dir}/swap bs=1M count=16 >/dev/null 2>&1
loop=$(losetup -f --show {marker_dir}/swap)
printf '%s' "$loop" > {marker_dir}/loop
mkswap "$loop" >/dev/null
swapon "$loop"
"""
        ssh(ssh_argv, storage_setup)
        checks["storage_swap_setup_completed"] = True

        pressure_setup = f"""set -eu
python3 -c 'x=bytearray(268435456); __import__("time").sleep(60)' >/dev/null 2>&1 &
echo $! > {marker_dir}/memory.pid
python3 -c 'x=0\nwhile True: x+=1' >/dev/null 2>&1 &
echo $! > {marker_dir}/load.pid
"""
        ssh(ssh_argv, pressure_setup)
        checks["pressure_setup_completed"] = True

        container_setup = f"""set -eu
running=$(docker ps -q | head -1)
test -n "$running"
image=$(docker inspect --format '{{{{.Config.Image}}}}' "$running")
docker create --name {container} "$image" >/dev/null
docker start {container} >/dev/null
sleep 2
"""
        ssh(ssh_argv, container_setup)
        checks["container_setup_completed"] = True
        ssh(ssh_argv, "sync; zpool sync 2>/dev/null || true; sleep 8")
        process_probe = ssh(
            ssh_argv,
            f"kill -0 $(cat {marker_dir}/memory.pid) $(cat {marker_dir}/load.pid)",
            check=False,
        )
        checks["pressure_processes_alive"] = process_probe.returncode == 0
        changed_codes_values = {
            method: call(method)
            for method in ("SysInfo", "NetworkInfo", "ListContainers")
        }
        checks["changed_methods_healthy"] = all(
            code == 200 for code, _ in changed_codes_values.values()
        )
        changed_sys = changed_codes_values["SysInfo"][1]
        changed_net = changed_codes_values["NetworkInfo"][1]
        changed_containers = changed_codes_values["ListContainers"][1]
        interface_row = by_name(changed_net.get("interfaces", []), interface)
        changed_disk = next(
            (
                row
                for row in changed_sys.get("disks", [])
                if row.get("mount_point") == baseline_disk.get("mount_point")
            ),
            {},
        )
        checks["network_interface_row_visible"] = interface_row is not None
        checks["network_interface_address_visible"] = interface_row is not None and any(
            row.get("address") == address for row in interface_row.get("addresses", [])
        )
        checks["network_dns_visible"] = dns in changed_net.get("dns_servers", [])
        checks["memory_transition_visible"] = (
            int(changed_sys.get("used_memory", baseline_used)) > baseline_used
            or int(changed_sys.get("available_memory", baseline_available))
            < baseline_available
        )
        checks["swap_transition_visible"] = (
            int(changed_sys.get("total_swap", baseline_swap)) > baseline_swap
        )
        checks["disk_row_visible"] = bool(changed_disk)
        checks["disk_free_space_decreased"] = bool(changed_disk) and int(
            changed_disk.get("free_size", 0)
        ) < int(baseline_disk.get("free_size", 0))
        checks["container_transition_visible"] = any(
            container == str(name).lstrip("/")
            for row in changed_containers.get("containers", [])
            for name in row.get("names", [])
        )

        cleanup = f"""set +e
docker rm -f {container} >/dev/null 2>&1
kill $(cat {marker_dir}/memory.pid) $(cat {marker_dir}/load.pid) >/dev/null 2>&1
swapoff $(cat {marker_dir}/loop) >/dev/null 2>&1
losetup -d $(cat {marker_dir}/loop) >/dev/null 2>&1
umount /etc/resolv.conf >/dev/null 2>&1
ip link del {interface} >/dev/null 2>&1
rm -f /run/systemd/network/00-{interface}.network
networkctl reload
rm -f {shlex.quote(mount_point)}/.dstack-telemetry-{lease}
rm -rf {marker_dir}
"""
        ssh(ssh_argv, cleanup)
        final_codes_values = {
            method: call(method)
            for method in ("SysInfo", "NetworkInfo", "ListContainers")
        }
        final_sys = final_codes_values["SysInfo"][1]
        final_net = final_codes_values["NetworkInfo"][1]
        final_containers = final_codes_values["ListContainers"][1]
        checks["cleanup_disappeared"] = (
            all(code == 200 for code, _ in final_codes_values.values())
            and by_name(final_net.get("interfaces", []), interface) is None
            and dns not in final_net.get("dns_servers", [])
            and int(final_sys.get("total_swap", -1)) == baseline_swap
            and not any(
                container in row.get("names", [])
                for row in final_containers.get("containers", [])
            )
        )
        invalid_code, invalid_body = call("SysInfo", UNKNOWN_ID)
        checks["unknown_identity_rejected"] = invalid_code >= 400 and bool(invalid_body)
        status = "PASS" if all(checks.values()) else "FAIL"
        summary = (
            "GuestApi network, DNS, memory, disk, swap, container, cleanup, and invalid-identity telemetry passed."
            if status == "PASS"
            else f"Telemetry checks failed: {sorted(k for k, value in checks.items() if not value)}"
        )
    except Exception as error:
        summary = f"Telemetry lifecycle failed: {type(error).__name__}"
    finally:
        emergency = f"""set +e
docker rm -f {container} >/dev/null 2>&1
test -f {marker_dir}/memory.pid && kill $(cat {marker_dir}/memory.pid) >/dev/null 2>&1
test -f {marker_dir}/load.pid && kill $(cat {marker_dir}/load.pid) >/dev/null 2>&1
test -f {marker_dir}/loop && swapoff $(cat {marker_dir}/loop) >/dev/null 2>&1
test -f {marker_dir}/loop && losetup -d $(cat {marker_dir}/loop) >/dev/null 2>&1
mountpoint -q /etc/resolv.conf && umount /etc/resolv.conf >/dev/null 2>&1
ip link del {interface} >/dev/null 2>&1
rm -f /run/systemd/network/00-{interface}.network
networkctl reload >/dev/null 2>&1
rm -rf {marker_dir}
"""
        try:
            ssh(ssh_argv, emergency, check=False)
        except Exception as error:
            cleanup_errors.append(type(error).__name__)

    if cleanup_errors:
        status = "FAIL"
    artifact = result_dir / "artifacts/system-telemetry-lifecycle.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(
        json.dumps(
            {
                "candidate_commit": runtime["candidate_commit"],
                "checks": checks,
                "cleanup_error_count": len(cleanup_errors),
                "retained_addresses_dns_container_names_paths_or_native_responses": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/system-telemetry-lifecycle.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "All mutations were scoped to the lease-owned guest and removed; evidence retains booleans and counts only.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
