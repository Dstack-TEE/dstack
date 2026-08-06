#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Privileged end-to-end coverage for the optional libvirt nwfilter backend."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import signal
import socket
import struct
import subprocess
import threading
import time
import urllib.request
import uuid
from pathlib import Path

CASE_ID = "tc-vmm-compute-ne-001"
TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


def run(argv, timeout=60):
    return subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)


def sudo(*argv, timeout=60):
    return run(["sudo", "-n", *argv], timeout)


def rpc(base, method, value, timeout=60):
    request = urllib.request.Request(
        f"{base}/prpc/{method}?json",
        data=json.dumps(value).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(request, timeout=timeout).read() or b"{}")


def netd(socket_path, value):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(30)
    client.connect(str(socket_path))
    client.sendall(json.dumps(value).encode())
    client.shutdown(socket.SHUT_WR)
    chunks = []
    while chunk := client.recv(65536):
        chunks.append(chunk)
    response = json.loads(b"".join(chunks))
    if not response.get("ok"):
        raise RuntimeError(response.get("error", "netd request failed"))
    return response["tap"]


def bindings():
    output = run(["virsh", "-c", "qemu:///system", "nwfilter-binding-list"])
    if output.returncode:
        raise RuntimeError(output.stderr)
    return output.stdout


def tap_name(instance, vm_id, nic):
    digest = hashlib.sha256(f"{instance}\0{vm_id}\0{nic}".encode()).hexdigest()
    return "dt" + digest[:12]


def start(argv, log, *, root=False, cwd=None):
    command = ["sudo", "-n", *argv] if root else argv
    return subprocess.Popen(
        command,
        cwd=cwd,
        stdout=log.open("a"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
        text=True,
    )


def stop(process):
    if process and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(5)


def wait_for(predicate, message, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.25)
    raise TimeoutError(message)


def wait_netd(path, process, message):
    wait_for(lambda: path.exists() or process.poll() is not None, message)
    if process.poll() is not None:
        raise RuntimeError(f"{message}: netd exited with {process.returncode}")
    # Existence can briefly refer to the old listener during a restart.
    time.sleep(0.5)


def packet_probe(tap, bridge, expected_mac, root):
    """Inject guest egress frames and prove clean-traffic drops forged identities."""
    capture = root / "spoof.pcap"
    tcpdump = start(
        ["tcpdump", "-U", "-n", "-e", "-i", bridge, "-w", str(capture)],
        root / "tcpdump.log",
        root=True,
    )
    try:
        time.sleep(1)
        fd = os.open("/dev/net/tun", os.O_RDWR)
        fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", tap.encode(), IFF_TAP | IFF_NO_PI))
        good = bytes.fromhex(expected_mac.replace(":", ""))
        bad = b"\x02\xaa\xbb\xcc\xdd\xee"
        broadcast = b"\xff" * 6

        def arp(source_mac, source_ip):
            return (
                broadcast + source_mac + b"\x08\x06" + b"\x00\x01\x08\x00\x06\x04\x00\x01"
                + source_mac + socket.inet_aton(source_ip) + b"\x00" * 6
                + socket.inet_aton("192.0.2.1")
            )

        # One allowed identity and each prohibited identity are deliberately unique.
        os.write(fd, arp(good, "192.0.2.2"))
        os.write(fd, arp(good, "192.0.2.99"))
        os.write(fd, arp(bad, "192.0.2.2"))
        os.write(fd, arp(bad, "192.0.2.99"))
        os.close(fd)
        time.sleep(2)
    finally:
        stop(tcpdump)
    decoded = run(["tcpdump", "-n", "-e", "-r", str(capture)]).stdout
    return {
        "capture": decoded,
        "normal_seen": "192.0.2.2" in decoded and expected_mac in decoded.lower(),
        "ip_spoof_blocked": "192.0.2.99" not in decoded,
        "mac_spoof_blocked": "02:aa:bb:cc:dd:ee" not in decoded.lower(),
        "arp_spoof_blocked": not (
            "02:aa:bb:cc:dd:ee" in decoded.lower() or "192.0.2.99" in decoded
        ),
    }


def make_config(template, root, image_store, binary, supervisor, bridge, port, instance):
    text = template
    replacements = {
        'temp_dir = "/tmp"': f'temp_dir = "{root}/data"\nrun_path = "{root}/vms"',
        'address = "unix:./vmm.sock"': f'address = "127.0.0.1:{port}"',
        '# path = ""': f'path = "{image_store}"',
        'qemu_path = ""': 'qemu_path = "/usr/bin/qemu-system-x86_64"',
        'platform = "auto"': 'platform = "tdx"',
        'instance_id = ""': f'instance_id = "{instance}"',
        'exe = "./supervisor"': f'exe = "{supervisor}"',
        'sock = "./run/supervisor.sock"': f'sock = "{root}/supervisor.sock"',
        'pid_file = "./run/supervisor.pid"': f'pid_file = "{root}/supervisor.pid"',
        'log_file = "./run/supervisor.log"': f'log_file = "{root}/supervisor.log"',
        '[key_provider]\nenabled = true': '[key_provider]\nenabled = false',
        '[cvm.networking]\nmode = "user"': f'[cvm.networking]\nmode = "bridge"\nbridge = "{bridge}"',
        '[cvm.network_filter]\nmode = "none"': '[cvm.network_filter]\nmode = "libvirt"',
        'socket = "/run/dstack/netd.sock"': f'socket = "{root.parent}/netd.sock"',
    }
    for old, new in replacements.items():
        if old not in text:
            raise RuntimeError(f"VMM template is missing {old!r}")
        text = text.replace(old, new, 1)
    text += '\n[cvm.tee_simulator]\nmock_attestation_seed = "' + "12" * 32 + '"\n'
    path = root / "vmm.toml"
    path.write_text(text)
    return path


def main():
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise SystemExit("wrong case")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repo = Path(runtime["repository"])
    binary = Path(runtime["prepared_binaries"]["dstack_vmm"]["path"])
    supervisor = binary.with_name("supervisor")
    image_store = Path(os.environ["DSTACK_TEST_IMAGE_STORE"])
    image = os.environ["DSTACK_TEST_NO_TEE_GUEST_IMAGE"]
    root = result_dir / "artifacts/libvirt-network-filter"
    root.mkdir(parents=True)
    bridge = "dtnf" + uuid.uuid4().hex[:7]
    sock = root / "netd.sock"
    processes = []
    owned = []
    evidence = {"matrix": {}, "candidate_commit": runtime["candidate_commit"]}
    template = (repo / "dstack/vmm/vmm.toml").read_text()
    for directory in (root / "a", root / "b"):
        directory.mkdir(exist_ok=True)
    config_a = make_config(template, root / "a", image_store, binary, supervisor, bridge, 18481, "filter-a")
    config_b = make_config(template, root / "b", image_store, binary, supervisor, bridge, 18482, "filter-b")

    def prepare(instance, vm, nic, mac, ip):
        value = {"operation": "prepare", "instance_id": instance, "vm_id": vm,
                 "nic_index": nic, "bridge": bridge, "mac": mac,
                 "qemu_uid": os.getuid(), "filter": "clean-traffic",
                 "parameters": {"IP": ip}}
        tap = netd(sock, value)
        owned.append((instance, vm, nic, tap))
        return tap

    try:
        for args in (("link", "add", bridge, "type", "bridge"),
                     ("addr", "add", "192.0.2.1/24", "dev", bridge),
                     ("link", "set", bridge, "up")):
            result = sudo("ip", *args)
            if result.returncode:
                raise RuntimeError(result.stderr)
        netd_process = start([str(binary), "--config", str(config_a), "netd", "--allow-uid", str(os.getuid())], root / "netd.log", root=True)
        processes.append(netd_process)
        wait_netd(sock, netd_process, "netd socket was not created")

        values = [None, None]
        errors = []
        def worker(index):
            try:
                values[index] = prepare(f"filter-{index}", f"concurrent-{index}", 0,
                                        f"02:00:00:00:00:1{index}", f"192.0.2.{10 + index}")
            except Exception as error:  # captured into deterministic evidence
                errors.append(str(error))
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        [thread.start() for thread in threads]
        [thread.join() for thread in threads]
        if errors or len(set(values)) != 2:
            raise RuntimeError(f"concurrent prepare failed: {errors}, {values}")
        first = values[0]
        netd(sock, {"operation": "remove", "instance_id": "filter-0", "vm_id": "concurrent-0", "nic_index": 0})
        owned[:] = [item for item in owned if item[3] != first]
        evidence["matrix"]["concurrent_vmm"] = {
            "taps": values, "other_survived": Path("/sys/class/net", values[1]).exists()
        }

        probe_tap = prepare("filter-probe", "spoof", 0, "02:00:00:00:00:20", "192.0.2.2")
        evidence["matrix"]["spoof_filter"] = packet_probe(
            probe_tap, bridge, "02:00:00:00:00:20", root
        )

        stop(netd_process)
        netd_process = start([str(binary), "--config", str(config_a), "netd", "--allow-uid", str(os.getuid())], root / "netd-restart.log", root=True)
        processes.append(netd_process)
        wait_netd(sock, netd_process, "netd did not restart")
        check = netd(sock, {"operation": "check", "instance_id": "filter-probe", "vm_id": "spoof", "nic_index": 0})
        evidence["matrix"]["netd_restart"] = {"tap": check, "binding_present": check in bindings()}

        # A real API-launched, two-NIC QEMU guest; simulator use is lifecycle evidence only.
        vmm = start([str(binary), "--config", str(config_a)], root / "vmm.log", cwd=root / "a")
        processes.append(vmm)
        base = "http://127.0.0.1:18481"
        wait_for(lambda: run(["curl", "-sf", base + "/"]).returncode == 0, "VMM did not listen")
        compose = {"manifest_version": 1, "name": "filter-simulator", "runner": "none",
                   "gateway_enabled": False, "public_logs": True, "public_sysinfo": True,
                   "key_provider": "tpm", "kms_enabled": False}
        created = rpc(base, "CreateVm", {"name": "filter-simulator", "image": image,
            "compose_file": json.dumps(compose), "vcpu": 1, "memory": 1024,
            "disk_size": 1, "stopped": False, "no_tee": True,
            "simulated_tee": "dstack-tdx", "networks": [
                {"mode": "bridge", "bridge_name": bridge},
                {"mode": "bridge", "bridge_name": bridge}]})
        vm_id = created["id"]
        vm_dir = root / "a/vms" / vm_id
        manifest = wait_for(lambda: json.loads((vm_dir / "vm-manifest.json").read_text()) if (vm_dir / "vm-manifest.json").is_file() else None, "VM manifest missing")
        launch = json.loads((vm_dir / "launch.json").read_text())
        macs = re.findall(r"mac=([0-9a-f:]{17})", json.dumps(launch), re.IGNORECASE)
        wait_for(lambda: sum(1 for line in bindings().splitlines() if "dt" in line) >= 4, "two VM bindings missing")
        evidence["matrix"]["multi_nic_simulator"] = {
            "vm_id": vm_id, "nic_count": len(manifest["networks"]),
            "macs": macs,
            "qemu_started": (vm_dir / "qemu.pid").is_file(), "attestation_tested": False,
        }

        # VMM and libvirtd restarts must preserve the running QEMU and its bindings.
        before = bindings()
        stop(vmm)
        vmm = start([str(binary), "--config", str(config_a)], root / "vmm-restart.log", cwd=root / "a")
        processes.append(vmm)
        wait_for(lambda: run(["curl", "-sf", base + "/"]).returncode == 0, "VMM restart failed")
        evidence["matrix"]["vmm_restart"] = {"bindings_preserved": bindings() == before}
        libvirt_restart = sudo("systemctl", "restart", "libvirtd", timeout=90)
        evidence["matrix"]["libvirtd_restart"] = {
            "returncode": libvirt_restart.returncode, "bindings_present": vm_id in (vm_dir / "vm-manifest.json").read_text() and "dt" in bindings()
        }

        old_qemu_pid = int((vm_dir / "qemu.pid").read_text())
        stop(vmm)
        stop(netd_process)
        sudo("kill", "-KILL", str(old_qemu_pid))
        vm_taps = [tap_name("filter-a", vm_id, nic) for nic in range(2)]
        for tap in vm_taps:
            sudo("virsh", "-c", "qemu:///system", "nwfilter-binding-delete", tap)
            sudo("ip", "link", "del", tap)
        netd_process = start([str(binary), "--config", str(config_a), "netd", "--allow-uid", str(os.getuid())], root / "netd-reboot.log", root=True)
        processes.append(netd_process)
        wait_netd(sock, netd_process, "netd reboot-equivalent restart failed")
        vmm = start([str(binary), "--config", str(config_a)], root / "vmm-reboot.log", cwd=root / "a")
        processes.append(vmm)
        wait_for(lambda: run(["curl", "-sf", base + "/"]).returncode == 0, "VMM reboot-equivalent restart failed")
        new_qemu_pid = wait_for(
            lambda: int((vm_dir / "qemu.pid").read_text()) if (vm_dir / "qemu.pid").is_file() and int((vm_dir / "qemu.pid").read_text()) != old_qemu_pid else None,
            "persisted VM did not auto-start", 120)
        wait_for(lambda: all(tap in bindings() for tap in vm_taps), "bindings were not recreated", 60)
        evidence["matrix"]["host_reboot_equivalent"] = {
            "method": "stop VMM/QEMU/netd, remove ephemeral TAPs, restart persisted state",
            "physical_reboot": False,
            "old_qemu_pid": old_qemu_pid, "new_qemu_pid": new_qemu_pid,
            "bindings_recreated": True,
        }
        rpc(base, "StopVm", {"id": vm_id})
        rpc(base, "RemoveVm", {"id": vm_id})
        wait_for(lambda: not vm_dir.exists(), "VM removal did not finish")
        evidence["matrix"]["host_reboot_equivalent"]["cleanup_after_recovery"] = True

        # Launch failure after prepare must not leak a binding. A stopped VM is
        # created first, then its qemu path is made to fail before StartVm.
        failing = root / "qemu-fail"
        failing.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "QEMU emulator version 9.2.0"; exit 0; fi\nexit 42\n')
        failing.chmod(0o755)
        failed_config = config_b.read_text().replace('/usr/bin/qemu-system-x86_64', str(failing))
        config_b.write_text(failed_config)
        bad_vmm = start([str(binary), "--config", str(config_b)], root / "vmm-fail.log", cwd=root / "b")
        processes.append(bad_vmm)
        bad_base = "http://127.0.0.1:18482"
        wait_for(lambda: run(["curl", "-sf", bad_base + "/"]).returncode == 0, "failure VMM did not listen")
        before_failure = bindings()
        try:
            rpc(bad_base, "CreateVm", {"name": "must-fail", "image": image,
                "compose_file": json.dumps(compose), "vcpu": 1, "memory": 1024,
                "disk_size": 1, "stopped": False, "no_tee": True,
                "networks": [{"mode": "bridge", "bridge_name": bridge}]})
        except Exception:
            pass
        time.sleep(2)
        evidence["matrix"]["qemu_failure_rollback"] = {"no_new_binding": bindings() == before_failure}
    finally:
        for process in reversed(processes):
            stop(process)
        for instance, vm, nic, tap in reversed(owned):
            if sock.exists():
                try:
                    netd(sock, {"operation": "remove", "instance_id": instance, "vm_id": vm, "nic_index": nic})
                except Exception:
                    sudo("virsh", "-c", "qemu:///system", "nwfilter-binding-delete", tap)
                    sudo("ip", "link", "del", tap)
        sudo("ip", "link", "del", bridge)

    required = evidence["matrix"]
    spoof = required.get("spoof_filter", {})
    passed = (
        all(name in required for name in ("concurrent_vmm", "spoof_filter", "netd_restart",
            "multi_nic_simulator", "vmm_restart", "libvirtd_restart",
            "qemu_failure_rollback", "host_reboot_equivalent"))
        and all(spoof.get(key) for key in ("normal_seen", "ip_spoof_blocked", "mac_spoof_blocked", "arp_spoof_blocked"))
        and required["multi_nic_simulator"]["nic_count"] == 2
        and len(set(required["multi_nic_simulator"]["macs"])) == 2
        and required["qemu_failure_rollback"]["no_new_binding"]
    )
    artifact = result_dir / "artifacts/vmm-network-lifecycle.json"
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    status = "PASS" if passed else "FAIL"
    observed = f"{len(required)}/8 libvirt network-filter phases recorded"
    result = {"schema_version": "1.0", "case_id": CASE_ID, "provisional": False,
              "status": status, "summary": observed,
              "steps": [{"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": observed} for n in range(1, 4)],
              "evidence": [{"path": "artifacts/vmm-network-lifecycle.json",
                            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}],
              "remarks": "TEE simulation validates VMM/QEMU/network lifecycle only; TDX/SNP attestation is out of scope."}
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
