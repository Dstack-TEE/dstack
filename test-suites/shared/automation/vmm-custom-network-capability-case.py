#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise lease-owned bridge/tap and VMM user, bridge, and custom networking."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import uuid
from pathlib import Path

CASE_ID = "tc-vmm-compute-ne-001"


def run(argv, *, timeout=90):
    """Run one bounded subprocess without raising for its exit status."""
    return subprocess.run(
        argv, text=True, capture_output=True, timeout=timeout, check=False
    )


def config_text(source, image_store, qemu):
    """Return an isolated VMM configuration for controlled dry runs."""
    return (
        source.replace("[image]\n", f'[image]\npath = "{image_store}"\n', 1)
        .replace('platform = "auto"', 'platform = "tdx"', 1)
        .replace('qemu_path = ""', f'qemu_path = "{qemu}"', 1)
    )


def request(image, networks=None):
    """Build one one-shot RPC-shaped VM request."""
    value = {
        "name": "network-case",
        "image": image,
        "compose_file": json.dumps(
            {
                "manifest_version": 1,
                "name": "network-case",
                "runner": "none",
                "gateway_enabled": False,
            }
        ),
        "vcpu": 1,
        "memory": 1024,
        "disk_size": 1,
        "no_tee": True,
    }
    if networks is not None:
        value["networks"] = networks
    return value


def main():
    """Execute the network lifecycle matrix and write case evidence."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise SystemExit("wrong case")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repo = Path(runtime["repository"])
    binary = Path(runtime["prepared_binaries"]["dstack_vmm"]["path"])
    image_store = Path(os.environ["DSTACK_TEST_IMAGE_STORE"])
    image = os.environ["DSTACK_TEST_NO_TEE_GUEST_IMAGE"]
    root = result_dir / "artifacts/network"
    root.mkdir(parents=True)
    suffix = uuid.uuid4().hex[:8]
    bridge = f"dtbr{suffix}"
    tap = f"dttap{suffix}"
    qemu = root / "qemu-success"
    qemu.write_text(
        '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "QEMU emulator version 9.2.0"; fi\nexit 0\n'
    )
    qemu.chmod(0o755)
    config = root / "vmm.toml"
    config.write_text(
        config_text((repo / "dstack/vmm/vmm.toml").read_text(), image_store, qemu)
    )
    baseline = run(["ip", "-j", "link", "show"]).stdout
    rows = []
    cleanup_errors = []

    def ip(*args):
        return run(["sudo", "-n", "ip", *args], timeout=20)

    def execute(name, networks, ok=True):
        row = root / name
        row.mkdir()
        req = row / "vm.json"
        req.write_text(json.dumps(request(image, networks)))
        work = row / "work"
        proc = run(
            [
                str(binary),
                "--config",
                str(config),
                "run",
                str(req),
                "--workdir",
                str(work),
                "--dry-run",
            ]
        )
        combined = proc.stdout + proc.stderr
        manifest = (
            json.loads((work / "vm-manifest.json").read_text())
            if (work / "vm-manifest.json").is_file()
            else {}
        )
        netdevs = re.findall(r"-netdev\s+(\S+)", combined)
        devices = re.findall(r"-device\s+(virtio-net-pci,\S+)", combined)
        matched = (proc.returncode == 0) == ok
        rows.append(
            {
                "name": name,
                "returncode": proc.returncode,
                "expected_success": ok,
                "matched": matched,
                "networks": manifest.get("networks", []),
                "netdevs": netdevs,
                "devices": devices,
                "diagnostic_tail": combined[-700:].replace(str(root), "<case-root>"),
            }
        )
        return rows[-1]

    try:
        for argv in (
            ("link", "add", bridge, "type", "bridge"),
            ("addr", "add", "192.0.2.1/30", "dev", bridge),
            ("link", "set", bridge, "up"),
            ("tuntap", "add", "dev", tap, "mode", "tap", "user", str(os.getuid())),
            ("link", "set", tap, "master", bridge),
            ("link", "set", tap, "up"),
        ):
            p = ip(*argv)
            if p.returncode:
                raise RuntimeError(p.stderr)
        bridge_state = json.loads(
            run(["ip", "-j", "link", "show", "dev", bridge]).stdout
        )[0]
        tap_state = json.loads(run(["ip", "-j", "link", "show", "dev", tap]).stdout)[0]
        route_state = json.loads(
            run(["ip", "-j", "route", "show", "dev", bridge]).stdout
        )
        execute("default", None)
        execute("user", [{"mode": "user"}])
        execute("bridge", [{"mode": "bridge", "bridge_name": bridge}])
        execute(
            "bridge-user", [{"mode": "bridge", "bridge_name": bridge}, {"mode": "user"}]
        )
        execute(
            "missing-bridge",
            [{"mode": "bridge", "bridge_name": f"missing{suffix}"}],
            False,
        )
        execute("user-with-bridge", [{"mode": "user", "bridge_name": bridge}], False)
        execute("custom-rpc", [{"mode": "custom"}], False)
        cargo_runs = [
            run(
                [
                    "cargo",
                    "test",
                    "--manifest-path",
                    str(repo / "dstack/Cargo.toml"),
                    "-p",
                    "dstack-vmm",
                    "--target-dir",
                    os.environ.get(
                        "DSTACK_TEST_SHARED_CARGO_TARGET",
                        "/home/kvin/.cache/dstack-test/vmm-internal-batch/target",
                    ),
                    "--",
                    "--nocapture",
                ],
                timeout=180,
            )
        ]
    finally:
        for argv in (("link", "del", tap), ("link", "del", bridge)):
            p = ip(*argv)
            if p.returncode and "Cannot find device" not in p.stderr:
                cleanup_errors.append(p.stderr.strip())
    after = run(["ip", "-j", "link", "show"]).stdout
    by = {r["name"]: r for r in rows}
    multi = by.get("bridge-user", {})
    macs = [
        re.search(r"mac=([^,]+)", x).group(1)
        for x in multi.get("devices", [])
        if re.search(r"mac=([^,]+)", x)
    ]
    passed = (
        len(rows) == 7
        and all(r["matched"] for r in rows)
        and any(
            x.startswith(f"bridge,id=net0,br={bridge}") for x in by["bridge"]["netdevs"]
        )
        and any(x.startswith("user,id=net0") for x in by["user"]["netdevs"])
        and len(multi.get("netdevs", [])) == 2
        and len(macs) == 2
        and len(set(macs)) == 2
        and bridge_state.get("ifname") == bridge
        and tap_state.get("master") in (bridge, bridge_state.get("ifindex"))
        and bool(route_state)
        and all(item.returncode == 0 for item in cargo_runs)
        and not cleanup_errors
        and bridge not in after
        and tap not in after
    )
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "rows": rows,
        "lease": {
            "bridge": bridge,
            "tap": tap,
            "bridge_state": bridge_state,
            "tap_state": tap_state,
            "route_state": route_state,
        },
        "cargo": [
            {
                "returncode": item.returncode,
                "tail": (item.stdout + item.stderr)[-2000:],
            }
            for item in cargo_runs
        ],
        "baseline_sha256": hashlib.sha256(baseline.encode()).hexdigest(),
        "cleanup_errors": cleanup_errors,
        "cleanup_restored": bridge not in after and tap not in after,
        "vm_started": False,
        "mkosi_build_tested": False,
    }
    artifact = result_dir / "artifacts/vmm-network-lifecycle.json"
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    status = "PASS" if passed else "FAIL"
    observed = (
        f"{sum(bool(row.get('matched')) for row in rows)}/{len(rows)} request rows matched; "
        f"cleanup={evidence.get('cleanup_restored')}; "
        f"cargo={','.join(str(item.returncode) for item in cargo_runs)}"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": observed}
            for n in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/vmm-network-lifecycle.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "A unique lease-owned bridge and TAP were created and removed; the existing mkosi image was runtime input only and no VM was started.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
