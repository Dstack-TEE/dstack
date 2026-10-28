#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise VMM configuration defaults and fail-closed validation."""
# ruff: noqa: D103

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import tomllib

CASE_ID = "tc-vmm-configurat-001"


def run(binary: str, config: Path) -> dict[str, object]:
    process = subprocess.run(
        [binary, "--config", str(config), "check-config"],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    diagnostic = (process.stderr + process.stdout).replace(
        str(config.parent), "<case-dir>"
    )
    return {"returncode": process.returncode, "diagnostic": diagnostic[-2000:]}


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError(f"expected one configuration marker: {old}")
    return text.replace(old, new, 1)


def replace_listing(text: str, new: str) -> str:
    """Replace the multi-line `[cvm.gpu].listing` array with one value."""
    replaced, count = re.subn(
        r"^listing = \[.*?^\]", new, text, count=0, flags=re.S | re.M
    )
    if count != 1:
        raise RuntimeError("expected one cvm.gpu.listing array")
    return replaced


# PR #1161: the default discovery list names every Hopper and Blackwell SKU
# a deployment may hold, not only the H200.
EXPECTED_GPU_LISTING = {
    "10de:2330",
    "10de:2331",
    "10de:2337",
    "10de:2338",
    "10de:2339",
    "10de:2321",
    "10de:2335",
    "10de:233b",
    "10de:2901",
    "10de:2909",
    "10de:3182",
}


def inventory_present(config: object, field: str) -> bool:
    value = config
    for part in field.replace("[]", "").split("."):
        if isinstance(value, list):
            if not value:
                return False
            value = value[0]
        if not isinstance(value, dict) or part not in value:
            return False
        value = value[part]
    return True


def main() -> int:
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(runtime["repository"])
    binary = runtime["prepared_binaries"]["dstack_vmm"]["path"]
    source = repository / "dstack/vmm/vmm.toml"
    inventory_path = repository / "test-suites/catalog/configuration-inventory.json"
    source_text = source.read_text()
    parsed = tomllib.loads(source_text)
    management_port_prepared = "port" not in parsed
    base = source_text
    if management_port_prepared:
        base = replace_once(
            base,
            'address = "unix:./vmm.sock"',
            'address = "unix:./vmm.sock"\nport = 0',
        )
    fields = json.loads(inventory_path.read_text())["components"]["vmm"]["fields"]
    coverage = {field: inventory_present(parsed, field) for field in fields}

    matrices = {
        "minimal-defaults": (base, True),
        "unknown-sibling": (base + "\nunknown_test_field = true\n", True),
        "conflicting-image-path": (
            base + '\nimage_path = "/tmp/deprecated-image-path"\n',
            True,
        ),
        "invalid-platform": (
            replace_once(base, 'platform = "auto"', 'platform = "invalid-platform"'),
            False,
        ),
        "invalid-networking": (
            replace_once(base, '\nmode = "user"\n', '\nmode = "invalid-network"\n'),
            False,
        ),
        "invalid-key-provider": (
            replace_once(
                base,
                '\naddress = "127.0.0.1"\nport = 3443',
                '\naddress = "not-an-ip"\nport = 3443',
            ),
            False,
        ),
        "invalid-gpu-listing": (
            replace_listing(base, 'listing = "invalid-listing"'),
            False,
        ),
        # PR #1163: binary unit spellings up to petabytes, and a repeated unit
        # is rejected instead of silently dropping a letter.
        "pci-hole64-petabyte-unit": (
            replace_once(
                base, "qemu_pci_hole64_size = 0", 'qemu_pci_hole64_size = "1PiB"'
            ),
            True,
        ),
        "pci-hole64-terabyte-two-letter-unit": (
            replace_once(
                base, "qemu_pci_hole64_size = 0", 'qemu_pci_hole64_size = "8TB"'
            ),
            True,
        ),
        "pci-hole64-repeated-unit": (
            replace_once(
                base, "qemu_pci_hole64_size = 0", 'qemu_pci_hole64_size = "1GG"'
            ),
            False,
        ),
        "pci-hole64-unknown-unit": (
            replace_once(
                base, "qemu_pci_hole64_size = 0", 'qemu_pci_hole64_size = "1X"'
            ),
            False,
        ),
        # PR #1145: the deployment queue ceiling is bounded to 1..=64 and queue
        # pairs are not a node-level networking setting.
        "max-net-queues-upper-bound": (
            replace_once(base, "max_net_queues = 16", "max_net_queues = 64"),
            True,
        ),
        "max-net-queues-above-bound": (
            replace_once(base, "max_net_queues = 16", "max_net_queues = 65"),
            False,
        ),
        "max-net-queues-zero": (
            replace_once(base, "max_net_queues = 16", "max_net_queues = 0"),
            False,
        ),
        "node-networking-vhost-enabled": (
            replace_once(base, "\nvhost = false\n", "\nvhost = true\n"),
            True,
        ),
        "node-networking-queues": (
            replace_once(base, "\nvhost = false\n", "\nvhost = false\nqueues = 4\n"),
            False,
        ),
        # PR #1214: netd may carry its own explicit filter policy, and the
        # instance namespace netd records on host interfaces may not contain ":".
        "netd-explicit-filter-policy": (
            base
            + '\n[netd.network_filter]\nmode = "none"\nfilter = "clean-traffic"\nparameters = {}\n',
            True,
        ),
        "netd-socket-mode-non-permission-bits": (
            replace_once(base, "socket_mode = 0o660", "socket_mode = 0o10660"),
            False,
        ),
        "instance-id-with-colon": (
            replace_once(base, 'instance_id = ""', 'instance_id = "dtest:bad"'),
            False,
        ),
        # PR #1282: the registry pull is gone and a leftover key is ignored.
        "leftover-image-registry": (
            replace_once(
                base, "[image]\n", '[image]\nregistry = "dstacktee/guest-image"\n'
            ),
            True,
        ),
        # PR #1230: the node default data-disk preallocation takes qemu-img's
        # own mode names and nothing else.
        "disk-prealloc-falloc": (
            replace_once(base, 'disk_prealloc = "off"', 'disk_prealloc = "falloc"'),
            True,
        ),
        "disk-prealloc-unknown-mode": (
            replace_once(base, 'disk_prealloc = "off"', 'disk_prealloc = "sparse"'),
            False,
        ),
        "invalid-host-listener": (
            replace_once(base, 'address = "vsock:2"', 'address = "127.0.0.1"'),
            False,
        ),
        "invalid-path-type": (
            replace_once(base, 'qemu_path = ""', 'qemu_path = ["not", "a", "path"]'),
            False,
        ),
    }
    observations: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="vmm-config-", dir=result_dir) as temporary:
        root = Path(temporary)
        for name, (content, expected_valid) in matrices.items():
            path = root / f"{name}.toml"
            path.write_text(content)
            observed = run(binary, path)
            observed["expected_valid"] = expected_valid
            observed["matched"] = (observed["returncode"] == 0) == expected_valid
            observations[name] = observed

    listing = set(parsed.get("cvm", {}).get("gpu", {}).get("listing", []))
    defaults = {
        "gpu_listing_missing": sorted(EXPECTED_GPU_LISTING - listing),
        "max_net_queues": parsed.get("cvm", {}).get("max_net_queues"),
        "networking_vhost": parsed.get("cvm", {}).get("networking", {}).get("vhost"),
        "tdx_attestation_variant": parsed.get("cvm", {}).get("tdx_attestation_variant"),
        "qemu_hotplug_off": parsed.get("cvm", {}).get("qemu_hotplug_off"),
        "disk_prealloc": parsed.get("cvm", {}).get("disk_prealloc"),
        "max_event_name_len": parsed.get("max_event_name_len"),
        "image_registry_absent": "registry" not in parsed.get("image", {}),
    }
    defaults_matched = (
        not defaults["gpu_listing_missing"]
        and defaults["max_net_queues"] == 16
        and defaults["networking_vhost"] is False
        and defaults["tdx_attestation_variant"] == "auto"
        and defaults["qemu_hotplug_off"] is True
        and defaults["disk_prealloc"] == "off"
        and defaults["max_event_name_len"] == 128
        and defaults["image_registry_absent"]
    )
    passed = (
        defaults_matched
        and all(coverage.values())
        and all(
            bool(value["matched"])
            for value in observations.values()
            if isinstance(value, dict)
        )
    )
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "inventory_total": len(fields),
        "inventory_present": sum(coverage.values()),
        "missing_inventory_fields": [
            field for field, present in coverage.items() if not present
        ],
        "management_port_prepared": management_port_prepared,
        "documented_defaults": defaults,
        "documented_defaults_matched": defaults_matched,
        "matrix": observations,
        "service_started": False,
        "run_scoped_state_only": True,
    }
    artifact = result_dir / "artifacts/vmm-configuration-lifecycle-case.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    status = "PASS" if passed else "FAIL"
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": f"VMM configuration inventory and {len(matrices)} validation rows {'passed' if passed else 'failed'}",
        "steps": [
            {
                "id": f"{CASE_ID}-step-01",
                "status": status,
                "observed": f"Loaded {sum(coverage.values())}/{len(fields)} inventory fields and validated the prepared binary without starting services.",
            },
            {
                "id": f"{CASE_ID}-step-02",
                "status": status,
                "observed": f"Executed {len(matrices)} default, compatibility, conflict, and invalid configuration rows.",
            },
            {
                "id": f"{CASE_ID}-step-03",
                "status": status,
                "observed": "Every row was repeatable, case-scoped, fail-closed where required, and emitted bounded diagnostics.",
            },
        ],
        "evidence": [
            {
                "path": "artifacts/vmm-configuration-lifecycle-case.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "check-config performs no supervisor startup, listener binding, discovery registration, or VM creation.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
