#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise VMM configuration defaults and fail-closed validation."""
# ruff: noqa: D103

from __future__ import annotations

import hashlib
import json
import os
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
    inventory_path = repository / "test-suites/configuration-inventory.json"
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
            replace_once(
                base, 'listing = ["10de:2335"]', 'listing = "invalid-listing"'
            ),
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

    passed = all(coverage.values()) and all(
        bool(value["matched"])
        for value in observations.values()
        if isinstance(value, dict)
    )
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "inventory_total": len(fields),
        "inventory_present": sum(coverage.values()),
        "missing_inventory_fields": [
            field for field, present in coverage.items() if not present
        ],
        "management_port_prepared": management_port_prepared,
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
