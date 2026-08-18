#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the QEMU platform command matrix in one shared Cargo invocation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

CASE_ID = "tc-vmm-compute-ne-007"
ROW_TESTS = {
    "no-tee": {
        "app::qemu::tests::qemu_command_builder_does_not_require_prepared_paths_to_exist"
    },
    "tdx-full": {"app::tests::selects_mr_config_version_for_each_tee_mode"},
    "tdx-lite": {"app::tests::tdx_auto_variant_uses_lite_for_2g_supported_image"},
    "amd-sev-snp": {
        "app::qemu::tests::amd_sev_snp_uses_confidential_virtio_pci_options",
        "app::tests::amd_sev_snp_sys_config_includes_measurement_input_and_mr_config",
    },
    "gcp-tdx": {
        "app::tests::simulator_config_is_written_separately_with_measurement_inputs"
    },
    "nitro-tpm": {
        "app::tests::simulator_config_is_written_separately_with_measurement_inputs"
    },
    "nitro-enclave": {
        "app::tests::instance_platform_overrides_node_simulator_template"
    },
    "swtpm": {
        "app::qemu::tests::swtpm_is_omitted_when_simulator_provides_the_tpm",
        "app::tests::vm_measurement_config_includes_swtpm",
    },
    "gpu-command": {
        "app::qemu::tests::qemu_command_builder_does_not_require_prepared_paths_to_exist"
    },
    "network-matrix": {
        "app::qemu::tests::qemu_command_builder_does_not_require_prepared_paths_to_exist",
        "app::tests::vm_measurement_config_ignores_networking_changes",
    },
    "host-share-measurement": {
        "app::qemu::tests::qemu_command_builder_does_not_require_prepared_paths_to_exist"
    },
    "restart-determinism": {
        "app::tests::auto_restart_policy_backs_off_caps_and_exhausts_once",
        "app::tests::auto_restart_policy_resets_only_after_healthy_window",
    },
    "invalid-custom-recovery": {
        "app::qemu::tests::qemu_command_builder_does_not_require_prepared_paths_to_exist"
    },
}


def main() -> int:
    """Run and record all platform command rows."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise RuntimeError("wrong case")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(runtime["repository"])
    target = os.environ.get(
        "DSTACK_TEST_SHARED_CARGO_TARGET",
        runtime.get("cargo_target_dir")
        or str(
            Path(
                os.environ.get(
                    "DSTACK_TEST_CACHE_ROOT", Path.home() / ".cache/dstack-test"
                )
            )
            / "vmm-internal-batch/target"
        ),
    )
    process = subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(repository / "dstack/Cargo.toml"),
            "-p",
            "dstack-vmm",
            "--target-dir",
            target,
            "--",
            "--nocapture",
        ],
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    output = process.stdout + process.stderr
    passed_tests = {
        match.group(1)
        for match in re.finditer(r"^test ([^ ]+) \.\.\. ok$", output, re.MULTILINE)
    }
    rows = {
        row: sorted(tests) for row, tests in ROW_TESTS.items() if tests <= passed_tests
    }
    missing = sorted(set(ROW_TESTS) - set(rows))
    passed = process.returncode == 0 and not missing
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "expected_rows": sorted(ROW_TESTS),
        "observed_rows": sorted(rows),
        "row_test_bindings": rows,
        "missing_rows": missing,
        "cargo_returncode": process.returncode,
        "diagnostic_tail": output[-4000:],
        "shared_target": target,
        "physical_gpu_started": False,
        "vm_started": False,
        "mkosi_build_tested": False,
    }
    artifact_path = result_dir / "artifacts/vmm-qemu-platform-matrix.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + chr(10))
    status = "PASS" if passed else "FAIL"
    summary = (
        f"{len(rows)}/{len(ROW_TESTS)} QEMU platform rows matched; "
        f"cargo={process.returncode}"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {
                "id": f"{CASE_ID}-step-{number:02d}",
                "status": status,
                "observed": summary,
            }
            for number in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/vmm-qemu-platform-matrix.json",
                "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "The matrix generates candidate QEMU commands with controlled prepared inputs; no VM, physical GPU, or image build is started.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + chr(10))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
