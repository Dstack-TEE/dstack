#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the QEMU platform command matrix in one shared Cargo invocation."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

CASE_ID = "tc-vmm-compute-ne-007"
EXPECTED = {
    "no-tee",
    "tdx-full",
    "tdx-lite",
    "amd-sev-snp",
    "gcp-tdx",
    "nitro-tpm",
    "nitro-enclave",
    "swtpm",
    "gpu-command",
    "network-matrix",
    "host-share-measurement",
    "restart-determinism",
    "invalid-custom-recovery",
}
MARKER = "DSTACK_PLATFORM_ROW "


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
        or "/home/kvin/.cache/dstack-test/vmm-internal-batch/target",
    )
    process = subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(repository / "dstack/Cargo.toml"),
            "-p",
            "dstack-vmm",
            "volume_qemu_command_is_readonly_ordered_and_does_not_require_paths",
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
    observed = {
        line.split(MARKER, 1)[1].strip()
        for line in output.splitlines()
        if MARKER in line
    }
    missing = sorted(EXPECTED - observed)
    unexpected = sorted(observed - EXPECTED)
    passed = process.returncode == 0 and not missing and not unexpected
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "expected_rows": sorted(EXPECTED),
        "observed_rows": sorted(observed),
        "missing_rows": missing,
        "unexpected_rows": unexpected,
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
        f"{len(observed)}/{len(EXPECTED)} QEMU platform rows matched; "
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
