#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute VMM internal unit matrices with a shared Cargo target."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

CASES = {
    "tc-vmm-volume-008": {
        "filter": "volume",
        "minimum_tests": 7,
        "subject": "verity volume parsing, confinement, validation, deduplication, measurement, and readonly QEMU attachment",
    },
    "tc-vmm-tdxvariant-005": {
        "filter": "app::tests::tdx_",
        "minimum_tests": 7,
        "subject": "TDX legacy/lite/auto boundaries, requirements precedence, historical capability, and corrected retry",
    },
    "tc-vmm-internal-001": {
        "filter": "app::host_share::tests",
        "minimum_tests": 4,
        "subject": "host-share FAT32 contents, capacity failures, symlink confinement, and atomic concurrent publication",
    },
    "tc-vmm-internal-002": {
        "filter": "app::id_pool::tests",
        "minimum_tests": 4,
        "subject": "ID allocation bounds, reuse, exhaustion, concurrency, and restart reconstruction",
    },
    "tc-vmm-internal-003": {
        "filter": "app::image::tests",
        "minimum_tests": 4,
        "subject": "image metadata, versions, missing artifacts, concurrency, and path confinement",
    },
    "tc-vmm-internal-004": {
        "filter": "app::mr_config::tests",
        "minimum_tests": 4,
        "subject": "TDX and SNP measurement carriers, mutations, deterministic derivation, and GPU policy binding",
    },
    "tc-vmm-internal-005": {
        "filter": "app::vm_info::tests",
        "minimum_tests": 4,
        "subject": "VM info optional values, gateway URLs, ports, fallbacks, and networking projections",
    },
    "tc-vmm-internal-008": {
        "filter": "vm_launcher::tests",
        "minimum_tests": 5,
        "subject": "QEMU and swtpm readiness, bilateral failure cleanup, deadlines, and socket lifecycle",
        "test_args": ["--test-threads=1"],
    },
}


def main() -> int:
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASES:
        raise SystemExit(f"unsupported VMM internal unit case: {case_id}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    row = CASES[case_id]
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    command = [
        "cargo", "test", "--locked", "--offline", "-p", "dstack-vmm",
        str(row["filter"]), "--", "--nocapture", *row.get("test_args", []),
    ]
    process = subprocess.run(
        command,
        cwd=Path(runtime["repository"]) / "dstack",
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    output = process.stdout + process.stderr
    matches = [int(value) for value in re.findall(r"(\d+) passed; 0 failed", output)]
    passed_tests = max(matches, default=0)
    passed = process.returncode == 0 and passed_tests >= int(row["minimum_tests"])
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "case_id": case_id,
        "cargo_target_dir_shared": True,
        "filter": row["filter"],
        "minimum_tests": row["minimum_tests"],
        "passed_tests": passed_tests,
        "returncode": process.returncode,
        "diagnostic_tail": output[-3000:],
        "vm_started": False,
    }
    artifact = result_dir / "artifacts/vmm-internal-unit.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        f"{passed_tests} candidate VMM unit rows passed for {row["subject"]}."
        if passed
        else f"Candidate VMM unit matrix failed for {row["subject"]}."
    )
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {
                "id": f"{case_id}-step-{number:02d}",
                "status": status,
                "observed": observed,
            }
            for number in range(1, 5)
        ],
        "evidence": [{
            "path": "artifacts/vmm-internal-unit.json",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }],
        "remarks": "The immutable Cargo target is shared across compatible cases; result state and evidence remain case-scoped. No VM or service was started.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
