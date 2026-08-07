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
        "expected_tests": [
            "volume_extraction_keeps_other_compose_fields_opaque",
            "resolve_volume_source_rejects_escape_symlink_and_qemu_metachars",
            "resolve_volumes_resolves_measured_source",
            "resolve_volumes_attaches_duplicate_root_once",
            "vm_measurement_config_includes_verity_volume_count",
        ],
        "subject": "current verity volume parsing, confinement, deduplication, resolution, and measurement",
    },
    "tc-vmm-tdxvariant-005": {
        "filter": "app::tests::tdx_",
        "expected_tests": [
            "tdx_auto_variant_uses_legacy_for_low_non_2g_memory",
            "tdx_auto_variant_uses_lite_for_2g_supported_image",
            "tdx_auto_variant_falls_back_to_legacy_when_image_lacks_lite_support",
            "tdx_requirements_measure_acpi_tables_overrides_lite_to_legacy",
            "tdx_requirements_skip_acpi_tables_overrides_legacy_to_lite",
        ],
        "subject": "current TDX legacy/lite/auto memory, image-capability, and requirements precedence",
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
        "expected_tests": [
            "manifest_v2_omits_init_script_hashes",
            "manifest_v3_includes_empty_init_script_hashes",
        ],
        "subject": "current manifest-version measurement carrier behavior",
    },
    "tc-vmm-internal-005": {
        "filter": "app::vm_info::tests",
        "expected_tests": [
            "sanitize_optional_filters_empty_owned_values",
            "sanitize_optional_filters_empty_borrowed_values",
        ],
        "subject": "current VM-info optional owned and borrowed value sanitization",
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
    expected_tests = row.get("expected_tests")
    expected_count = (
        len(expected_tests) if isinstance(expected_tests, list) else row["minimum_tests"]
    )
    named_tests_present = (
        all(name in output for name in expected_tests)
        if isinstance(expected_tests, list)
        else True
    )
    passed = (
        process.returncode == 0
        and passed_tests >= int(expected_count)
        and named_tests_present
    )
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "case_id": case_id,
        "cargo_target_dir_shared": True,
        "filter": row["filter"],
        "minimum_tests": expected_count,
        "expected_tests": expected_tests or [],
        "named_tests_present": named_tests_present,
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
