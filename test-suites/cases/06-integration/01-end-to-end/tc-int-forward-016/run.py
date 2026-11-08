#!/usr/bin/env python3
"""Run focused unit matrices for non-rotation changes in the forward interval."""

import json
import os
import pathlib
import subprocess
import time

CASE = "tc-int-forward-016"
TESTS = [
    ("qemu-acpi", "golden_tests::tests::three_numa_nodes_match_qemu_byte_for_byte"),
    (
        "qemu-acpi",
        "golden_tests::tests::numa_nodes_without_pxb_match_qemu_byte_for_byte",
    ),
    ("qemu-acpi", "golden_tests::tests::extra_root_devices_are_validated"),
    (
        "dstack-vmm",
        "app::tests::annotations_round_trip_and_stay_out_of_plain_manifests",
    ),
    (
        "dstack-vmm",
        "app::qemu::tests::passth_nic_connects_to_its_sidecar_which_publishes_the_port_map",
    ),
    (
        "dstack-vmm",
        "app::qemu::tests::amd_sev_snp_qmp_capabilities_extracts_launch_params",
    ),
    ("dstack-guest-agent", "http_routes::tests::test_validate_container_name"),
    ("ra-rpc", "server_key_possession::check_key_possession"),
    ("tpm2", "commands::tests::rejects_short_response"),
    ("dstack-types", "tests::extra_root_devices_are_serialized_only_when_present"),
    ("dstack-types", "tests::numa_nodes_keep_their_legacy_serialization"),
]


def main():
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE:
        raise SystemExit("unsupported case")
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repo = pathlib.Path(runtime["repository"])
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = runtime["cargo_target_dir"]
    rows = []
    for package, filt in TESTS:
        start = time.monotonic()
        r = subprocess.run(
            ["cargo", "test", "-p", package, filt, "--", "--nocapture"],
            cwd=repo / "dstack",
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
        )
        passed = int(r.returncode == 0)
        rows.append(
            {
                "package": package,
                "filter": filt,
                "returncode": r.returncode,
                "passed": passed,
                "duration_seconds": round(time.monotonic() - start, 3),
            }
        )
        if r.returncode or passed != 1:
            break
    status = "PASS" if len(rows) == len(TESTS) else "FAIL"
    rd = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    (rd / "artifacts").mkdir(parents=True, exist_ok=True)
    (rd / "artifacts/forward-interval-matrix.json").write_text(
        json.dumps({"status": status, "rows": rows}, indent=2) + "\n"
    )
    (rd / "result.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "case_id": CASE,
                "provisional": False,
                "status": status,
                "summary": f"{len(rows)}/{len(TESTS)} forward interval rows passed",
            },
            indent=2,
        )
        + "\n"
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
