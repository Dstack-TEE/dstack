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
    # PR #1204: the declared QEMU version is read from the binary at qemu_path
    # before every start, an explicit qemu_version wins, a wrapper banner does
    # not hide it, and an undetectable version fails the start.
    "qemu-version-per-start": {
        "config::tests::qemu_version_follows_the_binary_at_qemu_path",
        "config::tests::explicit_qemu_version_wins_over_the_binary",
        "config::tests::a_wrapper_banner_does_not_hide_the_version",
        "config::tests::an_undetectable_qemu_version_fails_the_start",
        "config::tests::test_parse_qemu_version_without_qemu_wording",
    },
    # PR #1145 and PR #1214: every bridge/macvtap NIC uses a netd-built
    # interface, and vhost-net plus vCPU-scaled queue pairs shape the netdev.
    "network-data-plane": {
        "app::qemu::tests::every_bridge_nic_gets_the_netd_tap",
        "app::qemu::tests::disabling_vhost_keeps_the_netd_tap_and_turns_the_data_plane_off",
        "app::qemu::tests::multiqueue_bridge_uses_the_netd_tap_and_derives_vectors",
        "app::qemu::tests::macvtap_queues_take_one_inherited_descriptor_each",
        "app::qemu::tests::macvtap_keeps_a_single_fd_argument_for_one_queue",
        "app::qemu::tests::custom_netdev_keeps_its_string_and_stays_single_queue",
        "app::qemu::tests::user_mode_ignores_vhost_and_keeps_its_netdev",
        "app::network::tests::queue_pairs_default_to_the_vcpu_count_up_to_the_cap",
        "app::network::tests::a_node_that_never_asked_for_vhost_keeps_the_old_device_shape",
        "app::network::tests::user_mode_stays_single_queue_whatever_the_vcpu_count",
    },
    # PR #1065: GPU sanitization before attach uses a VFIO PCI hot reset and
    # refuses topologies where the reset would reach other devices.
    "gpu-sanitize-topology": {
        "gpu_reset::tests::normalizes_short_pci_slots",
        "gpu_reset::tests::recognizes_pci_slots",
        "gpu_reset::tests::formats_dependent_devices_with_pci_slot_and_function",
        "gpu_reset::tests::skips_sanitization_when_gpu_passthrough_is_disabled",
        "gpu_reset::tests::finds_a_dedicated_upstream_bridge",
        "gpu_reset::tests::rejects_a_bridge_shared_with_another_device",
    },
}


def absent_pci_slot() -> str:
    """Pick a syntactically valid PCI slot that this host does not have."""
    devices = Path("/sys/bus/pci/devices")
    for bus in range(0xFF, 0xF0, -1):
        slot = f"0000:{bus:02x}:1f.7"
        if not (devices / slot).exists():
            return slot
    raise RuntimeError("could not find an absent PCI slot")


def sanitize_gpu_rejections(binary: Path) -> dict[str, dict[str, object]]:
    """Run `dstack-vmm sanitize-gpu` rows that must fail before any reset.

    Both rows fail before a VFIO device is opened: one names no slot, the
    other names a slot the host does not have. Neither needs a GPU or root.
    """
    rows: dict[str, dict[str, object]] = {}
    absent = absent_pci_slot()
    for name, argv, fragment in (
        ("no-slots", [str(binary), "sanitize-gpu"], "<SLOTS>"),
        (
            "absent-slot",
            [str(binary), "sanitize-gpu", "--timeout-ms", "100", absent],
            f"failed to resolve PCI device {absent}",
        ),
    ):
        process = subprocess.run(
            argv, text=True, capture_output=True, timeout=30, check=False
        )
        output = process.stdout + process.stderr
        rows[name] = {
            "returncode": process.returncode,
            "expected_fragment": fragment,
            "fragment_present": fragment in output,
            "hot_reset_attempted": "issuing VFIO PCI hot reset" in output,
            "matched": process.returncode != 0
            and fragment in output
            and "issuing VFIO PCI hot reset" not in output,
            "diagnostic_tail": output[-600:],
        }
    return rows


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
    binary = Path(runtime["prepared_binaries"]["dstack_vmm"]["path"])
    sanitize_rows = sanitize_gpu_rejections(binary)
    sanitize_matched = all(bool(row["matched"]) for row in sanitize_rows.values())
    passed = process.returncode == 0 and not missing and sanitize_matched
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "expected_rows": sorted(ROW_TESTS),
        "observed_rows": sorted(rows),
        "row_test_bindings": rows,
        "missing_rows": missing,
        "sanitize_gpu_cli_rejections": sanitize_rows,
        "sanitize_gpu_cli_rejections_matched": sanitize_matched,
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
        f"sanitize-gpu rejections matched={sanitize_matched}; "
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
