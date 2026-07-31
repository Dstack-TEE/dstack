#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute the shared KMS onboarding and authorization regression matrix."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

ROWS = {
    "tc-kms-keys-certs-001": [
        (
            "disk and environment hierarchy isolation",
            "disk_and_environment_hierarchy_has_documented_isolation_boundaries",
        ),
        (
            "derived application K256 isolation and root signature",
            "derived_app_k256_keys_are_stable_isolated_and_root_signed",
        ),
        (
            "environment key signature remains app scoped",
            "environment_public_key_signatures_bind_domain_app_key_and_timestamp",
        ),
    ],
    "tc-kms-keys-certs-002": [
        (
            "environment public key hierarchy is stable and app isolated",
            "disk_and_environment_hierarchy_has_documented_isolation_boundaries",
        ),
        (
            "legacy and timestamped signatures bind all freshness inputs",
            "environment_public_key_signatures_bind_domain_app_key_and_timestamp",
        ),
    ],
    "tc-kms-bootstrap--002": [
        ("valid onboarding DNS identity", "onboarding_domain_accepts_dns_name"),
        (
            "invalid and boundary DNS identities reject",
            "onboarding_domain_rejects_empty_overlong_and_invalid_labels",
        ),
        (
            "onboarded private material is atomic and owner-only",
            "private_write_is_atomic_and_owner_only",
        ),
    ],
    "tc-kms-bootstrap--003": [
        (
            "finish persistence writes private material atomically",
            "private_write_is_atomic_and_owner_only",
        ),
        (
            "persisted identity accepts the configured DNS name",
            "onboarding_domain_accepts_dns_name",
        ),
        (
            "invalid transition identity leaves no accepted state",
            "onboarding_domain_rejects_empty_overlong_and_invalid_labels",
        ),
    ],
    "tc-kms-bootstrap--004": [
        (
            "SNP provisioning identity includes verified device and chain fields",
            "attestation_info_response_uses_snp_boot_info_and_chip_id",
        ),
        (
            "application identity changes authorization binding",
            "app_id_changes_host_data_and_authorization_binding",
        ),
        (
            "chip identity changes device-bound digests",
            "chip_id_maps_to_device_id_and_changes_chip_bound_digests",
        ),
    ],
    "tc-kms-attestatio-001": [
        (
            "matching measured input is accepted and mismatch rejects",
            "accepts_recomputed_matching_measurement_and_rejects_mismatch",
        ),
        (
            "measured field mutations reject stale evidence",
            "measured_input_changes_reject_until_measurement_is_recomputed",
        ),
        (
            "application mutation changes authorization binding",
            "app_id_changes_host_data_and_authorization_binding",
        ),
        (
            "malformed binding hashes reject",
            "rejects_empty_or_malformed_binding_hashes",
        ),
        ("missing machine binding rejects", "rejects_missing_machine_binding_inputs"),
        ("unsafe machine configuration rejects", "rejects_unsafe_machine_config"),
    ],
}


def run_matrix(repo: Path, target: str, cache: Path) -> dict:
    """Run every unique command once and atomically publish its cache."""
    rows = []
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = target
    for description, test_filter in sorted(
        {row for values in ROWS.values() for row in values}, key=lambda row: row[1]
    ):
        started = time.monotonic()
        command = [
            "cargo",
            "test",
            "--manifest-path",
            "dstack/Cargo.toml",
            "-p",
            "dstack-kms",
            test_filter,
            "--",
            "--nocapture",
        ]
        proc = subprocess.run(
            command,
            cwd=repo,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        rows.append(
            {
                "description": description,
                "filter": test_filter,
                "command": command,
                "status": "PASS"
                if proc.returncode == 0 and "test result: ok" in proc.stdout
                else "FAIL",
                "exit_code": proc.returncode,
                "duration_seconds": round(time.monotonic() - started, 3),
                "output": proc.stdout,
            }
        )
        if rows[-1]["status"] != "PASS":
            break
    payload = {"schema_version": "1.0", "rows": rows}
    temporary = cache.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    temporary.replace(cache)
    return payload


def main() -> int:
    """Select case-owned rows from the shared commit-keyed matrix."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    case_id = manifest.get("case_id") or manifest.get("id")
    if case_id not in ROWS:
        raise SystemExit(f"unsupported case id: {case_id}")
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repo = Path(runtime["repository"])
    target = runtime["cargo_target_dir"]
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    cache_dir = Path(runtime["cache_dir_resolved"]) / "kms-shared-controller"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache = cache_dir / f"{commit}.json"
    with (cache_dir / f"{commit}.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        payload = (
            json.loads(cache.read_text())
            if cache.exists()
            else run_matrix(repo, target, cache)
        )

    by_filter = {row["filter"]: row for row in payload["rows"]}
    selected = []
    for description, test_filter in ROWS[case_id]:
        row = dict(
            by_filter.get(
                test_filter,
                {
                    "filter": test_filter,
                    "status": "FAIL",
                    "output": "shared matrix stopped before this row",
                },
            )
        )
        row["description"] = description
        selected.append(row)
    status = "PASS" if all(row["status"] == "PASS" for row in selected) else "FAIL"
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    detail = artifacts / "kms-shared-controller.json"
    detail.write_text(
        json.dumps({"case_id": case_id, "commit": commit, "rows": selected}, indent=2)
        + "\n"
    )
    artifact = {
        "path": "artifacts/kms-shared-controller.json",
        "step_id": f"{case_id}-step-02",
        "name": "KMS shared controller matrix",
        "description": "Exact simulator-backed KMS policy and persistence commands with native output.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    steps = []
    groups = [selected[:1], selected, selected[-1:]]
    for number, group in enumerate(groups, 1):
        group_status = (
            "PASS"
            if group and all(row["status"] == "PASS" for row in group)
            else "FAIL"
        )
        steps.append(
            {
                "id": f"{case_id}-step-{number:02d}",
                "status": group_status,
                "observed": "; ".join(
                    f"{row['description']}: {row['status']}" for row in group
                ),
            }
        )
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": f"{sum(row['status'] == 'PASS' for row in selected)}/{len(selected)} KMS shared-controller rows passed",
        "steps": steps,
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(detail.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "Functional attestation binding uses constructed verified evidence; no physical-origin trust claim is made.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
