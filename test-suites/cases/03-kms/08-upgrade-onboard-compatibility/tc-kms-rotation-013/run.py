#!/usr/bin/env python3
"""Run the focused root/app key rotation and migration test matrix."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import time

CASE = "tc-kms-rotation-013"
TESTS = {
    "dstack-kms": [
        "main_service::tests::sealed_env_derivation_is_separate_and_shared_with_app_keys",
        "main_service::tests::app_epoch_derivation_is_separate_and_epoch_zero_is_unchanged",
        "onboard_service::tests::rotation_imports_the_keyring_and_generates_the_next_epoch",
        "onboard_service::tests::onboarding_checks_the_handover_against_the_current_epoch",
        "onboard_service::tests::join_imports_and_stores_every_epoch",
        "onboard_service::tests::a_keyring_serves_the_current_epoch_it_holds",
        "onboard_service::tests::an_unregistered_deployment_can_only_join_at_epoch_0",
        "main_service::tests::authorization_selects_epochs_without_a_serving_epoch_snapshot",
        "main_service::tests::self_authorization_cache_cannot_authorize_a_different_operation",
        "onboard_service::tests::compatibility_ca_survives_restart_and_recovers_a_missing_certificate",
    ],
    "dstack-util": [
        "system_setup::luks::test_validate_luks2_header_root_epoch_token",
        "system_setup::luks::test_disk_key_migration_with_cryptsetup",
        "crypto::sealed_env_tests::sealed_env_round_trips_and_binds_info",
        "system_setup::sealed_env_file_tests::sealed_env_binds_both_epochs_and_rejects_mislabeled_versions",
        "system_setup::sealed_env_file_tests::legacy_env_migration_skips_denied_intermediate_epochs",
        "system_setup::sealed_env_file_tests::sealed_env_binds_both_epochs_and_rejects_mislabeled_versions",
        "system_setup::sealed_env_file_tests::legacy_env_migration_skips_denied_intermediate_epochs",
    ],
}


def main() -> int:
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE:
        raise SystemExit("unsupported case")
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repo = pathlib.Path(runtime["repository"])
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = runtime["cargo_target_dir"]
    rows = []
    for package, filters in TESTS.items():
        for test_filter in filters:
            started = time.monotonic()
            command = ["cargo", "test", "-p", package, test_filter, "--", "--nocapture"]
            result = subprocess.run(
                command,
                cwd=repo / "dstack",
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=300,
            )
            rows.append(
                {
                    "package": package,
                    "filter": test_filter,
                    "returncode": result.returncode,
                    "duration_seconds": round(time.monotonic() - started, 3),
                    "output_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                    "passed": int(
                        next(
                            (
                                line.split()[2]
                                for line in result.stdout.splitlines()
                                if line.startswith("test result: ok.")
                                and " passed;" in line
                            ),
                            "0",
                        )
                    ),
                }
            )
            if result.returncode or rows[-1]["passed"] != 1:
                break
        if rows[-1]["returncode"]:
            break
    passed = sum(row["returncode"] == 0 for row in rows)
    status = (
        "PASS"
        if len(rows) == sum(map(len, TESTS.values())) and passed == len(rows)
        else "FAIL"
    )
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifact = result_dir / "artifacts/key-rotation-matrix.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(
        json.dumps(
            {
                "candidate_commit": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=repo, text=True
                ).strip(),
                "status": status,
                "rows": rows,
            },
            indent=2,
        )
        + "\n"
    )
    (result_dir / "result.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "case_id": CASE,
                "provisional": False,
                "status": status,
                "summary": f"{passed}/{len(rows)} focused rotation rows passed",
                "artifacts": [{"path": "artifacts/key-rotation-matrix.json"}],
            },
            indent=2,
        )
        + "\n"
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
