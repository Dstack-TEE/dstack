#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for the promoted KMS build gate."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-kms-build-001"
IMAGE_BUILD_FILES = (
    "dstack/kms/dstack-app/builder/Dockerfile",
    "dstack/gateway/dstack-app/builder/Dockerfile",
    "dstack/verifier/builder/Dockerfile",
    "dstack/kms/dstack-app/docker-compose.yaml",
)
ONBOARD_PAGE = "dstack/kms/src/www/onboard.html"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def run(command: list[str], cwd: pathlib.Path, env: dict[str, str]) -> dict[str, Any]:
    """Run one bounded build command."""
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=600,
        check=False,
    )
    output = completed.stdout[-12000:]
    return {
        "command": command,
        "returncode": completed.returncode,
        "output_bytes": len(completed.stdout.encode()),
        "output_tail_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "output_tail": output,
    }


def packaging_pins(repository: pathlib.Path) -> dict[str, Any]:
    """Check that image builds are locked and remote page scripts are pinned."""
    unlocked = [
        f"{name}:{number}"
        for name in IMAGE_BUILD_FILES
        for number, line in enumerate(
            (repository / name).read_text().splitlines(), start=1
        )
        if re.search(r"cargo build .*-p dstack-", line) and "--locked" not in line
    ]
    locked_builds = sum(
        bool(re.search(r"cargo build .*--locked.*-p dstack-", line))
        for name in IMAGE_BUILD_FILES
        for line in (repository / name).read_text().splitlines()
    )
    tags = re.findall(
        r"<script\b[^>]*\bsrc=[^>]*>", (repository / ONBOARD_PAGE).read_text()
    )
    unpinned = [
        tag
        for tag in tags
        if not re.search(r'src="https://[^"]+@\d+\.\d+\.\d+/', tag)
        or not re.search(r'integrity="sha384-[A-Za-z0-9+/]{64}"', tag)
        or 'crossorigin="anonymous"' not in tag
    ]
    return {
        "locked_image_builds": locked_builds,
        "unlocked_image_builds": unlocked,
        "remote_scripts": len(tags),
        "unpinned_remote_scripts": unpinned,
        "passed": locked_builds == len(IMAGE_BUILD_FILES)
        and not unlocked
        and bool(tags)
        and not unpinned,
    }


def main() -> int:
    """Run the promoted KMS build case."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    workspace = repository / "dstack"
    env = os.environ.copy()
    target = runtime.get("cargo_target_dir") or runtime.get("shared_cargo_target")
    if target:
        env["CARGO_TARGET_DIR"] = str(target)

    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    cargo = shutil.which("cargo") or str(pathlib.Path.home() / ".cargo/bin/cargo")
    if not pathlib.Path(cargo).is_file():
        raise RuntimeError("cargo executable is unavailable")
    commands = [
        [cargo, "build", "--locked", "-p", "dstack-kms"],
        [cargo, "test", "--locked", "-p", "dstack-kms"],
        [cargo, "build", "--locked", "--offline", "-p", "dstack-kms"],
        [cargo, "test", "--locked", "-p", "ct_monitor"],
        [cargo, "check", "--locked", "-p", "definitely-not-a-kms-package"],
    ]
    observations = [run(command, workspace, env) for command in commands]
    positive = all(item["returncode"] == 0 for item in observations[:4])
    negative = observations[4]["returncode"] != 0
    ct_monitor = re.search(
        r"test result: ok\. (\d+) passed", observations[3]["output_tail"]
    )
    ct_monitor_passed = bool(ct_monitor) and int(ct_monitor.group(1)) >= 6
    pins = packaging_pins(repository)
    positive = positive and ct_monitor_passed and pins["passed"]
    # PR #1190: the shared image build library that the KMS, gateway, and
    # verifier release images use now generates OCI metadata and an export
    # phase. Its checked-in orchestration tests run with a mock Docker and no
    # network, so they gate the build scripts without building an image.
    build_lib = run(
        [
            shutil.which("python3") or "python3",
            "-m",
            "unittest",
            "discover",
            "-s",
            "dstack/build/shared/tests",
            "-v",
        ],
        repository,
        env,
    )
    observations.append(build_lib)
    build_lib_passed = build_lib["returncode"] == 0 and "OK" in build_lib["output_tail"]
    positive = positive and build_lib_passed
    status = "PASS" if positive and negative else "FAIL"
    evidence = {
        "workspace": "dstack",
        "target_directory": env.get("CARGO_TARGET_DIR", "cargo-default"),
        "observations": observations,
        "packaging_pins": pins,
        "checks": {
            "locked_build_test_offline": positive,
            "image_build_library_tests": build_lib_passed,
            "ct_monitor_tests": ct_monitor_passed,
            "packaging_pins": pins["passed"],
            "failure_gate": negative,
        },
    }
    atomic_json(artifacts / "kms-build-regression.json", evidence)
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": (
            "Promoted KMS locked build, test, offline rebuild, and failure-detection gate passed."
            if status == "PASS"
            else "Promoted KMS build regression gate failed; inspect bounded command evidence."
        ),
        "steps": [
            {
                "id": f"{case_id}-step-01",
                "status": "PASS" if positive else "FAIL",
                "observed": "Locked build/test, offline rebuild, ct_monitor tests, image build library tests, and packaging pins passed."
                if positive
                else "A locked build/test/offline command, the ct_monitor or image build library tests, or a packaging pin failed.",
            },
            {
                "id": f"{case_id}-step-02",
                "status": "PASS" if negative else "FAIL",
                "observed": "Controlled invalid package gate failed closed."
                if negative
                else "Controlled invalid package gate was accepted.",
            },
            {
                "id": f"{case_id}-step-03",
                "status": "PASS" if status == "PASS" else "FAIL",
                "observed": "Harness wrote bounded hashed build evidence without modifying source inputs.",
            },
        ],
        "artifacts": [
            {
                "path": "artifacts/kms-build-regression.json",
                "step_id": f"{case_id}-step-01",
                "name": "KMS build regression evidence",
                "description": "Bounded command status, output sizes, hashes, and tails for locked build/test, offline rebuild, and failure detection.",
            }
        ],
        "remarks": "Deterministic promoted build harness; no image build, service restart, or host mutation performed.",
    }
    atomic_json(result_dir / "result.json", result)
    atomic_json(artifacts / "manifest.json", {"artifacts": result["artifacts"]})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
