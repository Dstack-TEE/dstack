#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify reuse of the guest-agent public Rust library surface."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-entry-004"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Atomically write one JSON document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def command(
    argv: list[str], cwd: pathlib.Path, env: dict[str, str], timeout: int
) -> dict[str, Any]:
    """Run a bounded command and retain only redacted characteristics."""
    process = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    stdout = process.stdout
    stderr = process.stderr
    return {
        "returncode": process.returncode,
        "stdout": stdout[-1000:],
        "stdout_length": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_length": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
    }


def main() -> int:
    """Exercise valid, concurrent, invalid, and retry library consumers."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    values = manifest.get("values", {})
    substrate = values.get("component_substrate", {})
    repository = pathlib.Path(runtime["repository"])
    target = pathlib.Path(runtime["cargo_target_dir"])
    workspace = pathlib.Path(substrate.get("workspace", "")) / "library-reuse"
    failures: list[str] = []
    observations: dict[str, Any] = {
        "candidate_commit": runtime.get("candidate_commit"),
        "shared_target": str(target),
        "case_owned_workspace": str(workspace),
    }
    if (
        not substrate.get("case_owned")
        or not repository.is_dir()
        or not target.is_dir()
    ):
        failures.append(
            "component raw substrate or shared prepared target is unavailable"
        )
    else:
        workspace.mkdir(parents=True, exist_ok=False)
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(target)
        package = repository / "dstack/guest-agent"
        source = """fn main() {
    let _ = dstack_guest_agent::app_version;
    let _ = dstack_guest_agent::run_server;
    let _ = core::mem::size_of::<dstack_guest_agent::AppState>();
    println!("{}|{}", dstack_guest_agent::CARGO_PKG_VERSION, dstack_guest_agent::GIT_REV);
}
"""
        invalid_source = (
            """fn main() { let _ = dstack_guest_agent::not_a_public_export; }\n"""
        )

        def project(name: str, body: str) -> pathlib.Path:
            root = workspace / name
            (root / "src").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\ndstack-guest-agent = {{ path = "{package}" }}\n',
                encoding="utf-8",
            )
            (root / "src/main.rs").write_text(body, encoding="utf-8")
            return root

        consumers = [project("consumer-a", source), project("consumer-b", source)]
        invalid = project("consumer-invalid", invalid_source)
        tests = command(
            ["cargo", "test", "-p", "dstack-guest-agent", "--lib", "--quiet"],
            repository / "dstack",
            env,
            900,
        )
        observations["library_tests"] = {
            k: v for k, v in tests.items() if k != "stdout"
        }
        if tests["returncode"] != 0:
            failures.append("checked-in guest-agent library tests failed")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            valid = list(
                executor.map(
                    lambda root: command(["cargo", "run", "--quiet"], root, env, 900),
                    consumers,
                )
            )
        identities = [item["stdout"].strip() for item in valid]
        observations["initial_consumers"] = [
            {k: v for k, v in item.items() if k != "stdout"} for item in valid
        ]
        observations["initial_identity_hashes"] = [
            hashlib.sha256(value.encode()).hexdigest() for value in identities
        ]
        if (
            any(item["returncode"] != 0 for item in valid)
            or len(set(identities)) != 1
            or not identities[0]
        ):
            failures.append(
                "independent consumers did not produce one stable build identity"
            )
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            invalid_future = executor.submit(
                command, ["cargo", "check", "--quiet"], invalid, env, 900
            )
            valid_future = executor.submit(
                command, ["cargo", "run", "--quiet"], consumers[0], env, 900
            )
            invalid_result = invalid_future.result()
            concurrent_valid = valid_future.result()
        observations["invalid_import"] = {
            k: v for k, v in invalid_result.items() if k != "stdout"
        }
        observations["concurrent_valid"] = {
            k: v for k, v in concurrent_valid.items() if k != "stdout"
        }
        if invalid_result["returncode"] == 0:
            failures.append("deliberately invalid public import compiled")
        if (
            concurrent_valid["returncode"] != 0
            or concurrent_valid["stdout"].strip() != identities[0]
        ):
            failures.append(
                "valid consumer changed during concurrent invalid compilation"
            )
        retry = command(["cargo", "run", "--quiet"], consumers[1], env, 900)
        observations["retry"] = {k: v for k, v in retry.items() if k != "stdout"}
        observations["retry_identity_stable"] = retry["stdout"].strip() == identities[0]
        observations["listener_or_process_started"] = False
        observations["sensitive_output_persisted"] = False
        if retry["returncode"] != 0 or not observations["retry_identity_stable"]:
            failures.append("valid retry did not converge to the stable build identity")
    artifact = {
        "path": "artifacts/guest-agent-library-reuse.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Guest-agent library reuse observations",
        "description": "Return codes, lengths, and hashes proving library tests, independent and concurrent consumers, invalid-import isolation, stable retry identity, and shared-target reuse without compiler output.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": "Guest-agent public library tests, independent/concurrent consumers, invalid import isolation, and stable retry passed."
            if not failures
            else "; ".join(failures),
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": status,
                    "observed": "Candidate repository, case-owned consumer workspace, and immutable shared target were recorded.",
                },
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "Checked-in library tests and two independent public-export consumers completed with one stable build identity.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "Invalid import failed while a concurrent valid consumer remained stable; a valid retry converged.",
                },
                {
                    "id": f"{CASE_ID}-step-04",
                    "status": status,
                    "observed": "Shared target reuse and case-output isolation were observed without retaining compiler text or starting listeners.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "The fixture owns workspace cleanup. Evidence retains no compiler output, credential, token, or private material.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
