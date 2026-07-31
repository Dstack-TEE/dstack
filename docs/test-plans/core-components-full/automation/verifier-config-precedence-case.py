#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise verifier configuration precedence, modes, outage, and recovery."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

CASE_ID = "tc-ver-build-002"
IMAGE_HASH = "14ad42d0270b444eaeb53918a5a94d9b17eec7a817cd336173b17c5327541c67"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def prepared_binary(runtime: dict[str, Any], name: str) -> pathlib.Path:
    """Resolve one prepared binary from the runtime manifest."""
    item = runtime["prepared_binaries"][name]
    return pathlib.Path(item.get("resolved_path") or item["path"])


def allocate_port() -> int:
    """Allocate an ephemeral loopback TCP port."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def clean_verifier_env() -> dict[str, str]:
    """Return an environment without ambient verifier overrides."""
    return {k: v for k, v in os.environ.items() if not k.startswith("DSTACK_VERIFIER_")}


def write_config(
    path: pathlib.Path, port: int, cache: pathlib.Path, timeout: int = 2
) -> None:
    """Write a complete valid case-owned verifier configuration."""
    path.write_text(
        "\n".join(
            [
                'address = "127.0.0.1"',
                f"port = {port}",
                f'image_cache_dir = "{cache}"',
                'image_download_url = "http://127.0.0.1:1/{OS_IMAGE_HASH}.tar.gz"',
                f"image_download_timeout_secs = {timeout}",
                "[attestation]",
                "insecure_allow_external_trust_anchors = false",
                "",
            ]
        )
    )


def run_command(
    name: str,
    command: list[str],
    workspace: pathlib.Path,
    environment: dict[str, str],
    timeout: int = 180,
) -> tuple[dict[str, Any], subprocess.CompletedProcess[str]]:
    """Run one command and retain native stdout/stderr in the debug workspace."""
    completed = subprocess.run(
        command,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    (workspace / f"{name}.stdout").write_text(completed.stdout)
    (workspace / f"{name}.stderr").write_text(completed.stderr)
    row = {
        "name": name,
        "returncode": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
    }
    return row, completed


def require_rejection(
    row: dict[str, Any], completed: subprocess.CompletedProcess[str], text: str
) -> None:
    """Require an expected fail-closed diagnostic."""
    if (
        completed.returncode == 0
        or text.lower() not in (completed.stdout + completed.stderr).lower()
    ):
        raise AssertionError(f"{row['name']} did not reject with {text!r}")
    row["expected_rejection"] = True
    row["passed"] = True


def require_valid_verification(
    row: dict[str, Any], completed: subprocess.CompletedProcess[str]
) -> None:
    """Require a complete successful one-shot verification response."""
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(f"{row['name']} returned non-JSON output") from error
    details = response.get("details", {})
    if completed.returncode or response.get("is_valid") is not True:
        raise AssertionError(f"{row['name']} did not return a valid response")
    for field in ("quote_verified", "os_image_hash_verified", "event_log_verified"):
        if details.get(field) is not True:
            raise AssertionError(f"{row['name']} did not set {field}")
    row["passed"] = True


def wait_health(port: int, process: subprocess.Popen[str]) -> None:
    """Wait for a case-owned verifier health endpoint."""
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"verifier exited before health check: rc={process.returncode}"
            )
        try:
            with urllib.request.urlopen(url, timeout=0.5) as response:
                payload = json.loads(response.read())
                if response.status == 200 and payload.get("status") == "ok":
                    return
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.1)
    raise AssertionError("verifier health endpoint did not become ready")


def start_and_stop_service(
    name: str,
    binary: pathlib.Path,
    config: pathlib.Path,
    port: int,
    workspace: pathlib.Path,
    environment: dict[str, str],
) -> dict[str, Any]:
    """Start, health-check, and cleanly stop one case-owned service instance."""
    stdout_path = workspace / f"{name}.stdout"
    stderr_path = workspace / f"{name}.stderr"
    with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
        process = subprocess.Popen(
            [str(binary), "--config", str(config)],
            env=environment,
            text=True,
            stdout=stdout,
            stderr=stderr,
        )
        try:
            wait_health(port, process)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    return {
        "name": name,
        "returncode": process.returncode,
        "health_port": port,
        "passed": True,
        "stdout_sha256": hashlib.sha256(stdout_path.read_bytes()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr_path.read_bytes()).hexdigest(),
    }


def main() -> int:
    """Execute the configuration and process lifecycle matrix."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise SystemExit("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    fixture = pathlib.Path(
        runtime["environment"]["DSTACK_TEST_VERIFIER_FULL_TDX_IMAGE_DIR"]
    )
    binary = prepared_binary(runtime, "dstack_verifier")
    workspace = result_dir / "debug-workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    status = "PASS"
    summary = "Verifier config precedence, modes, outage, restart, and isolation matrix passed."
    stage = "prerequisites"
    environment = clean_verifier_env()
    try:
        if (
            hashlib.sha256((fixture / "sha256sum.txt").read_bytes()).hexdigest()
            != IMAGE_HASH
        ):
            raise AssertionError("full-TDX fixture identity changed")
        if not binary.is_file():
            raise AssertionError("prepared verifier is missing")

        target = runtime["cargo_target_dir"]
        test_env = environment | {"CARGO_TARGET_DIR": str(target)}
        stage = "source config matrix"
        row, completed = run_command(
            "source-config-matrix",
            [
                shutil.which("cargo", path=test_env["PATH"]) or "cargo",
                "test",
                "--manifest-path",
                str(repository / "dstack/Cargo.toml"),
                "-p",
                "dstack-verifier",
                "config_file_precedence_validation_and_unknown_field_matrix",
                "--bin",
                "dstack-verifier",
            ],
            workspace,
            test_env,
            300,
        )
        if (
            completed.returncode
            or "1 passed; 0 failed" not in completed.stdout + completed.stderr
        ):
            raise AssertionError("source config matrix failed")
        row["passed"] = True
        rows.append(row)

        request_source = repository / "dstack/verifier/fixtures/quote-report.json"
        request = workspace / "valid-request.json"
        shutil.copy2(request_source, request)
        cache = workspace / "cached-image"
        shutil.copytree(fixture, cache / "images" / IMAGE_HASH, dirs_exist_ok=True)
        config = workspace / "verifier.toml"
        file_port = allocate_port()
        write_config(config, file_port, cache)

        stage = "valid verify mode"
        row, completed = run_command(
            "verify-valid",
            [str(binary), "--config", str(config), "--verify", str(request)],
            workspace,
            environment,
        )
        require_valid_verification(row, completed)
        rows.append(row)

        stage = "top-level env precedence"
        env = environment | {"DSTACK_VERIFIER_PORT": "0"}
        row, completed = run_command(
            "env-port-precedence",
            [str(binary), "--config", str(config), "--verify", str(request)],
            workspace,
            env,
        )
        require_rejection(row, completed, "port must not be zero")
        rows.append(row)

        env = environment | {"DSTACK_VERIFIER_IMAGE_DOWNLOAD_TIMEOUT_SECS": "0"}
        row, completed = run_command(
            "env-timeout-precedence",
            [str(binary), "--config", str(config), "--verify", str(request)],
            workspace,
            env,
        )
        require_rejection(row, completed, "must be greater than zero")
        rows.append(row)

        stage = "nested env precedence"
        env = environment | {
            "DSTACK_VERIFIER_ATTESTATION__INSECURE_ALLOW_EXTERNAL_TRUST_ANCHORS": "true",
            "DSTACK_VERIFIER_ATTESTATION__ROOT_CA__TDX": str(
                workspace / "missing-root.der"
            ),
        }
        row, completed = run_command(
            "nested-root-precedence",
            [str(binary), "--config", str(config), "--verify", str(request)],
            workspace,
            env,
        )
        require_rejection(row, completed, "failed to read TDX root CA")
        rows.append(row)

        env = environment | {"DSTACK_VERIFIER_UNKNOWN_POLICY": "true"}
        row, completed = run_command(
            "unknown-env-field",
            [str(binary), "--config", str(config), "--verify", str(request)],
            workspace,
            env,
        )
        require_rejection(row, completed, "unknown field")
        rows.append(row)

        stage = "verify-cert mode"
        invalid_cert = workspace / "invalid-cert.pem"
        invalid_cert.write_text(
            "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
        )
        row, completed = run_command(
            "verify-cert-invalid",
            [str(binary), "--config", str(config), "--verify-cert", str(invalid_cert)],
            workspace,
            environment,
        )
        require_rejection(row, completed, "failed to verify RA-TLS certificate")
        rows.append(row)

        stage = "service restart and env port"
        env_port = allocate_port()
        env = environment | {"DSTACK_VERIFIER_PORT": str(env_port)}
        rows.append(
            start_and_stop_service(
                "service-env-port", binary, config, env_port, workspace, env
            )
        )
        rows.append(
            start_and_stop_service(
                "service-restart", binary, config, env_port, workspace, env
            )
        )
        adjacent_port = allocate_port()
        adjacent_config = workspace / "adjacent.toml"
        write_config(adjacent_config, adjacent_port, cache)
        rows.append(
            start_and_stop_service(
                "adjacent-service",
                binary,
                adjacent_config,
                adjacent_port,
                workspace,
                environment,
            )
        )

        stage = "concurrent duplicate verify"
        concurrent_requests = []
        for index in range(2):
            item = workspace / f"concurrent-{index}.json"
            shutil.copy2(request_source, item)
            concurrent_requests.append(item)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    run_command,
                    f"concurrent-{index}",
                    [str(binary), "--config", str(config), "--verify", str(item)],
                    workspace,
                    environment,
                )
                for index, item in enumerate(concurrent_requests)
            ]
            for future in futures:
                row, completed = future.result()
                require_valid_verification(row, completed)
                rows.append(row)

        stage = "dependency outage and recovery"
        recovery_cache = workspace / "recovery-cache"
        recovery_config = workspace / "recovery.toml"
        write_config(recovery_config, allocate_port(), recovery_cache, 1)
        outage_request = workspace / "outage-request.json"
        shutil.copy2(request_source, outage_request)
        row, completed = run_command(
            "image-dependency-outage",
            [
                str(binary),
                "--config",
                str(recovery_config),
                "--verify",
                str(outage_request),
            ],
            workspace,
            environment,
        )
        require_rejection(row, completed, "Failed to download image")
        rows.append(row)
        shutil.copytree(
            fixture, recovery_cache / "images" / IMAGE_HASH, dirs_exist_ok=True
        )
        recovery_request = workspace / "recovery-request.json"
        shutil.copy2(request_source, recovery_request)
        row, completed = run_command(
            "image-dependency-recovery",
            [
                str(binary),
                "--config",
                str(recovery_config),
                "--verify",
                str(recovery_request),
            ],
            workspace,
            environment,
        )
        require_valid_verification(row, completed)
        rows.append(row)
    except (
        AssertionError,
        KeyError,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        status = "FAIL"
        summary = f"{stage}: {error}"

    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "rows": rows,
        "passed_rows": sum(bool(row.get("passed")) for row in rows),
        "row_count": len(rows),
        "workspace_retained": status != "PASS",
        "covered_behaviors": [
            "embedded_file_environment_precedence",
            "nested_attestation_environment_override",
            "unknown_and_invalid_config_rejection",
            "verify_and_verify_cert_mode_selection",
            "service_environment_port_restart_and_adjacent_isolation",
            "concurrent_duplicate_verification",
            "image_dependency_outage_and_recovery",
        ],
    }
    artifact = {
        "path": "artifacts/verifier-config-precedence-matrix.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "Verifier configuration precedence matrix",
        "description": "Row results and hashed native outputs for precedence, modes, lifecycle, outage, and recovery.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": status,
                    "observed": f"{evidence['passed_rows']}/{evidence['row_count']} precedence, mode, and validation rows passed.",
                },
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "Concurrent verification and image dependency outage/recovery were exercised.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "Environment-selected port, restart, and adjacent service isolation were exercised.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "The invalid certificate row proves independent verify-cert mode selection and fail-closed parsing; certificate trust mutation coverage remains in tc-ver-cli-cert-o-002.",
        },
    )
    if status == "PASS":
        shutil.rmtree(workspace, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
