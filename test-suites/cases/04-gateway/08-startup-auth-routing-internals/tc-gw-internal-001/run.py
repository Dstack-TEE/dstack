#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway production certificate startup and resource-limit lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import signal
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

import tomllib

CASE_ID = "tc-gw-internal-001"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def health(url: str, token: str) -> int | None:
    """Request authenticated health without retaining its body."""
    request = urllib.request.Request(url, method="GET")
    request.add_header("X-Admin-Token", token)
    try:
        with urllib.request.urlopen(
            request, timeout=2, context=ssl._create_unverified_context()
        ) as response:
            response.read(4096)
            return int(response.status)
    except urllib.error.HTTPError as error:
        error.read(4096)
        return int(error.code)
    except (OSError, TimeoutError, urllib.error.URLError):
        return None


def wait_health(url: str, token: str, expected: int = 200) -> bool:
    """Wait for a bounded health state."""
    for _ in range(80):
        if health(url, token) == expected:
            return True
        time.sleep(0.1)
    return False


def wait_exit(process: subprocess.Popen[bytes], timeout: float = 8.0) -> int | None:
    """Wait for a candidate process to exit within a bounded interval."""
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def limits(pid: int) -> tuple[int, int]:
    """Read only the open-file soft and hard limits from procfs."""
    text = pathlib.Path(f"/proc/{pid}/limits").read_text()
    match = re.search(
        r"^Max open files\s+(\d+)\s+(\d+)\s+files\s*$", text, re.MULTILINE
    )
    if match is None:
        raise AssertionError("Max open files limit was unavailable")
    return int(match.group(1)), int(match.group(2))


def start(
    binary: str, config: pathlib.Path, environment: dict[str, str]
) -> subprocess.Popen[bytes]:
    """Start a case-owned candidate without retaining native output."""
    return subprocess.Popen(
        [binary, "--config", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        start_new_session=True,
    )


def stop(process: subprocess.Popen[bytes] | None) -> None:
    """Stop a run-owned process group if it is still alive."""
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            pass


def main() -> int:
    """Run production startup, failure, resource, and restart checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    gateway = values["gateway"]
    config_path = pathlib.Path(gateway["config"])
    config = tomllib.loads(config_path.read_text())
    core = config["core"]
    tls = config["tls"]
    token = pathlib.Path(gateway["admin_auth_token_file"]).read_text().strip()
    health_url = str(gateway["health_url"])
    binary = str(values["prepared_binaries"]["dstack_gateway"]["path"])
    guest_socket = str(
        values["gateway_guest_simulator"]["services"]["DstackGuest"]["socket"]
    )
    environment = {**os.environ, "DSTACK_AGENT_ADDRESS": f"unix:{guest_socket}"}
    original_pid = int(gateway["pid"])
    workspace = pathlib.Path(values["component_substrate"]["workspace"])
    restarted: subprocess.Popen[bytes] | None = None
    status = "FAIL"
    summary = "Gateway production startup matrix did not complete"
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    try:
        key_path = pathlib.Path(tls["key"])
        cert_path = pathlib.Path(tls["certs"])
        ca_path = pathlib.Path(tls["mutual"]["ca_certs"])
        private_files = [key_path, cert_path, ca_path]
        soft, hard = limits(original_pid)
        san = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(cert_path),
                "-noout",
                "-ext",
                "subjectAltName",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        startup_checks = {
            "production_mode": core["debug"]["insecure_skip_attestation"] is False,
            "debug_listener_disabled": core["debug"]["insecure_enable_debug_rpc"]
            is False,
            "production_domain_selected": core["rpc_domain"] == "localhost",
            "ulimit_enabled": core["set_ulimit"] is True,
            "ulimit_raised_to_hard": soft == hard and soft >= 1024,
            "crypto_provider_explicit": core["proxy"]["tls_crypto_provider"]
            in {"aws-lc-rs", "ring"},
            "private_files_exist": all(
                path.is_file() and path.stat().st_size > 0 for path in private_files
            ),
            "private_file_modes": all(
                (path.stat().st_mode & 0o777) == 0o600 for path in private_files
            ),
            "alternate_name_present": san.returncode == 0
            and b"DNS:localhost" in san.stdout,
            "initial_health": health(health_url, token) == 200,
            "debug_config_has_no_key_material": "key_file" not in core["debug"],
        }

        conflict = start(binary, config_path, environment)
        conflict_code = wait_exit(conflict)
        if conflict_code is None:
            stop(conflict)
        conflict_rejected = (
            conflict_code not in {None, 0} and health(health_url, token) == 200
        )

        invalid_config = workspace / "config/gateway-invalid-cert.toml"
        invalid_text = config_path.read_text()
        proxy_cert = str(core["proxy"]["cert_chain"])
        marker = f'cert_chain = "{proxy_cert}"'
        if invalid_text.count(marker) != 1:
            raise AssertionError("static proxy certificate field was ambiguous")
        invalid_config.write_text(
            invalid_text.replace(
                marker, f'cert_chain = "{workspace / "data/absent-cert.pem"}"', 1
            )
        )
        invalid = start(binary, invalid_config, environment)
        invalid_code = wait_exit(invalid)
        if invalid_code is None:
            stop(invalid)
        invalid_rejected = (
            invalid_code not in {None, 0} and health(health_url, token) == 200
        )

        os.kill(original_pid, signal.SIGTERM)
        for _ in range(80):
            if not pathlib.Path(f"/proc/{original_pid}").exists():
                break
            time.sleep(0.1)
        original_exited = not pathlib.Path(f"/proc/{original_pid}").exists()
        restarted = start(binary, config_path, environment)
        restart_healthy = wait_health(health_url, token)
        restart_soft, restart_hard = (
            limits(restarted.pid) if restart_healthy else (0, 0)
        )
        checks = {
            **startup_checks,
            "bind_conflict_rejected": conflict_rejected,
            "invalid_certificate_rejected": invalid_rejected,
            "original_exited": original_exited,
            "restart_healthy": restart_healthy,
            "restart_ulimit_raised": restart_soft == restart_hard
            and restart_soft == hard,
            "no_private_temporary_files": not list(workspace.glob("**/.*.tmp")),
        }
        if not all(checks.values()):
            raise AssertionError(
                f"startup checks failed: {sorted(k for k, value in checks.items() if not value)}; conflict_nonzero={conflict_code not in {None, 0}}; invalid_nonzero={invalid_code not in {None, 0}}"
            )
        observation = {
            "candidate_commit": runtime["candidate_commit"],
            "checks": checks,
            "initial_open_file_soft": soft,
            "initial_open_file_hard": hard,
            "restart_open_file_soft": restart_soft,
            "restart_open_file_hard": restart_hard,
            "private_file_count": len(private_files),
            "bind_conflict_returncode_nonzero": conflict_code not in {None, 0},
            "invalid_certificate_returncode_nonzero": invalid_code not in {None, 0},
        }
        evidence_path = result_dir / "artifacts/gateway-production-startup.json"
        atomic_json(evidence_path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-production-startup.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "Gateway production startup matrix",
                "description": "Modes, counts, resource limits, return-code classes, and booleans only; no path, certificate, key, token, URL, or native output is retained.",
            }
        )
        steps = [
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The case-owned candidate started in production certificate mode with no debug listener or debug key configuration.",
            },
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "Simulator-attested production TLS material contained the requested alternate name, used mode 0600, and the process raised its open-file soft limit to the hard limit.",
            },
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Bind conflict and missing static certificate starts failed without disturbing the original healthy listener.",
            },
            {
                "id": f"{CASE_ID}-step-04",
                "status": "PASS",
                "observed": "The original process exited and a same-config restart converged healthy with identical resource policy and no private temporary file.",
            },
        ]
        status = "PASS"
        summary = "Gateway production attested certificate mode, private material, resource limits, startup failures, isolation, and restart passed."
    except Exception as error:  # noqa: BLE001
        steps = [
            {
                "id": f"{CASE_ID}-step-{n:02d}",
                "status": "FAIL" if n == 1 else "NOT_RUN",
                "observed": str(error) if n == 1 else "Not run after failure.",
            }
            for n in range(1, 5)
        ]
        summary = f"Gateway production startup matrix failed: {error}"
    finally:
        stop(restarted)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    evidence = [
        {
            "path": item["path"],
            "sha256": hashlib.sha256(
                (result_dir / item["path"]).read_bytes()
            ).hexdigest(),
        }
        for item in artifacts
    ]
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "evidence": evidence,
            "remarks": "No path, certificate, key, token, endpoint, simulator material, environment value, or native process output is retained.",
            "duration_seconds": round(time.monotonic() - started, 3),
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
