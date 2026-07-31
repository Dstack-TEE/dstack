#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D103, E701, E702
"""Exercise the authorization service as a case-owned Docker deployment."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CASE_ID = "tc-kms-runtime-004"


def docker(args: list[str], timeout: int = 300) -> dict[str, Any]:
    command = "docker " + " ".join(shlex.quote(v) for v in args)
    started = time.monotonic()
    done = subprocess.run(
        ["sudo", "su", "kvin", "-c", command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    return {
        "args": args,
        "exit_code": done.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "output_sha256": hashlib.sha256(done.stdout.encode()).hexdigest(),
        "output_tail": done.stdout[-8000:],
    }


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(
    port: int, path: str, body: dict[str, Any] | None = None
) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            return int(response.status), json.loads(response.read())
    except urllib.error.HTTPError as error:
        raw = error.read()
        return int(error.code), json.loads(raw) if raw else {}


def wait_health(port: int, want: int) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    last = {}
    while time.monotonic() < deadline:
        try:
            status, last = request(port, "/")
            if status == want:
                return last
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"container health did not reach {want}: {last}")


def main() -> int:
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repo = Path(runtime["repository"])
    package = repo / "dstack/kms/auth-eth"
    app_dir = repo / "dstack/kms/dstack-app"
    suffix = hashlib.sha256(f"{os.getpid()}-{time.time_ns()}".encode()).hexdigest()[:10]
    image = f"dstack-test-auth-runtime004:{suffix}"
    network = f"dstack-runtime004-{suffix}"
    auth = f"dstack-auth-{suffix}"
    rpc = f"dstack-rpc-{suffix}"
    port = free_port()
    root = Path(tempfile.mkdtemp(prefix="dstack-auth-container-"))
    runs = {}
    checks = {}
    retained = {}
    dockerfile = root / "Dockerfile"
    dockerfile.write_text(
        """FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci\nCOPY tsconfig.json ./\nCOPY src ./src\nRUN npm run build && npm prune --omit=dev\nUSER node\nCMD ["node", "dist/main.js"]\n"""
    )
    mock = root / "mock-rpc.py"
    helper = (
        repo
        / "docs/test-plans/core-components-full/automation/kms-runtime-001-capability-case.py"
    ).read_text()
    a = helper.index("GATEWAY_SELECTOR")
    b = helper.index("\n\ndef request(", a)
    mock_source = helper[a:b].replace(
        'ThreadingHTTPServer(("127.0.0.1", port)',
        'ThreadingHTTPServer(("0.0.0.0", port)',
    )
    mock.write_text(
        "#!/usr/bin/env python3\nimport http.server,json\nfrom typing import Any\n"
        + mock_source
        + "\nrun_mock_rpc(8545)\n"
    )
    compose_env = root / "compose.env"
    compose_env.write_text(
        "KMS_IMAGE=example.invalid/dstack-kms:test\n"
        "IMAGE_DOWNLOAD_URL=http://images.invalid/test.tar.gz\n"
        "AUTH_WEBHOOK_URL=http://auth-api:8000\n"
        "GIT_REPOSITORY=https://example.invalid/dstack.git\n"
        "GIT_REV=deadbeef\n"
        "ETH_RPC_URL=http://rpc:8545\n"
        "KMS_CONTRACT_ADDR=0x1111111111111111111111111111111111111111\n"
    )
    valid = {
        "mrAggregated": "0x01",
        "osImageHash": "0x02",
        "appId": "0x03",
        "composeHash": "0x04",
        "instanceId": "0x05",
        "deviceId": "0x06",
        "tcbStatus": "UpToDate",
        "advisoryIds": [],
        "mrSystem": "0x07",
    }

    def start_auth() -> dict[str, Any]:
        return docker(
            [
                "run",
                "-d",
                "--name",
                auth,
                "--network",
                network,
                "-p",
                f"127.0.0.1:{port}:8000",
                "-e",
                "HOST=0.0.0.0",
                "-e",
                "PORT=8000",
                "-e",
                "ETH_RPC_URL=http://rpc:8545",
                "-e",
                "KMS_CONTRACT_ADDR=0x" + "11" * 20,
                "--restart",
                "unless-stopped",
                image,
            ]
        )

    try:
        runs["compose_dev_config"] = docker(
            [
                "compose",
                "--env-file",
                str(compose_env),
                "-f",
                str(app_dir / "compose-dev.yaml"),
                "config",
            ],
            120,
        )
        runs["compose_simple_config"] = docker(
            [
                "compose",
                "--env-file",
                str(compose_env),
                "-f",
                str(app_dir / "compose-simple.yaml"),
                "config",
            ],
            120,
        )
        runs["build"] = docker(
            ["build", "-f", str(dockerfile), "-t", image, str(package)], 600
        )
        if runs["build"]["exit_code"]:
            raise RuntimeError(runs["build"]["output_tail"])
        runs["network"] = docker(["network", "create", network])
        runs["auth_start"] = start_auth()
        outage = wait_health(port, 500)
        outage_status, outage_boot = request(port, "/bootAuth/app", valid)
        runs["rpc_start"] = docker(
            [
                "run",
                "-d",
                "--name",
                rpc,
                "--network",
                network,
                "--network-alias",
                "rpc",
                "-v",
                f"{mock}:/mock-rpc.py:ro",
                "python:3.11-slim",
                "python",
                "/mock-rpc.py",
            ]
        )
        healthy = wait_health(port, 200)
        app_status, app = request(port, "/bootAuth/app", valid)
        kms_status, kms = request(port, "/bootAuth/kms", valid)
        runs["restart"] = docker(["restart", auth])
        restarted = wait_health(port, 200)
        runs["replace_remove"] = docker(["rm", "-f", auth])
        runs["replace_start"] = start_auth()
        replaced = wait_health(port, 200)
        runs["logs"] = docker(["logs", auth])
        runs["inspect"] = docker(["inspect", auth])
        inspect_text = runs["inspect"]["output_tail"]
        log_text = runs["logs"]["output_tail"]
        checks = {
            "compose_dev_valid": runs["compose_dev_config"]["exit_code"] == 0,
            "compose_simple_valid": runs["compose_simple_config"]["exit_code"] == 0,
            "candidate_image_built": runs["build"]["exit_code"] == 0,
            "outage_health": outage.get("status") == "error",
            "outage_fails_closed": outage_status == 200
            and outage_boot.get("isAllowed") is False,
            "recovery_healthy": healthy.get("status") == "ok",
            "app_kms_allowed": app_status == 200
            and app.get("isAllowed") is True
            and kms_status == 200
            and kms.get("isAllowed") is True,
            "restart_healthy": restarted.get("status") == "ok",
            "replacement_identity": replaced == healthy,
            "single_auth_process": inspect_text.count('"dist/main.js"') == 1,
            "no_secret_material": "PRIVATE_KEY" not in inspect_text
            and "PRIVATE_KEY" not in log_text
            and "WALLET" not in inspect_text,
        }
    finally:
        preliminary = bool(checks) and all(checks.values())
        if preliminary:
            runs["cleanup_auth"] = docker(["rm", "-f", auth])
            runs["cleanup_rpc"] = docker(["rm", "-f", rpc])
            runs["cleanup_network"] = docker(["network", "rm", network])
            runs["cleanup_image"] = docker(["image", "rm", image])
            shutil.rmtree(root, ignore_errors=True)
            checks["cleanup_complete"] = all(
                runs[k]["exit_code"] == 0
                for k in (
                    "cleanup_auth",
                    "cleanup_rpc",
                    "cleanup_network",
                    "cleanup_image",
                )
            )
        else:
            checks["cleanup_complete"] = False
            retained = {
                "auth": auth,
                "rpc": rpc,
                "network": network,
                "image": image,
                "workspace": str(root),
                "host_port": port,
            }
    groups = {
        "compose_contract": all(
            checks.get(k, False)
            for k in (
                "compose_dev_valid",
                "compose_simple_valid",
                "candidate_image_built",
            )
        ),
        "dependency_recovery": all(
            checks.get(k, False)
            for k in (
                "outage_health",
                "outage_fails_closed",
                "recovery_healthy",
                "app_kms_allowed",
            )
        ),
        "restart_replacement_security": all(
            checks.get(k, False)
            for k in (
                "restart_healthy",
                "replacement_identity",
                "single_auth_process",
                "no_secret_material",
            )
        ),
        "cleanup": checks.get("cleanup_complete", False),
    }
    status = "PASS" if all(groups.values()) else "FAIL"
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    detail = artifacts / "kms-runtime-004-container.json"
    detail.write_text(
        json.dumps(
            {
                "groups": groups,
                "checks": checks,
                "runs": runs,
                "retained_debug": retained,
            },
            indent=2,
        )
        + "\n"
    )
    artifact = {
        "path": "artifacts/kms-runtime-004-container.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Authorization container lifecycle",
        "description": "Candidate image, compose contracts, dependency outage/recovery, app/KMS decisions, restart, replacement, secret absence, and owned Docker cleanup.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    passed = sum(groups.values())
    summary = f"{passed}/{len(groups)} authorization container groups passed"
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 4)
        ],
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(detail.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "All Docker operations use sudo su kvin -c; failures retain named containers, network, image, workspace, and host port for command-level debugging.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
