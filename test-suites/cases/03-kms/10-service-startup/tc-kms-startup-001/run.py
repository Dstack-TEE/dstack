#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise KMS onboarding-to-main listener startup and fail-closed restart."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-kms-startup-001"
PRIVATE_NAMES = {"root-ca.key", "root-k256.key", "rpc.key", "tmp-ca.key"}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic JSON evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def emit(step: int, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step."""
    step_id = f"{CASE_ID}-step-{step:02d}"
    print(f"STEP {step_id} START", flush=True)
    print(f"EVIDENCE {step_id} - {observed}", flush=True)
    print(f"STEP {step_id} END - {status}", flush=True)
    return {"id": step_id, "status": status, "observed": observed}


def port_open(port: int) -> bool:
    """Return whether a loopback TCP listener accepts connections."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def wait_for(predicate: Any, timeout: float, description: str) -> None:
    """Wait for a bounded lifecycle predicate."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise RuntimeError(f"timeout waiting for {description}")


def request(
    url: str, body: bytes | None = None, content_type: str = ""
) -> tuple[int, bytes]:
    """Issue one bounded HTTP request with local TLS verification disabled."""
    headers = {"content-type": content_type} if content_type else {}
    req = urllib.request.Request(url, data=body, headers=headers)
    context = ssl._create_unverified_context()  # noqa: SLF001
    try:
        with urllib.request.urlopen(req, timeout=15, context=context) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except urllib.error.URLError:
        return 0, b""


def public_snapshot(cert_dir: pathlib.Path) -> dict[str, Any]:
    """Record public hashes and private metadata without reading private material."""
    result: dict[str, Any] = {}
    for path in sorted(cert_dir.iterdir()):
        if not path.is_file():
            continue
        stat = path.stat()
        row: dict[str, Any] = {
            "size": stat.st_size,
            "mode": oct(stat.st_mode & 0o777),
            "inode": stat.st_ino,
            "mtime_ns": stat.st_mtime_ns,
        }
        if path.name not in PRIVATE_NAMES:
            row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        result[path.name] = row
    return result


def start_candidate(
    binary: pathlib.Path, config: pathlib.Path, log: pathlib.Path, agent: str
) -> subprocess.Popen[str]:
    """Start a case-owned candidate KMS and retain its process group on failure."""
    stream = log.open("a", encoding="utf-8")
    return subprocess.Popen(
        [str(binary), "--config", str(config)],
        stdout=stream,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
        env={**os.environ, "DSTACK_AGENT_ADDRESS": agent},
    )


def stop_process(process: subprocess.Popen[str]) -> None:
    """Stop a case-owned process group after successful verification."""
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(5)


def main() -> int:
    """Run listener state, transition, failure, restart, isolation, and redaction checks."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"unsupported case: {os.environ.get('DSTACK_TEST_CASE_ID')}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    onboard = values["kms_onboard"]
    source = values["kms_onboard_source"]
    ports = values["component_substrate"]["ports"]
    workspace = pathlib.Path(values["component_substrate"]["workspace"])
    cert_dir = pathlib.Path(onboard["cert_dir"])
    config = pathlib.Path(onboard["config"])
    candidate = pathlib.Path(runtime["prepared_binaries"]["dstack_kms"]["path"])
    expected_head = runtime["candidate_commit"]
    agent_socket = values["kms_guest_simulator"]["services"]["DstackGuest"]["socket"]
    agent = f"unix:{agent_socket}"
    original_pid = int(onboard["pid"])
    target_rpc = int(ports["kms"])
    onboard_port = int(ports["onboard"])
    admin_port = int(ports["debug"])
    processes: list[subprocess.Popen[str]] = []
    steps: list[dict[str, str]] = []
    evidence: dict[str, Any] = {
        "candidate_commit": expected_head,
        "ports": {"rpc": target_rpc, "onboard": onboard_port, "admin": admin_port},
    }
    status = "FAIL"
    failure = ""

    try:
        os.killpg(original_pid, signal.SIGTERM)
        wait_for(
            lambda: not port_open(onboard_port),
            10,
            "fixture onboarding listener shutdown",
        )
        candidate_log = workspace / "logs/startup-candidate.log"
        process = start_candidate(candidate, config, candidate_log, agent)
        processes.append(process)
        atomic_json(
            artifacts / "retained-debug.json",
            {
                "pid": process.pid,
                "config": str(config),
                "log": str(candidate_log),
                "ports": evidence["ports"],
            },
        )
        wait_for(lambda: port_open(onboard_port), 20, "candidate onboarding listener")
        health_code, health_body = request(f"http://127.0.0.1:{onboard_port}/health")
        main_before = port_open(target_rpc)
        admin_before = port_open(admin_port)
        premature_code, _ = request(
            f"http://127.0.0.1:{onboard_port}/prpc/KMS.GetKmsKey?json",
            b"{}",
            "application/json",
        )
        step1_ok = (
            health_code == 200
            and health_body == b"OK"
            and not main_before
            and not admin_before
            and premature_code >= 400
        )
        evidence["uninitialized"] = {
            "health": health_code,
            "main_open": main_before,
            "admin_open": admin_before,
            "kms_on_onboard": premature_code,
        }
        steps.append(
            emit(
                1,
                "PASS" if step1_ok else "FAIL",
                "Only onboarding health/RPC were reachable; main and admin listeners remained closed.",
            )
        )
        if not step1_ok:
            raise RuntimeError(
                f"uninitialized listener isolation failed: {evidence['uninitialized']}"
            )

        domain = f"{manifest['lease_id']}.startup.test"
        onboard_code, onboard_body = request(
            f"{onboard['prpc_url']}/Onboard.Onboard?json",
            json.dumps(
                {"source_url": source["rpc_url"], "domain": domain},
                separators=(",", ":"),
            ).encode(),
            "application/json",
        )
        if onboard_code != 200:
            raise RuntimeError(
                f"onboarding failed with HTTP {onboard_code}, bytes={len(onboard_body)}"
            )
        pre_finish = public_snapshot(cert_dir)
        transition_samples: list[dict[str, bool]] = []
        finish_code, finish_body = request(
            f"{onboard['prpc_url']}/Onboard.Finish?json", b"{}", "application/json"
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            sample = {
                "onboard": port_open(onboard_port),
                "main": port_open(target_rpc),
                "admin": port_open(admin_port),
            }
            transition_samples.append(sample)
            if sample["main"] and sample["admin"] and not sample["onboard"]:
                break
            time.sleep(0.025)
        overlap = any(
            row["onboard"] and (row["main"] or row["admin"])
            for row in transition_samples
        )
        main_health, main_health_body = request(
            f"https://127.0.0.1:{target_rpc}/health"
        )
        metrics_code, metrics_body = request(f"https://127.0.0.1:{target_rpc}/metrics")
        admin_missing, _ = request(
            f"http://127.0.0.1:{admin_port}/prpc/Admin.ClearImageCache?json",
            b"{}",
            "application/json",
        )
        wrong_main, _ = request(
            f"https://127.0.0.1:{target_rpc}/prpc/Admin.ClearImageCache?json",
            b"{}",
            "application/json",
        )
        step2_ok = (
            finish_code == 200
            # pRPC JSON encodes google.protobuf.Empty as JSON null.
            and finish_body in {b"null", b"{}", b""}
            and transition_samples[-1]
            == {"onboard": False, "main": True, "admin": True}
            and not overlap
            and main_health == 200
            and main_health_body == b"OK"
            and metrics_code == 200
            and b"dstack" in metrics_body.lower()
            and admin_missing in {401, 403}
            and wrong_main >= 400
        )
        evidence["transition"] = {
            "finish": finish_code,
            "samples": transition_samples,
            "overlap": overlap,
            "main_health": main_health,
            "metrics": metrics_code,
            "admin_missing_auth": admin_missing,
            "admin_method_on_main": wrong_main,
        }
        steps.append(
            emit(
                2,
                "PASS" if step2_ok else "FAIL",
                f"Finish transitioned across {len(transition_samples)} samples with overlap={overlap}; main/admin/metrics/health opened in initialized mode.",
            )
        )
        if not step2_ok:
            raise RuntimeError(f"listener transition failed: {evidence['transition']}")

        conflict_log = workspace / "logs/startup-bind-conflict.log"
        conflict = start_candidate(candidate, config, conflict_log, agent)
        processes.append(conflict)
        try:
            conflict_rc = conflict.wait(15)
        except subprocess.TimeoutExpired:
            conflict_rc = None
            stop_process(conflict)
        invalid_config = workspace / "config/startup-invalid.toml"
        config_text = config.read_text(encoding="utf-8")
        invalid_text, replacements = re.subn(
            rf"(?m)^port = {target_rpc}$", "port = 70000", config_text, count=1
        )
        if replacements != 1:
            raise RuntimeError("target RPC port was not uniquely mutable")
        invalid_config.write_text(invalid_text, encoding="utf-8")
        invalid = subprocess.run(
            [str(candidate), "--config", str(invalid_config)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
            env={**os.environ, "DSTACK_AGENT_ADDRESS": agent},
        )
        invalid_output = invalid.stdout[-2000:]
        (artifacts / "invalid-config.log").write_text(invalid_output)
        still_healthy, _ = request(f"https://127.0.0.1:{target_rpc}/health")
        step3_ok = (
            conflict_rc not in {None, 0}
            and invalid.returncode != 0
            and still_healthy == 200
        )
        evidence["failures"] = {
            "bind_conflict_rc": conflict_rc,
            "invalid_config_rc": invalid.returncode,
            "main_after_failures": still_healthy,
        }
        steps.append(
            emit(
                3,
                "PASS" if step3_ok else "FAIL",
                "Bind conflict and boundary-invalid configuration failed explicitly while the committed instance stayed healthy.",
            )
        )
        if not step3_ok:
            raise RuntimeError(
                f"startup failure handling failed: {evidence['failures']}"
            )

        before_restart = public_snapshot(cert_dir)
        stop_process(process)
        wait_for(
            lambda: not port_open(target_rpc) and not port_open(admin_port),
            10,
            "initialized listeners shutdown",
        )
        restarted_log = workspace / "logs/startup-restarted.log"
        restarted = start_candidate(candidate, config, restarted_log, agent)
        processes.append(restarted)
        atomic_json(
            artifacts / "retained-debug.json",
            {
                "pid": restarted.pid,
                "config": str(config),
                "log": str(restarted_log),
                "ports": evidence["ports"],
            },
        )
        wait_for(
            lambda: port_open(target_rpc) and port_open(admin_port),
            20,
            "restarted main and admin listeners",
        )
        after_restart = public_snapshot(cert_dir)
        restart_health, restart_body = request(f"https://127.0.0.1:{target_rpc}/health")
        stable_names = {"root-ca.crt", "root-ca.key", "root-k256.key"}
        stable = all(
            before_restart.get(name) == after_restart.get(name) for name in stable_names
        )
        logs = (
            candidate_log.read_text(errors="replace")
            + restarted_log.read_text(errors="replace")
            + conflict_log.read_text(errors="replace")
        )
        private_leak = any(
            re.search(r"-----BEGIN (?:EC |PRIVATE )?PRIVATE KEY-----", logs, re.I)
            for _ in [0]
        )
        step4_ok = (
            stable
            and restart_health == 200
            and restart_body == b"OK"
            and not port_open(onboard_port)
            and not private_leak
        )
        evidence["restart"] = {
            "stable_ca_and_keys": stable,
            "health": restart_health,
            "onboard_open": port_open(onboard_port),
            "private_pem_in_logs": private_leak,
            "pre_finish_file_count": len(pre_finish),
        }
        steps.append(
            emit(
                4,
                "PASS" if step4_ok else "FAIL",
                "Committed state restarted only main/admin listeners with unchanged CA/key metadata and no private PEM in logs.",
            )
        )
        if not step4_ok:
            raise RuntimeError(
                f"restart/isolation/redaction failed: {evidence['restart']}"
            )
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        if not steps or steps[-1]["status"] != "FAIL":
            steps.append(emit(min(len(steps) + 1, 4), "FAIL", failure))
    finally:
        atomic_json(artifacts / "startup-lifecycle.json", evidence)
        if status == "PASS":
            for process in reversed(processes):
                stop_process(process)

    artifact_entries = [
        {
            "path": f"artifacts/{path.name}",
            "name": path.name,
            "description": "Sanitized KMS startup lifecycle evidence.",
        }
        for path in sorted(artifacts.iterdir())
    ]
    atomic_json(artifacts / "manifest.json", {"artifacts": artifact_entries})
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": "KMS onboarding/main/admin/metrics/health startup lifecycle passed."
        if status == "PASS"
        else failure,
        "steps": steps,
        "artifacts": artifact_entries,
        "remarks": "Failure leaves the candidate PID, ports, config path, state, and logs recorded in retained-debug.json for in-place debugging; private key contents are never read or persisted.",
    }
    atomic_json(result_dir / "result.json", result)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
