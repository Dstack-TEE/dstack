#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway debug-key generation and artifact publication safety."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-gw-internal-002"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def run(binary: pathlib.Path, address: str, cwd: pathlib.Path) -> subprocess.CompletedProcess[bytes]:
    """Run the generator with bounded output that is never persisted."""
    return subprocess.run(
        [str(binary), address], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60, check=False,
    )


def artifact_facts(path: pathlib.Path) -> dict[str, Any]:
    """Inspect structure and metadata without retaining private values."""
    raw = path.read_bytes()
    value = json.loads(raw)
    return {
        "exists": path.is_file(),
        "mode": stat.S_IMODE(path.stat().st_mode),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "keys": sorted(value),
        "debug_only": value.get("debug_only") is True,
        "key_pem_nonempty": isinstance(value.get("key_pem"), str) and bool(value["key_pem"]),
        "quote_nonempty": isinstance(value.get("quote_base64"), str) and bool(value["quote_base64"]),
        "event_log_is_string": isinstance(value.get("event_log"), str),
        "vm_config_is_string": isinstance(value.get("vm_config"), str),
    }


def main() -> int:
    """Run normal, duplicate, concurrent, and dependency-failure matrices."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    manifest = json.loads(pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    binary = pathlib.Path(runtime["cargo_target_dir"]) / "release/gen_debug_key"
    simulator = manifest["values"]["gateway_guest_simulator"]["services"]["DstackGuest"]
    address = f"unix:{simulator['socket']}"
    workspace = pathlib.Path(manifest["values"]["component_substrate"]["workspace"])
    normal_dir = workspace / "data/debug-key-normal"
    concurrent_dir = workspace / "data/debug-key-concurrent"
    failure_dir = workspace / "data/debug-key-failure"
    for directory in (normal_dir, concurrent_dir, failure_dir):
        directory.mkdir(parents=True, exist_ok=False)
    status = "FAIL"
    summary = "Gateway debug-key artifact matrix did not complete"
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    try:
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise AssertionError("prepared shared-target release/gen_debug_key is unavailable")
        first = run(binary, address, normal_dir)
        output = normal_dir / "debug_key.json"
        if first.returncode != 0 or not output.is_file():
            raise AssertionError(f"initial generation failed: rc={first.returncode}")
        facts = artifact_facts(output)
        expected_keys = ["debug_only", "event_log", "key_pem", "quote_base64", "vm_config"]
        initial_hash = facts["sha256"]

        duplicate = run(binary, address, normal_dir)
        duplicate_facts = artifact_facts(output)

        left = subprocess.Popen([str(binary), address], cwd=concurrent_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        right = subprocess.Popen([str(binary), address], cwd=concurrent_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        concurrent_codes = sorted([left.wait(timeout=60), right.wait(timeout=60)])
        concurrent_output = concurrent_dir / "debug_key.json"
        concurrent_facts = artifact_facts(concurrent_output)

        bad_address = "unix:" + str(failure_dir / "absent.sock")
        failed = run(binary, bad_address, failure_dir)
        checks = {
            "initial_generation_succeeds": first.returncode == 0,
            "artifact_mode_restricted": facts["mode"] == 0o600,
            "artifact_schema_exact": facts["keys"] == expected_keys,
            "artifact_explicitly_debug_only": facts["debug_only"],
            "artifact_fields_present": all(facts[key] for key in ("key_pem_nonempty", "quote_nonempty", "event_log_is_string", "vm_config_is_string")),
            "duplicate_refused": duplicate.returncode != 0 and duplicate_facts["sha256"] == initial_hash,
            "concurrent_single_winner": concurrent_codes == [0, 1],
            "concurrent_artifact_complete": concurrent_facts["keys"] == expected_keys and concurrent_facts["mode"] == 0o600,
            "dependency_failure_publishes_nothing": failed.returncode != 0 and not (failure_dir / "debug_key.json").exists(),
            "temporary_files_removed": not list(workspace.glob("data/debug-key-*/*.tmp")),
        }
        if not all(checks.values()):
            raise AssertionError(f"debug-key checks failed: {sorted(k for k, value in checks.items() if not value)}")
        observation = {
            "candidate_commit": runtime["candidate_commit"],
            "checks": checks,
            "initial_returncode": first.returncode,
            "duplicate_returncode_nonzero": duplicate.returncode != 0,
            "concurrent_returncodes": concurrent_codes,
            "dependency_failure_returncode_nonzero": failed.returncode != 0,
            "artifact_mode": facts["mode"],
            "artifact_size": facts["size"],
            "artifact_keys": facts["keys"],
        }
        evidence_path = result_dir / "artifacts/gateway-debug-key-safety.json"
        atomic_json(evidence_path, observation)
        artifacts.append({
            "path": "artifacts/gateway-debug-key-safety.json", "step_id": f"{CASE_ID}-step-02",
            "name": "Gateway debug-key artifact safety matrix",
            "description": "Return codes, permissions, sizes, field names, and booleans only; no key, quote, event log, VM config, endpoint, or native output is retained.",
        })
        steps = [
            {"id": f"{CASE_ID}-step-01", "status": "PASS", "observed": "The prepared candidate generator and case-owned simulator started from a clean output baseline."},
            {"id": f"{CASE_ID}-step-02", "status": "PASS", "observed": "The generator published one complete debug_only artifact with mode 0600 and the exact schema."},
            {"id": f"{CASE_ID}-step-03", "status": "PASS", "observed": "Duplicate and concurrent publication produced exactly one winner without changing the existing artifact; dependency failure published nothing."},
            {"id": f"{CASE_ID}-step-04", "status": "PASS", "observed": "No temporary file or private value remained in case evidence."},
        ]
        status = "PASS"
        summary = "Gateway debug-key atomic publication, restrictive permissions, no-overwrite concurrency, dependency failure, labeling, and redaction passed."
    except Exception as error:  # noqa: BLE001
        steps = [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": "FAIL" if n == 1 else "NOT_RUN", "observed": str(error) if n == 1 else "Not run after failure."}
            for n in range(1, 5)
        ]
        summary = f"Gateway debug-key artifact matrix failed: {error}"
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    evidence = [{"path": item["path"], "sha256": hashlib.sha256((result_dir / item["path"]).read_bytes()).hexdigest()} for item in artifacts]
    atomic_json(result_dir / "result.json", {
        "schema_version": "1.0", "case_id": CASE_ID, "provisional": False, "status": status,
        "summary": summary, "steps": steps, "artifacts": artifacts, "evidence": evidence,
        "remarks": "No private key, quote, event log, VM config, simulator address, certificate, credential, or native process output is retained.",
        "duration_seconds": round(time.monotonic() - started, 3),
    })
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
