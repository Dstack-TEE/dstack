#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Certbot Cloudflare DNS API success, authorization, outage, and recovery."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

CASE_ID = "tc-gw-certbot-003"


def load_support():
    """Load the case-owned bounded Cloudflare API model."""
    path = Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("certbot_cloudflare_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Cloudflare support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_tests(
    runtime: dict[str, object], env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run the three candidate Cloudflare client tests against the local model."""
    return subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-p",
            "certbot",
            "dns01_client::cloudflare::tests::",
            "--",
            "--nocapture",
        ],
        cwd=Path(str(runtime["repository"])) / "dstack",
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )


def passed_count(completed: subprocess.CompletedProcess[str]) -> int:
    """Return the largest successful Rust test count without retaining output."""
    output = completed.stdout + completed.stderr
    return max(
        (int(value) for value in re.findall(r"(\d+) passed; 0 failed", output)),
        default=0,
    )


def main() -> int:
    """Run valid, wrong-token, provider-outage, and restored API observations."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    support = load_support()
    state = support.DnsState(["example.test", "adjacent.test"])
    server = support.CloudflareServer(state)
    worker = threading.Thread(
        target=server.serve_forever, name="certbot-cloudflare-api", daemon=True
    )
    worker.start()
    base_env = os.environ.copy()
    base_env.update(
        {
            "CARGO_TARGET_DIR": str(runtime["cargo_target_dir"]),
            "TEST_DOMAIN": "certbot.example.test",
            "CLOUDFLARE_API_TOKEN": support.SENTINEL_TOKEN,
            "CLOUDFLARE_API_URL": f"http://127.0.0.1:{server.server_port}/client/v4",
        }
    )
    valid = run_tests(runtime, base_env)
    valid_passed = passed_count(valid)
    wrong_env = base_env.copy()
    wrong_env["CLOUDFLARE_API_TOKEN"] = "invalid-sentinel"
    wrong = run_tests(runtime, wrong_env)
    with state.lock:
        state.failure = True
    outage = run_tests(runtime, base_env)
    with state.lock:
        state.failure = False
    recovery = run_tests(runtime, base_env)
    recovery_passed = passed_count(recovery)
    snapshot = state.snapshot()
    operation_count = len(state.operations)
    server.shutdown()
    server.server_close()
    worker.join(2)
    checks = {
        "valid_add_list_remove_matrix": valid.returncode == 0 and valid_passed >= 3,
        "wrong_token_rejected": wrong.returncode != 0,
        "provider_outage_rejected": outage.returncode != 0,
        "recovery_matrix": recovery.returncode == 0 and recovery_passed >= 3,
        "all_records_cleaned": all(not records for records in snapshot.values()),
        "bounded_api_activity": 10 <= operation_count < 100,
        "server_reaped": not worker.is_alive(),
    }
    passed = all(checks.values())
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "checks": checks,
        "valid_passed": valid_passed,
        "recovery_passed": recovery_passed,
        "wrong_token_nonzero": wrong.returncode != 0,
        "outage_nonzero": outage.returncode != 0,
        "operation_count": operation_count,
        "remaining_record_counts": [len(rows) for rows in snapshot.values()],
        "retained_credentials_domains_records_or_endpoints": False,
    }
    artifact = result_dir / "artifacts/certbot-cloudflare-boundaries.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        "Cloudflare TXT/CAA mutation, authorization, outage, cleanup, and recovery passed."
        if passed
        else f"Cloudflare checks failed: {sorted(k for k, value in checks.items() if not value)}"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": observed}
            for n in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/certbot-cloudflare-boundaries.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "The candidate Certbot client used a loopback-only Cloudflare API model. Evidence retains counts, statuses, and booleans only.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
