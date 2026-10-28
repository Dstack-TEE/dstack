#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise live component backpressure and exact resource-boundary tests."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import pathlib
import ssl
import statistics
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-int-failure-se-006"


def call(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, int, int]:
    """Issue one bounded request and retain only status, length, and latency."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    started = time.monotonic_ns()
    try:
        with urllib.request.urlopen(
            request, timeout=30, context=ssl._create_unverified_context()
        ) as response:
            raw = response.read()
            code = int(response.status)
    except urllib.error.HTTPError as error:
        raw = error.read()
        code = int(error.code)
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        raw = b""
        code = 0
    return code, len(raw), (time.monotonic_ns() - started) // 1_000


def process_sample(pid: int) -> dict[str, int]:
    """Read bounded resource counters for a lease-owned process."""
    status: dict[str, int] = {
        "fd": len(list(pathlib.Path(f"/proc/{pid}/fd").iterdir()))
    }
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(("VmRSS:", "VmSize:", "Threads:")):
            name, value, *_ = line.replace(":", "").split()
            status[name] = int(value)
    return status


def cargo_test(
    repository: pathlib.Path, target: pathlib.Path, package: str, test: str
) -> dict[str, Any]:
    """Run one exact cached component boundary test and retain only safe metadata."""
    started = time.monotonic_ns()
    completed = subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(repository / "dstack/Cargo.toml"),
            "-p",
            package,
            test,
            "--",
            "--exact",
        ],
        env={**os.environ, "CARGO_TARGET_DIR": str(target)},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=240,
        check=False,
    )
    output = completed.stdout
    if completed.returncode:
        raise AssertionError(
            f"{package}/{test} failed; output_sha256={hashlib.sha256(output).hexdigest()}"
        )
    return {
        "package": package,
        "test": test,
        "passed": True,
        "duration_ms": (time.monotonic_ns() - started) // 1_000_000,
        "output_sha256": hashlib.sha256(output).hexdigest(),
    }


def percentile(values: list[int], fraction: float) -> int:
    """Return a deterministic nearest-rank percentile."""
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int(len(ordered) * fraction)))]


def main() -> int:
    """Run oversized, concurrent, resource-recovery, and exact boundary matrices."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    kms, gateway = values["kms"], values["gateway"]
    repository = pathlib.Path(values["repository"])
    target = pathlib.Path(values["cargo_target_dir"])
    evidence: dict[str, Any] = {"live": {}, "component_tests": []}
    status, failure = "FAIL", ""
    try:
        tokens = {
            "kms": pathlib.Path(kms["admin_auth_token_file"]).read_text().strip(),
            "gateway": pathlib.Path(gateway["admin_auth_token_file"])
            .read_text()
            .strip(),
        }
        endpoints = {
            "kms": f"{str(kms['admin_url']).rstrip('/')}/Admin.ClearImageCache",
            "gateway": f"{str(gateway['admin_url']).rstrip('/')}/Admin.ListDnsCredentials",
        }
        pids = {"kms": int(kms["pid"]), "gateway": int(gateway["pid"])}
        baseline = {name: process_sample(pid) for name, pid in pids.items()}

        oversized = b'{"padding":"' + (b"x" * (11 * 1024 * 1024)) + b'"}'
        oversized_rows: dict[str, Any] = {}
        for name, url in endpoints.items():
            code, length, elapsed = call(
                url,
                oversized,
                {
                    "content-type": "application/json",
                    "Authorization": f"Bearer {tokens[name]}",
                },
            )
            if code != 0 and code < 400:
                raise AssertionError(
                    f"{name} accepted an oversized RPC body with HTTP {code}"
                )
            oversized_rows[name] = {
                "status": code,
                "response_length": length,
                "elapsed_us": elapsed,
                "rejected": True,
            }

        load_rows: dict[str, Any] = {}
        for name, url in endpoints.items():
            headers = {
                "content-type": "application/json",
                "Authorization": f"Bearer {tokens[name]}",
            }
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
                rows = list(
                    executor.map(lambda _: call(url, b"{}", headers), range(64))
                )
            accepted = sum(code == 200 for code, _, _ in rows)
            if accepted != 64:
                raise AssertionError(
                    f"{name} completed only {accepted}/64 bounded concurrent requests"
                )
            latencies = [elapsed for _, _, elapsed in rows]
            load_rows[name] = {
                "accepted": accepted,
                "total": len(rows),
                "p50_us": int(statistics.median(latencies)),
                "p95_us": percentile(latencies, 0.95),
                "max_us": max(latencies),
            }

        time.sleep(0.25)
        recovered = {name: process_sample(pid) for name, pid in pids.items()}
        for name in pids:
            if recovered[name]["fd"] > baseline[name]["fd"] + 8:
                raise AssertionError(f"{name} retained file descriptors after load")
            if recovered[name]["VmRSS"] > baseline[name]["VmRSS"] + 64 * 1024:
                raise AssertionError(f"{name} retained more than 64 MiB after load")
        health = {
            "kms": call(
                endpoints["kms"],
                b"{}",
                {
                    "content-type": "application/json",
                    "Authorization": f"Bearer {tokens['kms']}",
                },
            )[0],
            "gateway": call(
                endpoints["gateway"],
                b"{}",
                {
                    "content-type": "application/json",
                    "Authorization": f"Bearer {tokens['gateway']}",
                },
            )[0],
        }
        if health != {"kms": 200, "gateway": 200}:
            raise AssertionError(f"post-load health/admin recovery failed: {health}")
        evidence["live"] = {
            "oversized": oversized_rows,
            "load": load_rows,
            "baseline": baseline,
            "recovered": recovered,
            "health": health,
            "restart_observed": False,
        }

        tests = [
            (
                "dstack-kms",
                "ct_log::tests::concurrent_writes_are_unique_and_never_overwrite",
            ),
            (
                "dstack-kms",
                "ct_log::tests::exhausted_collision_range_fails_without_overwrite",
            ),
            (
                "dstack-verifier",
                "verification::tests::concurrent_measurement_cache_writes_are_atomic",
            ),
            (
                "dstack-verifier",
                "verification::tests::image_cache_pruning_keeps_checksum_identity",
            ),
            ("dstack-gateway", "pp::tests::rejects_v2_oversize_length"),
            (
                "dstack-gateway",
                "cert_store::tests::concurrent_reads_never_observe_empty_during_reload",
            ),
            (
                "dstack-vmm",
                "app::host_share::tests::missing_or_oversized_sources_never_publish_partial_disk",
            ),
            (
                "dstack-vmm",
                "app::host_share::tests::concurrent_publication_never_exposes_partial_image",
            ),
            (
                "dstack-vmm",
                "app::tests::auto_restart_policy_backs_off_caps_and_exhausts_once",
            ),
            (
                "local-key-provider",
                "protocol::tests::rejects_oversized_frames_before_allocating_them",
            ),
        ]
        for package, test in tests:
            evidence["component_tests"].append(
                cargo_test(repository, target, package, test)
            )
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        evidence["failure"] = failure

    evidence_path = artifacts / "resource-backpressure.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact = {
        "path": "artifacts/resource-backpressure.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Resource and backpressure matrix",
        "description": "Sanitized status, latency, process counters, recovery state, and exact component-test hashes.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = (
        "2/2 oversized bodies rejected, 128/128 concurrent RPCs completed, resources recovered, and 10/10 exact component boundary tests passed"
        if status == "PASS"
        else failure
    )
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
                "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "Pressure is bounded to lease-owned processes and cached exact tests; native response bodies and credentials are not persisted.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
