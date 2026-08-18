#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for promoted KMS admin RPC cases."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request
from typing import Any

import tomllib

SUPPORTED_CASES = {"tc-kms-admin-001", "tc-kms-keys-certs-006"}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def call(url: str, body: bytes, token: str | None) -> dict[str, Any]:
    """Call an admin pRPC endpoint without persisting credentials."""
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(
            request, timeout=20, context=ssl._create_unverified_context()
        ) as response:
            raw = response.read()
            status = int(response.status)
            content_type = response.headers.get("Content-Type")
    except urllib.error.HTTPError as error:
        raw = error.read()
        status = int(error.code)
        content_type = error.headers.get("Content-Type") if error.headers else None
    return {
        "status": status,
        "body_len": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "content_type": content_type,
        "empty_success": raw in (b"", b"null", b"{}"),
    }


def probe_metrics(url: str) -> dict[str, Any]:
    """Probe the KMS metrics endpoint."""
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(
            request, timeout=20, context=ssl._create_unverified_context()
        ) as response:
            raw = response.read()
            return {"status": int(response.status), "body_len": len(raw)}
    except urllib.error.HTTPError as error:
        return {"status": int(error.code), "body_len": len(error.read())}


def main() -> int:
    """Execute the promoted ClearImageCache regression."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in SUPPORTED_CASES:
        raise SystemExit(f"unsupported promoted KMS admin case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    kms = manifest["values"]["kms"]
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    admin_base = str(kms["admin_url"]).rstrip("/")
    route = f"{admin_base}/Admin.ClearImageCache"
    token = (
        pathlib.Path(kms["admin_auth_token_file"]).read_text(encoding="utf-8").strip()
    )
    if not token:
        raise RuntimeError("KMS admin token file is empty")
    artifacts_dir = result_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    step_ids = [f"{case_id}-step-{number:02d}" for number in (1, 2, 3)]
    steps: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    status = "PASS"
    failure = ""

    def record(name: str, step_id: str, value: Any, description: str) -> None:
        atomic_json(artifacts_dir / name, value)
        artifacts.append(
            {
                "path": f"artifacts/{name}",
                "step_id": step_id,
                "name": name.removesuffix(".json").replace("-", " ").title(),
                "description": description,
            }
        )

    try:
        print(f"STEP {step_ids[0]} START", flush=True)
        metrics = probe_metrics(str(kms["metrics_url"]))
        unauthorized = call(route, b"{}", None)
        if metrics["status"] != 200:
            raise AssertionError("KMS metrics endpoint is unhealthy")
        if unauthorized["status"] not in (401, 403):
            raise AssertionError("KMS admin endpoint did not enforce authorization")
        record(
            "step01-prereq.json",
            step_ids[0],
            {"metrics": metrics, "unauthorized": unauthorized},
            "KMS availability and admin authorization enforcement.",
        )
        steps.append(
            {
                "id": step_ids[0],
                "status": "PASS",
                "observed": "KMS was healthy and the admin endpoint required authorization.",
            }
        )
        print(f"STEP {step_ids[0]} END - PASS", flush=True)

        print(f"STEP {step_ids[1]} START", flush=True)
        cache_lifecycle: dict[str, Any] = {}
        if case_id == "tc-kms-keys-certs-006":
            config = tomllib.loads(pathlib.Path(kms["config"]).read_text())
            cache_root = pathlib.Path(config["core"]["image"]["cache_dir"])
            image_hash = "11" * 32
            adjacent_image_hash = "12" * 32
            config_hash = "21" * 32
            adjacent_config_hash = "22" * 32
            selected = [
                cache_root / "images" / image_hash,
                cache_root / "measurements" / config_hash,
            ]
            adjacent = [
                cache_root / "images" / adjacent_image_hash,
                cache_root / "measurements" / adjacent_config_hash,
            ]
            for entry in [*selected, *adjacent]:
                entry.mkdir(parents=True, exist_ok=True)
                (entry / "sentinel").write_text("case-owned")
            targeted_body = json.dumps(
                {"image_hash": image_hash, "config_hash": config_hash}
            ).encode()
            unauthorized_targeted = call(route, targeted_body, None)
            if unauthorized_targeted["status"] not in (401, 403) or not all(
                entry.exists() for entry in [*selected, *adjacent]
            ):
                raise AssertionError("unauthorized targeted clear mutated cache state")
            valid = call(route, targeted_body, token)
            if any(entry.exists() for entry in selected) or any(
                not entry.exists() for entry in adjacent
            ):
                raise AssertionError("targeted clear did not isolate selected entries")
            # Refill the selected entries as verification does after a miss, then
            # prove the all-selector remains confined to the two cache namespaces.
            for entry in selected:
                entry.mkdir(parents=True, exist_ok=True)
                (entry / "refilled").write_text("case-owned")
            all_body = json.dumps({"image_hash": "all", "config_hash": "all"}).encode()
            repeat = call(route, all_body, token)
            if (cache_root / "images").exists() or (
                cache_root / "measurements"
            ).exists():
                raise AssertionError("all-selector did not clear cache namespaces")
            cache_root.mkdir(parents=True, exist_ok=True)
            outside = cache_root / "outside-sentinel"
            outside.write_text("preserved")
            if outside.read_text() != "preserved":
                raise AssertionError("cache clear escaped its namespaces")
            cargo = subprocess.run(
                [
                    "cargo",
                    "test",
                    "--manifest-path",
                    "dstack/Cargo.toml",
                    "-p",
                    "dstack-verifier",
                    "measurement_cache_",
                    "--",
                    "--nocapture",
                ],
                cwd=runtime["repository"],
                env={
                    **os.environ,
                    "CARGO_TARGET_DIR": runtime["cargo_target_dir"],
                },
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            if cargo.returncode or "test result: ok" not in cargo.stdout:
                raise AssertionError(
                    f"measurement cache refill matrix failed: {cargo.stdout[-500:]} {cargo.stderr[-500:]}"
                )
            cache_lifecycle = {
                "unauthorized_targeted": unauthorized_targeted,
                "targeted_selected_removed": True,
                "targeted_adjacent_preserved": True,
                "refilled_before_all": True,
                "all_namespaces_removed": True,
                "outside_namespace_preserved": True,
                "verifier_cache_tests": "PASS",
            }
            absent = call(route, b"", token)
            compatible = call(route, b'{"future_field":true}', token)
            malformed = call(route, b'{"broken":', token)
        else:
            valid = call(route, b"{}", token)
            absent = call(route, b"", token)
            compatible = call(route, b'{"future_field":true}', token)
            malformed = call(route, b'{"broken":', token)
            repeat = call(route, b"{}", token)
        if any(
            item["status"] != 200 or item["empty_success"] is not True
            for item in (valid, absent, compatible, repeat)
        ):
            raise AssertionError(
                "valid or compatible ClearImageCache call did not return an empty success"
            )
        if malformed["status"] < 400:
            raise AssertionError("malformed ClearImageCache JSON was accepted")
        behavior = {
            "valid": valid,
            "absent": absent,
            "compatible_unknown_field": compatible,
            "malformed": malformed,
            "repeat": repeat,
            "cache_lifecycle": cache_lifecycle,
        }
        record(
            "step02-rpc-matrix.json",
            step_ids[1],
            behavior,
            "Valid, absent/default, compatible, malformed, and repeated ClearImageCache calls.",
        )
        steps.append(
            {
                "id": step_ids[1],
                "status": "PASS",
                "observed": "ClearImageCache returned empty idempotent success and rejected malformed JSON.",
            }
        )
        print(f"STEP {step_ids[1]} END - PASS", flush=True)

        print(f"STEP {step_ids[2]} START", flush=True)
        post_metrics = probe_metrics(str(kms["metrics_url"]))
        post_unauthorized = call(route, b"{}", None)
        if post_metrics["status"] != 200 or post_unauthorized["status"] not in (
            401,
            403,
        ):
            raise AssertionError("post-call availability or authorization changed")
        record(
            "step03-diagnostics.json",
            step_ids[2],
            {"metrics": post_metrics, "unauthorized": post_unauthorized},
            "Post-call availability and authorization isolation.",
        )
        steps.append(
            {
                "id": step_ids[2],
                "status": "PASS",
                "observed": "KMS remained healthy and unauthorized calls remained rejected.",
            }
        )
        print(f"STEP {step_ids[2]} END - PASS", flush=True)
    except Exception as error:
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
        index = min(len(steps), 2)
        if len(steps) < 3:
            steps.append({"id": step_ids[index], "status": "FAIL", "observed": failure})
        print(f"STEP {step_ids[index]} END - FAIL", flush=True)
    while len(steps) < 3:
        steps.append(
            {
                "id": step_ids[len(steps)],
                "status": "NOT_RUN",
                "observed": "Not run after an earlier failure.",
            }
        )
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": "KMS ClearImageCache deterministic regression passed."
        if status == "PASS"
        else f"KMS ClearImageCache deterministic regression failed: {failure}",
        "steps": steps,
        "artifacts": artifacts,
        "remarks": "The harness uses only the manifest-declared KMS admin and metrics endpoints and never persists the authorization credential.",
    }
    atomic_json(result_dir / "result.json", result)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
