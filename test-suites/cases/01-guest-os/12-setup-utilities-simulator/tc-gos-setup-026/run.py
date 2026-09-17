#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic `dstack-util gpu-info` collector output-contract regression."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE = "tc-gos-setup-026"
TOP_LEVEL = {"gpus", "error", "cc_ready", "cc_enabled", "sample_age_ms"}
DEVICE_FIELDS = {
    "index",
    "uuid",
    "pci_bus_id",
    "utilization_gpu",
    "utilization_memory",
    "memory_total_bytes",
    "memory_used_bytes",
    "memory_free_bytes",
    "temperature_c",
    "power_usage_mw",
    "errors",
}
OPTIONAL_NUMBERS = DEVICE_FIELDS - {"index", "uuid", "pci_bus_id", "errors"}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Atomically write JSON evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def run(
    binary: pathlib.Path, *args: str, log_level: str | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run dstack-util with stdin closed, as the guest agent does."""
    environment = os.environ.copy()
    environment.pop("RUST_LOG", None)
    if log_level is not None:
        environment["RUST_LOG"] = log_level
    return subprocess.run(
        [str(binary), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=30,
        check=False,
    )


def nvidia_display_devices() -> int:
    """Count NVIDIA display-class PCI devices with the lspci::sysfs rule."""
    count = 0
    for device in pathlib.Path("/sys/bus/pci/devices").glob("*"):
        try:
            klass = (device / "class").read_text().strip()
            vendor = (device / "vendor").read_text().strip()
        except OSError:
            continue
        if klass[:6] in ("0x0300", "0x0302") and vendor == "0x10de":
            count += 1
    return count


def parse_document(completed: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    """Require exit 0 and exactly one JSON object line on stdout."""
    if completed.returncode != 0:
        raise AssertionError(f"gpu-info exited with {completed.returncode}")
    text = completed.stdout.decode("utf-8")
    lines = text.splitlines()
    if len(lines) != 1 or not text.endswith("\n"):
        raise AssertionError(
            f"stdout carried {len(lines)} lines instead of one JSON document"
        )
    value = json.loads(lines[0])
    if not isinstance(value, dict) or set(value) != TOP_LEVEL:
        raise AssertionError(
            f"unexpected top-level fields: {sorted(value) if isinstance(value, dict) else type(value)}"
        )
    return value


def classify(value: dict[str, Any]) -> dict[str, Any]:
    """Validate the documented unavailable / no-GPU / sampled shapes."""
    gpus, error = value["gpus"], value["error"]
    if not isinstance(gpus, list) or not isinstance(error, str):
        raise AssertionError("gpus/error have the wrong JSON types")
    if value["sample_age_ms"] is not None:
        raise AssertionError(
            "the collector set sample_age_ms, which belongs to the agent cache"
        )
    for name in ("cc_ready", "cc_enabled"):
        if value[name] not in (None, True, False):
            raise AssertionError(f"{name} is not an optional bool")
    if error:
        if gpus or value["cc_ready"] is not None or value["cc_enabled"] is not None:
            raise AssertionError("an unavailable result carried devices or CC state")
        return {"shape": "unavailable", "gpu_count": 0}
    if not gpus:
        if value["cc_ready"] is not None or value["cc_enabled"] is not None:
            raise AssertionError("a no-GPU result carried CC state")
        return {"shape": "no-gpu", "gpu_count": 0}
    indexes = []
    error_count = 0
    for device in gpus:
        if not isinstance(device, dict) or set(device) != DEVICE_FIELDS:
            raise AssertionError("a GPU device has unexpected fields")
        if not isinstance(device["index"], int) or not isinstance(device["uuid"], str):
            raise AssertionError("a GPU device has an invalid index or uuid")
        if not isinstance(device["errors"], list) or not all(
            isinstance(e, str) for e in device["errors"]
        ):
            raise AssertionError("GPU device errors is not a list of strings")
        for name in OPTIONAL_NUMBERS:
            if device[name] is not None and (
                not isinstance(device[name], int) or device[name] < 0
            ):
                raise AssertionError(
                    f"GPU device {name} is not an optional unsigned integer"
                )
        indexes.append(device["index"])
        error_count += len(device["errors"])
    if indexes != list(range(len(gpus))):
        raise AssertionError(f"GPU indexes are not NVML order: {indexes}")
    return {"shape": "sampled", "gpu_count": len(gpus), "query_errors": error_count}


def main() -> int:
    """Execute the collector output-contract matrix."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    prepared = runtime.get("prepared_binaries", {}).get("dstack_util", {})
    binary = pathlib.Path(prepared.get("resolved_path") or prepared.get("path") or "")
    if not binary.is_file():
        raise RuntimeError("prepared dstack-util binary is unavailable")
    steps: list[dict[str, str]] = []
    failures: list[str] = []
    evidence: dict[str, Any] = {}
    try:
        print(f"STEP {case_id}-step-01 START", flush=True)
        nvidia = nvidia_display_devices()
        default = run(binary, "gpu-info")
        document = parse_document(default)
        shape = classify(document)
        if nvidia == 0 and shape["shape"] == "sampled":
            raise AssertionError(
                "the collector sampled GPUs on a host without NVIDIA display devices"
            )
        if shape["shape"] == "unavailable" and b"WARN" not in default.stderr:
            raise AssertionError("an unavailable NVML result was not logged on stderr")
        evidence["default"] = {
            "exit_code": default.returncode,
            "host_nvidia_display_devices": nvidia,
            "stdout_lines": 1,
            "stderr_bytes": len(default.stderr),
            **shape,
            "error_sha256": hashlib.sha256(document["error"].encode()).hexdigest(),
        }
        print(json.dumps(evidence["default"], sort_keys=True), flush=True)
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": f"gpu-info exited 0 with one {shape['shape']} JSON document on stdout.",
            }
        )
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)

        print(f"STEP {case_id}-step-02 START", flush=True)
        # Verbose logging must still land on stderr only, or the agent's
        # parser would read log lines as the document.
        verbose = run(binary, "gpu-info", log_level="trace")
        verbose_document = parse_document(verbose)
        classify(verbose_document)
        if verbose.stdout.count(b"\n") != 1:
            raise AssertionError("trace logging leaked into stdout")
        if shape["shape"] != "sampled" and verbose_document != document:
            raise AssertionError("an unsampled result changed between runs")
        rejected = run(binary, "gpu-info", "--unexpected")
        if rejected.returncode == 0 or rejected.stdout.strip():
            raise AssertionError(
                "an unknown gpu-info argument was accepted or wrote stdout"
            )
        evidence["verbose_and_invalid"] = {
            "trace_stdout_lines": 1,
            "trace_stderr_bytes": len(verbose.stderr),
            "stable_unsampled_document": shape["shape"] != "sampled",
            "invalid_argument_exit": rejected.returncode,
            "invalid_argument_stdout_bytes": len(rejected.stdout.strip()),
        }
        print(json.dumps(evidence["verbose_and_invalid"], sort_keys=True), flush=True)
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Trace logging stayed on stderr, the document was stable, and an unknown argument was rejected without stdout.",
            }
        )
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)

        print(f"STEP {case_id}-step-03 START", flush=True)
        # Every sample is a fresh process: nothing may outlive the command.
        before = {p.name for p in pathlib.Path("/proc").iterdir() if p.name.isdigit()}
        again = run(binary, "gpu-info")
        classify(parse_document(again))
        leftovers = []
        for pid in {
            p.name for p in pathlib.Path("/proc").iterdir() if p.name.isdigit()
        } - before:
            try:
                if pathlib.Path(f"/proc/{pid}/exe").resolve() == binary.resolve():
                    leftovers.append(pid)
            except OSError:
                continue
        if leftovers:
            raise AssertionError(f"gpu-info left processes behind: {leftovers}")
        evidence["repeat"] = {"exit_code": again.returncode, "resident_collectors": 0}
        print(json.dumps(evidence["repeat"], sort_keys=True), flush=True)
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "A repeated one-shot sample succeeded and no collector process remained.",
            }
        )
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for number in range(1, 4):
            sid = f"{case_id}-step-{number:02d}"
            if not any(step["id"] == sid for step in steps):
                steps.append({"id": sid, "status": "FAIL", "observed": failures[-1]})
    evidence["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    artifact = {
        "name": "GPU collector CLI matrix",
        "path": "artifacts/gpu-info-cli-matrix.json",
        "step_id": f"{case_id}-step-01",
        "description": "Records exit codes, stdout line counts, response shape, device and error counts, an error-text digest, and the prepared binary digest.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "GPU telemetry collector CLI output contract passed."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Runs the prepared dstack-util on the fixture host; GPU-positive sampling inside a CVM is covered by tc-gos-platform-009.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
