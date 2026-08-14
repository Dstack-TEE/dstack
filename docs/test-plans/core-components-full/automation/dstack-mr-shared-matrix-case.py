#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the shared dstack-mr CLI, configuration, artifact, and cmdline matrix."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any

CASE_IDS = {"tc-ver-tools-001", "tc-ver-tools-002"}
IMAGE_HASH = "14ad42d0270b444eaeb53918a5a94d9b17eec7a817cd336173b17c5327541c67"
MATRIX_VERSION = 1
BASE_ARGS = ["--cpu", "2", "--memory", "2G", "--qemu-version", "9.2.1"]
REGISTERS = ("mrtd", "rtmr0", "rtmr1", "rtmr2")


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


def copy_fixture(source: pathlib.Path, destination: pathlib.Path) -> None:
    """Create an isolated copy, using reflinks when the filesystem supports them."""
    destination.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["cp", "--archive", "--reflink=auto", f"{source}/.", str(destination)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def changed_registers(baseline: dict[str, str], output: dict[str, str]) -> list[str]:
    """Return the ordered register names changed from baseline."""
    return [name for name in REGISTERS if output[name] != baseline[name]]


def run_cli(
    binary: pathlib.Path,
    metadata: pathlib.Path,
    args: list[str],
    workspace: pathlib.Path,
    name: str,
) -> tuple[dict[str, Any], dict[str, str] | None, str]:
    """Run one CLI row and retain bounded command output for debugging."""
    completed = subprocess.run(
        [str(binary), "measure", str(metadata), *args, "--json"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    (workspace / f"{name}.stdout").write_text(completed.stdout)
    (workspace / f"{name}.stderr").write_text(completed.stderr)
    output = None
    if completed.returncode == 0:
        output = json.loads(completed.stdout)
    row = {
        "name": name,
        "returncode": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
    }
    return row, output, completed.stderr


def require_success(
    row: dict[str, Any],
    output: dict[str, str] | None,
    expected_changed: list[str] | None,
) -> dict[str, str]:
    """Require a valid four-register output and optionally an exact change set."""
    if row["returncode"] != 0 or output is None:
        raise AssertionError(f"{row['name']} unexpectedly failed")
    if set(output) != set(REGISTERS) or any(
        len(output[name]) != 96 for name in REGISTERS
    ):
        raise AssertionError(f"{row['name']} returned an invalid measurement schema")
    if expected_changed is not None:
        observed = row.get("changed_registers", [])
        if observed != expected_changed:
            raise AssertionError(
                f"{row['name']} changed {observed}, expected {expected_changed}"
            )
    row["passed"] = True
    return output


def require_rejection(row: dict[str, Any], diagnostic: str, fragment: str) -> None:
    """Require a bounded fail-closed diagnostic."""
    if row["returncode"] == 0 or fragment.lower() not in diagnostic.lower():
        raise AssertionError(f"{row['name']} did not reject with {fragment!r}")
    row["expected_rejection"] = True
    row["passed"] = True


def mutate_last_byte(path: pathlib.Path) -> None:
    """Flip one byte without changing artifact length."""
    with path.open("r+b") as stream:
        stream.seek(-1, os.SEEK_END)
        value = stream.read(1)
        stream.seek(-1, os.SEEK_END)
        stream.write(bytes([value[0] ^ 1]))


def execute_matrix(
    binary: pathlib.Path, fixture: pathlib.Path, workspace: pathlib.Path
) -> dict[str, Any]:
    """Execute the complete shared matrix once."""
    rows: list[dict[str, Any]] = []

    def accepted(
        name: str, metadata: pathlib.Path, args: list[str], expected: list[str] | None
    ):
        row, output, _ = run_cli(binary, metadata, args, workspace, name)
        if baseline:
            row["changed_registers"] = changed_registers(baseline, output or baseline)
        result = require_success(row, output, expected)
        rows.append(row)
        return result

    def rejected(name: str, metadata: pathlib.Path, args: list[str], fragment: str):
        row, _, diagnostic = run_cli(binary, metadata, args, workspace, name)
        require_rejection(row, diagnostic, fragment)
        rows.append(row)

    row, baseline_output, _ = run_cli(
        binary, fixture / "metadata.json", [*BASE_ARGS], workspace, "baseline"
    )
    baseline: dict[str, str] = {}
    baseline = require_success(row, baseline_output, None)
    row["changed_registers"] = []
    rows.append(row)

    repeated = accepted(
        "deterministic-repeat", fixture / "metadata.json", [*BASE_ARGS], []
    )
    if repeated != baseline:
        raise AssertionError("deterministic repeat changed output")
    accepted(
        "historical-four-part-version",
        fixture / "metadata.json",
        [*BASE_ARGS, "--dstack-os-version", "0.5.4.1"],
        [],
    )
    accepted(
        "cpu-count",
        fixture / "metadata.json",
        ["--cpu", "4", "--memory", "2G", "--qemu-version", "9.2.1"],
        ["rtmr0"],
    )
    accepted(
        "memory-size",
        fixture / "metadata.json",
        ["--cpu", "2", "--memory", "4G", "--qemu-version", "9.2.1"],
        ["rtmr0"],
    )
    accepted(
        "qemu-8-compatibility",
        fixture / "metadata.json",
        ["--cpu", "2", "--memory", "2G", "--qemu-version", "8.2.2"],
        ["mrtd", "rtmr0"],
    )
    accepted(
        "qemu-10-compatibility",
        fixture / "metadata.json",
        ["--cpu", "2", "--memory", "2G", "--qemu-version", "10.0.0"],
        ["rtmr0"],
    )
    accepted(
        "advanced-machine-fields",
        fixture / "metadata.json",
        [
            *BASE_ARGS,
            "--two-pass-add-pages",
            "true",
            "--pic",
            "true",
            "--smm",
            "true",
            "--pci-hole64-size",
            "0x100000000",
            "--num-nics",
            "3",
            "--num-verity-volumes",
            "2",
            "--hotplug-off",
            "true",
            "--root-verity",
            "false",
        ],
        None,
    )
    accepted(
        "gpu-topology-functional",
        fixture / "metadata.json",
        [
            *BASE_ARGS,
            "--num-gpus",
            "1",
            "--num-nvswitches",
            "1",
            "--pci-hole64-size",
            "16T",
        ],
        ["rtmr0"],
    )
    rejected(
        "hugepage-numa-unsupported",
        fixture / "metadata.json",
        [*BASE_ARGS, "--hugepages"],
        "NUMA node binding",
    )
    rejected(
        "swtpm-unsupported",
        fixture / "metadata.json",
        [*BASE_ARGS, "--swtpm"],
        "swtpm measurement is not supported",
    )
    rejected(
        "unsupported-qemu-version",
        fixture / "metadata.json",
        ["--cpu", "2", "--memory", "2G", "--qemu-version", "7.2.0"],
        "Unsupported QEMU version",
    )

    invalid_version = workspace / "invalid-version"
    copy_fixture(fixture, invalid_version)
    metadata_value = json.loads((invalid_version / "metadata.json").read_text())
    metadata_value["version"] = "0.5.10.1.2"
    atomic_json(invalid_version / "metadata.json", metadata_value)
    rejected(
        "invalid-image-version",
        invalid_version / "metadata.json",
        [*BASE_ARGS],
        "expected MAJOR.MINOR.PATCH[.SUFFIX]",
    )

    for name, filename, expected in (
        ("firmware-mutation", "ovmf.fd", ["mrtd"]),
        ("kernel-mutation", "bzImage", ["rtmr1"]),
        ("initrd-mutation", "initramfs.cpio.gz", ["rtmr2"]),
    ):
        directory = workspace / name
        copy_fixture(fixture, directory)
        mutate_last_byte(directory / filename)
        accepted(name, directory / "metadata.json", [*BASE_ARGS], expected)

    cmdline = workspace / "cmdline-mutation"
    copy_fixture(fixture, cmdline)
    metadata_value = json.loads((cmdline / "metadata.json").read_text())
    metadata_value["cmdline"] += " matrix.boundary=1"
    atomic_json(cmdline / "metadata.json", metadata_value)
    accepted("cmdline-mutation", cmdline / "metadata.json", [*BASE_ARGS], ["rtmr2"])

    for name, filename, fragment in (
        ("missing-firmware", "ovmf.fd", "No such file"),
        ("missing-kernel", "bzImage", "No such file"),
        ("missing-initrd", "initramfs.cpio.gz", "No such file"),
    ):
        directory = workspace / name
        copy_fixture(fixture, directory)
        (directory / filename).unlink()
        rejected(name, directory / "metadata.json", [*BASE_ARGS], fragment)

    malformed = workspace / "malformed-metadata"
    malformed.mkdir()
    (malformed / "metadata.json").write_text("{")
    rejected(
        "malformed-metadata",
        malformed / "metadata.json",
        [*BASE_ARGS],
        "parse image metadata",
    )
    recovered = accepted(
        "recovery-after-failures", fixture / "metadata.json", [*BASE_ARGS], []
    )
    if recovered != baseline:
        raise AssertionError("recovery output changed from baseline")

    isolated = workspace / "adjacent-identity"
    copy_fixture(fixture, isolated)
    adjacent = accepted(
        "adjacent-copy-isolation", isolated / "metadata.json", [*BASE_ARGS], []
    )
    if adjacent != baseline:
        raise AssertionError("adjacent fixture identity changed output")

    return {
        "matrix_version": MATRIX_VERSION,
        "image_hash": IMAGE_HASH,
        "rows": rows,
        "row_count": len(rows),
        "passed_rows": sum(bool(row.get("passed")) for row in rows),
    }


def main() -> int:
    """Execute or reuse the run-scoped shared matrix and emit case evidence."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASE_IDS:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    fixture = pathlib.Path(
        runtime["environment"]["DSTACK_TEST_VERIFIER_FULL_TDX_IMAGE_DIR"]
    )
    binary = prepared_binary(runtime, "dstack_mr_cli")
    run_id = os.environ["DSTACK_TEST_RUN_ID"]
    commit = runtime["candidate_commit"]
    cache_root = pathlib.Path("/tmp/dstack-mr-shared-matrix") / run_id / commit
    cache_path = cache_root / "matrix.json"
    lock_path = cache_root / "matrix.lock"
    cache_root.mkdir(parents=True, exist_ok=True)
    workspace = result_dir / "debug-workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    status = "PASS"
    summary = (
        "Shared dstack-mr configuration, artifact, cmdline, and recovery matrix passed."
    )
    matrix: dict[str, Any] = {}
    reused = False
    try:
        if (
            hashlib.sha256((fixture / "sha256sum.txt").read_bytes()).hexdigest()
            != IMAGE_HASH
        ):
            raise AssertionError(
                "fixture identity does not match the expected image hash"
            )
        with lock_path.open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if cache_path.is_file():
                cached = json.loads(cache_path.read_text())
                if (
                    cached.get("matrix_version") == MATRIX_VERSION
                    and cached.get("candidate_commit") == commit
                    and cached.get("status") == "PASS"
                ):
                    matrix = cached["matrix"]
                    reused = True
            if not matrix:
                matrix = execute_matrix(binary, fixture, workspace)
                atomic_json(
                    cache_path,
                    {
                        "matrix_version": MATRIX_VERSION,
                        "candidate_commit": commit,
                        "status": "PASS",
                        "executed_by_case_id": case_id,
                        "matrix": matrix,
                    },
                )
    except (
        AssertionError,
        KeyError,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        status = "FAIL"
        summary = str(error)

    focus = (
        "supported platform/configuration fields and fail-closed unsupported settings"
        if case_id == "tc-ver-tools-001"
        else "firmware, kernel, initrd, cmdline, QEMU, missing-artifact, and recovery boundaries"
    )
    evidence = {
        "candidate_commit": commit,
        "shared_matrix_reused": reused,
        "focus": focus,
        "matrix": matrix,
        "workspace_retained": status != "PASS",
        "remarks": "GPU topology is functional measurement coverage only; hugepage/NUMA is an expected unsupported row on this host. No image build is exercised.",
    }
    artifact = {
        "path": "artifacts/dstack-mr-shared-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "Shared dstack-mr measurement matrix",
        "description": "Run-scoped shared row results, exact register change sets, expected rejections, and output hashes.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "Prepared CLI and hash-bound image fixture were selected.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": f"The shared matrix recorded {matrix.get('passed_rows', 0)}/{matrix.get('row_count', 0)} passing rows; reused={reused}.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Expected failures were followed by an identical baseline recovery.",
                },
                {
                    "id": f"{case_id}-step-04",
                    "status": status,
                    "observed": "An adjacent fixture copy produced identical output and no persistent state.",
                },
            ],
            "artifacts": [artifact],
            "remarks": evidence["remarks"],
        },
    )
    if status == "PASS":
        shutil.rmtree(workspace, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
