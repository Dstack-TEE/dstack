#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic dstack-util random and hexadecimal CLI regression."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import subprocess
import tempfile
from typing import Any

CASE = "tc-gos-setup-021"


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
    binary: pathlib.Path, *args: str, input_data: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run dstack-util without decoding random stdout."""
    return subprocess.run(
        [str(binary), *args],
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )


def main() -> int:
    """Execute promoted rand/hex coverage."""
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
    steps = []
    failures = []
    evidence = {}
    try:
        print(f"STEP {case_id}-step-01 START", flush=True)
        first = run(binary, "rand", "--bytes", "32")
        second = run(binary, "rand", "-n", "32")
        encoded = run(binary, "rand", "--bytes", "16", "--hex")
        if first.returncode or second.returncode or encoded.returncode:
            raise AssertionError("valid random stdout mode failed")
        if (
            len(first.stdout) != 32
            or len(second.stdout) != 32
            or len(encoded.stdout) != 32
        ):
            raise AssertionError("random output length mismatch")
        if first.stdout == second.stdout:
            raise AssertionError("independent random outputs repeated")
        bytes.fromhex(encoded.stdout.decode())
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Raw and hex random modes returned exact lengths without reuse.",
            }
        )
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)
        print(f"STEP {case_id}-step-02 START", flush=True)
        with tempfile.TemporaryDirectory(dir=result_dir) as directory:
            output = pathlib.Path(directory) / "random.bin"
            written = run(binary, "rand", "--bytes", "48", "--output", str(output))
            before = output.read_bytes()
            repeat = run(binary, "rand", "--bytes", "8", "--output", str(output))
            after = output.read_bytes()
            if written.returncode or len(before) != 48:
                raise AssertionError("file output failed")
            if repeat.returncode or len(after) != 8 or before == after:
                raise AssertionError("atomic existing-file replacement failed")
            mode = stat.S_IMODE(output.stat().st_mode)
            if mode != 0o600:
                raise AssertionError(f"random output mode was {mode:o}")
            binary_input = bytes(range(256))
            hexed = run(binary, "hex", input_data=binary_input)
            if hexed.returncode or hexed.stdout.decode() != binary_input.hex():
                raise AssertionError("hex stdin encoding mismatch")
        evidence["matrix"] = {
            "raw_lengths": [len(first.stdout), len(second.stdout)],
            "hex_length": len(encoded.stdout),
            "file_length": 48,
            "file_mode": "0600",
            "atomic_replacement": True,
            "binary_hex_exact": True,
            "random_values_persisted": False,
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Atomic owner-only file replacement and independent hex decoding matched.",
            }
        )
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)
        print(f"STEP {case_id}-step-03 START", flush=True)
        post = run(binary, "rand", "--bytes", "32")
        if post.returncode or post.stdout in (first.stdout, second.stdout):
            raise AssertionError("post-error random recovery failed")
        evidence["matrix"]["post_error_recovery"] = True
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Post-error retry succeeded with a fresh value and no random bytes were persisted.",
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
    evidence["sensitive_values_persisted"] = False
    artifact = {
        "name": "Random and hex CLI matrix",
        "path": "artifacts/rand-hex-matrix.json",
        "step_id": f"{case_id}-step-02",
        "description": "Records only lengths, permissions, boolean assertions, and the prepared binary digest; random bytes are not persisted.",
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
            "summary": "Random and hexadecimal CLI regression passed."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "No generated random value was written to result artifacts or logs.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
