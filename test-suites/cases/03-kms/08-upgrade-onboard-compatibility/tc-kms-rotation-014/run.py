#!/usr/bin/env python3
"""Run the complete Foundry contract rotation suite."""

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

CASE = "tc-kms-rotation-014"


def main():
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE:
        raise SystemExit("unsupported case")
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repo = pathlib.Path(runtime["repository"])
    # Build into case-owned directories: other cases compile the same package
    # in parallel, so the shared out/ and cache/ must not be cleaned or reused.
    build = pathlib.Path(tempfile.mkdtemp(prefix=f"{CASE}-forge-"))
    commands = [
        [
            "forge",
            "test",
            "--offline",
            "--ffi",
            "--out",
            str(build / "out"),
            "--cache-path",
            str(build / "cache"),
            "--match-path",
            path,
        ]
        for path in [
            "test/DstackKms.t.sol",
            "test/DstackApp.t.sol",
            "test/UpgradesWithPlugin.t.sol",
            # TEE platform policy on legacy apps (#1567) and Manage.s.sol (#1567, #1577).
            "test/LegacyAppCompat.t.sol",
            "test/ManageScript.t.sol",
        ]
    ]
    outputs = []
    for command in commands:
        shutil.rmtree(build, ignore_errors=True)
        result = subprocess.run(
            command,
            cwd=repo / "dstack/kms/auth-eth",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=600,
        )
        outputs.append(result)
    shutil.rmtree(build, ignore_errors=True)
    out = "\n".join(r.stdout for r in outputs)
    passed = sum(
        int(m.group(1))
        for r in outputs
        for m in [
            re.search(
                r"(?:Suite result: ok\.|Ran .*?:) (\d+) (?:passed|tests passed)",
                r.stdout,
            )
        ]
        if m
    )
    status = (
        "PASS" if all(r.returncode == 0 for r in outputs) and passed > 0 else "FAIL"
    )
    rd = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    (rd / "artifacts").mkdir(parents=True, exist_ok=True)
    (rd / "artifacts/contract-rotation-matrix.json").write_text(
        json.dumps(
            {
                "status": status,
                "passed": passed,
                "output_sha256": hashlib.sha256(out.encode()).hexdigest(),
            },
            indent=2,
        )
        + "\n"
    )
    (rd / "result.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "case_id": CASE,
                "provisional": False,
                "status": status,
                "summary": f"{passed} contract rotation tests passed",
                "steps": [
                    {
                        "id": f"{CASE}-step-01",
                        "status": status,
                        "observed": f"{passed} contract rotation tests passed",
                    }
                ],
            },
            indent=2,
        )
        + "\n"
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
