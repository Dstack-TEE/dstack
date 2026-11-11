#!/usr/bin/env python3
"""Run all local epoch authorization backend suites."""

import json
import os
import pathlib
import subprocess

CASE = "tc-kms-rotation-015"


def main():
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE:
        raise SystemExit("unsupported case")
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repo = pathlib.Path(runtime["repository"])
    env = dict(os.environ, CARGO_TARGET_DIR=str(runtime["cargo_target_dir"]))
    rows = []
    for path, cmd in [
        ("dstack", ["cargo", "test", "--locked", "-p", "dstack-auth"]),
        ("dstack/kms/auth-eth", ["npm", "test", "--", "--run"]),
    ]:
        r = subprocess.run(
            cmd,
            cwd=repo / path,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=900,
        )
        rows.append(
            {
                "path": path,
                "command": cmd,
                "returncode": r.returncode,
                "output_tail": r.stdout[-4000:] if r.returncode else "",
            }
        )
    status = "PASS" if all(x["returncode"] == 0 for x in rows) else "FAIL"
    rd = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    (rd / "artifacts").mkdir(parents=True, exist_ok=True)
    (rd / "artifacts/backend-rotation-matrix.json").write_text(
        json.dumps({"status": status, "rows": rows}, indent=2) + "\n"
    )
    (rd / "result.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "case_id": CASE,
                "provisional": False,
                "status": status,
                "summary": f"{sum(not x['returncode'] for x in rows)}/{len(rows)} "
                "epoch authorization backend suites passed",
                "steps": [
                    {
                        "id": f"{CASE}-step-01",
                        "status": status,
                        "observed": ", ".join(
                            f"{x['path']}: rc={x['returncode']}" for x in rows
                        ),
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
