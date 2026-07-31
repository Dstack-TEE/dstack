#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Promote mined replay specs only after they actually replay.

Mining a passing attempt produces a candidate harness, not a verified one: a
recording can be stale, because a checked-in helper's interface may have moved
since the attempt ran. Registering a spec on the strength of the original PASS
is how nine cases previously entered the registry claiming to be deterministic
while every rerun failed.

This tool registers each candidate, replays it against a fresh lease, and keeps
the registration only for the cases that pass. Failures are reported with the
replay error and left unregistered.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

ENTRYPOINT = "automation/replay-case.py"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON so a reader never observes a partial document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", dir=path.parent, delete=False, encoding="utf-8"
    ) as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")
        temporary = handle.name
    os.replace(temporary, path)


def set_execution(index: dict[str, Any], case_id: str, execution: dict | None) -> bool:
    """Attach or detach a case's execution entrypoint in the index."""
    for chapter in index["chapters"]:
        for section in chapter["sections"]:
            for case in section.get("cases", []):
                if case["id"] != case_id:
                    continue
                if execution is None:
                    case.pop("execution", None)
                else:
                    case["execution"] = execution
                return True
    return False


def main() -> int:
    """Verify every mined spec and promote the ones that replay."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=pathlib.Path, required=True)
    parser.add_argument("--runtime-manifest", type=pathlib.Path, required=True)
    parser.add_argument(
        "--run-id", required=True, help="run id for verification sweeps"
    )
    parser.add_argument("--tool", type=pathlib.Path, required=True, help="dstack-test")
    parser.add_argument(
        "--source-run", required=True, help="run the specs were mined from"
    )
    args = parser.parse_args()

    plan = args.plan.resolve()
    replay_dir = plan / "automation" / "replay"
    candidates = sorted(path.stem for path in replay_dir.glob("*.json"))
    if not candidates:
        raise SystemExit(f"no mined specs in {replay_dir}")

    index_path = plan / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    already = {
        case["id"]
        for chapter in index["chapters"]
        for section in chapter["sections"]
        for case in section.get("cases", [])
        if (case.get("execution") or {}).get("entrypoint") not in (None, ENTRYPOINT)
    }
    pending = [case_id for case_id in candidates if case_id not in already]
    execution = {"entrypoint": ENTRYPOINT, "args": [], "timeout_seconds": 300}
    for case_id in pending:
        if not set_execution(index, case_id, execution):
            raise SystemExit(f"mined case is not in the index: {case_id}")
    atomic_json(index_path, index)

    command = [
        str(args.tool),
        "sweep",
        "--plan",
        str(plan),
        "--run-id",
        args.run_id,
        "--workers",
        "4",
        "--runtime-manifest",
        str(args.runtime_manifest),
    ]
    for case_id in pending:
        command += ["--case", case_id]
    subprocess.run(command, check=False, capture_output=True, text=True)

    verified: list[str] = []
    rejected: dict[str, str] = {}
    run_dir = plan / "results" / args.run_id
    for case_id in pending:
        matches = list(run_dir.glob(f"cases/*/*/{case_id}/result.json"))
        if not matches:
            rejected[case_id] = "verification produced no result"
            continue
        result = json.loads(matches[0].read_text(encoding="utf-8"))
        if result.get("status") == "PASS":
            verified.append(case_id)
        else:
            rejected[case_id] = str(result.get("summary", result.get("status")))

    # Roll back every case that did not replay, so the index never claims a
    # deterministic harness that does not reproduce.
    index = json.loads(index_path.read_text(encoding="utf-8"))
    for case_id in rejected:
        set_execution(index, case_id, None)
        (replay_dir / f"{case_id}.json").unlink(missing_ok=True)
    atomic_json(index_path, index)

    promoted_path = plan / "automation" / "promoted-passing-cases.json"
    promoted = json.loads(promoted_path.read_text(encoding="utf-8"))
    known = {entry["case_id"] for entry in promoted["cases"]}
    for case_id in verified:
        if case_id in known:
            continue
        promoted["cases"].append(
            {
                "case_id": case_id,
                "source_run": args.source_run,
                "source_status": "PASS",
                "entrypoint": ENTRYPOINT,
                "environment": "MINED_REPLAY",
                "notes": f"mined from {args.source_run} and verified by replay",
            }
        )
    promoted["cases"].sort(key=lambda entry: entry["case_id"])
    atomic_json(promoted_path, promoted)

    report = {
        "candidates": len(candidates),
        "attempted": len(pending),
        "verified": sorted(verified),
        "verified_count": len(verified),
        "rejected": rejected,
        "rejected_count": len(rejected),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
