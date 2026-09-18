#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise bounded journald retention, rotation, producer redaction, and recovery."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import secrets
import subprocess
import time

CASE_ID = "tc-gos-platform-007"


def run(
    argv: list[str], *, data: bytes | None = None, timeout: int = 60
) -> subprocess.CompletedProcess[bytes]:
    """Run one bounded host or guest command."""
    return subprocess.run(
        argv, input=data, capture_output=True, timeout=timeout, check=False
    )


def write(path: pathlib.Path, value: object) -> None:
    """Write deterministic JSON evidence."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def vm_ids(blob: bytes) -> list[str]:
    """Return stable VM identities from one inventory response."""
    return sorted(str(x.get("id")) for x in json.loads(blob) if isinstance(x, dict))


def main() -> int:
    """Execute the lease-owned journald lifecycle."""
    result = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest.get("values") or {}
    ssh = [str(x) for x in values.get("ssh_argv") or []]
    status = "FAIL"
    summary = "journald lifecycle did not execute"
    started = time.monotonic()
    evidence: dict[str, object] = {
        "candidate_commit": runtime.get("candidate_commit"),
        "guest_image": values.get("image"),
    }
    token = "dstack-secret-" + secrets.token_hex(16)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    marker = secrets.token_hex(8)
    try:
        if not ssh or values.get("destructive_actions_allowed") is not True:
            raise RuntimeError("fixture omitted lease-owned guest SSH")
        store = pathlib.Path(
            str((runtime.get("environment") or {}).get("DSTACK_TEST_IMAGE_STORE", ""))
        )
        metadata = json.loads(
            (store / str(values["image"]) / "metadata.json").read_text()
        )
        if metadata.get("builder") != "mkosi":
            raise RuntimeError("fixture did not boot a mkosi image")
        evidence["mkosi"] = {
            k: metadata.get(k) for k in ("builder", "is_dev", "git_revision")
        }
        script = (
            pathlib.Path(str(runtime["repository"]))
            / "test-suites/shared/automation/journal-lifecycle.sh"
        )
        installed = run(
            [*ssh, "install -m 0755 /dev/stdin /run/dstack-test-journal-case"],
            data=script.read_bytes(),
            timeout=60,
        )
        if installed.returncode:
            raise RuntimeError("guest script installation failed")
        inventory = [str(x) for x in values.get("list_vms_argv") or []]
        before = run(inventory, timeout=30)
        if before.returncode:
            raise RuntimeError("baseline VM inventory query failed")
        completed = run(
            [*ssh, "/run/dstack-test-journal-case", token, token_hash, marker],
            timeout=300,
        )
        log = completed.stdout + completed.stderr
        (artifacts / "journal-lifecycle.log").write_bytes(log)
        if completed.returncode:
            raise RuntimeError(
                f"guest lifecycle rc={completed.returncode}: {log.decode(errors='replace')[-1600:]}"
            )
        rows = [
            line
            for line in completed.stdout.decode().splitlines()
            if line.startswith("{")
        ]
        matrix = json.loads(rows[-1])
        after = run(inventory, timeout=30)
        if after.returncode:
            raise RuntimeError("recovery VM inventory query failed")
        matrix["inventory_stable"] = vm_ids(before.stdout) == vm_ids(after.stdout)
        required = (
            "baseline",
            "rotation",
            "redacted",
            "unprivileged_denied",
            "invalid_closed",
            "outage",
            "recovered",
            "cleanup",
            "inventory_stable",
        )
        if any(matrix.get(k) is not True for k in required):
            raise RuntimeError(f"unexpected journal matrix: {matrix}")
        evidence["matrix"] = matrix
        evidence["sentinel_sha256"] = token_hash
        status = "PASS"
        summary = "Journald policy, bounded rotation, producer-side redaction, unprivileged isolation, invalid input, outage, recovery, cleanup, and adjacent-VM isolation passed."
    except Exception as error:
        summary = f"{type(error).__name__}: {error}"
    finally:
        if ssh:
            evidence["cleanup_returncode"] = run(
                [
                    *ssh,
                    "rm -f /run/systemd/journald.conf.d/99-dstack-test.conf /run/dstack-test-journal-case; systemctl restart systemd-journald.service; rm -rf /run/dstack-test-journal",
                ],
                timeout=60,
            ).returncode
    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    path = artifacts / "journal-lifecycle.json"
    write(path, evidence)
    artifact = {
        "path": "artifacts/journal-lifecycle.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "Journald lifecycle",
        "description": "Redacted mkosi provenance, bounded retention, rotation, producer redaction, isolation, failure, recovery, cleanup, and adjacent-VM evidence.",
    }
    write(artifacts / "manifest.json", {"artifacts": [artifact]})
    write(
        result / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
                for n in range(1, 5)
            ],
            "artifacts": [artifact],
            "evidence": [
                {
                    "path": artifact["path"],
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            ],
            "remarks": "Journald retains producer payloads verbatim; the tested security contract requires producers to emit only a sentinel hash and [REDACTED], never the plaintext token.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
