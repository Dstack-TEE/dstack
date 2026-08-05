#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise real WireGuard isolation and accelerated checker recovery policy."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-observabil-003"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def run(
    argv: list[str], *, data: bytes | None = None, timeout: int = 180
) -> subprocess.CompletedProcess[bytes]:
    """Run one bounded command."""
    return subprocess.run(
        argv, input=data, capture_output=True, timeout=timeout, check=False
    )


def main() -> int:
    """Run the checker recovery matrix inside a lease-owned mkosi guest."""
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest.get("values") or {}
    ssh = [str(value) for value in values.get("ssh_argv") or []]
    status = "PASS"
    summary = "WireGuard configuration and checker recovery lifecycle passed."
    evidence: dict[str, Any] = {}
    try:
        if not ssh or values.get("destructive_actions_allowed") is not True:
            raise RuntimeError("fixture omitted lease-owned guest controls")
        repository = pathlib.Path(str(runtime["repository"]))
        checker = repository / "os/common/rootfs/wg-checker.sh"
        script = (
            repository
            / "docs/test-plans/core-components-full/automation/wireguard-checker-lifecycle.sh"
        )
        installed = run(
            [*ssh, "install -m 0755 /dev/stdin /run/dstack-test-wireguard-lifecycle"],
            data=script.read_bytes(),
        )
        installed_checker = run(
            [*ssh, "install -m 0755 /dev/stdin /run/dstack-test-wg-checker.sh"],
            data=checker.read_bytes(),
        )
        if installed.returncode or installed_checker.returncode:
            raise RuntimeError(
                "failed to install WireGuard lifecycle or candidate checker"
            )
        expected_sha = hashlib.sha256(checker.read_bytes()).hexdigest()
        executed = run(
            [
                *ssh,
                "/run/dstack-test-wireguard-lifecycle",
                expected_sha,
                "/run/dstack-test-wg-checker.sh",
            ],
            timeout=240,
        )
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / "wireguard-checker-lifecycle.log").write_bytes(
            executed.stdout + executed.stderr
        )
        rows = [
            row
            for row in executed.stdout.decode(errors="replace").splitlines()
            if row.startswith("{")
        ]
        if executed.returncode or not rows:
            tail = (executed.stdout + executed.stderr).decode(errors="replace")[-2000:]
            raise RuntimeError(f"WireGuard lifecycle rc={executed.returncode}: {tail}")
        evidence = json.loads(rows[-1])
        required = (
            "real_interface",
            "address_route",
            "dns_observed",
            "no_handshake_observed",
            "periodic_refresh",
            "no_handshake_force",
            "stale_handshake_force",
            "fresh_handshake_not_forced",
            "steady_no_handshake_force",
            "steady_force_rate_limited",
            "refresh_failure_observed",
            "refresh_recovery",
            "missing_wg_noop",
            "missing_config_noop",
            "interface_isolated",
        )
        if evidence.get("checks", 0) < 24 or not all(
            evidence.get(key) is True for key in required
        ):
            raise RuntimeError("WireGuard evidence omitted a required row")
    except (
        KeyError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        status = "FAIL"
        summary = f"{type(error).__name__}: {error}"
    artifact_entries = [
        {
            "path": "artifacts/wireguard-checker-lifecycle.json",
            "step_id": f"{CASE_ID}-step-01",
            "name": "WireGuard checker matrix",
            "description": "Boolean and count evidence for isolated interface/configuration, handshake timing, refresh faults, recovery, and no-op boundaries.",
        },
        {
            "path": "artifacts/wireguard-checker-lifecycle.log",
            "step_id": f"{CASE_ID}-step-02",
            "name": "WireGuard checker native log",
            "description": "Bounded native output with no WireGuard private keys, configuration content, or credentials.",
        },
    ]
    atomic_json(artifacts / "wireguard-checker-lifecycle.json", evidence)
    atomic_json(artifacts / "manifest.json", {"artifacts": artifact_entries})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": status,
                    "observed": "A real WireGuard interface, address, peer, route, DNS view, and zero-handshake baseline were isolated in a network namespace."
                    if status == "PASS"
                    else summary,
                },
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "The packaged checker performed periodic and forced refresh for no/stale handshakes, avoided forcing a fresh handshake, reached a forced refresh for a never-handshaken peer under a uniform 10s clock, rate limited forced refresh while the gateway stayed unreachable, and exposed an injected failure."
                    if status == "PASS"
                    else summary,
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "Recovery succeeded; absent wg/config were no-ops; the namespace, trigger config, keys, and logs were cleaned without altering guest routing."
                    if status == "PASS"
                    else summary,
                },
            ],
            "artifacts": artifact_entries,
            "remarks": "Time and refresh outcomes are accelerated through PATH-injected case-owned commands while the exact current-HEAD checker script overlaid into the mkosi guest and a real WireGuard kernel interface are exercised. Private keys are never persisted as evidence.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
