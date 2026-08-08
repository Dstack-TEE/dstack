#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Exercise real WireGuard isolation and the gateway checker startup contract."""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-observabil-003"
UNIT = "dstack-gateway-checker.service"
# The checker's misconfigured exit code is pinned by the unit's
# RestartPreventExitStatus. Read it from the source rather than restating it, so
# this case cannot keep passing against a value the product no longer uses.
EXIT_CONST_RE = re.compile(r"^const EXIT_MISCONFIGURED: i32 = (\d+);$", re.MULTILINE)


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
    """Run the checker startup matrix inside a lease-owned mkosi guest."""
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
    summary = "WireGuard isolation and gateway checker startup contract passed."
    evidence: dict[str, Any] = {}
    try:
        if not ssh or values.get("destructive_actions_allowed") is not True:
            raise RuntimeError("fixture omitted lease-owned guest controls")
        repository = pathlib.Path(str(runtime["repository"]))
        checker_source = repository / "dstack/dstack-util/src/gateway_checker.rs"
        matched = EXIT_CONST_RE.search(checker_source.read_text())
        if not matched:
            raise RuntimeError(f"cannot read EXIT_MISCONFIGURED from {checker_source}")
        misconfigured_exit = matched.group(1)
        script = (
            repository
            / "docs/test-plans/core-components-full/automation/gateway-checker-lifecycle.sh"
        )
        installed = run(
            [*ssh, "install -m 0755 /dev/stdin /run/dstack-test-gateway-lifecycle"],
            data=script.read_bytes(),
        )
        if installed.returncode:
            raise RuntimeError("failed to install the gateway checker lifecycle driver")
        executed = run(
            [*ssh, "/run/dstack-test-gateway-lifecycle", UNIT, misconfigured_exit],
            timeout=240,
        )
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / "gateway-checker-lifecycle.log").write_bytes(
            executed.stdout + executed.stderr
        )
        rows = [
            row
            for row in executed.stdout.decode(errors="replace").splitlines()
            if row.startswith("{")
        ]
        if executed.returncode or not rows:
            tail = (executed.stdout + executed.stderr).decode(errors="replace")[-2000:]
            raise RuntimeError(
                f"gateway checker lifecycle rc={executed.returncode}: {tail}"
            )
        evidence = json.loads(rows[-1])
        evidence["misconfigured_exit_code"] = int(misconfigured_exit)
        required = (
            "real_interface",
            "address_route",
            "dns_observed",
            "no_handshake_observed",
            "disabled_exits_zero",
            "missing_app_id_exit_code",
            "missing_urls_exit_code",
            "unit_restart_on_failure",
            "unit_prevents_restart",
            "unit_runs_subcommand",
            "legacy_script_absent",
            "interface_isolated",
        )
        if evidence.get("checks", 0) < 24 or not all(
            evidence.get(key) is True for key in required
        ):
            raise RuntimeError("gateway checker evidence omitted a required row")
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
            "path": "artifacts/gateway-checker-lifecycle.json",
            "step_id": f"{CASE_ID}-step-01",
            "name": "Gateway checker startup matrix",
            "description": "Boolean and count evidence for isolated interface/configuration, checker exit codes per startup condition, and the shipped unit's restart policy.",
        },
        {
            "path": "artifacts/gateway-checker-lifecycle.log",
            "step_id": f"{CASE_ID}-step-02",
            "name": "Gateway checker native log",
            "description": "Bounded native output with no WireGuard private keys, configuration content, or credentials.",
        },
    ]
    atomic_json(artifacts / "gateway-checker-lifecycle.json", evidence)
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
                    "observed": "The packaged checker exited 0 for an app that never enabled dstack-gateway, and exited with the pinned misconfigured code for a missing gateway app id and for a missing gateway URL."
                    if status == "PASS"
                    else summary,
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "The installed unit was loaded with Restart=on-failure, inhibited restart for exactly the misconfigured exit code, ran the dstack-util subcommand rather than the removed shell script, and the namespace and guest routing were left unchanged."
                    if status == "PASS"
                    else summary,
                },
            ],
            "artifacts": artifact_entries,
            "remarks": "Refresh timing (periodic interval, handshake staleness, retry backoff) is covered by dstack-util's gateway_checker unit tests over a pure decision function; this case covers the process/systemd boundary those tests cannot reach. The misconfigured exit code is read from the product source at run time. Private keys are never persisted as evidence.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
