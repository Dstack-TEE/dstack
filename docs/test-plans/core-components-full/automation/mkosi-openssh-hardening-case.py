#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise OpenSSH hardening inside a lease-owned mkosi guest."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import time

CASE_ID = "tc-gos-yocto-002"


def run(
    argv: list[str], *, data: bytes | None = None, timeout: int = 60
) -> subprocess.CompletedProcess[bytes]:
    """Run one bounded command."""
    return subprocess.run(
        argv, input=data, capture_output=True, timeout=timeout, check=False
    )


def write_json(path: pathlib.Path, value: object) -> None:
    """Write deterministic JSON evidence."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def ssh_with(
    ssh: list[str], options: list[str], command: str, *, user: str | None = None
) -> list[str]:
    """Insert client options before the fixture SSH destination."""
    destination = ssh[-1]
    if user is not None:
        destination = f"{user}@{destination.split('@', 1)[-1]}"
    return [*ssh[:-1], *options, destination, command]


def main() -> int:
    """Run the complete mkosi OpenSSH hardening lifecycle."""
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
    ssh = [str(item) for item in values.get("ssh_argv") or []]
    list_vms = [str(item) for item in values.get("list_vms_argv") or []]
    image = str(values.get("image", ""))
    status = "FAIL"
    summary = "mkosi OpenSSH hardening lifecycle did not execute"
    evidence: dict[str, object] = {
        "candidate_commit": runtime.get("candidate_commit"),
        "guest_image": image,
    }
    started = time.monotonic()
    try:
        if (
            not ssh
            or not list_vms
            or values.get("destructive_actions_allowed") is not True
        ):
            raise RuntimeError("fixture omitted lease-owned SSH or inventory controls")
        store = pathlib.Path(
            str((runtime.get("environment") or {}).get("DSTACK_TEST_IMAGE_STORE", ""))
        )
        metadata = json.loads((store / image / "metadata.json").read_text())
        if metadata.get("backend") != "mkosi" or metadata.get("is_dev") is not True:
            raise RuntimeError("fixture did not boot a mkosi development image")
        evidence["mkosi"] = {
            key: metadata.get(key) for key in ("backend", "is_dev", "git_revision")
        }
        inventory_before = run(list_vms, timeout=30)
        if inventory_before.returncode:
            raise RuntimeError("baseline VM inventory query failed")
        script = (
            pathlib.Path(str(runtime["repository"]))
            / "docs/test-plans/core-components-full/automation/mkosi-openssh-hardening.sh"
        )
        installed = run(
            [*ssh, "install -m 0755 /dev/stdin /run/dstack-test-openssh"],
            data=script.read_bytes(),
            timeout=180,
        )
        if installed.returncode:
            raise RuntimeError(
                f"guest script install failed: {installed.stderr.decode(errors='replace')[-500:]}"
            )
        checked = run([*ssh, "/run/dstack-test-openssh"], timeout=120)
        log = checked.stdout + checked.stderr
        (artifacts / "mkosi-openssh.log").write_bytes(log)
        if checked.returncode:
            raise RuntimeError(
                f"mkosi OpenSSH policy rc={checked.returncode}: {log.decode(errors='replace')[-1600:]}"
            )
        rows = [
            line
            for line in checked.stdout.decode().splitlines()
            if line.startswith("{")
        ]
        matrix = json.loads(rows[-1])

        authorized = run([*ssh, "true"], timeout=30).returncode == 0
        password = run(
            ssh_with(
                ssh,
                [
                    "-o",
                    "PreferredAuthentications=password",
                    "-o",
                    "PubkeyAuthentication=no",
                    "-o",
                    "BatchMode=yes",
                ],
                "true",
            ),
            timeout=30,
        )
        with tempfile.TemporaryDirectory(dir=artifacts) as temporary:
            key = pathlib.Path(temporary) / "unauthorized"
            generated = run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                timeout=30,
            )
            if generated.returncode:
                raise RuntimeError("failed to generate ephemeral unauthorized SSH key")
            unauthorized_options = [
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-i",
                str(key),
            ]
            unauthorized = run(ssh_with(ssh, unauthorized_options, "true"), timeout=30)
            empty_account = run(
                ssh_with(ssh, unauthorized_options, "true", user="nobody"), timeout=30
            )
        restarted = run([*ssh, "systemctl restart sshd.service"], timeout=30)
        recovered = False
        for _ in range(30):
            if run([*ssh, "true"], timeout=10).returncode == 0:
                recovered = True
                break
            time.sleep(1)
        inventory_after = run(list_vms, timeout=30)
        if inventory_after.returncode:
            raise RuntimeError("recovery VM inventory query failed")
        before = json.loads(inventory_before.stdout)
        after = json.loads(inventory_after.stdout)
        before_ids = sorted(
            str(row.get("id")) for row in before if isinstance(row, dict)
        )
        after_ids = sorted(str(row.get("id")) for row in after if isinstance(row, dict))
        matrix.update(
            {
                "authorized_key": authorized,
                "password_rejected": password.returncode != 0,
                "unauthorized_key_rejected": unauthorized.returncode != 0,
                "empty_account_rejected": empty_account.returncode != 0,
                "service_restart_attempted": restarted.returncode in (0, 255),
                "service_recovered": recovered,
                "inventory_stable": before_ids == after_ids,
            }
        )
        evidence["inventory"] = {
            "before_count": len(before_ids),
            "after_count": len(after_ids),
        }
        evidence["matrix"] = matrix
        required = (
            "password_auth_disabled",
            "empty_password_disabled",
            "keyboard_interactive_disabled",
            "public_key_enabled",
            "root_password_disabled",
            "native_config_valid",
            "invalid_config_rejected",
            "concurrent_validation",
            "authorized_key",
            "password_rejected",
            "unauthorized_key_rejected",
            "empty_account_rejected",
            "service_restart_attempted",
            "service_recovered",
            "inventory_stable",
        )
        if any(matrix.get(key) is not True for key in required):
            raise RuntimeError(f"unexpected OpenSSH matrix: {matrix}")
        status = "PASS"
        summary = "OpenSSH image policy, authorized and rejected authentication, invalid-config failure, concurrency, restart recovery, and VM isolation passed inside mkosi."
    except Exception as error:
        summary = f"{type(error).__name__}: {error}"
    finally:
        if ssh:
            evidence["cleanup_returncode"] = run(
                [*ssh, "rm -f /run/dstack-test-openssh"], timeout=30
            ).returncode
    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    write_json(artifacts / "mkosi-openssh.json", evidence)
    artifact = {
        "path": "artifacts/mkosi-openssh.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "mkosi OpenSSH hardening",
        "description": "Guest provenance and redacted native policy, authentication, fault, concurrency, recovery, and isolation evidence.",
    }
    write_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    observed = (
        summary
        if status == "FAIL"
        else "The lease-owned mkosi guest enforced native password and account hardening while retaining only the provisioned key path across restart."
    )
    write_json(
        result / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-{number:02d}",
                    "status": status,
                    "observed": observed,
                }
                for number in range(1, 4)
            ],
            "artifacts": [artifact],
            "remarks": "The mkosi development guest proves OpenSSH image policy and authentication behavior; its lease-installed access path is test tooling and does not claim production SSH exposure.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
