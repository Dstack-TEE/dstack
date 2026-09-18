#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise KMS atomic-temp crash handling and complete cold-backup recovery."""

from __future__ import annotations

import json
import os
import shutil
import signal
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

CASE_ID = "tc-kms-keys-certs-009"
PRIVATE_NAMES = {"root-ca.key", "root-k256.key", "rpc.key", "tmp-ca.key"}


def call_meta(url: str) -> dict[str, object]:
    """Read public identity metadata without persisting native certificate bodies."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(
        f"{url}/KMS.GetMeta?json",
        data=b"{}",
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, context=ctx, timeout=20) as response:
        return json.loads(response.read())


def public_identity(meta: dict[str, object]) -> dict[str, object]:
    """Return only stable public trust-anchor fields."""
    ca = meta.get("ca_cert")
    k256 = meta.get("k256_pubkey")
    if not isinstance(ca, str) or not ca or not isinstance(k256, str) or not k256:
        raise AssertionError("GetMeta omitted public KMS identity")
    return {"ca_cert": ca, "k256_pubkey": k256}


def stop(pid: int) -> None:
    """Stop one lease-owned KMS process."""
    if not Path(f"/proc/{pid}").exists():
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline and Path(f"/proc/{pid}").exists():
        time.sleep(0.1)
    if Path(f"/proc/{pid}").exists():
        os.kill(pid, signal.SIGKILL)


def start(binary: str, config: str, socket: str, log: Path) -> subprocess.Popen[bytes]:
    """Start a replacement KMS with the same case-owned configuration."""
    output = log.open("ab")
    return subprocess.Popen(
        [binary, "--config", config],
        env={**os.environ, "DSTACK_AGENT_ADDRESS": f"unix:{socket}"},
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def wait_meta(url: str, timeout: float = 30) -> dict[str, object]:
    """Wait for the KMS main listener and return metadata."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return call_meta(url)
        except (OSError, urllib.error.HTTPError, ValueError):
            time.sleep(0.2)
    raise TimeoutError("replacement KMS did not become ready")


def ensure_owner_only(directory: Path) -> None:
    """Require owner-only modes for every private-key backup file."""
    for name in PRIVATE_NAMES:
        path = directory / name
        if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise AssertionError(f"backup private file mode is unsafe: {name}")


def main() -> int:
    """Execute backup, orphan-temp restart, corruption fail-closed, and restore."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    case = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    values = case["values"]
    kms = values["kms"]
    substrate = values["component_substrate"]
    if substrate.get("destructive_actions_allowed") is not True:
        raise RuntimeError("fixture did not authorize lease-scoped destructive actions")
    cert_dir = Path(kms["cert_dir"])
    workspace = Path(substrate["workspace"])
    backup = workspace / "data/cold-backup"
    staging = workspace / "data/restore-staging"
    binary = str(runtime["prepared_binaries"]["dstack_kms"]["path"])
    socket = str(values["kms_guest_simulator"]["services"]["DstackGuest"]["socket"])
    url = str(kms["rpc_prpc_url"])
    replacement: subprocess.Popen[bytes] | None = None
    rows: list[dict[str, object]] = []
    status = "FAIL"
    failure = ""
    try:
        original_identity = public_identity(call_meta(url))
        stop(int(kms["pid"]))
        shutil.copytree(cert_dir, backup, copy_function=shutil.copy2)
        backup.chmod(0o700)
        ensure_owner_only(backup)
        rows.append(
            {
                "name": "cold_backup",
                "status": "PASS",
                "complete_file_count": len(list(backup.iterdir())),
                "private_modes_owner_only": True,
            }
        )

        orphan = cert_dir / "root-ca.private-tmp"
        orphan.write_bytes(b"interrupted partial private material")
        orphan.chmod(0o600)
        replacement = start(
            binary, str(kms["config"]), socket, artifacts / "orphan-temp-restart.log"
        )
        orphan_identity = public_identity(wait_meta(url))
        if orphan_identity != original_identity:
            raise AssertionError("orphan atomic temp changed KMS identity")
        stop(replacement.pid)
        replacement.wait(timeout=5)
        replacement = None
        orphan.unlink(missing_ok=True)
        rows.append(
            {"name": "orphan_atomic_temp", "status": "PASS", "identity_preserved": True}
        )

        root_k256 = cert_dir / "root-k256.key"
        root_k256.write_bytes(b"truncated")
        root_k256.chmod(0o600)
        replacement = start(
            binary, str(kms["config"]), socket, artifacts / "corrupt-key-start.log"
        )
        try:
            exit_code = replacement.wait(timeout=12)
        except subprocess.TimeoutExpired as error:
            raise AssertionError("KMS served with a corrupted root key") from error
        replacement = None
        if exit_code == 0:
            raise AssertionError("KMS accepted a corrupted root key")
        rows.append(
            {"name": "corruption_fail_closed", "status": "PASS", "exit_nonzero": True}
        )

        shutil.copytree(backup, staging, copy_function=shutil.copy2)
        ensure_owner_only(staging)
        for entry in cert_dir.iterdir():
            if entry.is_file():
                entry.unlink()
            elif entry.is_dir():
                shutil.rmtree(entry)
        for entry in staging.iterdir():
            shutil.copy2(entry, cert_dir / entry.name)
        ensure_owner_only(cert_dir)
        replacement = start(
            binary, str(kms["config"]), socket, artifacts / "restored-start.log"
        )
        restored_identity = public_identity(wait_meta(url))
        if restored_identity != original_identity:
            raise AssertionError("restored public trust-anchor identity changed")
        rows.append(
            {"name": "complete_restore", "status": "PASS", "identity_preserved": True}
        )
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        rows.append({"name": "failure", "status": "FAIL", "diagnostic": failure})
    finally:
        if replacement is not None:
            stop(replacement.pid)
            try:
                replacement.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(replacement.pid, signal.SIGKILL)
                replacement.wait(timeout=5)
        # If failure happened after corruption, restore the complete backup before
        # retaining the fixture so interactive debugging starts from valid keys.
        if (
            backup.is_dir()
            and (cert_dir / "root-k256.key").read_bytes() == b"truncated"
        ):
            for entry in backup.iterdir():
                shutil.copy2(entry, cert_dir / entry.name)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(backup, ignore_errors=True)
        (cert_dir / "root-ca.private-tmp").unlink(missing_ok=True)

    evidence_path = artifacts / "kms-crash-backup.json"
    evidence_path.write_text(
        json.dumps({"rows": rows, "private_material_persisted": False}, indent=2) + "\n"
    )
    artifact = {
        "path": "artifacts/kms-crash-backup.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "KMS crash and cold-backup matrix",
        "description": "Sanitized mode, fail-closed, restart, and public-identity recovery observations.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = (
        "4/4 KMS crash and cold-backup groups passed" if status == "PASS" else failure
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 4)
        ],
        "artifacts": [artifact],
        "remarks": "The backup remained in the lease-owned workspace, private contents were never recorded, and all copies were deleted.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
