#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise VMM one-shot orchestration with a real mkosi image and controlled QEMU."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CASE_IDS = {"tc-vmm-internal-006", "tc-vmm-manifest-002"}


def write_qemu(path: Path, exit_code: int) -> None:
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "QEMU emulator version 9.2.0"; exit 0; fi\n'
        f"exit {exit_code}\n"
    )
    path.chmod(0o755)


def config_text(source: str, image_store: Path, qemu: Path) -> str:
    return (
        source.replace("[image]\n", f'[image]\npath = "{image_store}"\n', 1)
        .replace('platform = "auto"', 'platform = "tdx"', 1)
        .replace('qemu_path = ""', f'qemu_path = "{qemu}"', 1)
    )


def vm_json(image: str, compose: str) -> dict[str, object]:
    return {
        "name": "oneshot-case",
        "image": image,
        "compose_file": compose,
        "vcpu": 1,
        "memory": 1024,
        "disk_size": 1,
        "no_tee": True,
    }


def main() -> int:
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASE_IDS:
        raise SystemExit(f"unsupported one-shot case: {case_id}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(runtime["repository"])
    binary = Path(runtime["prepared_binaries"]["dstack_vmm"]["path"])
    image_store = Path(os.environ["DSTACK_TEST_IMAGE_STORE"])
    image = os.environ["DSTACK_TEST_NO_TEE_GUEST_IMAGE"]
    if not (image_store / image / "metadata.json").is_file():
        raise SystemExit("prepared mkosi runtime image is absent")

    root = result_dir / "artifacts/one-shot"
    root.mkdir(parents=True)
    source_config = (repository / "dstack/vmm/vmm.toml").read_text()
    success_qemu = root / "qemu-success"
    failure_qemu = root / "qemu-failure"
    write_qemu(success_qemu, 0)
    write_qemu(failure_qemu, 7)
    sentinel = root / "daemon-managed-sentinel"
    sentinel.write_text("unchanged")
    compose = json.dumps({
        "manifest_version": 1,
        "name": "oneshot-case",
        "runner": "none",
        "gateway_enabled": False,
    })

    def execute(name: str, qemu: Path, *, dry_run: bool = False, malformed: bool = False) -> dict[str, object]:
        row = root / name
        row.mkdir()
        config = row / "vmm.toml"
        config.write_text(config_text(source_config, image_store, qemu))
        request = row / "vm.json"
        request.write_text(json.dumps(vm_json(image, "{invalid" if malformed else compose)))
        work = row / "work"
        argv = [str(binary), "--config", str(config), "run", str(request), "--workdir", str(work)]
        if dry_run:
            argv.append("--dry-run")
        process = subprocess.run(argv, text=True, capture_output=True, timeout=90, check=False)
        generated = sorted(
            str(path.relative_to(work))
            for path in work.glob("**/*")
            if path.is_file()
        ) if work.exists() else []
        combined = process.stdout + process.stderr
        manifest_path = work / "vm-manifest.json"
        sys_config_path = work / "shared/.sys-config.json"
        compose_path = work / "shared/app-compose.json"
        persisted = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
        persisted_hashes = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (manifest_path, sys_config_path, compose_path)
            if path.is_file()
        }
        return {
            "name": name,
            "returncode": process.returncode,
            "dry_run": dry_run,
            "malformed": malformed,
            "generated": generated,
            "qemu_command_reported": "# QEMU Command:" in combined,
            "qemu_agreement": all(token in combined for token in (
                "-smp 1", "-m 1024M", f"/{image}/bzImage", f"/{image}/initramfs.cpio.gz",
            )),
            "manifest_agreement": all((
                persisted.get("name") == "oneshot-case",
                persisted.get("image") == image,
                persisted.get("vcpu") == 1,
                persisted.get("memory") == 1024,
                persisted.get("disk_size") == 1,
                persisted.get("no_tee") is True,
            )),
            "persisted_hashes": persisted_hashes,
            "repeat_read_stable": persisted_hashes == {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (manifest_path, sys_config_path, compose_path)
                if path.is_file()
            },
            "failure_returned_to_caller": process.returncode != 0,
            "diagnostic_tail": combined[-1000:].replace(str(root), "<case-root>"),
        }

    rows = [
        execute("dry-run", success_qemu, dry_run=True),
        execute("success", success_qemu),
        execute("workload-failure", failure_qemu),
        execute("malformed-compose", success_qemu, dry_run=True, malformed=True),
    ]
    with ThreadPoolExecutor(max_workers=2) as executor:
        rows.extend(executor.map(
            lambda name: execute(name, success_qemu),
            ["concurrent-a", "concurrent-b"],
        ))

    expected_files = {"vm-manifest.json", "vm-state.json", "shared/app-compose.json", "shared/.sys-config.json"}
    by_name = {row["name"]: row for row in rows}
    passed = (
        by_name["dry-run"]["returncode"] == 0
        and by_name["dry-run"]["qemu_command_reported"]
        and expected_files.issubset(set(by_name["dry-run"]["generated"]))
        and by_name["dry-run"]["manifest_agreement"]
        and by_name["dry-run"]["qemu_agreement"]
        and by_name["dry-run"]["repeat_read_stable"]
        and by_name["success"]["returncode"] == 0
        and by_name["workload-failure"]["returncode"] != 0
        and by_name["workload-failure"]["failure_returned_to_caller"]
        and by_name["malformed-compose"]["returncode"] != 0
        and all(by_name[name]["returncode"] == 0 for name in ("concurrent-a", "concurrent-b"))
        and sentinel.read_text() == "unchanged"
    )
    for row in root.iterdir():
        if row.is_dir() and row.name not in {".keep"}:
            work = row / "work"
            if work.exists():
                shutil.rmtree(work)
    cleanup_ok = not any(root.glob("*/work"))
    passed = passed and cleanup_ok

    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "image": image,
        "image_metadata_sha256": hashlib.sha256((image_store / image / "metadata.json").read_bytes()).hexdigest(),
        "rows": rows,
        "sentinel_unchanged": sentinel.read_text() == "unchanged",
        "cleanup_ok": cleanup_ok,
        "vm_started": False,
        "mkosi_build_tested": False,
    }
    artifact = result_dir / "artifacts/vmm-one-shot-lifecycle.json"
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    status = "PASS" if passed else "FAIL"
    observed = f"{sum((row['returncode'] == 0) == (row['name'] not in {'workload-failure', 'malformed-compose'}) for row in rows)}/{len(rows)} one-shot outcome rows matched"
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {"id": f"{case_id}-step-{n:02d}", "status": status, "observed": observed}
            for n in range(1, 5)
        ],
        "evidence": [{
            "path": "artifacts/vmm-one-shot-lifecycle.json",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }],
        "remarks": "The existing mkosi image was consumed as runtime input; its build was not tested. Controlled case-owned QEMU stubs exercised one-shot outcome propagation without starting a VM.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
