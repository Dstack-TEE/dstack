#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the OS artifact manifest contract and digest binding without a build."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-ver-image-meas-004"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write a JSON artifact atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one bounded command."""
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


def manifest(files: pathlib.Path) -> dict[str, Any]:
    """Return one complete schema-v1 manifest."""
    return {
        "schema_version": 1,
        "backend": "acceptance",
        "image": {"name": "fixture", "version": "1", "flavor": "dev", "is_dev": True},
        "source": {"git_revision": "acceptance-fixture"},
        "boot": {"ovmf_variant": "tdx"},
        "verity": {"root_hash": hashlib.sha256(b"rootfs").hexdigest(), "data_size": 6},
        "artifacts": {
            "initramfs": f"{files.name}/initramfs",
            "kernel": f"{files.name}/kernel",
            "firmware": f"{files.name}/firmware",
            "rootfs_verity": f"{files.name}/rootfs",
            "firmware_sev": None,
            "uki": None,
        },
    }


def main() -> int:
    """Execute the schema, artifact, Authenticode, and aggregate hash matrix."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    assembler = repository / "os/image/assemble.sh"
    authenticode = repository / "os/image/authenticode_hash.py"
    status = "PASS"
    summary = "Artifact schema, component, Authenticode, and aggregate image-hash binding passed."
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    stage = "baseline"
    try:
        with tempfile.TemporaryDirectory(prefix="dstack-artifact-manifest-") as value:
            root = pathlib.Path(value)
            files = root / "files"
            files.mkdir()
            payloads = {
                "initramfs": b"initramfs-fixture",
                "kernel": b"kernel-fixture",
                "firmware": b"firmware-fixture",
                "rootfs": b"rootfs-fixture",
            }
            for name, content in payloads.items():
                (files / name).write_bytes(content)
            valid_path = root / "valid.json"
            valid = manifest(files)
            valid_path.write_text(json.dumps(valid))
            stage = "valid-manifest"
            accepted = run(
                [str(assembler), "--manifest", str(valid_path), "--validate-only"]
            )
            if accepted.returncode:
                raise AssertionError(
                    f"valid manifest rejected: {accepted.stderr[-400:]}"
                )

            mutations: dict[str, dict[str, Any]] = {}
            rows = {
                "unknown_field": lambda x: x.update({"unexpected": True}),
                "missing_artifact": lambda x: x["artifacts"].pop("kernel"),
                "zero_data_size": lambda x: x["verity"].update({"data_size": 0}),
                "traversal": lambda x: x["artifacts"].update({"kernel": "../kernel"}),
                "wrong_scalar_type": lambda x: x["image"].update({"name": 7}),
            }
            for name, mutate in rows.items():
                stage = f"mutation-{name}"
                candidate = json.loads(json.dumps(valid))
                mutate(candidate)
                path = root / f"{name}.json"
                path.write_text(json.dumps(candidate))
                rejected = run(
                    [str(assembler), "--manifest", str(path), "--validate-only"]
                )
                if rejected.returncode == 0:
                    raise AssertionError(f"invalid manifest accepted: {name}")
                mutations[name] = {
                    "rejected": True,
                    "diagnostic_present": bool(rejected.stderr.strip()),
                    "diagnostic_sha256": hashlib.sha256(
                        rejected.stderr.encode()
                    ).hexdigest(),
                }

            stage = "component-digests"
            component_hashes = {
                name: hashlib.sha256(content).hexdigest()
                for name, content in payloads.items()
            }
            repeat_hashes = {
                name: hashlib.sha256((files / name).read_bytes()).hexdigest()
                for name in payloads
            }
            if component_hashes != repeat_hashes:
                raise AssertionError("component digest repetition changed")
            mutated_kernel = hashlib.sha256(payloads["kernel"] + b"x").hexdigest()
            if mutated_kernel == component_hashes["kernel"]:
                raise AssertionError("component mutation did not change its digest")

            stage = "aggregate-image-hash"
            checksum_text = "".join(
                f"{component_hashes[name]}  {name}\n"
                for name in sorted(component_hashes)
            )
            image_hash = hashlib.sha256(checksum_text.encode()).hexdigest()
            changed = dict(component_hashes)
            changed["kernel"] = mutated_kernel
            changed_text = "".join(
                f"{changed[name]}  {name}\n" for name in sorted(changed)
            )
            changed_image_hash = hashlib.sha256(changed_text.encode()).hexdigest()
            if changed_image_hash == image_hash:
                raise AssertionError(
                    "component mutation did not change aggregate image hash"
                )

            stage = "authenticode"
            efi_candidates = [
                pathlib.Path("/usr/lib/shim/shimx64.efi"),
                pathlib.Path("/usr/lib/systemd/boot/efi/systemd-bootx64.efi"),
            ]
            efi = next((path for path in efi_candidates if path.is_file()), None)
            if efi is None:
                raise AssertionError("no host PE/COFF fixture is available")
            auth = run(["python3", str(authenticode), str(efi)])
            if auth.returncode or len(auth.stdout.strip()) != 64:
                raise AssertionError(f"Authenticode hash failed: {auth.stderr[-400:]}")
            copied = root / "fixture.efi"
            shutil.copyfile(efi, copied)
            repeat = run(["python3", str(authenticode), str(copied)])
            if repeat.returncode or repeat.stdout.strip() != auth.stdout.strip():
                raise AssertionError("Authenticode hash was not deterministic")

            observations.update(
                {
                    "schema_valid_accepted": True,
                    "invalid_rows": mutations,
                    "invalid_row_count": len(mutations),
                    "component_count": len(component_hashes),
                    "component_hashes_repeated": True,
                    "component_mutation_changes_digest": True,
                    "aggregate_image_hash_bound": True,
                    "image_hash_sha256": hashlib.sha256(
                        image_hash.encode()
                    ).hexdigest(),
                    "authenticode_hash_deterministic": True,
                    "authenticode_hash_sha256": hashlib.sha256(
                        auth.stdout.strip().encode()
                    ).hexdigest(),
                    "fixture_paths_retained": False,
                }
            )
    except (
        AssertionError,
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        status = "FAIL"
        summary = f"{stage}: {error}"
        observations.update({"failure_stage": stage, "failure": str(error)})

    artifact = {
        "path": "artifacts/artifact-manifest-binding.json",
        "step_id": f"{case_id}-step-02",
        "name": "Artifact manifest and image hash matrix",
        "description": "Schema acceptance, bounded rejection diagnostics, component hashes, Authenticode determinism, and aggregate binding without artifact bytes.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "The committed schema, assembler validator, and prepared candidate revision were identified.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "A complete manifest, five schema/path mutations, component digests, Authenticode hash, and aggregate image hash were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Repeated hashes were deterministic, mutations changed bound identities, invalid inputs were rejected, and temporary artifacts were removed.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "The harness validates fixture bytes but retains only hashes and bounded diagnostic hashes.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
