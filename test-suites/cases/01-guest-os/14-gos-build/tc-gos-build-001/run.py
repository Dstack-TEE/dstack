#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Verify builder provenance and the shipped kernel contract of a candidate image."""

from __future__ import annotations

import bz2
import hashlib
import json
import lzma
import os
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
import time
import zlib
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-build-001"

# Regression pins for post-baseline kernel changes. The candidate fragment and
# parity contract are also checked in full; these stay explicit so a later edit
# of those files cannot silently drop the behaviour the PRs introduced.
REQUIRED_KERNEL_CONFIG = {
    # PR #1182: tc and checkpoint/restore capabilities Incus needs.
    "CONFIG_NET_SCHED": "y",
    "CONFIG_NET_CLS_ACT": "y",
    "CONFIG_NET_SCH_HTB": "y",
    "CONFIG_NET_SCH_INGRESS": "y",
    "CONFIG_NET_CLS_U32": "y",
    "CONFIG_NET_ACT_POLICE": "y",
    "CONFIG_CHECKPOINT_RESTORE": "y",
    "CONFIG_MACVLAN": "y",
    "CONFIG_NETFILTER_XT_MATCH_COMMENT": "m",
    # PR #1192: the SWIOTLB bounce buffer can grow at runtime.
    "CONFIG_SWIOTLB_DYNAMIC": "y",
    # PR #1220: guest halt polling is a loadable module.
    "CONFIG_CPU_IDLE_GOV_HALTPOLL": "y",
    "CONFIG_HALTPOLL_CPUIDLE": "m",
    # Required for this case to read the shipped configuration at all.
    "CONFIG_IKCONFIG": "y",
}
# PR #1160: bare-metal drivers and debug paths unreachable in a CVM.
DISABLED_KERNEL_CONFIG = (
    "CONFIG_TIGON3",
    "CONFIG_E100",
    "CONFIG_E1000",
    "CONFIG_E1000E",
    "CONFIG_SKY2",
    "CONFIG_FORCEDETH",
    "CONFIG_8139TOO",
    "CONFIG_R8169",
    "CONFIG_NET_TULIP",
    "CONFIG_PCCARD",
    "CONFIG_AGP",
    "CONFIG_MACINTOSH_DRIVERS",
    "CONFIG_NVRAM",
    "CONFIG_PROVIDE_OHCI1394_DMA_INIT",
    "CONFIG_EARLY_PRINTK_DBGP",
    "CONFIG_NETCONSOLE",
)


def decompress_stream(payload: bytes) -> bytes:
    """Decompress a kernel payload by its magic, ignoring trailing bytes."""
    if payload[:2] == b"\x1f\x8b":
        return zlib.decompressobj(31).decompress(payload)
    if payload[:6] == b"\xfd7zXZ\x00":
        return lzma.LZMADecompressor(lzma.FORMAT_XZ).decompress(payload)
    if payload[:3] == b"\x5d\x00\x00":
        return lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(payload)
    if payload[:3] == b"BZh":
        return bz2.BZ2Decompressor().decompress(payload)
    tool = {b"\x28\xb5\x2f\xfd": "zstd", b"\x02\x21\x4c\x18": "lz4"}.get(payload[:4])
    if tool and shutil.which(tool):
        process = subprocess.run(
            [tool, "-dc"], input=payload, capture_output=True, timeout=60, check=False
        )
        if process.stdout:
            return process.stdout
    raise RuntimeError(f"unsupported kernel payload compression: {payload[:6].hex()}")


def embedded_kernel_config(bzimage: bytes) -> str:
    """Return the IKCONFIG .config embedded in an x86 bzImage."""
    if bzimage[0x202:0x206] != b"HdrS":
        raise RuntimeError("kernel image has no x86 boot protocol header")
    setup_sects = bzimage[0x1F1] or 4
    protected_mode = (setup_sects + 1) * 512
    offset, length = struct.unpack_from("<II", bzimage, 0x248)
    vmlinux = decompress_stream(
        bzimage[protected_mode + offset : protected_mode + offset + length]
    )
    start = vmlinux.find(b"IKCFG_ST")
    end = vmlinux.find(b"IKCFG_ED", start + 1)
    if start < 0 or end < 0:
        raise RuntimeError("kernel image carries no IKCONFIG block")
    return zlib.decompressobj(31).decompress(vmlinux[start + 8 : end]).decode()


def config_value(config: str, key: str) -> str | None:
    """Return a symbol's value, or None when it is unset or absent."""
    match = re.search(rf"^{re.escape(key)}=(.*)$", config, re.M)
    return match.group(1) if match else None


def run_checker(argv: list[str]) -> dict[str, Any]:
    """Run one candidate checker script and keep a bounded transcript."""
    process = subprocess.run(
        argv, text=True, capture_output=True, timeout=60, check=False
    )
    return {
        "argv": [Path(item).name for item in argv],
        "returncode": process.returncode,
        "stderr_tail": process.stderr[-1500:],
    }


def main() -> int:
    """Validate candidate scripts and artifact metadata without mutating it."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = (manifest.get("values") or {}).get("image_assembly") or {}
    repository = Path(str(runtime["repository"]))
    image_dir = Path(str(values.get("input_dir", "")))
    assemble = repository / "os/image/assemble.sh"
    check_output = repository / "os/mkosi/tests/check-output.sh"
    syntax = subprocess.run(
        ["bash", "-n", str(assemble), str(check_output)],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    metadata_path = image_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected = os.environ.get("DSTACK_TEST_GUEST_IMAGE_BUILDER", "mkosi").strip()
    checker = check_output.read_text(encoding="utf-8")
    provenance_checks = {
        "scripts_parse": syntax.returncode == 0,
        "builder_present": isinstance(metadata.get("builder"), str)
        and bool(metadata["builder"]),
        "builder_matches": metadata.get("builder") == expected,
        "mkosi_checker_requires_builder": '"builder"' in checker,
        "mkosi_checker_matches_builder": 'd["builder"] == "mkosi"' in checker,
    }

    # Step 4: the configuration embedded in the shipped bzImage.
    kernel_path = image_dir / str(metadata.get("kernel") or "bzImage")
    kernel_evidence: dict[str, Any] = {}
    kernel_checks: dict[str, bool] = {}
    try:
        kernel_bytes = kernel_path.read_bytes()
        config = embedded_kernel_config(kernel_bytes)
        kernel_evidence["bzimage_sha256"] = hashlib.sha256(kernel_bytes).hexdigest()
        kernel_evidence["config_sha256"] = hashlib.sha256(config.encode()).hexdigest()
        wrong = {
            key: config_value(config, key)
            for key, want in REQUIRED_KERNEL_CONFIG.items()
            if config_value(config, key) != want
        }
        enabled = {
            key: config_value(config, key)
            for key in DISABLED_KERNEL_CONFIG
            if config_value(config, key) not in (None, "n")
        }
        parity = json.loads(
            (repository / "os/mkosi/parity.json").read_text(encoding="utf-8")
        )
        # Same semantics as os/mkosi/tests/check-parity.py: "=n" is satisfied
        # only by an explicit "is not set" record.
        parity_missing = [
            line
            for line in parity.get("required_kernel_config", [])
            if not re.search(
                "^"
                + re.escape(
                    f"# {line.split('=', 1)[0]} is not set"
                    if line.endswith("=n")
                    else line
                )
                + "$",
                config,
                re.M,
            )
        ]
        kernel_evidence.update(
            {
                "pinned_mismatches": wrong,
                "unexpectedly_enabled": enabled,
                "parity_required_missing": parity_missing,
                "parity_required_count": len(parity.get("required_kernel_config", [])),
            }
        )
        with tempfile.TemporaryDirectory(prefix="tc-gos-build-001-") as scratch:
            config_file = Path(scratch) / "config"
            config_file.write_text(config, encoding="utf-8")
            fragment = run_checker(
                [
                    str(repository / "os/common/scripts/check-kernel-config.sh"),
                    str(config_file),
                    str(repository / "os/mkosi/components/kernel/kernel.config"),
                ]
            )
            lxc = run_checker(
                [
                    str(repository / "os/common/scripts/check-lxc-kernel-config.sh"),
                    str(config_file),
                ]
            )
        kernel_evidence["fragment_checker"] = fragment
        kernel_evidence["lxc_checker"] = lxc
        kernel_checks = {
            "embedded_config_extracted": bool(config),
            "pinned_options_present": not wrong,
            "unreachable_drivers_disabled": not enabled,
            "parity_required_config_present": not parity_missing
            and kernel_evidence["parity_required_count"] > 0,
            "candidate_fragment_satisfied": fragment["returncode"] == 0,
            "lxc_checkconfig_satisfied": lxc["returncode"] == 0,
        }
    except (OSError, RuntimeError, ValueError, zlib.error, lzma.LZMAError) as error:
        kernel_evidence["error"] = f"{type(error).__name__}: {error}"
        kernel_checks = {"embedded_config_extracted": False}

    # Step 5: the recorded command line and the measured bundle boundary.
    cmdline = str(metadata.get("cmdline") or "")
    tokens = cmdline.split()
    parameters = dict(token.split("=", 1) for token in tokens if "=" in token)
    root_hash = parameters.get("dstack.rootfs_hash", "")
    data_size = parameters.get("dstack.rootfs_size", "")
    declared = subprocess.run(
        [
            "bash",
            "-c",
            f". {shlex.quote(str(repository / 'os/image/kernel-cmdline.sh'))} && "
            'dstack_kernel_cmdline "$1" "$2"',
            "kernel-cmdline",
            root_hash or "missing",
            data_size or "missing",
        ],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    checksums = (image_dir / "sha256sum.txt").read_text(encoding="utf-8")
    schema = json.loads(
        (repository / "os/spec/artifact-manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    artifacts_schema = schema.get("properties", {}).get("artifacts", {})
    kernel_devel_schema = artifacts_schema.get("properties", {}).get("kernel_devel", {})
    variants = kernel_devel_schema.get("oneOf", [])
    cmdline_checks = {
        "mmconfig_enabled": "pci=nommconf" not in tokens,
        "early_pci_scan_disabled": "pci=noearly" in tokens,
        "rootfs_parameters_present": bool(root_hash) and bool(data_size),
        "matches_candidate_definition": declared.returncode == 0
        and declared.stdout.strip() == cmdline,
        "kernel_devel_outside_measured_bundle": "kernel-devel" not in checksums
        and not any("kernel-devel" in path.name for path in image_dir.iterdir()),
        "manifest_schema_kernel_devel_optional": "kernel_devel"
        not in artifacts_schema.get("required", [])
        and {"type": "null"} in variants
        and {"$ref": "#/$defs/artifactPath"} in variants,
    }

    groups = {
        "provenance": provenance_checks,
        "kernel_config": kernel_checks,
        "cmdline_and_bundle": cmdline_checks,
    }
    passed = all(all(group.values()) for group in groups.values())
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    evidence_path = artifacts / "builder-provenance.json"
    evidence_path.write_text(
        json.dumps(
            {
                "candidate_commit": runtime.get("candidate_commit"),
                "image": values.get("candidate_image"),
                "builder": metadata.get("builder"),
                "expected_builder": expected,
                "metadata_sha256": hashlib.sha256(
                    metadata_path.read_bytes()
                ).hexdigest(),
                "cmdline": cmdline,
                "kernel": kernel_evidence,
                "checks": groups,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    def step(number: int, checks: dict[str, bool], success: str) -> dict[str, str]:
        failed = sorted(name for name, value in checks.items() if not value)
        return {
            "id": f"{CASE_ID}-step-{number:02d}",
            "status": "PASS" if checks and not failed else "FAIL",
            "observed": success
            if checks and not failed
            else f"Failed checks: {failed}",
        }

    steps = [
        step(
            1,
            {"scripts_parse": provenance_checks["scripts_parse"]},
            "Candidate assembly and mkosi output-check scripts parse.",
        ),
        step(
            2,
            {
                name: provenance_checks[name]
                for name in ("builder_present", "builder_matches")
            },
            f"Candidate image records builder={expected!r}.",
        ),
        step(
            3,
            {
                name: provenance_checks[name]
                for name in (
                    "mkosi_checker_requires_builder",
                    "mkosi_checker_matches_builder",
                )
            },
            "The mkosi output contract requires builder=mkosi.",
        ),
        step(
            4,
            kernel_checks,
            "The shipped bzImage embeds a configuration that satisfies the pinned "
            "Incus, SWIOTLB, halt-polling and driver-removal options, the parity "
            "contract, the candidate fragment and lxc-checkconfig.",
        ),
        step(
            5,
            cmdline_checks,
            "The recorded command line equals the candidate definition with MMCONFIG "
            "enabled, and the kernel development archive stays outside the measured "
            "bundle while the manifest schema keeps it optional.",
        ),
    ]
    status = "PASS" if passed else "FAIL"
    summary = (
        f"Candidate image records builder={expected!r} and ships the declared kernel "
        "configuration and command line."
        if passed
        else "Failed steps: "
        + ", ".join(item["id"] for item in steps if item["status"] != "PASS")
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": steps,
        "evidence": [
            {
                "path": "artifacts/builder-provenance.json",
                "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "The protected image store was read-only; retained evidence contains no credentials.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
