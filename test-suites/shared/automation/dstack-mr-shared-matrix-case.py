#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the shared dstack-mr CLI, configuration, artifact, and cmdline matrix."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import tempfile
from typing import Any

CASE_IDS = {"tc-ver-tools-001", "tc-ver-tools-002"}
IMAGE_HASH = "14ad42d0270b444eaeb53918a5a94d9b17eec7a817cd336173b17c5327541c67"
MATRIX_VERSION = 5


def machine_args(
    cpu: str = "2",
    memory: str = "2G",
    qemu: str = "9.2.1",
    hotplug_off: bool = True,
) -> list[str]:
    """Spell out a measured VM shape, including every RTMR[0] input the
    `measure` CLI defaults.

    `--hotplug-off` reaches the ACPI tables, and its CLI default follows the
    VMM default (true since PR #1405, false before). Every row passes it
    explicitly so the matrix measures the same machine on either CLI.
    """
    return [
        "--cpu",
        cpu,
        "--memory",
        memory,
        "--qemu-version",
        qemu,
        "--hotplug-off",
        "true" if hotplug_off else "false",
    ]


BASE_ARGS = machine_args()
REGISTERS = ("mrtd", "rtmr0", "rtmr1", "rtmr2")
# OVMF's QemuKernelLoaderFsDxe appends this to the image-provided command line
# before measuring it into RTMR[2] (PR #1199 made it a named constant).
OVMF_INITRD_CMDLINE_SUFFIX = " initrd=initrd"
# The four fixed RTMR[1] events that follow the kernel Authenticode digest.
RTMR1_TRAILING_EVENTS = (
    b"Calling EFI Application from Boot Option",
    b"\x00\x00\x00\x00",
    b"Exit Boot Services Invocation",
    b"Exit Boot Services Returned with Success",
)
# The TDX measurement document version that carries the command line string
# instead of its digest (PR #1199).
TDX_MEASUREMENT_DOCUMENT_VERSION = 4
# Boot-protocol `write` fields filled in the way QEMU's x86 loader fills them
# for -kernel: (offset, bytes). An image whose metadata declares
# `kernel_header_normalized` must measure identically once they are cleared
# again (PR #1189).
QEMU_LOADER_HEADER_WRITES = (
    (0x210, bytes([0xB0])),
    (0x218, (0x7FC00000).to_bytes(4, "little")),
    (0x21C, (0x0062A954).to_bytes(4, "little")),
    (0x224, (0xFE00).to_bytes(2, "little")),
    (0x228, (0x20000).to_bytes(4, "little")),
)
LOADFLAGS_OFFSET = 0x211
LOADED_HIGH = 0x01
CAN_USE_HEAP = 0x80
# Every boot-protocol `write` field, which is what an image built while dstack
# normalized the header ships zeroed: (offset, size).
NORMALIZED_ZERO_FIELDS = (
    (0x210, 1),
    (0x218, 4),
    (0x21C, 4),
    (0x224, 2),
    (0x226, 1),
    (0x227, 1),
    (0x228, 4),
    (0x23C, 4),
    (0x240, 8),
    (0x250, 8),
)
# The canonical boot-loader layout dstack's OVMF writes on every QEMU version,
# and dstack-mr predicts: QEMU's values for a guest with 2 GiB or more of RAM
# below 4G. See os/image/README.md and
# 0007-OvmfPkg-QemuKernelLoaderFsDxe-normalize-setup-header.patch.
CANONICAL_REAL_ADDR_HIGH = 0x10000
CANONICAL_CMDLINE_ADDR_HIGH = 0x20000
CANONICAL_REAL_ADDR_LOW = 0x90000
CANONICAL_CMDLINE_ADDR_LOW = 0x9A000
CANONICAL_SETUP_HEAP_GAP = 0x200
CANONICAL_LOW_MEMORY_SPLIT = 0x80000000
CANONICAL_ACPI_DATA_SIZE = 0x28000
CANONICAL_INITRD_ADDR_MAX_DEFAULT = 0x37FFFFFF
CANONICAL_INITRD_ALIGNMENT = 0x1000
# XLF_CAN_BE_LOADED_ABOVE_4G raises QEMU's initrd ceiling. Bit 6 is
# XLF_5LEVEL_ENABLED and must not be read as it (PR #1229).
XLF_CAN_BE_LOADED_ABOVE_4G = 0x02
XLF_5LEVEL_ENABLED = 0x40
XLF_OFFSET = 0x236
NORMALIZED_INDEPENDENCE_ROWS = tuple(
    (memory, qemu)
    for memory in ("1G", "2G", "3G", "8G")
    for qemu in ("8.2.2", "9.2.1", "10.2.1")
)
# Native golden vectors that pin the measured byte layout. A change to any of
# them silently invalidates every deployed os_image_hash. The bound vectors
# pin how host-supplied firmware, kernel, and measurement-document bytes are
# rejected before they reach a measurement.
NATIVE_TESTS = (
    (
        "dstack-mr",
        (
            "kernel::tests::the_normalized_flag_selects_which_kernel_bytes_are_measured",
            "kernel::tests::only_the_patched_digest_moves_with_guest_memory",
            "kernel::tests::tdx_kernel_patch_uses_precomputed_digest_at_2g_and_high_memory",
            "kernel::tests::only_xlf_bit_1_raises_the_initrd_ceiling",
            "kernel::tests::a_malformed_pe_header_is_rejected_instead_of_panicking",
            "tdx::tests::measured_kernel_cmdline_appends_the_ovmf_suffix",
            "tdx::tests::rtmr2_command_line_event_digest_is_stable",
            "tdx::tests::rtmr2_replay_is_stable",
            "tdx::tests::tdx_measurement_document_cbor_is_stable",
            "tdx::tests::read_varuint_rejects_values_larger_than_u64",
            "tdx::tests::measure_td_hob_from_witness_data_rejects_more_ranges_than_a_firmware_has_sections",
            "tdx::tests::measure_td_hob_from_witness_data_rejects_ranges_whose_addresses_wrap",
            "tdvf::tests::parse_rejects_a_zero_length_guid_table_entry",
            "tdvf::tests::parse_reports_a_table_without_the_metadata_entry",
            "tdvf::tests::parse_rejects_more_sections_than_the_blob_holds",
            "tdvf::tests::parse_rejects_a_section_whose_data_runs_past_the_blob",
            "tdvf::tests::parse_rejects_a_section_larger_than_any_real_firmware_measures",
            "tdvf::tests::parse_rejects_a_section_whose_guest_address_wraps",
        ),
    ),
    (
        "dstack-types",
        (
            "image_info_tests::metadata_declares_whether_the_kernel_header_is_normalized",
            "tdx_measurement_cbor_tests::the_kernel_header_flag_round_trips",
            "tdx_measurement_cbor_tests::a_pre_normalization_document_does_not_drift",
            "tdx_measurement_cbor_tests::unknown_versions_are_rejected",
            "tdx_measurement_cbor_tests::an_oversized_command_line_is_rejected_by_name",
            "cbor_canonicalization_tests::cbor_decoders_reject_trailing_bytes",
            "cbor_canonicalization_tests::the_aws_measurement_document_names_and_checks_its_version",
            "mr_config::tests::a_document_without_a_version_is_not_a_v3_document",
        ),
    ),
)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def prepared_binary(runtime: dict[str, Any], name: str) -> pathlib.Path:
    """Resolve one prepared binary from the runtime manifest."""
    item = runtime["prepared_binaries"][name]
    return pathlib.Path(item.get("resolved_path") or item["path"])


def copy_fixture(source: pathlib.Path, destination: pathlib.Path) -> None:
    """Create an isolated copy, using reflinks when the filesystem supports them."""
    destination.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["cp", "--archive", "--reflink=auto", f"{source}/.", str(destination)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def sha384(data: bytes) -> bytes:
    """Return a raw SHA-384 digest."""
    return hashlib.sha384(data).digest()


def replay(events: list[bytes]) -> str:
    """Replay an RTMR event digest sequence from the all-zero register."""
    register = bytes(48)
    for event in events:
        register = sha384(register + event)
    return register.hex()


def authenticode_sha384(data: bytes) -> bytes:
    """Independently compute the PE/COFF Authenticode SHA-384 of a kernel.

    Follows the Authenticode layout (checksum and certificate directory
    excluded, sections in file order, trailing data minus the certificate
    table) plus the zero padding to an 8-byte boundary that OVMF's measurement
    applies. It deliberately shares no code with dstack-mr.
    """
    (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise AssertionError("kernel is not a PE/COFF image")
    coff = pe_offset + 4
    (sections,) = struct.unpack_from("<H", data, coff + 2)
    (optional_size,) = struct.unpack_from("<H", data, coff + 16)
    optional = coff + 20
    (magic,) = struct.unpack_from("<H", data, optional)
    checksum = optional + 64
    certificate_directory = optional + (112 if magic == 0x20B else 96) + 4 * 8
    (headers_size,) = struct.unpack_from("<I", data, optional + 60)
    digest = hashlib.sha384()
    digest.update(data[:checksum])
    digest.update(data[checksum + 4 : certificate_directory])
    digest.update(data[certificate_directory + 8 : headers_size])
    hashed = headers_size
    raw_sections = []
    for index in range(sections):
        entry = optional + optional_size + 40 * index
        size, pointer = struct.unpack_from("<II", data, entry + 16)
        if size:
            raw_sections.append((pointer, size))
    for pointer, size in sorted(raw_sections):
        digest.update(data[pointer : pointer + size])
        hashed += size
    table, table_size = struct.unpack_from("<II", data, certificate_directory)
    if table and table_size and len(data) - hashed > table_size:
        digest.update(data[hashed : len(data) - table_size])
    if len(data) % 8:
        digest.update(bytes(8 - len(data) % 8))
    return digest.digest()


def zeroed_setup_header(kernel: bytes) -> bytes:
    """Return the kernel with every boot-loader-written field zeroed.

    What an image built while dstack normalized the header ships, reproduced
    here because the build-side normalizer no longer exists: OVMF writes the
    canonical layout instead (see `canonical_setup_header`).
    """
    out = bytearray(kernel)
    for offset, size in NORMALIZED_ZERO_FIELDS:
        out[offset : offset + size] = bytes(size)
    out[LOADFLAGS_OFFSET] &= ~CAN_USE_HEAP & 0xFF
    return bytes(out)


def setup_header_is_zeroed(kernel: bytes) -> bool:
    """Whether every boot-loader-written field is already zero."""
    return kernel == zeroed_setup_header(kernel)


def canonical_setup_header(kernel: bytes, initrd_size: int) -> bytes:
    """Return the kernel in the canonical boot-loader layout.

    An independent implementation of what dstack's OVMF writes before the
    kernel blob is measured, and therefore of what `dstack-mr` must predict
    for an image that does not declare `kernel_header_normalized`.
    """
    out = bytearray(kernel)
    protocol = int.from_bytes(out[0x206:0x208], "little")
    if protocol < 0x0202:
        raise AssertionError(f"boot protocol {protocol:#06x} predates the layout")
    if out[LOADFLAGS_OFFSET] & LOADED_HIGH:
        real_addr = CANONICAL_REAL_ADDR_HIGH
        cmdline_addr = CANONICAL_CMDLINE_ADDR_HIGH
    else:
        real_addr = CANONICAL_REAL_ADDR_LOW
        cmdline_addr = CANONICAL_CMDLINE_ADDR_LOW
    out[0x210] = 0xB0
    out[LOADFLAGS_OFFSET] |= CAN_USE_HEAP
    heap_end = cmdline_addr - real_addr - CANONICAL_SETUP_HEAP_GAP
    out[0x224:0x228] = heap_end.to_bytes(4, "little")
    out[0x228:0x22C] = cmdline_addr.to_bytes(4, "little")
    if initrd_size:
        if protocol >= 0x020C:
            xlf = int.from_bytes(out[XLF_OFFSET : XLF_OFFSET + 2], "little")
            initrd_max = (
                0xFFFFFFFF
                if xlf & XLF_CAN_BE_LOADED_ABOVE_4G
                else CANONICAL_INITRD_ADDR_MAX_DEFAULT
            )
        elif protocol >= 0x0203:
            declared = int.from_bytes(out[0x22C:0x230], "little")
            initrd_max = declared or CANONICAL_INITRD_ADDR_MAX_DEFAULT
        else:
            initrd_max = CANONICAL_INITRD_ADDR_MAX_DEFAULT
        available = CANONICAL_LOW_MEMORY_SPLIT - CANONICAL_ACPI_DATA_SIZE
        if initrd_max >= available:
            initrd_max = available - 1
        if initrd_size >= initrd_max:
            raise AssertionError("initrd does not fit below the canonical ceiling")
        initrd_addr = (initrd_max - initrd_size) & ~(CANONICAL_INITRD_ALIGNMENT - 1)
        out[0x218:0x21C] = initrd_addr.to_bytes(4, "little")
        out[0x21C:0x220] = initrd_size.to_bytes(4, "little")
    return bytes(out)


def rtmr1_from_kernel_digest(kernel_digest: bytes) -> str:
    """Replay RTMR[1] from the kernel Authenticode digest OVMF measures."""
    return replay([kernel_digest, *(sha384(event) for event in RTMR1_TRAILING_EVENTS)])


def measured_cmdline_event(cmdline: str) -> bytes:
    """Return the RTMR[2] command-line event: UTF-16LE with a trailing NUL."""
    return sha384(cmdline.encode("utf-16-le") + b"\x00\x00")


def rtmr2_oracle(base_cmdline: str, initrd_digest: bytes, suffix: str) -> str:
    """Replay RTMR[2] from a base command line, a suffix, and the initrd digest."""
    return replay([measured_cmdline_event(base_cmdline + suffix), initrd_digest])


def run_tool(
    command: list[str], workspace: pathlib.Path, name: str, timeout: int = 120
) -> subprocess.CompletedProcess[bytes]:
    """Run a helper tool and retain its bounded output for debugging."""
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    (workspace / f"{name}.stdout").write_bytes(completed.stdout[-65536:])
    (workspace / f"{name}.stderr").write_bytes(completed.stderr[-65536:])
    return completed


def set_metadata(directory: pathlib.Path, **fields: Any) -> dict[str, Any]:
    """Rewrite selected metadata.json fields in an isolated image copy."""
    value = json.loads((directory / "metadata.json").read_text())
    value.update(fields)
    atomic_json(directory / "metadata.json", value)
    return value


def changed_registers(baseline: dict[str, str], output: dict[str, str]) -> list[str]:
    """Return the ordered register names changed from baseline."""
    return [name for name in REGISTERS if output[name] != baseline[name]]


def run_cli(
    binary: pathlib.Path,
    metadata: pathlib.Path,
    args: list[str],
    workspace: pathlib.Path,
    name: str,
) -> tuple[dict[str, Any], dict[str, str] | None, str]:
    """Run one CLI row and retain bounded command output for debugging."""
    completed = subprocess.run(
        [str(binary), "measure", str(metadata), *args, "--json"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    (workspace / f"{name}.stdout").write_text(completed.stdout)
    (workspace / f"{name}.stderr").write_text(completed.stderr)
    output = None
    if completed.returncode == 0:
        output = json.loads(completed.stdout)
    row = {
        "name": name,
        "returncode": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
    }
    return row, output, completed.stderr


def run_diagnose(
    binary: pathlib.Path,
    image: pathlib.Path,
    vm_config: dict[str, Any],
    workspace: pathlib.Path,
    name: str,
) -> tuple[dict[str, Any], dict[str, str] | None, str]:
    """Run one `diagnose` row from a VmConfig and keep only its registers."""
    config = workspace / f"{name}.vm-config.json"
    config.write_text(json.dumps(vm_config))
    completed = subprocess.run(
        [
            str(binary),
            "diagnose",
            "--vm-config",
            str(config),
            "--image-dir",
            str(image),
            "--json",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    (workspace / f"{name}.stdout").write_text(completed.stdout)
    (workspace / f"{name}.stderr").write_text(completed.stderr)
    output = None
    if completed.returncode == 0:
        document = json.loads(completed.stdout)
        output = {register: document[register] for register in REGISTERS}
    row = {
        "name": name,
        "returncode": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
    }
    return row, output, completed.stderr


def require_success(
    row: dict[str, Any],
    output: dict[str, str] | None,
    expected_changed: list[str] | None,
) -> dict[str, str]:
    """Require a valid four-register output and optionally an exact change set."""
    if row["returncode"] != 0 or output is None:
        raise AssertionError(f"{row['name']} unexpectedly failed")
    if set(output) != set(REGISTERS) or any(
        len(output[name]) != 96 for name in REGISTERS
    ):
        raise AssertionError(f"{row['name']} returned an invalid measurement schema")
    if expected_changed is not None:
        observed = row.get("changed_registers", [])
        if observed != expected_changed:
            raise AssertionError(
                f"{row['name']} changed {observed}, expected {expected_changed}"
            )
    row["passed"] = True
    return output


def require_rejection(row: dict[str, Any], diagnostic: str, fragment: str) -> None:
    """Require a bounded fail-closed diagnostic."""
    if row["returncode"] == 0 or fragment.lower() not in diagnostic.lower():
        raise AssertionError(f"{row['name']} did not reject with {fragment!r}")
    row["expected_rejection"] = True
    row["passed"] = True


def mutate_last_byte(path: pathlib.Path) -> None:
    """Flip one byte without changing artifact length."""
    with path.open("r+b") as stream:
        stream.seek(-1, os.SEEK_END)
        value = stream.read(1)
        stream.seek(-1, os.SEEK_END)
        stream.write(bytes([value[0] ^ 1]))


def execute_matrix(
    binary: pathlib.Path,
    image_binary: pathlib.Path,
    repository: pathlib.Path,
    cargo_target: str,
    fixture: pathlib.Path,
    workspace: pathlib.Path,
) -> dict[str, Any]:
    """Execute the complete shared matrix once."""
    rows: list[dict[str, Any]] = []

    def accepted(
        name: str, metadata: pathlib.Path, args: list[str], expected: list[str] | None
    ):
        row, output, _ = run_cli(binary, metadata, args, workspace, name)
        if baseline:
            row["changed_registers"] = changed_registers(baseline, output or baseline)
        result = require_success(row, output, expected)
        rows.append(row)
        return result

    def rejected(name: str, metadata: pathlib.Path, args: list[str], fragment: str):
        row, _, diagnostic = run_cli(binary, metadata, args, workspace, name)
        require_rejection(row, diagnostic, fragment)
        rows.append(row)

    row, baseline_output, _ = run_cli(
        binary, fixture / "metadata.json", [*BASE_ARGS], workspace, "baseline"
    )
    baseline: dict[str, str] = {}
    baseline = require_success(row, baseline_output, None)
    row["changed_registers"] = []
    rows.append(row)

    repeated = accepted(
        "deterministic-repeat", fixture / "metadata.json", [*BASE_ARGS], []
    )
    if repeated != baseline:
        raise AssertionError("deterministic repeat changed output")
    rejected(
        "removed-dstack-os-version-flag",
        fixture / "metadata.json",
        [*BASE_ARGS, "--dstack-os-version", "0.5.4.1"],
        "unexpected argument",
    )
    accepted(
        "cpu-count",
        fixture / "metadata.json",
        machine_args(cpu="4"),
        ["rtmr0"],
    )
    high_memory = accepted(
        "memory-size",
        fixture / "metadata.json",
        machine_args(memory="4G"),
        ["rtmr0"],
    )
    # A pre-normalization image keeps modelling QEMU's setup-header rewrite, so
    # its kernel digest still moves with guest RAM below the 2 GiB placement.
    low_memory = accepted(
        "legacy-kernel-digest-low-memory",
        fixture / "metadata.json",
        machine_args(memory="1G"),
        ["rtmr0", "rtmr1"],
    )
    accepted(
        "qemu-8-compatibility",
        fixture / "metadata.json",
        machine_args(qemu="8.2.2"),
        ["mrtd", "rtmr0"],
    )
    accepted(
        "qemu-10-compatibility",
        fixture / "metadata.json",
        machine_args(qemu="10.0.0"),
        ["rtmr0"],
    )
    accepted(
        "advanced-machine-fields",
        fixture / "metadata.json",
        [
            *machine_args(hotplug_off=False),
            "--two-pass-add-pages",
            "true",
            "--pic",
            "true",
            "--smm",
            "true",
            "--pci-hole64-size",
            "0x100000000",
            "--num-nics",
            "3",
            "--num-verity-volumes",
            "2",
            "--root-verity",
            "false",
        ],
        None,
    )
    # `diagnose` rebuilds the machine from a VmConfig the way the verifier does,
    # so it must honour every measured field `measure` does (PR #1367).
    diagnose_shape = {
        "cpu_count": 2,
        "memory_size": 2 << 30,
        "qemu_version": "9.2.1",
        "num_nics": 3,
        "num_verity_volumes": 2,
        "hotplug_off": True,
    }
    measured_shape = accepted(
        "diagnose-shape-measure",
        fixture / "metadata.json",
        [*BASE_ARGS, "--num-nics", "3", "--num-verity-volumes", "2"],
        ["rtmr0"],
    )
    row, diagnosed, _ = run_diagnose(
        binary, fixture, diagnose_shape, workspace, "diagnose-matches-measure"
    )
    require_success(row, diagnosed, None)
    if diagnosed != measured_shape:
        raise AssertionError(
            "diagnose predicted other registers than measure for the same VM shape"
        )
    rows.append(row)
    row, _, diagnostic = run_diagnose(
        binary,
        fixture,
        {**diagnose_shape, "swtpm": True},
        workspace,
        "diagnose-swtpm-unsupported",
    )
    require_rejection(row, diagnostic, "swtpm measurement is not supported")
    rows.append(row)
    gpu_topology = [
        "--num-gpus",
        "1",
        "--num-nvswitches",
        "1",
        "--pci-hole64-size",
        "16T",
    ]
    # Root-port hotplug AML is not modeled, so GPU passthrough is measured only
    # with PCI hotplug off (PR #1387).
    rejected(
        "gpu-topology-requires-hotplug-off",
        fixture / "metadata.json",
        [*machine_args(hotplug_off=False), *gpu_topology],
        "set hotplug_off for GPU passthrough",
    )
    accepted(
        "gpu-topology-functional",
        fixture / "metadata.json",
        [*machine_args(hotplug_off=True), *gpu_topology],
        ["rtmr0"],
    )
    accepted(
        "hugepage-numa-topology",
        fixture / "metadata.json",
        [*BASE_ARGS, "--hugepages"],
        ["rtmr0"],
    )
    rejected(
        "swtpm-unsupported",
        fixture / "metadata.json",
        [*BASE_ARGS, "--swtpm"],
        "swtpm measurement is not supported",
    )
    rejected(
        "unsupported-qemu-version",
        fixture / "metadata.json",
        machine_args(qemu="7.2.0"),
        "Unsupported QEMU version",
    )

    invalid_version = workspace / "invalid-version"
    copy_fixture(fixture, invalid_version)
    metadata_value = json.loads((invalid_version / "metadata.json").read_text())
    metadata_value["version"] = "0.5.10.1.2"
    atomic_json(invalid_version / "metadata.json", metadata_value)
    accepted(
        "ignored-legacy-image-version",
        invalid_version / "metadata.json",
        [*BASE_ARGS],
        [],
    )

    for name, filename, expected in (
        ("firmware-mutation", "ovmf.fd", ["mrtd"]),
        ("kernel-mutation", "bzImage", ["rtmr1"]),
        ("initrd-mutation", "initramfs.cpio.gz", ["rtmr2"]),
    ):
        directory = workspace / name
        copy_fixture(fixture, directory)
        mutate_last_byte(directory / filename)
        accepted(name, directory / "metadata.json", [*BASE_ARGS], expected)

    cmdline = workspace / "cmdline-mutation"
    copy_fixture(fixture, cmdline)
    metadata_value = json.loads((cmdline / "metadata.json").read_text())
    metadata_value["cmdline"] += " matrix.boundary=1"
    atomic_json(cmdline / "metadata.json", metadata_value)
    mutated_cmdline = accepted(
        "cmdline-mutation", cmdline / "metadata.json", [*BASE_ARGS], ["rtmr2"]
    )

    fixture_metadata = json.loads((fixture / "metadata.json").read_text())
    initrd_digest = sha384((fixture / fixture_metadata["initrd"]).read_bytes())
    for name, cmdline_value, observed in (
        ("rtmr2-cmdline-suffix-oracle", fixture_metadata["cmdline"], baseline),
        (
            "rtmr2-cmdline-suffix-oracle-mutated",
            metadata_value["cmdline"],
            mutated_cmdline,
        ),
    ):
        composed = rtmr2_oracle(
            cmdline_value, initrd_digest, OVMF_INITRD_CMDLINE_SUFFIX
        )
        bare = rtmr2_oracle(cmdline_value, initrd_digest, "")
        doubled = rtmr2_oracle(
            cmdline_value, initrd_digest, OVMF_INITRD_CMDLINE_SUFFIX * 2
        )
        if observed["rtmr2"] != composed:
            raise AssertionError(
                f"{name}: RTMR2 is not the image cmdline plus {OVMF_INITRD_CMDLINE_SUFFIX!r}"
            )
        if observed["rtmr2"] in (bare, doubled):
            raise AssertionError(f"{name}: RTMR2 matched a mis-composed command line")
        rows.append(
            {
                "name": name,
                "composition": "metadata.cmdline + ' initrd=initrd', UTF-16LE, NUL",
                "bare_cmdline_rejected": True,
                "doubled_suffix_rejected": True,
                "passed": True,
            }
        )

    rows.extend(
        normalization_rows(
            binary,
            image_binary,
            fixture,
            workspace,
            baseline,
            high_memory,
            low_memory,
            initrd_digest,
        )
    )
    rows.extend(native_rows(repository, cargo_target, workspace))

    for name, filename, fragment in (
        ("missing-firmware", "ovmf.fd", "No such file"),
        ("missing-kernel", "bzImage", "No such file"),
        ("missing-initrd", "initramfs.cpio.gz", "No such file"),
    ):
        directory = workspace / name
        copy_fixture(fixture, directory)
        (directory / filename).unlink()
        rejected(name, directory / "metadata.json", [*BASE_ARGS], fragment)

    malformed = workspace / "malformed-metadata"
    malformed.mkdir()
    (malformed / "metadata.json").write_text("{")
    rejected(
        "malformed-metadata",
        malformed / "metadata.json",
        [*BASE_ARGS],
        "parse image metadata",
    )
    recovered = accepted(
        "recovery-after-failures", fixture / "metadata.json", [*BASE_ARGS], []
    )
    if recovered != baseline:
        raise AssertionError("recovery output changed from baseline")

    isolated = workspace / "adjacent-identity"
    copy_fixture(fixture, isolated)
    adjacent = accepted(
        "adjacent-copy-isolation", isolated / "metadata.json", [*BASE_ARGS], []
    )
    if adjacent != baseline:
        raise AssertionError("adjacent fixture identity changed output")

    return {
        "matrix_version": MATRIX_VERSION,
        "image_hash": IMAGE_HASH,
        "rows": rows,
        "row_count": len(rows),
        "passed_rows": sum(bool(row.get("passed")) for row in rows),
    }


def normalization_rows(
    binary: pathlib.Path,
    image_binary: pathlib.Path,
    fixture: pathlib.Path,
    workspace: pathlib.Path,
    baseline: dict[str, str],
    high_memory: dict[str, str],
    low_memory: dict[str, str],
    initrd_digest: bytes,
) -> list[dict[str, Any]]:
    """Exercise both measured setup-header forms and the TDX measurement document.

    An image that does not declare `kernel_header_normalized` is measured in
    the canonical boot-loader layout, which dstack's OVMF writes before the
    kernel blob is measured on every QEMU version. An image that declares the
    flag is measured as the plain Authenticode hash of the kernel file it
    ships, whichever layout that header holds -- zeros for the images built
    before the follow-up, QEMU's layout after it. dstack-mr
    keeps both, so both are exercised here against independent replays.
    """
    rows: list[dict[str, Any]] = []
    metadata = json.loads((fixture / "metadata.json").read_text())
    kernel_name = metadata["kernel"]
    initrd_size = (fixture / metadata["initrd"]).stat().st_size

    def measure(name: str, directory: pathlib.Path, args: list[str]) -> dict[str, str]:
        row, output, _ = run_cli(
            binary, directory / "metadata.json", args, workspace, name
        )
        result = require_success(row, output, None)
        return result

    def normalize(name: str, kernel: pathlib.Path) -> None:
        zeroed = zeroed_setup_header(kernel.read_bytes())
        kernel.write_bytes(zeroed)
        (workspace / f"{name}.stdout").write_bytes(zeroed[0x200:0x258])

    # The historical image declares no flag, so it is measured in the canonical
    # boot-loader layout, and its shipped header still carries a
    # boot-loader-written field.
    if "kernel_header_normalized" in metadata:
        raise AssertionError(
            "the historical fixture unexpectedly declares normalization"
        )
    if setup_header_is_zeroed((fixture / kernel_name).read_bytes()):
        raise AssertionError(
            "the historical kernel unexpectedly has a zeroed setup header"
        )
    rows.append({"name": "legacy-header-not-normalized", "passed": True})

    # What dstack's OVMF writes is what dstack-mr predicts: RTMR[1] of an
    # image without the flag replays from the canonical layout, computed here
    # without dstack-mr. This is the pairing that lets a verifier or KMS from
    # any release measure a guest booted on any QEMU version.
    canonical_kernel = canonical_setup_header(
        (fixture / kernel_name).read_bytes(), initrd_size
    )
    canonical_rtmr1 = rtmr1_from_kernel_digest(authenticode_sha384(canonical_kernel))
    if baseline["rtmr1"] != canonical_rtmr1:
        raise AssertionError(
            "RTMR[1] without the flag is not the canonical boot-loader layout"
        )
    if canonical_setup_header(canonical_kernel, initrd_size) != canonical_kernel:
        raise AssertionError("the canonical layout is not idempotent")
    if canonical_kernel == (fixture / kernel_name).read_bytes():
        raise AssertionError("the canonical layout left the shipped header unchanged")
    rows.append(
        {
            "name": "canonical-layout-replays-rtmr1",
            "initrd_size": initrd_size,
            "passed": True,
        }
    )

    # Only XLF_CAN_BE_LOADED_ABOVE_4G raises the initrd ceiling. A kernel that
    # sets XLF_5LEVEL_ENABLED alone gets the default ceiling (PR #1229).
    shipped = (fixture / kernel_name).read_bytes()
    xlf = int.from_bytes(shipped[XLF_OFFSET : XLF_OFFSET + 2], "little")
    if not xlf & XLF_CAN_BE_LOADED_ABOVE_4G or not xlf & XLF_5LEVEL_ENABLED:
        raise AssertionError(f"the historical kernel XLF {xlf:#06x} lacks bit 1 or 6")
    five_level = workspace / "xlf-5level-only"
    copy_fixture(fixture, five_level)
    five_level_kernel = bytearray(shipped)
    five_level_kernel[XLF_OFFSET : XLF_OFFSET + 2] = (
        xlf & ~XLF_CAN_BE_LOADED_ABOVE_4G
    ).to_bytes(2, "little")
    (five_level / kernel_name).write_bytes(bytes(five_level_kernel))
    five_level_output = measure("xlf-5level-only", five_level, [*BASE_ARGS])
    default_ceiling = canonical_setup_header(bytes(five_level_kernel), initrd_size)
    raised_ceiling = bytearray(default_ceiling)
    raised_ceiling[0x218:0x21C] = canonical_kernel[0x218:0x21C]
    if raised_ceiling == bytearray(default_ceiling):
        raise AssertionError("the raised and default initrd ceilings coincide")
    if five_level_output["rtmr1"] != rtmr1_from_kernel_digest(
        authenticode_sha384(default_ceiling)
    ):
        raise AssertionError(
            "RTMR[1] of a 5-level-only kernel is not the default initrd ceiling"
        )
    if five_level_output["rtmr1"] == rtmr1_from_kernel_digest(
        authenticode_sha384(bytes(raised_ceiling))
    ):
        raise AssertionError("XLF_5LEVEL_ENABLED raised the initrd ceiling")
    rows.append({"name": "xlf-5level-does-not-raise-initrd-ceiling", "passed": True})

    # The image build writes the canonical layout into the kernel it ships and
    # declares the flag, so the declared digest of that file must equal the
    # digest a verifier recomputes for the same image without the flag. This is
    # what lets a release that predates the declaration verify these images, and
    # what makes the declared path independent of guest RAM.
    shipped_canonical = workspace / "shipped-canonical-kernel"
    copy_fixture(fixture, shipped_canonical)
    (shipped_canonical / kernel_name).write_bytes(canonical_kernel)
    set_metadata(shipped_canonical, kernel_header_normalized=True)
    shipped_output = measure(
        "shipped-canonical-kernel", shipped_canonical, [*BASE_ARGS]
    )
    if shipped_output["rtmr1"] != baseline["rtmr1"]:
        raise AssertionError(
            "a shipped canonical kernel declared normalized did not measure the "
            "same RTMR1 as the recomputed canonical layout"
        )
    if changed_registers(baseline, shipped_output):
        raise AssertionError(
            "shipping the canonical layout changed a register other than none"
        )
    for memory in ("2G", "3G", "8G"):
        varied = measure(
            f"shipped-canonical-{memory}",
            shipped_canonical,
            machine_args(memory=memory),
        )
        if varied["rtmr1"] != shipped_output["rtmr1"]:
            raise AssertionError(
                f"a shipped canonical kernel's RTMR1 moved with {memory} of RAM"
            )
    rows.append(
        {
            "name": "shipped-canonical-kernel-matches-recomputed-layout",
            "memory_sizes": ["2G", "3G", "8G"],
            "passed": True,
        }
    )

    # Declaring the flag without normalizing selects the plain digest of the
    # file exactly as shipped: dstack-mr does not rewrite the kernel itself.
    declared = workspace / "flag-without-normalization"
    copy_fixture(fixture, declared)
    set_metadata(declared, kernel_header_normalized=True)
    declared_output = measure("flag-without-normalization", declared, [*BASE_ARGS])
    shipped_digest = authenticode_sha384((declared / kernel_name).read_bytes())
    if changed_registers(baseline, declared_output) != ["rtmr1"]:
        raise AssertionError(
            "the normalization flag changed registers other than RTMR1"
        )
    if declared_output["rtmr1"] != rtmr1_from_kernel_digest(shipped_digest):
        raise AssertionError(
            "a declared-normalized image did not measure the shipped file"
        )
    rows.append({"name": "flag-selects-plain-kernel-digest", "passed": True})

    # An image that declares the flag: zeroed header plus the declaration.
    normalized = workspace / "normalized-image"
    copy_fixture(fixture, normalized)
    normalize("normalize-image", normalized / kernel_name)
    if not setup_header_is_zeroed((normalized / kernel_name).read_bytes()):
        raise AssertionError("zeroing left boot-loader fields in the header")
    set_metadata(normalized, kernel_header_normalized=True)
    normalized_digest = authenticode_sha384((normalized / kernel_name).read_bytes())
    normalized_output = measure("normalized-image", normalized, [*BASE_ARGS])
    if changed_registers(baseline, normalized_output) != ["rtmr1"]:
        raise AssertionError("normalization changed registers other than RTMR1")
    if normalized_output["rtmr1"] != rtmr1_from_kernel_digest(normalized_digest):
        raise AssertionError("normalized RTMR1 is not the plain Authenticode replay")
    if normalized_output["rtmr1"] == declared_output["rtmr1"]:
        raise AssertionError(
            "normalizing the header did not change the shipped file digest"
        )
    rows.append({"name": "normalized-image-plain-kernel-digest", "passed": True})

    # QEMU version and guest RAM must not reach RTMR1/RTMR2 of a normalized
    # image, while MRTD/RTMR0 keep their documented dependencies.
    observed: dict[str, dict[str, str]] = {}
    for memory, qemu in NORMALIZED_INDEPENDENCE_ROWS:
        name = f"normalized-{memory}-qemu-{qemu}"
        output = measure(name, normalized, machine_args(memory=memory, qemu=qemu))
        for register in ("rtmr1", "rtmr2"):
            if output[register] != normalized_output[register]:
                raise AssertionError(f"{name}: {register} depends on the host")
        observed[name] = output
    if (
        observed["normalized-2G-qemu-8.2.2"]["mrtd"]
        == observed["normalized-2G-qemu-9.2.1"]["mrtd"]
    ):
        raise AssertionError(
            "QEMU 8.x and 9.x page-add orders no longer differ in MRTD"
        )
    if (
        observed["normalized-1G-qemu-9.2.1"]["rtmr0"]
        == observed["normalized-8G-qemu-9.2.1"]["rtmr0"]
    ):
        raise AssertionError("guest memory no longer reaches RTMR0")
    if low_memory["rtmr1"] in (baseline["rtmr1"], high_memory["rtmr1"]):
        raise AssertionError(
            "the pre-normalization kernel digest stopped moving with RAM"
        )
    if high_memory["rtmr1"] != baseline["rtmr1"]:
        raise AssertionError(
            "the pre-normalization 2 GiB and high-memory digests diverged"
        )
    rows.append(
        {
            "name": "normalized-host-independence",
            "rows": sorted(observed),
            "stable_registers": ["rtmr1", "rtmr2"],
            "passed": True,
        }
    )

    # Boot-loader-written fields filled in as QEMU does are measured if they
    # are shipped, and normalizing them away restores the exact measurement.
    rewritten = workspace / "loader-rewritten-header"
    copy_fixture(normalized, rewritten)
    kernel = bytearray((rewritten / kernel_name).read_bytes())
    for offset, value in QEMU_LOADER_HEADER_WRITES:
        kernel[offset : offset + len(value)] = value
    kernel[LOADFLAGS_OFFSET] |= CAN_USE_HEAP
    (rewritten / kernel_name).write_bytes(bytes(kernel))
    if setup_header_is_zeroed((rewritten / kernel_name).read_bytes()):
        raise AssertionError("a loader-rewritten header was read as zeroed")
    rewritten_output = measure("loader-rewritten-header", rewritten, [*BASE_ARGS])
    if changed_registers(normalized_output, rewritten_output) != ["rtmr1"]:
        raise AssertionError(
            "shipping loader-written fields did not change exactly RTMR1"
        )
    normalize("renormalize-rewritten-header", rewritten / kernel_name)
    if (rewritten / kernel_name).read_bytes() != (
        normalized / kernel_name
    ).read_bytes():
        raise AssertionError(
            "normalizing a loader-rewritten header did not restore the image"
        )
    if measure("renormalized-header", rewritten, [*BASE_ARGS]) != normalized_output:
        raise AssertionError(
            "renormalized image measurement differs from the normalized image"
        )
    rows.append(
        {"name": "loader-fields-normalize-to-identical-measurement", "passed": True}
    )

    # The no-image-download document carries the base command line and the
    # normalization flag, and both replay to the CLI registers.
    documents: dict[str, dict[str, Any]] = {}
    for name, directory in (("legacy", fixture), ("normalized", normalized)):
        cbor = workspace / f"measurement-{name}.tdx.cbor"
        first = run_tool(
            [str(image_binary), "tdx-measurement-cbor", str(directory)],
            workspace,
            f"cbor-{name}",
        )
        second = run_tool(
            [str(image_binary), "tdx-measurement-cbor", str(directory)],
            workspace,
            f"cbor-{name}-repeat",
        )
        if (
            first.returncode
            or second.returncode
            or first.stdout != second.stdout
            or not first.stdout
        ):
            raise AssertionError(f"{name}: tdx-measurement-cbor was not deterministic")
        cbor.write_bytes(first.stdout)
        inspected = run_tool(
            [str(image_binary), "inspect-measurement", "tdx", str(cbor)],
            workspace,
            f"inspect-{name}",
        )
        if inspected.returncode:
            raise AssertionError(
                f"{name}: inspect-measurement rejected the generated document"
            )
        documents[name] = json.loads(inspected.stdout)
    legacy_doc, normalized_doc = documents["legacy"], documents["normalized"]
    for name, document, output, flag in (
        ("legacy", legacy_doc, baseline, None),
        ("normalized", normalized_doc, normalized_output, True),
    ):
        image = document["image"]
        if document["version"] != TDX_MEASUREMENT_DOCUMENT_VERSION:
            raise AssertionError(f"{name}: document version is {document['version']}")
        if "cmdline_sha384" in image or image["cmdline"] != metadata["cmdline"]:
            raise AssertionError(
                f"{name}: document does not carry the bare image cmdline"
            )
        if image.get("kernel_header_normalized") != flag:
            raise AssertionError(
                f"{name}: document normalization flag is {image.get('kernel_header_normalized')!r}"
            )
        if image["initrd_sha384"] != initrd_digest.hex():
            raise AssertionError(f"{name}: document initrd digest differs")
        kernel_digest = bytes.fromhex(image["kernel_authenticode"])
        if rtmr1_from_kernel_digest(kernel_digest) != output["rtmr1"]:
            raise AssertionError(
                f"{name}: document kernel digest does not replay to RTMR1"
            )
        if (
            rtmr2_oracle(image["cmdline"], initrd_digest, OVMF_INITRD_CMDLINE_SUFFIX)
            != output["rtmr2"]
        ):
            raise AssertionError(f"{name}: document cmdline does not replay to RTMR2")
    if (
        bytes.fromhex(normalized_doc["image"]["kernel_authenticode"])
        != normalized_digest
    ):
        raise AssertionError(
            "normalized document kernel digest is not the file Authenticode"
        )
    if (
        rtmr1_from_kernel_digest(
            bytes.fromhex(legacy_doc["image"]["kernel_authenticode"])
        )
        == low_memory["rtmr1"]
    ):
        raise AssertionError("legacy document digest also matched the 1 GiB rewrite")
    if legacy_doc["tdvf"] != normalized_doc["tdvf"]:
        raise AssertionError(
            "normalizing the kernel changed firmware measurement material"
        )
    rows.append({"name": "tdx-measurement-document-v4-replay", "passed": True})

    missing = workspace / "document-missing-rootfs-hash"
    copy_fixture(normalized, missing)
    set_metadata(
        missing,
        cmdline=" ".join(
            token
            for token in metadata["cmdline"].split()
            if not token.startswith("dstack.rootfs_hash=")
        ),
    )
    rejected = run_tool(
        [str(image_binary), "tdx-measurement-cbor", str(missing)],
        workspace,
        "cbor-missing-rootfs-hash",
    )
    if rejected.returncode == 0 or b"dstack.rootfs_hash" not in rejected.stderr:
        raise AssertionError(
            "a document without dstack.rootfs_hash was not rejected by name"
        )
    rows.append(
        {
            "name": "tdx-measurement-document-requires-rootfs-hash",
            "expected_rejection": True,
            "passed": True,
        }
    )
    return rows


def native_rows(
    repository: pathlib.Path, cargo_target: str, workspace: pathlib.Path
) -> list[dict[str, Any]]:
    """Run the exact native golden vectors for the measured byte layout."""
    rows: list[dict[str, Any]] = []
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = cargo_target
    cargo = shutil.which("cargo", path=environment.get("PATH")) or str(
        pathlib.Path.home() / ".cargo/bin/cargo"
    )
    for package, tests in NATIVE_TESTS:
        completed = subprocess.run(
            [cargo, "test", "-p", package, "--lib", "--", "--exact", *tests],
            cwd=repository / "dstack",
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=600,
            check=False,
        )
        (workspace / f"native-{package}.log").write_text(completed.stdout[-65536:])
        expected = f"test result: ok. {len(tests)} passed; 0 failed"
        missing = [
            test for test in tests if f"test {test} ... ok" not in completed.stdout
        ]
        if completed.returncode or expected not in completed.stdout or missing:
            raise AssertionError(f"native {package} golden vectors failed: {missing}")
        rows.append(
            {
                "name": f"native-{package}",
                "tests": list(tests),
                "output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
                "passed": True,
            }
        )
    return rows


def main() -> int:
    """Execute or reuse the run-scoped shared matrix and emit case evidence."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASE_IDS:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    fixture = pathlib.Path(
        runtime["environment"]["DSTACK_TEST_VERIFIER_FULL_TDX_IMAGE_DIR"]
    )
    binary = prepared_binary(runtime, "dstack_mr_cli")
    image_binary = prepared_binary(runtime, "dstack_mr_image")
    repository = pathlib.Path(runtime["repository"])
    cargo_target = str(runtime["cargo_target_dir"])
    run_id = os.environ["DSTACK_TEST_RUN_ID"]
    commit = runtime["candidate_commit"]
    cache_root = pathlib.Path("/tmp/dstack-mr-shared-matrix") / run_id / commit
    cache_path = cache_root / "matrix.json"
    lock_path = cache_root / "matrix.lock"
    cache_root.mkdir(parents=True, exist_ok=True)
    workspace = result_dir / "debug-workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    status = "PASS"
    summary = (
        "Shared dstack-mr configuration, artifact, cmdline, setup-header "
        "normalization, measurement-document, and recovery matrix passed."
    )
    matrix: dict[str, Any] = {}
    reused = False
    try:
        if (
            hashlib.sha256((fixture / "sha256sum.txt").read_bytes()).hexdigest()
            != IMAGE_HASH
        ):
            raise AssertionError(
                "fixture identity does not match the expected image hash"
            )
        with lock_path.open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if cache_path.is_file():
                cached = json.loads(cache_path.read_text())
                if (
                    cached.get("matrix_version") == MATRIX_VERSION
                    and cached.get("candidate_commit") == commit
                    and cached.get("status") == "PASS"
                ):
                    matrix = cached["matrix"]
                    reused = True
            if not matrix:
                matrix = execute_matrix(
                    binary, image_binary, repository, cargo_target, fixture, workspace
                )
                atomic_json(
                    cache_path,
                    {
                        "matrix_version": MATRIX_VERSION,
                        "candidate_commit": commit,
                        "status": "PASS",
                        "executed_by_case_id": case_id,
                        "matrix": matrix,
                    },
                )
    except (
        AssertionError,
        KeyError,
        OSError,
        ValueError,
        struct.error,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        status = "FAIL"
        summary = str(error)

    focus = (
        "supported platform/configuration fields, the kernel_header_normalized image "
        "declaration, TDX measurement document v4, and fail-closed unsupported settings"
        if case_id == "tc-ver-tools-001"
        else "firmware, kernel, setup-header normalization, initrd, cmdline suffix "
        "composition, QEMU, missing-artifact, and recovery boundaries"
    )
    evidence = {
        "candidate_commit": commit,
        "shared_matrix_reused": reused,
        "focus": focus,
        "matrix": matrix,
        "workspace_retained": status != "PASS",
        "remarks": "GPU and hugepage/NUMA topology are functional measurement coverage only. No image build is exercised.",
    }
    artifact = {
        "path": "artifacts/dstack-mr-shared-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "Shared dstack-mr measurement matrix",
        "description": "Run-scoped shared row results, exact register change sets, expected rejections, and output hashes.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
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
                    "observed": "Prepared CLI and hash-bound image fixture were selected.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": f"The shared matrix recorded {matrix.get('passed_rows', 0)}/{matrix.get('row_count', 0)} passing rows; reused={reused}.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Expected failures were followed by an identical baseline recovery.",
                },
                {
                    "id": f"{case_id}-step-04",
                    "status": status,
                    "observed": "An adjacent fixture copy produced identical output and no persistent state.",
                },
            ],
            "artifacts": [artifact],
            "remarks": evidence["remarks"],
        },
    )
    if status == "PASS":
        shutil.rmtree(workspace, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
