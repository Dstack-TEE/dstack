#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if (($# != 2)); then
    echo "usage: $0 QEMU_SYSTEM_X86_64 QEMU_VERSION" >&2
    exit 2
fi
qemu=$(realpath "$1")
version=$2
if [[ ! -x "$qemu" || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "invalid QEMU binary or semantic version" >&2
    exit 2
fi
crate_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
workspace=$(cd -- "$crate_dir/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/qemu-acpi-upstream.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
(cd "$workspace" && cargo build -p qemu-acpi --example dump)
rust_dump="$workspace/target/debug/examples/dump"

for topology in normal numa numa-pxb; do
    hugepages=0
    gpus=0
    case "$topology" in
        normal) ;;
        numa) hugepages=1 ;;
        numa-pxb) hugepages=1; gpus=8 ;;
    esac
    output="$tmp/$topology"
    mkdir "$output"
    args=(
        -cpu qemu64 -smp 8 -m 2048M -nographic -nodefaults -serial stdio
        -drive "file=/bin/sh,if=none,id=hd1,format=raw,readonly=on"
        -device "virtio-blk-pci,drive=hd1"
        -netdev "socket,id=net0,listen=:0" -device "virtio-net-pci,netdev=net0"
        -netdev "socket,id=net1,listen=:0" -device "virtio-net-pci,netdev=net1"
        -object "tdx-guest,id=tdx" -device "vhost-vsock-pci,guest-cid=3"
        -virtfs "local,path=/bin,mount_tag=host-shared,readonly=on,security_model=none,id=virtfs0"
        -drive "file=/bin/sh,if=none,id=hd0,format=raw,readonly=on"
        -device "virtio-blk-pci,drive=hd0"
    )
    machine=q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off,smm=off,pic=off
    if ((hugepages)); then
        args+=(
            -numa "node,nodeid=0,cpus=0-7,memdev=mem0"
            -object "memory-backend-ram,id=mem0,size=2048M"
        )
    fi
    if ((gpus)); then
        args+=(-device "pxb-pcie,id=pcie.node0,bus=pcie.0,addr=10,numa_node=0,bus_nr=5")
        for ((index = 0; index < gpus; index++)); do
            # The endpoint does not emit AML. pci-testdev avoids requiring real
            # VFIO hardware while preserving QEMU's root-port topology.
            args+=(
                -device "pcie-root-port,id=pci.$index,bus=pcie.node0,chassis=$index"
                -device "pci-testdev,bus=pci.$index"
            )
        done
    fi
    QEMU_DUMP_ACPI_DIR="$output" "$qemu" "${args[@]}" -machine "$machine"
    "$rust_dump" 2 8 "$version" "$gpus" 0 "$hugepages"
    cmp "$output/tables.bin" /tmp/rust.bin
    cmp "$output/loader.bin" /tmp/rust-loader.bin
    cmp "$output/rsdp.bin" /tmp/rust-rsdp.bin
    printf '%-8s %-8s tables+loader+rsdp match\n' "$version" "$topology"
done
