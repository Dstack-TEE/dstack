#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if (($# != 2)); then
    echo "usage: $0 QEMU_SYSTEM_X86_64 DSTACK_IMAGE_DIR" >&2
    exit 2
fi
qemu=$(realpath "$1")
image_dir=$(realpath "$2")
if [[ ! -x "$qemu" || ! -f "$image_dir/ovmf.fd" || ! -f "$image_dir/bzImage" ]]; then
    echo "QEMU binary or dstack image inputs are invalid" >&2
    exit 2
fi

crate_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
workspace=$(cd -- "$crate_dir/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/qemu-acpi-diff.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT

(cd "$workspace" && cargo build -p qemu-acpi --example dump)
rust_dump="$workspace/target/debug/examples/dump"

run_case() {
    local version=$1 topology=$2
    local hugepages=0 gpus=0
    case "$topology" in
        normal) ;;
        numa) hugepages=1 ;;
        numa-pxb) hugepages=1; gpus=8 ;;
        *) echo "invalid internal topology: $topology" >&2; exit 2 ;;
    esac

    local output="$tmp/$version-$topology"
    mkdir "$output"
    local args=(
        -L "$(dirname "$qemu")/../pc-bios"
        -cpu qemu64 -smp 8 -m 2048M -nographic -nodefaults -serial stdio
        -bios "$image_dir/ovmf.fd" -kernel "$image_dir/bzImage" -initrd /bin/sh
        -drive "file=/bin/sh,if=none,id=hd1,format=raw,readonly=on"
        -device "virtio-blk-pci,drive=hd1"
        -netdev "user,id=net0" -device "virtio-net-pci,netdev=net0"
        -netdev "user,id=net1" -device "virtio-net-pci,netdev=net1"
        -object "tdx-guest,id=tdx" -device "vhost-vsock-pci,guest-cid=3"
        -virtfs "local,path=/bin,mount_tag=host-shared,readonly=on,security_model=none,id=virtfs0"
        -drive "file=/bin/sh,if=none,id=hd0,format=raw,readonly=on"
        -device "virtio-blk-pci,drive=hd0"
    )
    local machine=q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off,smm=off,pic=off
    if ((hugepages)); then
        args+=(
            -numa "node,nodeid=0,cpus=0-7,memdev=mem0"
            -object "memory-backend-file,id=mem0,size=2048M,mem-path=/dev/hugepages,share=on,prealloc=no"
        )
    fi
    if ((gpus)); then
        args+=(-object "iommufd,id=iommufd0" -device "pxb-pcie,id=pcie.node0,bus=pcie.0,addr=10,numa_node=0,bus_nr=5")
        for ((index = 0; index < gpus; index++)); do
            args+=(
                -device "pcie-root-port,id=pci.$index,bus=pcie.node0,chassis=$index"
                -device "vfio-pci,host=00:00.0,bus=pci.$index,iommufd=iommufd0"
            )
        done
    fi

    QEMU_ACPI_COMPAT_VER="$version" QEMU_ACPI_DUMP_DIR="$output" \
        "$qemu" "${args[@]}" -machine "$machine"
    "$rust_dump" 2 8 "$version" "$gpus" 0 "$hugepages"
    cmp "$output/tables.bin" /tmp/rust.bin
    cmp "$output/loader.bin" /tmp/rust-loader.bin
    cmp "$output/rsdp.bin" /tmp/rust-rsdp.bin
    printf '%-6s %-8s tables+loader+rsdp match\n' "$version" "$topology"
}

for version in 8.0.0 8.2.0 9.0.0 9.1.0 9.2.0 10.0.0 10.2.0 11.0.0 11.1.0 11.2.0; do
    for topology in normal numa numa-pxb; do
        run_case "$version" "$topology"
    done
done
