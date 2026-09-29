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
    # pxb_buses: one guest NUMA node per bus, GPUs split evenly across them.
    local hugepages=0 gpus=0 pxb_buses=()
    case "$topology" in
        normal) ;;
        numa) hugepages=1 ;;
        numa-pxb) hugepages=1; gpus=8; pxb_buses=(5) ;;
        numa2-pxb) hugepages=1; gpus=8; pxb_buses=(5 10) ;;
        numa4-pxb-adjacent) hugepages=1; gpus=4; pxb_buses=(5 6 8 9) ;;
        *) echo "invalid internal topology: $topology" >&2; exit 2 ;;
    esac
    local nodes=${#pxb_buses[@]}
    ((hugepages && nodes == 0)) && nodes=1

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
    for ((node = 0; node < nodes; node++)); do
        args+=(
            -numa "node,nodeid=$node,cpus=$((node * 8 / nodes))-$(((node + 1) * 8 / nodes - 1)),memdev=mem$node"
            -object "memory-backend-file,id=mem$node,size=$((2048 / nodes))M,mem-path=/dev/hugepages,share=on,prealloc=no"
        )
        if ((gpus)); then
            args+=(-device "pxb-pcie,id=pcie.node$node,bus=pcie.0,addr=$((10 + node)),numa_node=$node,bus_nr=${pxb_buses[$node]}")
        fi
    done
    if ((gpus)); then
        args+=(-object "iommufd,id=iommufd0")
        for ((index = 0; index < gpus; index++)); do
            args+=(
                -device "pcie-root-port,id=pci.$index,bus=pcie.node$((index * nodes / gpus)),chassis=$index"
                -device "vfio-pci,host=00:00.0,bus=pci.$index,iommufd=iommufd0"
            )
        done
    fi

    QEMU_ACPI_COMPAT_VER="$version" QEMU_ACPI_DUMP_DIR="$output" \
        "$qemu" "${args[@]}" -machine "$machine"
    local numa=""
    ((nodes > 1)) && numa=$(IFS=,; echo "${pxb_buses[*]}")
    QEMU_ACPI_OUTPUT_DIR="$output/rust" \
        "$rust_dump" 2 8 "$version" "$gpus" 0 "$hugepages" 1 0 0 0 $((2048 << 20)) 0 0 "$numa"
    for blob in tables loader rsdp; do
        cmp "$output/$blob.bin" "$output/rust/$blob.bin"
    done
    printf '%-6s %-8s tables+loader+rsdp match\n' "$version" "$topology"
}

for version in 8.0.0 8.2.0 9.0.0 9.1.0 9.2.0 10.0.0 10.2.0 11.0.0 11.1.0 11.2.0; do
    for topology in normal numa numa-pxb numa2-pxb numa4-pxb-adjacent; do
        run_case "$version" "$topology"
    done
done
