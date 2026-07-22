#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
D=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=/dev/null
source "$D/versions.env"
[[ $KERNEL_VERSION == 7.* && $KERNEL_VERSION != *-rc* ]]
[[ $KERNEL_SHA256 =~ ^[0-9a-f]{64}$ ]]
grep -q "^Snapshot=$DEBIAN_SNAPSHOT" "$D/mkosi.conf"
grep -q 'Bootloader=systemd-boot' "$D/mkosi.conf"
for key in ACPI ACPI_TABLE_UPGRADE INTEL_TDX_GUEST TDX_GUEST_DRIVER \
 AMD_MEM_ENCRYPT SEV_GUEST TCG_TPM VIRTIO_PCI VIRTIO_NET BLK_DEV_NVME \
 DM_CRYPT DM_VERITY OVERLAY_FS CGROUPS USER_NS SECCOMP BPF_SYSCALL \
 NF_TABLES VSOCKETS HARDENED_USERCOPY; do
  grep -Eq "^CONFIG_${key}=(y|m)$" "$D/kernel.config" || { echo "missing CONFIG_$key"; exit 1; }
done
grep -q '0002-acpi-sandbox' "$D/scripts/build-kernel.sh"
grep -q -- '--fuzz=0' "$D/scripts/build-kernel.sh"
for service in dstack-guest-agent dstack-prepare app-compose wg-checker; do
  grep -q "$service" "$D/mkosi.postinst"
done
grep -q 'artifact-manifest.json' "$D/scripts/make-release-artifacts.sh"
grep -q 'image/assemble.sh' "$D/build.sh"
grep -q 'build-ovmf.sh' "$D/build.sh"
grep -q 'fbe0805b2091393406952e84724188f8c1941837' "$D/scripts/build-ovmf.sh"
grep -q 'rootfs.img.parted.verity' "$D/../image/assemble.sh"
bash -n "$D"/*.sh "$D"/scripts/*.sh "$D"/tests/*.sh
echo 'mkosi static acceptance passed'
