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
grep -q 'build-ovmf.sh' "$D/scripts/build-components.sh"
grep -q 'fbe0805b2091393406952e84724188f8c1941837' "$D/scripts/build-ovmf.sh"
grep -q 'AmdSev/AmdSevX64.dsc' "$D/scripts/build-ovmf.sh"
grep -q 'objcopy --strip-debug' "$D/build.sh"
grep -q 'prune-rootfs.sh' "$D/build.sh"
! grep -q '^[[:space:]]*ovmf$' "$D/mkosi.conf"
grep -q '"firmware_sev":"files/ovmf-sev.fd"' "$D/scripts/make-release-artifacts.sh"
grep -q 'measurement.snp.cbor' "$D/tests/check-output.sh"
grep -q '0001-validate-ocsp-response-freshness.patch' "$D/scripts/build-nvattest.sh"
grep -q -- '--fuzz=0' "$D/scripts/build-nvattest.sh"
grep -q '0001-pin-fetchcontent-inputs.patch' "$D/scripts/build-nvattest.sh"
grep -q '^NVATTEST_REVISION=9d12801cea8a198ea0f29640dfaf8a4017c841c5$' "$D/versions.env"
grep -q '0001-linux-7.1-drop-legacy-of-gpio-api.patch' "$D/scripts/build-nvidia.sh"
grep -q '^NVIDIA_VERSION=595.58.03$' "$D/versions.env"
grep -q '^STARGZ_VERSION=0.18.2$' "$D/versions.env"
grep -q '^NERDCTL_VERSION=2.2.1$' "$D/versions.env"
grep -q '^[[:space:]]*docker-cli$' "$D/mkosi.conf"
grep -q '^SYSBOX_VERSION=0.6.7$' "$D/versions.env"
grep -q '^ZFS_VERSION=2.4.0$' "$D/versions.env"
grep -q '0001-linux-6.19-7.1-compat.patch' "$D/scripts/build-zfs.sh"
grep -q -- '--fuzz=0' "$D/scripts/build-zfs.sh"
python3 -m json.tool "$D/parity.json" >/dev/null
grep -q 'rootfs.img.parted.verity' "$D/../image/assemble.sh"
bash -n "$D"/*.sh "$D"/scripts/*.sh "$D"/tests/*.sh
grep -Fq "[[ \$action == dev-image ]] && component_cache_args+=(--dev-cache)" "$D/build.sh"
grep -q 'scripts/build-components.sh' "$D/build.sh"
"$D/tests/test-dev-cache.sh"
echo 'mkosi static acceptance passed'
