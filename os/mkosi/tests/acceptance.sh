#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
D=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for component in dstack-rust image-tools container-stack sysbox nvattest kernel nvidia zfs ovmf; do
  test -f "$D/components/$component/$component.sh"
  test -x "$D/components/$component/$component-build.sh"
done
# shellcheck source=/dev/null
source "$D/versions.env"
[[ $KERNEL_VERSION == 7.* && $KERNEL_VERSION != *-rc* ]]
[[ $KERNEL_SHA256 =~ ^[0-9a-f]{64}$ ]]
grep -q "^Snapshot=$DEBIAN_SNAPSHOT" "$D/mkosi.conf"
grep -q '^Format=tar$' "$D/mkosi.conf"
grep -q '^Output=dstack-0.6.0$' "$D/mkosi.conf"
grep -q '^CompressOutput=gz$' "$D/mkosi.conf"
grep -q '^SplitArtifacts=$' "$D/mkosi.conf"
grep -q '^Bootable=no$' "$D/mkosi.conf"
grep -q '^Bootloader=none$' "$D/mkosi.conf"
for key in ACPI ACPI_TABLE_UPGRADE INTEL_TDX_GUEST TDX_GUEST_DRIVER \
 AMD_MEM_ENCRYPT SEV_GUEST TCG_TPM VIRTIO_PCI VIRTIO_NET BLK_DEV_NVME \
 DM_CRYPT DM_VERITY OVERLAY_FS CGROUPS USER_NS SECCOMP BPF_SYSCALL \
 NF_TABLES VSOCKETS HARDENED_USERCOPY; do
  grep -Eq "^CONFIG_${key}=(y|m)$" "$D/components/kernel/kernel.config" || { echo "missing CONFIG_$key"; exit 1; }
done
grep -q '0002-acpi-sandbox' "$D/components/kernel/kernel-build.sh"
grep -q -- '--fuzz=0' "$D/components/kernel/kernel-build.sh"
for service in dstack-guest-agent dstack-prepare app-compose wg-checker; do
  grep -q "$service" "$D/mkosi.skeleton/usr/lib/systemd/system-preset/80-dstack.preset"
done
grep -q 'artifact-manifest.json' "$D/scripts/make-release-artifacts.sh"
grep -q -- '--hard-dereference' "$D/scripts/make-release-artifacts.sh"
grep -q -- '--mode=g-s' "$D/scripts/make-release-artifacts.sh"
grep -q 'mksquashfs -.*-tar' "$D/scripts/make-release-artifacts.sh"
grep -q 'image/assemble.sh' "$D/mkosi.postoutput"
grep -q 'ovmf-build.sh' "$D/components/ovmf/ovmf.sh"
grep -q 'fbe0805b2091393406952e84724188f8c1941837' "$D/components/ovmf/ovmf-build.sh"
grep -q 'AmdSev/AmdSevX64.dsc' "$D/components/ovmf/ovmf-build.sh"
grep -q '0006-OvmfPkg-AmdSev-drop-embedded-grub.patch' "$D/components/ovmf/ovmf.sh"
grep -q 'objcopy --strip-debug' "$D/mkosi.build"
grep -q 'depmod -b.*KERNEL_VERSION-dstack' "$D/mkosi.build"
grep -q '^CleanPackageMetadata=yes$' "$D/mkosi.conf"
grep -q '^WithDocs=no$' "$D/mkosi.conf"
grep -q '/var/lib/docker/.dstack-keep' "$D/mkosi.conf"
grep -q '! -name .dstack-keep' "$D/scripts/normalize-skeleton-modes.sh"
grep -q '/var/lib/tpm2-tss/system/keystore 0755' \
  "$D/mkosi.skeleton/usr/lib/tmpfiles.d/dstack-image.conf"
grep -q '/var/lib/dpkg' "$D/mkosi.profiles/prod/mkosi.conf"
if grep -q '^[[:space:]]*ovmf$' "$D/mkosi.conf"; then
  echo 'distribution OVMF must not be installed in the guest rootfs' >&2
  exit 1
fi
grep -q '"firmware_sev":"files/ovmf-sev.fd"' "$D/scripts/make-release-artifacts.sh"
grep -q 'measurement.snp.cbor' "$D/tests/check-output.sh"
grep -q '0001-validate-ocsp-response-freshness.patch' "$D/components/nvattest/nvattest-build.sh"
grep -q -- '--fuzz=0' "$D/components/nvattest/nvattest-build.sh"
grep -q '0001-pin-fetchcontent-inputs.patch' "$D/components/nvattest/nvattest-build.sh"
grep -q 'COMPONENT_PATH/patches/0001-pin-fetchcontent-inputs.patch' "$D/components/nvattest/nvattest.sh"
grep -q '^NVATTEST_REVISION=9d12801cea8a198ea0f29640dfaf8a4017c841c5$' "$D/versions.env"
grep -q '0001-linux-7.1-drop-legacy-of-gpio-api.patch' "$D/components/nvidia/nvidia-build.sh"
grep -q '^NVIDIA_VERSION=595.58.03$' "$D/versions.env"
grep -q '^STARGZ_VERSION=0.18.2$' "$D/versions.env"
grep -q '^NERDCTL_VERSION=2.2.1$' "$D/versions.env"
grep -q '^[[:space:]]*docker-cli$' "$D/mkosi.conf"
grep -q '^SYSBOX_VERSION=0.6.7$' "$D/versions.env"
grep -q '^ZFS_VERSION=2.4.0$' "$D/versions.env"
grep -q '0001-linux-6.19-7.1-compat.patch' "$D/components/zfs/zfs-build.sh"
grep -q -- '--fuzz=0' "$D/components/zfs/zfs-build.sh"
python3 -m json.tool "$D/parity.json" >/dev/null
grep -q 'rootfs.img.parted.verity' "$D/../image/assemble.sh"
bash -n "$D"/*.sh "$D"/mkosi.build "$D"/mkosi.clean "$D"/mkosi.finalize \
  "$D"/mkosi.postoutput "$D"/scripts/*.sh "$D"/components/*/*.sh "$D"/tests/*.sh
grep -q 'Archiving UKI image' "$D/../image/assemble.sh"
grep -Fq "FLAVORS=\${FLAVORS:-prod}" "$D/build.sh"
grep -q 'DSTACK_COMPONENT_CACHE.*dev-image' "$D/build.sh"
grep -q 'write-source-manifest.py' "$D/build.sh"
grep -q 'DSTACK_SOURCE_REVISION.*revision' "$D/build.sh"
grep -q 'DSTACK_SOURCE_REVISION:?' "$D/scripts/make-release-artifacts.sh"
grep -q 'scripts/build-components.sh' "$D/mkosi.build"
grep -q '^BuildPackages=' "$D/mkosi.conf"
grep -q '^ToolsTree=yes$' "$D/mkosi.conf"
grep -q '^ToolsTreeProfiles=misc$' "$D/mkosi.conf"
grep -q '^Snapshot=20260721T000000Z$' "$D/mkosi.tools.conf"
grep -q 'clean -f' "$D/build.sh"
grep -q 'install-toolchains.sh' "$D/mkosi.build"
grep -q '^RUST_TOOLCHAIN_VERSION=1.92.0$' "$D/versions.env"
grep -q '^GO_TOOLCHAIN_VERSION=1.22.2$' "$D/versions.env"
for component in dstack-rust image-tools container-stack sysbox nvattest kernel nvidia zfs ovmf; do
  definition="$D/components/$component/$component.sh"
  grep -q "^COMPONENT_NAME=$component$" "$definition"
  grep -q '^component_cache_key()' "$definition"
  grep -q '^component_build()' "$definition"
  grep -q '^COMPONENT_CACHE_PATHS=' "$definition"
done
"$D/tests/test-dev-cache.sh"
"$D/tests/test-component-framework.sh"
"$D/tests/test-component-merge.sh"
echo 'mkosi static acceptance passed'
