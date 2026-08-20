#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# Most checks below are bare test/grep assertions. Without this they abort the
# run with no output at all, which says nothing about what regressed.
trap 'echo "acceptance check failed at line $LINENO: $BASH_COMMAND" >&2' ERR
D=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for component in dstack-rust image-tools container-stack sysbox nvattest kernel nvidia zfs ovmf; do
  test -f "$D/components/$component/$component.sh"
  test -x "$D/components/$component/$component-build.sh"
done
# shellcheck source=/dev/null
source "$D/versions.env"
[[ $KERNEL_VERSION != *-rc* ]]
[[ $KERNEL_SHA256 =~ ^[0-9a-f]{64}$ ]]
[[ $DSTACK_CODENAME == trixie ]]
release_root=$(mktemp -d)
"$D/scripts/write-os-release.sh" \
  "$release_root" "$DSTACK_VERSION" "$DSTACK_CODENAME"
grep -qx 'ID=dstack' "$release_root/usr/lib/os-release"
grep -qx 'ID_LIKE=debian' "$release_root/usr/lib/os-release"
grep -qx 'NAME="dstack"' "$release_root/usr/lib/os-release"
grep -qx "VERSION_ID=\"$DSTACK_VERSION\"" "$release_root/usr/lib/os-release"
grep -qx "VERSION_CODENAME=\"$DSTACK_CODENAME\"" \
  "$release_root/usr/lib/os-release"
grep -qx "PRETTY_NAME=\"dstack $DSTACK_VERSION ($DSTACK_CODENAME)\"" \
  "$release_root/usr/lib/os-release"
[[ $(readlink "$release_root/etc/os-release") == ../usr/lib/os-release ]]
rm -rf "$release_root"

grep -qx 'DISTRO_NAME = "dstack"' \
  "$D/../yocto/layers/meta-dstack/conf/distro/dstack.conf"
# The guest kernel must track the same series as the production Yocto backend.
# A different major/minor reintroduces the out-of-tree NVIDIA and ZFS
# compatibility patches that parity with Yocto exists to avoid.
yocto_series=$(sed -n 's/^PREFERRED_VERSION_linux-yocto ?= "\([0-9.]*\)%".*/\1/p' \
  "$D/../yocto/layers/meta-dstack/conf/distro/dstack.conf")
[[ -n $yocto_series ]]
[[ $KERNEL_VERSION == "$yocto_series".* ]]
grep -q "^Snapshot=$DEBIAN_SNAPSHOT" "$D/mkosi.conf"
grep -q '^Format=tar$' "$D/mkosi.conf"
# mkosi's own tar must not share the release name: sharing it made mkosi
# track the release tarball as one of its outputs, which clean/--force may
# delete. build.sh discards it once mkosi has finished with it.
grep -q '^Output=%i-%v-rootfs$' "$D/mkosi.conf"
# %i/%v expand in file order, so these must be declared before Output=.
grep -q "^ImageVersion=$DSTACK_VERSION\$" "$D/mkosi.conf"
awk '/^ImageVersion=/{v=NR} /^Output=/{o=NR} END{exit !(v && o && v < o)}' "$D/mkosi.conf"
grep -q '^Bootable=no$' "$D/mkosi.conf"
for package in iputils-ping dnsutils traceroute netcat-openbsd wget fdisk \
  dosfstools pciutils usbutils cpio; do
  grep -Eq "^[[:space:]]+$package$" "$D/mkosi.conf" || {
    echo "missing runtime diagnostic package: $package" >&2
    exit 1
  }
done
# SplitArtifacts must stay empty: the kernel split is produced even with
# Bootable=no and would drop a stray .vmlinuz beside the release artifacts.
grep -q '^SplitArtifacts=$' "$D/mkosi.conf"
# The rootfs tar is removed after mkosi returns, not in postoutput: mkosi
# stats it again to print its size once staging has been promoted.
grep -Fq 'rootfs.tar' "$D/build.sh"
if grep -Fq 'rootfs.tar"' "$D/mkosi.postoutput"; then
  echo 'removing the rootfs tar in postoutput breaks mkosi output bookkeeping' >&2
  exit 1
fi
# KernelCommandLine= is dead with Bootable=no and contradicted the command
# line actually measured into the UKI; the real one lives in the release script.
if grep -q '^KernelCommandLine=' "$D/mkosi.conf"; then
  echo 'KernelCommandLine= is unreachable with Bootable=no' >&2
  exit 1
fi
for key in ACPI ACPI_TABLE_UPGRADE INTEL_TDX_GUEST TDX_GUEST_DRIVER \
 AMD_MEM_ENCRYPT SEV_GUEST TCG_TPM VIRTIO_PCI VIRTIO_NET BLK_DEV_NVME \
 DM_CRYPT DM_VERITY OVERLAY_FS CGROUPS USER_NS SECCOMP BPF_SYSCALL \
 NF_TABLES VSOCKETS HARDENED_USERCOPY; do
  grep -Eq "^CONFIG_${key}=(y|m)$" "$D/components/kernel/kernel.config" || { echo "missing CONFIG_$key"; exit 1; }
done
# The hardening baseline is owned by the production audit script; read the
# requirements from it so the two cannot drift. x86_64_defconfig enables
# several of these, so the fragment must pin every one of them explicitly.
audit="$D/../yocto/tools/aws/audit-aws-ec2-image-hardening.sh"
test -f "$audit"
required=0
while read -r key want; do
  required=$((required + 1))
  grep -q "^${key}=${want}$" "$D/components/kernel/kernel.config" || {
    echo "kernel.config does not pin $key=$want required by $audit"; exit 1; }
done < <(sed -n 's/^require_config \(CONFIG_[A-Z0-9_]*\) \([ynm]\)$/\1 \2/p' "$audit")
[[ $required -ge 10 ]]
grep -q '0002-acpi-sandbox' "$D/components/kernel/kernel-build.sh"
grep -q -- '--fuzz=0' "$D/components/kernel/kernel-build.sh"
for service in dstack-guest-agent dstack-prepare app-compose dstack-gateway-checker; do
  grep -q "$service" "$D/mkosi.skeleton/usr/lib/systemd/system-preset/80-dstack.preset"
done
# The gateway checker is a dstack-util subcommand, not a shell script. It exits 0
# when the app did not enable dstack-gateway, so Restart must not be "always" or
# systemd respawns it every RestartSec forever on every gateway-less CVM.
gw_unit="$D/../common/rootfs/dstack-gateway-checker.service"
grep -q '^ExecStart=/bin/dstack-util gateway-checker ' "$gw_unit" || {
  echo 'dstack-gateway-checker.service must run the dstack-util gateway-checker subcommand'; exit 1; }
grep -q '^Restart=on-failure$' "$gw_unit" || {
  echo 'dstack-gateway-checker.service must use Restart=on-failure'; exit 1; }
# A permanent misconfiguration exits with EXIT_MISCONFIGURED. If the unit does
# not inhibit restarts for exactly that code, "fail loudly and stop" silently
# degrades into a RestartSec respawn loop, which is what this whole exit code
# exists to avoid.
checker_src="$D/../../dstack/dstack-util/src/gateway_checker.rs"
exit_code=$(sed -n 's/^const EXIT_MISCONFIGURED: i32 = \([0-9]\+\);$/\1/p' "$checker_src")
[[ -n $exit_code ]] || { echo "cannot read EXIT_MISCONFIGURED from $checker_src"; exit 1; }
grep -q "^RestartPreventExitStatus=${exit_code}\$" "$gw_unit" || {
  echo "dstack-gateway-checker.service must set RestartPreventExitStatus=$exit_code"; exit 1; }
# The loop's recovery paths only run while the loop runs, so systemd has to be
# the thing that notices a wedge. WatchdogSec is useless without Type=notify.
grep -q '^Type=notify$' "$gw_unit" || {
  echo 'dstack-gateway-checker.service must use Type=notify to arm the watchdog'; exit 1; }
grep -q '^WatchdogSec=' "$gw_unit" || {
  echo 'dstack-gateway-checker.service must set WatchdogSec'; exit 1; }
test ! -e "$D/../common/rootfs/wg-checker.sh"
test ! -e "$D/../common/rootfs/wg-checker.service"
# systemd enables any unit that matches no preset rule, so the enable list is
# only meaningful with a terminal disable. Without it, every package pulled in
# by Packages= would start at boot with no diff to 80-dstack.preset.
grep -q '^disable \*$' "$D/mkosi.skeleton/usr/lib/systemd/system-preset/99-dstack-default.preset"
# The TEE simulator serves synthetic quotes; its preset must not ship in prod.
if grep -rq 'dstack-tee-simulator' "$D/mkosi.skeleton/"; then
  echo 'simulator preset must live in the dev profile skeleton' >&2
  exit 1
fi
grep -q '^enable dstack-tee-simulator\.service$' \
  "$D/mkosi.profiles/dev/mkosi.skeleton/usr/lib/systemd/system-preset/85-dstack-dev.preset"
# Production must not retain the login stack that meta-dstack's disable_login()
# deletes; /etc masks alone are runtime-mutable via the dstack-prepare overlay.
for path in /usr/bin/login /usr/sbin/agetty /usr/lib/systemd/system/getty@.service \
  /usr/lib/systemd/system-generators/systemd-getty-generator; do
  grep -qF "        $path" "$D/mkosi.profiles/prod/mkosi.conf" || {
    echo "prod profile does not remove $path"; exit 1; }
done
# The dev component cache must be stored in mkosi's BuildDirectory. A
# BuildSources mount is an ephemeral overlay under BuildSourcesEphemeral=yes,
# so a cache placed there is silently discarded on every run.
# The single quotes are deliberate: these are grep patterns matching a literal
# $BUILDDIR/$SRCDIR in the generated script, not shell expansions.
# shellcheck disable=SC2016
grep -q 'DSTACK_DEV_CACHE_DIR="\$BUILDDIR/components"' "$D/mkosi.build"
# shellcheck disable=SC2016
grep -q 'toolchain_downloads="\$BUILDDIR/toolchains"' "$D/mkosi.build"
grep -q -- '--build-directory=' "$D/build.sh"
# shellcheck disable=SC2016
if grep -Fq 'DSTACK_DEV_CACHE_DIR="$SRCDIR' "$D/mkosi.build"; then
  echo 'dev cache must not live on an ephemeral source mount' >&2
  exit 1
fi
grep -q 'artifact-manifest.json' "$D/scripts/make-release-artifacts.sh"
grep -q -- '--hard-dereference' "$D/scripts/make-release-artifacts.sh"
grep -q -- '--mode=g-s' "$D/scripts/make-release-artifacts.sh"
grep -q 'mksquashfs -.*-tar' "$D/scripts/make-release-artifacts.sh"
grep -q 'image/assemble.sh' "$D/mkosi.postoutput"
grep -q 'ovmf-build.sh' "$D/components/ovmf/ovmf.sh"
# A generic OVMF produces measurement material dstack-mr cannot parse, so the
# revision must track meta-dstack's SRCREV. Read it from the recipe rather
# than restating the hash, which would happily pin a stale value.
ovmf_recipe="$D/../yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf_git.bb"
yocto_srcrev=$(sed -n 's/^SRCREV = "\([0-9a-f]\{40\}\)"/\1/p' "$ovmf_recipe")
[[ $yocto_srcrev =~ ^[0-9a-f]{40}$ ]]
grep -q "^OVMF_REVISION=$yocto_srcrev\$" "$D/versions.env"
# 0003 and 0005 are what make the prefix map reach the compiler and let
# stable202502 assemble with NASM 3.x; both were previously dropped.
for patch in 0003-Debug-prefix-map 0004-Reproduciable \
  0005-UefiCpuPkg-CpuExceptionHandlerLib-fix-push-instructi \
  0006-OvmfPkg-AmdSev-drop-embedded-grub; do
  grep -q "$patch" "$D/components/ovmf/ovmf-build.sh"
done
grep -q 'AmdSev/AmdSevX64.dsc' "$D/components/ovmf/ovmf-build.sh"
grep -q '0006-OvmfPkg-AmdSev-drop-embedded-grub.patch' "$D/components/ovmf/ovmf.sh"
grep -q '0005-UefiCpuPkg' "$D/components/ovmf/ovmf.sh"
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
grep -q '^NVIDIA_VERSION=595.58.03$' "$D/versions.env"
# GOTOOLCHAIN=local keeps the go command from downloading an unpinned
# toolchain when a module's go.mod names a newer release.
grep -q '^export GOTOOLCHAIN=local$' "$D/mkosi.build"
grep -q '^STARGZ_VERSION=0.18.2$' "$D/versions.env"
grep -q '^NERDCTL_VERSION=2.3.5$' "$D/versions.env"
grep -q '^[[:space:]]*docker-cli$' "$D/mkosi.conf"
grep -q '^SYSBOX_VERSION=0.6.7$' "$D/versions.env"
grep -q '^ZFS_VERSION=2.4.0$' "$D/versions.env"
grep -q -- '--fuzz=0' "$D/components/zfs/zfs-build.sh"
# ZFS 2.4.0 declares Linux-Maximum 6.18; no out-of-tree compat patch is carried.
test ! -e "$D/components/zfs/patches"
test ! -e "$D/components/nvidia/patches"
python3 -m json.tool "$D/parity.json" >/dev/null
grep -q 'rootfs.img.parted.verity' "$D/../image/assemble.sh"
# mkosi.postinst was missing here, so a syntax error in it only surfaced part
# way into a ~30 minute build.
bash -n "$D"/*.sh "$D"/mkosi.build "$D"/mkosi.clean "$D"/mkosi.finalize \
  "$D"/mkosi.postinst "$D"/mkosi.postoutput "$D"/scripts/*.sh \
  "$D"/components/*/*.sh "$D"/tests/*.sh "$D"/mkosi.skeleton/usr/bin/*.sh \
  "$D"/../image/kernel-cmdline.sh
# The Python helpers were only ever exercised by a real build. Keep the
# bytecode out of the source tree, which is mounted into the build sandbox.
pycache=$(mktemp -d)
trap 'rm -rf "$pycache"' EXIT
PYTHONPYCACHEPREFIX="$pycache" python3 -m py_compile "$D"/scripts/*.py "$D"/tests/*.py
# The UKI command line and the one recorded in metadata.json feed the same
# measurements, so both must come from the single shared definition.
grep -q 'kernel-cmdline.sh' "$D/scripts/make-release-artifacts.sh"
grep -q 'kernel-cmdline.sh' "$D/../image/assemble.sh"
if grep -q 'random.trust_bootloader' "$D/scripts/make-release-artifacts.sh"; then
  echo 'kernel command line must not be restated outside kernel-cmdline.sh' >&2
  exit 1
fi
grep -q 'Archiving UKI image' "$D/../image/assemble.sh"
grep -Fq "FLAVORS=\${FLAVORS:-prod}" "$D/build.sh"
# A cache hit must never be able to answer the question repro-check asks.
grep -Fq "if [[ \$action == repro-check ]]; then cache=0; fi" "$D/build.sh"
# repro-check compares the release tarballs, so it must archive unconditionally
# -- otherwise it compares absent files and reports no difference.
grep -Fq "if [[ \$action == repro-check ]]; then archive=1; fi" "$D/build.sh"
grep -Fq -e "--environment=\"DSTACK_TAR_RELEASE=\$archive\"" "$D/build.sh"
grep -Fq "DSTACK_TAR_RELEASE=\"\${DSTACK_TAR_RELEASE:-1}\"" "$D/mkosi.postoutput"
grep -Fq -e "--environment=\"DSTACK_COMPONENT_CACHE=\$cache\"" "$D/build.sh"
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
# Tracks the Go that oe-core pins for the production Yocto backend, so both
# backends compile the same Go components with the same toolchain. It must also
# stay >= the highest 'go' directive among them (nvidia-container-toolkit
# currently declares go 1.25.0); GOTOOLCHAIN=local turns a violation into a
# build failure rather than a silent download.
grep -q '^GO_TOOLCHAIN_VERSION=1.26.2$' "$D/versions.env"
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
