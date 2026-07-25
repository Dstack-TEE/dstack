#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 0022
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SELF="$ROOT/os/mkosi"
# shellcheck source=/dev/null
source "$SELF/versions.env"
TREE=${1:?mkosi root tree required}
KERNEL_TREE=${2:?kernel staging tree required}
OUT=${3:?artifact output directory required}
FLAVOR=${4:?flavor required}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:?}
export SOURCE_DATE_EPOCH TZ=UTC LC_ALL=C
mkdir -p "$OUT/files"

kernel="$KERNEL_TREE/usr/lib/modules/$KERNEL_VERSION-dstack/vmlinuz"
install -m0644 "$kernel" "$OUT/files/bzImage"

# Combined squashfs + dm-verity tree, matching Yocto's separate-hash=0 output.
rootfs="$OUT/files/rootfs.squashfs.verity"
# mksquashfs -noappend overwrites its filesystem but does not reliably remove
# a longer dm-verity tail left by a previous invocation.
truncate -s 0 "$rootfs"
# Privileged mkosi runs can inherit host default ACLs from their workspace.
# The guest rootfs does not rely on xattrs, so exclude this host-only metadata.
# A sorted tar stream also removes backing-filesystem directory/inode order and
# hardlink topology from the input. A single compressor worker then avoids
# host-CPU-dependent fragment ordering.
(cd "$TREE" && tar --sort=name --format=gnu \
  --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  --mode=g-s --hard-dereference -cf - .) | \
  env -u SOURCE_DATE_EPOCH mksquashfs - "$rootfs" -tar \
    -noappend -all-root -no-progress -exports -no-hardlinks -no-tailends \
    -no-xattrs -processors 1 -comp zstd -mkfs-time "$SOURCE_DATE_EPOCH" \
    -all-time "$SOURCE_DATE_EPOCH" >/dev/null
data_size=$(stat -c %s "$rootfs")
data_size=$(( (data_size + 4095) / 4096 * 4096 ))
truncate -s "$data_size" "$rootfs"
verity_output=$(veritysetup format "$rootfs" "$rootfs" \
  --hash-offset="$data_size" --data-block-size=4096 --hash-block-size=4096 \
  --uuid=00000000-0000-0000-0000-000000000000 \
  --salt="$(printf '%064x' 0)")
root_hash=$(awk '/Root hash:/ {print $3}' <<<"$verity_output")
[[ $root_hash =~ ^[0-9a-f]{64}$ ]] || { echo "failed to obtain verity root hash" >&2; exit 1; }

# Minimal custom initramfs that implements the same dstack.rootfs_* protocol.
ird=$(mktemp -d "$OUT/.initramfs.XXXXXX")
trap 'rm -rf "$ird"' EXIT
mkdir -p "$ird"/{bin,sbin,dev,proc,sys,run,root,usr/bin,usr/sbin,lib,lib64}
install -m0755 "$TREE/usr/bin/busybox" "$ird/bin/busybox"
for applet in sh mount mkdir cat grep head cut basename realpath switch_root; do
  ln -s busybox "$ird/bin/$applet"
done
verity_bin=$(find "$TREE" -type f \( -path '*/sbin/veritysetup' -o -path '*/bin/veritysetup' \) | head -1)
[[ -n $verity_bin ]] || { echo 'veritysetup missing from mkosi tree' >&2; exit 1; }
install -m0755 "$verity_bin" "$ird/sbin/veritysetup"
command -v lddtree >/dev/null || { echo 'lddtree (pax-utils) is required' >&2; exit 1; }
while read -r lib; do
  [[ $lib == "$verity_bin" ]] && continue
  rel=${lib#"$TREE"}
  [[ $rel == /* ]] || continue
  install -Dm0755 "$lib" "$ird$rel"
done < <(lddtree -l -R "$TREE" "${verity_bin#"$TREE"}")
install -m0755 "$ROOT/os/yocto/layers/meta-dstack/recipes-core/images/dstack-initscript/init" "$ird/init"
find "$ird" -print0 | xargs -0 touch -h -d "@$SOURCE_DATE_EPOCH"
(cd "$ird" && find . -print0 | sort -z | \
  cpio --null -o --format=newc --reproducible --owner=0:0 2>/dev/null) \
  | gzip -n -9 > "$OUT/files/initramfs.cpio.gz"

# OVMF is the pinned TDX build; the EFI stub comes from the Debian snapshot.
ovmf="$KERNEL_TREE/ovmf.fd"
ovmf_sev="$KERNEL_TREE/ovmf-sev.fd"
stub=$(find "$TREE/usr/lib/systemd/boot/efi" -type f -name 'linuxx64.efi.stub' | head -1)
[[ -f $ovmf && -f $ovmf_sev && -f $stub ]] || {
  echo 'TDX/SEV OVMF or systemd EFI stub missing' >&2; exit 1;
}
install -m0644 "$ovmf" "$OUT/files/ovmf.fd"
install -m0644 "$ovmf_sev" "$OUT/files/ovmf-sev.fd"

cmdline="console=ttyS0 init=/init panic=1 net.ifnames=0 biosdevname=0 mce=off oops=panic pci=noearly pci=nommconf random.trust_cpu=y random.trust_bootloader=n tsc=reliable no-kvmclock dstack.rootfs_hash=$root_hash dstack.rootfs_size=$data_size"
ukify build --efi-arch=x64 --stub="$stub" --linux="$kernel" \
  --initrd="$OUT/files/initramfs.cpio.gz" --cmdline="$cmdline" \
  --os-release="@$TREE/usr/lib/os-release" \
  --output="$OUT/files/dstack-uki.efi"
touch -d "@$SOURCE_DATE_EPOCH" "$OUT/files/"*

is_dev=false; name=dstack
if [[ $FLAVOR == dev ]]; then is_dev=true; name=dstack-dev; fi
python3 - "$OUT/artifact-manifest.json" "$name" "$FLAVOR" "$is_dev" \
  "${DSTACK_SOURCE_REVISION:?}" "$root_hash" "$data_size" "$DSTACK_VERSION" "$OVMF_VARIANT" <<'PY'
import json, sys
path,name,flavor,is_dev,revision,root_hash,data_size,version,ovmf_variant=sys.argv[1:]
data={"schema_version":1,"backend":"mkosi","image":{"name":name,"version":version,
"flavor":flavor,"is_dev":is_dev=="true"},"source":{"git_revision":revision},
"boot":{"ovmf_variant":ovmf_variant},"verity":{"root_hash":root_hash,"data_size":data_size},
"artifacts":{"initramfs":"files/initramfs.cpio.gz","kernel":"files/bzImage",
"firmware":"files/ovmf.fd","rootfs_verity":"files/rootfs.squashfs.verity",
"firmware_sev":"files/ovmf-sev.fd","uki":"files/dstack-uki.efi"},
"backend_metadata":{"machine":"dstack","distribution":"debian"}}
with open(path,"w") as f: json.dump(data,f,indent=2); f.write("\n")
PY
