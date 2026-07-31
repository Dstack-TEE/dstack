#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=/run/dstack-test-host-shared
MOUNT_POINT=$ROOT/mount
DISK=$ROOT/host-shared.img
BAD_DISK=$ROOT/bad.img
LABEL_LINK=/dev/disk/by-label/DSTACKSHR
GOOD_LOOP=
BAD_LOOP=
checks=0
check() { "$@"; checks=$((checks + 1)); }
# shellcheck disable=SC2317
cleanup() {
  set +e
  mountpoint -q "$MOUNT_POINT" && umount -l "$MOUNT_POINT"
  rm -f "$LABEL_LINK"
  test -n "$GOOD_LOOP" && losetup -d "$GOOD_LOOP" 2>/dev/null
  test -n "$BAD_LOOP" && losetup -d "$BAD_LOOP" 2>/dev/null
  rm -rf "$ROOT"
}
trap cleanup EXIT
mkdir -p "$MOUNT_POINT" /dev/disk/by-label
before_mounts=$(awk '$3=="9p" && $2 ~ /dstack-test-host-shared/{n++} END{print n+0}' /proc/mounts)
share_hash=$(sha256sum /dstack/.host-shared/.sys-config.json | awk '{print $1}')

truncate -s 16M "$DISK"
check mkfs.ext4 -q -L DSTACKSHR "$DISK"
GOOD_LOOP=$(losetup --find --show "$DISK")
mkdir -p "$ROOT/seed"
check mount "$GOOD_LOOP" "$ROOT/seed"
printf 'disk-source-ok\n' >"$ROOT/seed/source-marker"
sync
check umount "$ROOT/seed"
ln -sfn "$GOOD_LOOP" "$LABEL_LINK"
check dstack-util host-shared mount --mount-point "$MOUNT_POINT"
check mountpoint -q "$MOUNT_POINT"
check test "$(cat "$MOUNT_POINT/source-marker")" = disk-source-ok
check sh -c "findmnt -no OPTIONS '$MOUNT_POINT' | grep -Eq '(^|,)ro(,|$)'"
check test "$(findmnt -no SOURCE "$MOUNT_POINT")" = "$GOOD_LOOP"
check dstack-util host-shared unmount --mount-point "$MOUNT_POINT"
check sh -c "! mountpoint -q '$MOUNT_POINT'"
set +e
dstack-util host-shared unmount --mount-point "$MOUNT_POINT" >"$ROOT/duplicate-unmount.log" 2>&1
duplicate_unmount_rc=$?
set -e
check test "$duplicate_unmount_rc" -ne 0

rm -f "$LABEL_LINK"
losetup -d "$GOOD_LOOP"
GOOD_LOOP=
truncate -s 1M "$BAD_DISK"
BAD_LOOP=$(losetup --find --show "$BAD_DISK")
ln -sfn "$BAD_LOOP" "$LABEL_LINK"
check dstack-util host-shared mount --mount-point "$MOUNT_POINT"
check test "$(findmnt -no FSTYPE "$MOUNT_POINT")" = 9p
check test "$(sha256sum "$MOUNT_POINT/.sys-config.json" | awk '{print $1}')" = "$share_hash"
check dstack-util host-shared unmount --mount-point "$MOUNT_POINT"

rm -f "$LABEL_LINK"
losetup -d "$BAD_LOOP"
BAD_LOOP=
mkdir -p "$ROOT/fake-bin"
cat >"$ROOT/fake-bin/mount" <<'FAKE'
#!/bin/sh
printf 'injected mount dependency failure\n' >&2
exit 77
FAKE
chmod +x "$ROOT/fake-bin/mount"
set +e
env PATH="$ROOT/fake-bin:/bin:/usr/bin" dstack-util host-shared mount --mount-point "$MOUNT_POINT" >"$ROOT/dependency-fault.log" 2>&1
dependency_rc=$?
set -e
check test "$dependency_rc" -ne 0
check sh -c "! mountpoint -q '$MOUNT_POINT'"
check dstack-util host-shared mount --mount-point "$MOUNT_POINT"
check test "$(findmnt -no FSTYPE "$MOUNT_POINT")" = 9p
check dstack-util host-shared unmount --mount-point "$MOUNT_POINT"

rm -rf "$MOUNT_POINT"
printf invalid >"$MOUNT_POINT"
set +e
dstack-util host-shared mount --mount-point "$MOUNT_POINT" >"$ROOT/invalid-target.log" 2>&1
invalid_target_rc=$?
set -e
check test "$invalid_target_rc" -ne 0
check test -f "$MOUNT_POINT"
rm -f "$MOUNT_POINT"
mkdir -p "$MOUNT_POINT"
after_mounts=$(awk '$3=="9p" && $2 ~ /dstack-test-host-shared/{n++} END{print n+0}' /proc/mounts)
check test "$after_mounts" -eq "$before_mounts"
check sh -c "! losetup -j '$DISK' | grep -q ."
printf '{"checks":%d,"disk_source":true,"disk_read_only":true,"invalid_disk_fallback_9p":true,"nine_p_content_hash_matched":true,"duplicate_unmount_rejected":true,"dependency_fault_rejected":true,"dependency_recovery":true,"invalid_target_rejected":true,"mount_count_restored":true}\n' "$checks"
