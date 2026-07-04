#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Mount the verity volumes declared in app-compose.json and seed them into the CVM.
#
# Each volume has a target. A "docker" target seeds the docker overlay2 store, so
# its images become cache hits. A "/path" target mounts the volume's filesystem
# there, for data like model weights.
#
# This runs from dstack-prepare.sh before dockerd starts, so there is no restart.
#
# The host only supplies the bytes. Each volume is matched and verified against
# the measured verity_root from app-compose. Everything here is fail-safe: a
# volume that is missing or fails verification is skipped, and its images pull
# normally. See docs/verity-volumes.md.

COMPOSE="${1:-app-compose.json}"
STORE=/var/lib/docker

log() { echo "dstack-verity: $*"; }

# Nothing to do unless the compose file declares verity_volumes.
[ -f "$COMPOSE" ] || exit 0
count=$(jq '(.verity_volumes // []) | length' "$COMPOSE" 2>/dev/null || echo 0)
[ "${count:-0}" -gt 0 ] || exit 0
log "$count verity volume(s) requested"

if ! command -v veritysetup >/dev/null 2>&1; then
    log "veritysetup missing; skipping (images will pull)"
    exit 0
fi
modprobe dm-verity 2>/dev/null || true

# Candidate whole-disk block devices. Volumes are identified by root hash, not by
# name or attach order. The host tags each verity disk's serial with the root
# prefix, so the matching disk can be opened directly; a missing or wrong tag
# falls back to trying every disk.
mapfile -t DEVS < <(lsblk -dnro NAME,TYPE 2>/dev/null | awk '$2=="disk"{print "/dev/"$1}')

# Detect a device's filesystem from its magic bytes.
# `dstack verity` writes squashfs; ext4 is accepted too for hand-built volumes.
fs_type() { # $1 = device -> squashfs | ext4 | (empty)
    local magic
    # squashfs magic "hsqs" is at offset 0.
    magic=$(dd if="$1" bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$magic" = "68737173" ] && { echo squashfs; return; }
    # ext4 magic 0xEF53 (little-endian on disk) is at byte 1080.
    magic=$(dd if="$1" bs=1 skip=1080 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$magic" = "53ef" ] && echo ext4
}

# Byte size of the filesystem on $1.
#
# This is also the verity hash-tree offset, because a volume is laid out
# [ filesystem ][ hash tree ]. The size is read from the superblock and rounded
# up to a 4096 block. squashfs and ext4 record it differently.
#
# The superblock is untrusted, but that is safe. A tampered size just gives a
# wrong offset, and the verity open in open_volume then fails.
data_size() { # $1 = device, $2 = fs_type -> bytes (block-aligned)
    local bytes byte i=0 info block_count block_size
    case "$2" in
        squashfs)
            # bytes_used is a little-endian u64 at superblock offset 40. Rebuild
            # it byte by byte, low byte first.
            bytes=0
            for byte in $(dd if="$1" bs=1 skip=40 count=8 2>/dev/null | od -An -tu1); do
                bytes=$((bytes + byte * (1 << (8 * i))))
                i=$((i + 1))
            done
            # round up to the 4096 block boundary.
            [ "$bytes" -gt 0 ] && echo $(((bytes + 4095) / 4096 * 4096)) ;;
        ext4)
            info=$(dumpe2fs -h "$1" 2>/dev/null) || return 1
            block_count=$(awk -F: '/Block count/{gsub(/ /,"",$2);print $2;exit}' <<<"$info")
            block_size=$(awk -F: '/Block size/{gsub(/ /,"",$2);print $2;exit}' <<<"$info")
            [ -n "$block_count" ] && [ -n "$block_size" ] && echo $((block_count * block_size)) ;;
    esac
}

# Probe every candidate disk once, recording "dev fs off serial" for each that
# looks like a verity volume. Doing this once keeps per-volume matching cheap.
DEV_INFO=()
scan_devices() {
    local dev fs off serial
    for dev in "${DEVS[@]}"; do
        fs=$(fs_type "$dev") || continue
        [ -n "$fs" ] || continue
        off=$(data_size "$dev" "$fs") || continue
        { [ -n "$off" ] && [ "$off" -gt 0 ]; } || continue
        serial=$(cat "/sys/block/$(basename "$dev")/serial" 2>/dev/null)
        DEV_INFO+=("$dev $fs $off $serial")
    done
}

# Open $dev as /dev/mapper/$name if it verifies against $root.
# On success, echoes "/dev/mapper/$name <fs_type>".
try_open() { # $1 = dev, $2 = fs, $3 = off, $4 = root, $5 = name
    local dev="$1" fs="$2" off="$3" root="$4" name="$5"
    # $dev is both the data device and the hash device: it's one file, and
    # --hash-offset is where the hash tree starts inside it.
    veritysetup open "$dev" "$name" "$dev" "$root" --hash-offset="$off" \
        >/dev/null 2>&1 || return 1
    # Confirm the root matches: reading through verity must not fault.
    if dd if="/dev/mapper/$name" of=/dev/null bs=4096 count=1 >/dev/null 2>&1; then
        echo "/dev/mapper/$name $fs"
        return 0
    fi
    veritysetup close "$name" >/dev/null 2>&1
    return 1
}

# Open the volume matching $root as /dev/mapper/$name.
#
# First try the disk the host tagged for this root (its serial is the root
# prefix). That is the common path: one open, no probing. If nothing matches the
# tag, or it fails to verify, fall back to trying every disk.
open_volume() { # $1 = root hash, $2 = mapper name
    local root="$1" name="$2" entry dev fs off serial
    for entry in "${DEV_INFO[@]}"; do
        read -r dev fs off serial <<<"$entry"
        if [ -z "$serial" ] || [ "$serial" != "${root:0:20}" ]; then
            continue
        fi
        try_open "$dev" "$fs" "$off" "$root" "$name" && return 0
    done
    for entry in "${DEV_INFO[@]}"; do
        read -r dev fs off serial <<<"$entry"
        try_open "$dev" "$fs" "$off" "$root" "$name" && return 0
    done
    return 1
}

# Mount a verity-mapped device read-only, choosing per-fs options.
mount_ro() { # $1 = device, $2 = fs_type, $3 = mountpoint
    case "$2" in
        # noload: skip journal replay -- the device is read-only.
        ext4) mount -t ext4 -o ro,noload "$1" "$3" 2>/dev/null ;;
        *)    mount -t "$2" -o ro "$1" "$3" 2>/dev/null ;;
    esac
}

# True if $1 is a mountpoint (the spaces anchor the match to the whole field).
is_mounted() { grep -qsF " $1 " /proc/self/mountinfo; }

# umount the binds this seeding made -- undoes a partial seed. A no-op on reboot,
# where the diffs are already mounted so nothing was added to $bound.
unwind_binds() { local mp; for mp in "$@"; do umount "$mp" 2>/dev/null; done; }

# Seed the docker overlay2 store from a mounted volume.
#
# Bind-mount each big, already-extracted layer diff read-only, then copy the
# small metadata. No pull, no extraction. Contents merge into whatever is already
# in the store, so several volumes can seed one store.
#
# The diff binds are redone on every boot. /var/lib/docker is persistent, but
# bind mounts are not, so a reboot starts with empty diff/ dirs. The binds must
# go in before the metadata, or the metadata would point at empty layers.
#
# On any bind failure this copies no metadata and returns non-zero, so docker
# pulls the image cleanly instead of running it with empty layers.
seed_docker() { # $1 = mounted volume dir
    local vol="$1" layer_dir id file base repo src
    local bound=()

    # 1. (re)bind every layer's read-only diff. If one fails, unwind the binds
    #    done so far and bail, before any metadata is written.
    for layer_dir in "$vol"/overlay2/*/; do
        [ -d "$layer_dir" ] || continue
        id=$(basename "$layer_dir")
        [ "$id" = l ] && continue # `l/` is docker's symlink dir, not a layer
        mkdir -p "$STORE/overlay2/$id/diff"
        if ! is_mounted "$STORE/overlay2/$id/diff"; then
            if mount --bind "$layer_dir/diff" "$STORE/overlay2/$id/diff"; then
                bound+=("$STORE/overlay2/$id/diff")
            else
                unwind_binds "${bound[@]}"
                return 1
            fi
        fi
    done

    # 2. metadata (content-addressed) -- merge by copying directory *contents*
    #    (a plain `cp dir store/` would nest or clobber on the second volume). On
    #    any copy failure (e.g. a full disk), unwind this volume's binds and bail,
    #    so docker pulls cleanly instead of running against a half-written store.
    mkdir -p "$STORE/image/overlay2/imagedb" "$STORE/image/overlay2/layerdb" "$STORE/overlay2/l"
    if ! { cp -a "$vol/image/overlay2/imagedb/." "$STORE/image/overlay2/imagedb/" &&
        cp -a "$vol/image/overlay2/layerdb/." "$STORE/image/overlay2/layerdb/" &&
        cp -a "$vol/overlay2/l/." "$STORE/overlay2/l/"; } 2>/dev/null; then
        unwind_binds "${bound[@]}"
        return 1
    fi

    # repositories.json is a single name->id map; merge it rather than overwrite,
    # or a second volume would drop the first volume's image names. A failed merge
    # (which leaves the old map, missing this volume's names) also unwinds and bails.
    repo="$STORE/image/overlay2/repositories.json"
    src="$vol/image/overlay2/repositories.json"
    if [ -f "$repo" ] && command -v jq >/dev/null 2>&1; then
        if ! { jq -s '.[0] * .[1]' "$repo" "$src" > "$repo.tmp" 2>/dev/null && mv "$repo.tmp" "$repo"; }; then
            rm -f "$repo.tmp"
            unwind_binds "${bound[@]}"
            return 1
        fi
    elif ! cp -a "$src" "$repo" 2>/dev/null; then
        unwind_binds "${bound[@]}"
        return 1
    fi

    # 3. per-layer small writable files (link/lower), copied once. The layer dir
    #    stays writable because docker writes a `committed` marker into it.
    for layer_dir in "$vol"/overlay2/*/; do
        [ -d "$layer_dir" ] || continue
        id=$(basename "$layer_dir")
        [ "$id" = l ] && continue
        [ -e "$STORE/overlay2/$id/link" ] && continue
        for file in "$layer_dir"*; do
            base=$(basename "$file")
            [ "$base" = diff ] && continue
            cp -a "$file" "$STORE/overlay2/$id/" 2>/dev/null
        done
    done
    return 0
}

# Scan the disks once, then match each declared volume to its disk.
scan_devices
for i in $(seq 0 $((count - 1))); do
    root=$(jq -r ".verity_volumes[$i].verity_root // empty" "$COMPOSE")
    target=$(jq -r ".verity_volumes[$i].target // empty" "$COMPOSE")
    if [ -z "$root" ] || [ -z "$target" ]; then
        log "vol $i: missing verity_root/target; skip"
        continue
    fi

    read -r mapped fs < <(open_volume "$root" "verity$i")
    if [ -z "$mapped" ]; then
        log "vol $i ($target): no attached device matches ${root:0:12}...; skip (will pull)"
        continue
    fi

    if [ "$target" = docker ]; then
        # Mount on /run: it's a writable tmpfs, and the rootfs is read-only.
        mnt="/run/dstack-verity/$i"
        mkdir -p "$mnt"
        if mount_ro "$mapped" "$fs" "$mnt" && seed_docker "$mnt"; then
            log "vol $i: seeded docker store from ${root:0:12}..."
        else
            log "vol $i: seeding failed; skipping (images will pull)"
            # umount first: veritysetup close fails on a still-mounted device.
            umount "$mnt" 2>/dev/null
            veritysetup close "verity$i" 2>/dev/null
        fi
    else
        # The target must be on a writable fs (the rootfs is read-only), e.g. /run.
        if mkdir -p "$target" 2>/dev/null && mount_ro "$mapped" "$fs" "$target"; then
            log "vol $i: mounted ${root:0:12}... at $target"
        else
            log "vol $i: mount at $target failed (is it a writable path?); skipping"
            veritysetup close "verity$i" 2>/dev/null
        fi
    fi
done
exit 0
