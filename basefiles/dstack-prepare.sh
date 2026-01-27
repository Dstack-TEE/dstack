#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -e

log() {
	printf '%s\n' "$*" >&2
}

CMDLINE=$(cat /proc/cmdline)

get_cmdline_value() {
	local key="$1"
	for param in $CMDLINE; do
		case "$param" in
		"$key="*)
			echo "${param#*=}"
			return 0
			;;
		esac
	done
	return 1
}

read_uevent_property() {
	local file="$1"
	local key="$2"
	while IFS='=' read -r name value; do
		if [ "$name" = "$key" ]; then
			printf "%s" "$value"
			return 0
		fi
	done <"$file"
	return 1
}

find_block_by_property() {
	local key="$1"
	local value="$2"
	for entry in /sys/class/block/*; do
		[ -e "$entry/uevent" ] || continue
		local current
		current=$(read_uevent_property "$entry/uevent" "$key" || true)
		if [ "$current" = "$value" ]; then
			printf "/dev/%s" "$(basename "$entry")"
			return 0
		fi
	done
	return 1
}

resolve_block_spec() {
	local spec="$1"
	local device=""
	case "$spec" in
	"")
		return 1
		;;
	PARTLABEL=*)
		device=$(find_block_by_property PARTNAME "${spec#PARTLABEL=}" || true)
		;;
	PARTUUID=*)
		device=$(find_block_by_property PARTUUID "${spec#PARTUUID=}" || true)
		;;
	/dev/*)
		device="$spec"
		;;
	esac
	if [ -n "$device" ] && [ -b "$device" ]; then
		printf "%s" "$device"
		return 0
	fi
	return 1
}

WORK_DIR="/var/volatile/dstack"
DATA_MNT="$WORK_DIR/persistent"

OVERLAY_TMP="/var/volatile/overlay"
OVERLAY_PERSIST="$DATA_MNT/overlay"

# Prepare volatile dirs
mount_overlay() {
    local src=$1
    local dst=$2/$1
    mkdir -p $dst/upper $dst/work
    mount -t overlay overlay -o lowerdir=$src,upperdir=$dst/upper,workdir=$dst/work $src
}
mount_overlay /etc $OVERLAY_TMP
mount_overlay /usr $OVERLAY_TMP
mount_overlay /bin $OVERLAY_TMP
mount_overlay /home $OVERLAY_TMP

# Make sure the system time is synchronized
log "Syncing system time..."
# Let the chronyd correct the system time immediately
chronyc makestep

if ! [[ -e /dev/tdx_guest ]]; then
	modprobe tdx-guest
fi

# Setup configfs and TSM for TDX attestation
setup_tsm() {
	if ! grep -q configfs /proc/filesystems; then
		log "Warning: configfs not available in kernel, TSM may not work"
		return 1
	fi
	if ! mountpoint -q /sys/kernel/config 2>/dev/null; then
		log "Mounting configfs for TSM..."
		mount -t configfs none /sys/kernel/config
	fi
	if [[ -e /dev/tdx_guest ]] && [[ ! -d /sys/kernel/config/tsm/report/com.intel.dcap ]]; then
		log "Creating TSM report directory..."
		mkdir -p /sys/kernel/config/tsm/report/com.intel.dcap
	fi
}
setup_tsm || true

# Setup dstack system
log "Preparing dstack system..."

has_partition_table() {
	local disk="$1"
	local disk_name=$(basename "$disk")
	# Check sysfs for any child partitions
	for entry in /sys/class/block/${disk_name}/${disk_name}*; do
		[ -e "$entry/partition" ] || continue
		return 0
	done
	return 1
}

has_luks_header() {
	cryptsetup isLuks "$1" 2>/dev/null && return 0
	return 1
}

create_data_partition() {
	local disk="$1"
	log "Creating GPT partition table on ${disk}..."
	if ! command -v sgdisk >/dev/null 2>&1; then
		log "Error: sgdisk not available, cannot create partition table"
		return 1
	fi
	# Create GPT with single partition filling entire disk
	sgdisk -Z "$disk" >/dev/null || true # Zap any existing data
	sgdisk -n 1:1MiB:0 -c 1:dstack-data -t 1:8300 "$disk" >/dev/null || return 1
	# Trigger kernel to re-read partition table
	blockdev --rereadpt "$disk" >/dev/null || true
	udevadm settle >/dev/null || sleep 1
	part_device=$(
		lsblk -nr -o PATH "$disk" 2>/dev/null | sed -n '2p'
	)
	if [ -n "$part_device" ] && [ -b "$part_device" ]; then
		log "Created partition: $part_device"
		echo "$part_device"
		return 0
	fi
	log "Failed to create partition"
	return 1
}

choose_data_device() {
	local override="$1"
	local dev=""

	# 1. Check explicit override first
	if [ -n "$override" ]; then
		dev=$(resolve_block_spec "$override" || true)
		if [ -n "$dev" ]; then
			echo "$dev"
			return 0
		fi
		log "Warning: dstack data device override '$override' not found"
	fi

	# 2. Try to find partition with PARTLABEL=dstack-data
	local data_disk
	data_disk=$(resolve_block_spec "PARTLABEL=dstack-data" || true)
	if [ -n "$data_disk" ]; then
		echo "$data_disk"
		return 0
	fi

	# 3. Fallback to /dev/vdb for backward compatibility
	if [ ! -b /dev/vdb ]; then
		log "Error: No dstack-data partition found and /dev/vdb does not exist"
		return 1
	fi

	# 3.1. Check if /dev/vdb has LUKS header (0.5.x upgrade path)
	if has_luks_header /dev/vdb; then
		log "Detected LUKS on /dev/vdb (dstack 0.5.x upgrade), using whole disk"
		echo /dev/vdb
		return 0
	fi

	# 3.2. Check if /dev/vdb has partition table
	if has_partition_table /dev/vdb; then
		log "Error: /dev/vdb has partition table but no 'dstack-data' partition found"
		log "Please check partition labels or specify dstack.data_device kernel parameter"
		return 1
	fi

	# 3.3. /dev/vdb is empty, create partition table
	log "Empty disk detected at /dev/vdb, creating dstack-data partition..."
	local new_partition
	new_partition=$(create_data_partition /dev/vdb)
	if [ -z "$new_partition" ]; then
		log "Error: Failed to create partition on /dev/vdb"
		return 1
	fi
	echo "$new_partition"
	return 0
}

DATA_DEVICE_OVERRIDE=$(get_cmdline_value "dstack.data_device" || true)
if [ -z "$DATA_DEVICE_OVERRIDE" ] && [ -n "$DSTACK_DATA_DEVICE" ]; then
	DATA_DEVICE_OVERRIDE="$DSTACK_DATA_DEVICE"
fi
DATA_DEVICE=$(choose_data_device "$DATA_DEVICE_OVERRIDE" || true)
if [ ! -b "$DATA_DEVICE" ]; then
	log "Persistent data disk $DATA_DEVICE not found"
	exit 1
fi
log "Using persistent data disk $DATA_DEVICE"

# Auto-grow partition if disk was expanded
device_name=$(basename "$DATA_DEVICE")
if [ -f "/sys/class/block/${device_name}/partition" ]; then
	log "Detected partition ${DATA_DEVICE}, checking if parent disk was expanded..."

	parent_disk=$(lsblk -no PKNAME "$DATA_DEVICE" 2>/dev/null | head -n1 || true)
	if [ -n "$parent_disk" ]; then
		parent_disk="/dev/${parent_disk}"
	fi

	if [ -n "$parent_disk" ] && [ -b "$parent_disk" ]; then
		log "Parent disk: ${parent_disk}"
		if command -v sgdisk >/dev/null 2>&1; then
			log "Refreshing GPT on ${parent_disk}..."
			sgdisk -e "$parent_disk" 2>/dev/null || true
		fi
		if command -v parted >/dev/null 2>&1; then
			part_num=$(cat "/sys/class/block/${device_name}/partition" 2>/dev/null || echo "")
			if [ -n "$part_num" ]; then
				log "Growing partition ${part_num} on ${parent_disk} via parted..."
				parted --script "$parent_disk" resizepart "$part_num" 100% 2>/dev/null || log "Partition already at maximum size"
			fi
		else
			log "Warning: parted not available; unable to auto-resize ${DATA_DEVICE}"
		fi
		# Trigger kernel to re-read partition table
		blockdev --rereadpt "$parent_disk" 2>/dev/null || true
	fi
fi

dstack-util setup --work-dir $WORK_DIR --device "$DATA_DEVICE" --mount-point $DATA_MNT

log "Mounting docker dirs to persistent storage"
# Mount docker dirs to DATA_MNT
mkdir -p $DATA_MNT/var/lib/docker
mkdir -p $DATA_MNT/var/lib/containerd
# Create mount points (containerd may not have started yet to create them)
mkdir -p /var/lib/docker
mkdir -p /var/lib/containerd
mount --rbind $DATA_MNT/var/lib/docker /var/lib/docker
mount --rbind $DATA_MNT/var/lib/containerd /var/lib/containerd
mount --rbind $WORK_DIR /dstack

echo "======== Disk usage ========"
df -h
echo "============================"

cd /dstack

if [ $(jq 'has("init_script")' app-compose.json) == true ]; then
	log "Running init script"
	dstack-util notify-host -e "boot.progress" -d "init-script" || true
	source <(jq -r '.init_script' app-compose.json)
fi

RUNNER=$(jq -r '.runner' app-compose.json)
case "$RUNNER" in
docker-compose)
	if [[ ! -f docker-compose.yaml ]]; then
		jq -r '.docker_compose_file' app-compose.json >docker-compose.yaml
	fi
	dstack-util remove-orphans --no-dockerd -f docker-compose.yaml || true
	;;
esac
