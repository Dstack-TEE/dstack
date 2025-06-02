#!/bin/bash
set -e

WORK_DIR="/var/volatile/dstack"
DATA_MNT="$WORK_DIR/persistent"

# Prepare volatile dirs
mount_overlay() {
    local src=$1
    local dst=/var/volatile/$1
    mkdir -p $dst/upper $dst/work
    mount -t overlay overlay -o lowerdir=$src,upperdir=$dst/upper,workdir=$dst/work $src
}
mount_overlay /etc/wireguard
mount_overlay /etc/docker
mount_overlay /usr/bin
mount_overlay /home/root

# Disable the containerd-shim-runc-v2 temporarily to prevent the containers from starting
# before docker compose removal orphans. It will be enabled in app-compose.sh
chmod -x /usr/bin/containerd-shim-runc-v2

# Make sure the system time is synchronized
echo "Syncing system time..."
# Let the chronyd correct the system time immediately
chronyc makestep

modprobe tdx-guest

# Setup dstack system
echo "Preparing dstack system..."
dstack-util setup --work-dir $WORK_DIR --device /dev/vdb --mount-point $DATA_MNT

echo "Mounting docker dirs to persistent storage"
# Mount docker dirs to DATA_MNT
mkdir -p $DATA_MNT/var/lib/docker
mount --bind $DATA_MNT/var/lib/docker /var/lib/docker
mount --bind $WORK_DIR /dstack
