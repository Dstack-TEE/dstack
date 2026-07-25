# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# Single definition of the guest kernel command line.
#
# This string is measured twice over: it is baked into the UKI whose PE
# sections feed the GCP and AWS measurements, and it is recorded in
# metadata.json, from which dstack-mr derives the TDX RTMRs. A backend that
# builds the UKI and the assembler that writes metadata.json therefore have to
# agree exactly. They used to construct it independently, so a token added to
# one would have produced measurements describing a command line the guest
# never booted with -- and every existing check would still have passed.

# Emit the guest kernel command line.
#   $1 dm-verity root hash
#   $2 rootfs data size in bytes
dstack_kernel_cmdline() {
    local root_hash=${1:?root hash required}
    local data_size=${2:?data size required}
    echo "console=ttyS0 init=/init panic=1 net.ifnames=0 biosdevname=0" \
         "mce=off oops=panic pci=noearly pci=nommconf random.trust_cpu=y" \
         "random.trust_bootloader=n tsc=reliable no-kvmclock" \
         "dstack.rootfs_hash=$root_hash dstack.rootfs_size=$data_size"
}
