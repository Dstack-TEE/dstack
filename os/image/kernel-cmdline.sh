# SPDX-FileCopyrightText: Copyright (c) Hashforest Technology LLC
#
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

# `pci=nommconf` is deliberately absent. It confines PCI config space access to
# the legacy CF8h/CFCh port I/O path, which physically cannot reach past the
# first 256 bytes, so `pci_find_ext_capability()` short-circuits on
# `dev->cfg_size <= PCI_CFG_SPACE_SIZE` and the whole PCIe extended config space
# (offset >= 0x100) becomes unreadable. Blackwell GPU drivers walk that space to
# find NVIDIA's vendor DVSEC; with MMCONFIG off the reads return 0xFFFFFFFF, the
# driver asserts on every probe, and every later cuInit() fails with
# CUDA_ERROR_SYSTEM_NOT_READY (802). There is no substitute mechanism, so GPU
# passthrough requires MMCONFIG.
#
# `pci=noearly` is kept. It gates a different mechanism -- early type 1 scanning,
# which runs before ACPI is parsed and dispatches into vendor fixups keyed on the
# vendor/device/class triple read straight out of a host-controlled config space.
# GPU drivers bind during normal PCI enumeration and do not depend on it, and
# Intel's confidential-computing guest hardening names early PCI code as
# something to disable, so it stays off.

# Emit the guest kernel command line.
#   $1 dm-verity root hash
#   $2 rootfs data size in bytes
dstack_kernel_cmdline() {
    local root_hash=${1:?root hash required}
    local data_size=${2:?data size required}
    echo "console=ttyS0 init=/init panic=1 net.ifnames=0 biosdevname=0" \
         "mce=off oops=panic pci=noearly random.trust_cpu=y" \
         "random.trust_bootloader=n tsc=reliable no-kvmclock" \
         "dstack.rootfs_hash=$root_hash dstack.rootfs_size=$data_size"
}
