FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

LINUX_VERSION_EXTENSION = "-dstack"

SRC_URI += "file://dstack-docker.cfg \
            file://dstack-docker.scc \
            file://dstack-aws.cfg \
            file://dstack-aws.scc \
            file://dstack-tdx.cfg \
            file://dstack-tdx.scc \
            file://dstack-sysbox.cfg \
            file://dstack-sysbox.scc \
            file://dstack.cfg \
            file://dstack.scc"

# TDX guests need DMA_DIRECT_REMAP for shared (decrypted) coherent DMA so
# devices like NVMe can complete I/O. INTEL_TDX_GUEST does not select it
# upstream (and the symbol is promptless, so a .cfg fragment cannot set it),
# hence this Kconfig patch. Only touches the INTEL_TDX_GUEST Kconfig, so it is
# a no-op on AMD; scoped to the dstack confidential-guest machine.
SRC_URI:append:dstack = " file://0001-x86-tdx-select-dma-direct-remap.patch"

# Confidential guests are exposed to malicious ACPI tables supplied by the
# host: crafted AML can read/write the guest's encrypted (private) memory
# through the SystemMemory operation region handler. This "BadAML sandbox"
# walks the page tables and denies AML SystemMemory accesses that target
# encrypted pages, logging each decision. Ported from the Easy-TEE project.
# Applied unconditionally: dstack OS always runs inside a TEE, so every
# build needs this hardening (the hook is a runtime no-op when the platform
# reports no memory encryption).
SRC_URI:append = " file://0002-acpi-sandbox-block-aml-systemmemory-ram-access.patch"

# Upstream fixes for the atomic DMA pool on confidential guests, backported
# from the dma-mapping tree merged for v7.3 and absent from linux-6.18.y.
# 0001 above turns on DMA_DIRECT_REMAP, and with it atomic_pool_expand()
# registers each pool chunk in the gen_pool under the remapped virtual
# address returned by dma_common_contiguous_remap(). Both fixes are cases of
# dma-direct reconstructing a direct-map address from a struct page, which no
# longer matches that registration:
#
#   0003 dma_direct_alloc_pages() returns the CPU address from
#        dma_direct_alloc_from_pool() cast to a struct page * on the
#        atomic-pool path. Carries Cc: stable upstream.
#   0004 dma_direct_free_pages() looks the chunk up by page_address(), the
#        lookup misses, and the page is re-encrypted and returned to the page
#        allocator while the pool still owns it.
#
# Applied unconditionally: upstream bug fixes, inert on builds where the
# atomic DMA pool is never used.
SRC_URI:append = " file://0003-dma-direct-return-struct-page-from-alloc-from-pool.patch \
                   file://0004-dma-pool-free-atomic-pool-pages-by-physical-address.patch"

KERNEL_FEATURES:append = " features/cgroups/cgroups.scc \
                          features/overlayfs/overlayfs.scc \
                          features/netfilter/netfilter.scc \
                          features/fuse/fuse.scc \
                          features/xfs/xfs.scc \
                          cfg/fs/squashfs.scc \
                          dstack-docker.scc \
                          dstack-sysbox.scc \
                          dstack.scc"

KERNEL_FEATURES:append = " ${@bb.utils.contains("DISTRO_FEATURES", "dm-verity", " features/device-mapper/dm-verity.scc", "" ,d)}"

# Unified dstack confidential-guest machine. A single kernel image that boots
# on both Intel TDX and AMD SEV-SNP hosts (the kernel detects the platform at
# runtime). The base guest features and the tdx.scc / sev-snp.scc kconf
# fragments are reused from meta-confidential-compute; enabling both TDX and
# SEV here is what makes one image work on either platform.
KMACHINE:dstack ?= "common-pc-64"
COMPATIBLE_MACHINE:dstack = "^dstack$"
KERNEL_FEATURES:append:dstack = " features/scsi/disk.scc \
                                  cfg/virtio.scc \
                                  cfg/paravirt_kvm.scc \
                                  cfg/fs/ext4.scc \
                                  tdx.scc \
                                  sev-snp.scc \
                                  tpm2.scc \
                                  hyperv.scc \
                                  security-mitigations.scc \
                                  disk-encryption.scc \
                                  dstack-aws.scc \
                                  dstack-tdx.scc"

# disk-encryption.scc (above, from meta-confidential-compute) ships dm-crypt
# for the encrypted data volume but explicitly turns CONFIG_DM_VERITY off. The
# dstack rootfs is dm-verity, so re-enable it here -- this is the last dm-verity
# fragment in KERNEL_FEATURES for the dstack machine, so it wins the merge.
KERNEL_FEATURES:append:dstack = " ${@bb.utils.contains("DISTRO_FEATURES", "dm-verity", " features/device-mapper/dm-verity.scc", "", d)}"

# Enable BTF
KERNEL_DEBUG = "True"

do_deploy:append() {
    install -m 0644 ${B}/.config ${DEPLOYDIR}/kernel-config
}
