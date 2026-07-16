SUMMARY = "Development-only TEE ABI simulator for dstack"
DESCRIPTION = "Extensible TEE-platform simulator whose default TDX backend lets the development guest image exercise the production TDX userspace path on a non-TEE QEMU VM"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COREBASE}/meta/files/common-licenses/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

inherit systemd

DSTACK_MONOREPO_ROOT ?= "${@os.path.realpath(os.path.join(d.getVar('THISDIR'), '../../../../../..'))}"
DSTACK_CORE_SRC ?= "${DSTACK_MONOREPO_ROOT}/dstack"
DSTACK_RUST_SDK_SRC ?= "${DSTACK_MONOREPO_ROOT}/sdk/rust"
DSTACK_ROOTFS_SRC ?= "${DSTACK_MONOREPO_ROOT}/os/common/rootfs"

S = "${UNPACKDIR}/repo/dstack"
DSTACK_ROOTFS_FILES = "${UNPACKDIR}/repo/os/common/rootfs"

DEPENDS += "rsync-native"
RDEPENDS:${PN} += "fuse3-utils kernel-module-fuse"
do_unpack[depends] += "rsync-native:do_populate_sysroot"

SYSTEMD_SERVICE:${PN} = "dstack-tee-simulator.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"
EXTRA_CARGO_FLAGS = "-p dstack-tee-simulator"

inherit cargo_bin

do_unpack() {
    install -d "${S}" "${UNPACKDIR}/repo/sdk/rust" "${DSTACK_ROOTFS_FILES}"
    rsync -a --exclude=".git" --exclude=".worktrees" --exclude="target" \
        "${DSTACK_CORE_SRC}/" "${S}/"
    rsync -a --exclude=".git" --exclude="target" \
        "${DSTACK_RUST_SDK_SRC}/" "${UNPACKDIR}/repo/sdk/rust/"
    rsync -a "${DSTACK_ROOTFS_SRC}/" "${DSTACK_ROOTFS_FILES}/"
}

do_unpack[cleandirs] = "${UNPACKDIR}/repo"
do_unpack[nostamp] = "1"
do_unpack[vardeps] += "DSTACK_CORE_SRC DSTACK_RUST_SDK_SRC DSTACK_ROOTFS_SRC"

do_configure() {
    cargo_bin_do_configure
}

do_compile() {
    cargo_bin_do_compile
}

do_compile[network] = "1"

do_install() {
    install -d ${D}${bindir} ${D}${systemd_system_unitdir}
    install -m 0755 ${CARGO_BINDIR}/dstack-tee-simulator ${D}${bindir}
    install -m 0644 ${DSTACK_ROOTFS_FILES}/dstack-tee-simulator.service \
        ${D}${systemd_system_unitdir}

    install -d ${D}${sysconfdir}/systemd/system/dstack-prepare.service.d
    install -m 0644 \
        ${DSTACK_ROOTFS_FILES}/dstack-prepare.service.d/tee-simulator.conf \
        ${D}${sysconfdir}/systemd/system/dstack-prepare.service.d/tee-simulator.conf
}

FILES:${PN} += "${sysconfdir}/systemd/system/dstack-prepare.service.d/tee-simulator.conf"

# Cargo embeds build paths into binaries; allow TMPDIR references.
INSANE_SKIP:${PN} += "buildpaths"
INSANE_SKIP:${PN}-dbg += "buildpaths"
