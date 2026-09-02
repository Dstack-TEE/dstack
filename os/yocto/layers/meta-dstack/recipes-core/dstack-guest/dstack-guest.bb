SUMMARY = "Guest binaries for dstack, a decentralized computing stack"
DESCRIPTION = "${SUMMARY}"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COREBASE}/meta/COPYING.MIT;md5=3da9cfbcb788c80a0384361b4de20420"

inherit systemd pkgconfig

# Stage the monorepo core workspace and OS-owned rootfs files for the guest
# image. The public Rust SDK lives in its own Cargo workspace and is not needed
# to build guest-agent / dstack-util.
DSTACK_MONOREPO_ROOT ?= "${@os.path.realpath(os.path.join(d.getVar('THISDIR'), '../../../../../..'))}"
DSTACK_CORE_SRC ?= "${DSTACK_MONOREPO_ROOT}/dstack"
DSTACK_ROOTFS_SRC ?= "${DSTACK_MONOREPO_ROOT}/os/common/rootfs"

S = "${UNPACKDIR}/repo/dstack"
DSTACK_ROOTFS_FILES = "${UNPACKDIR}/repo/os/common/rootfs"

RDEPENDS:${PN} += "bash cryptsetup util-linux-blkid util-linux-mount"

DEPENDS += "rsync-native tpm2-tss"
DEPENDS += "cmake-native"

# aws-lc-sys cannot detect Yocto cross builds when the build and target share
# the same Rust target triple, and its cc builder then tries to execute a
# target binary on the build host. Use its supported CMake builder instead.
export AWS_LC_SYS_CMAKE_BUILDER = "1"

# Ensure rsync-native is built before unpack runs
do_unpack[depends] += "rsync-native:do_populate_sysroot"

DSTACK_SERVICES = "dstack-guest-agent.service dstack-guest-agent.socket dstack-prepare.service app-compose.service dstack-gateway-checker.service"
SYSTEMD_PACKAGES = "${@bb.utils.contains('DISTRO_FEATURES','systemd','${PN}','',d)}"
SYSTEMD_SERVICE:${PN} = "${@bb.utils.contains('DISTRO_FEATURES','systemd','${DSTACK_SERVICES}','',d)}"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"
EXTRA_CARGO_FLAGS = "-p dstack-guest-agent -p dstack-util -p dstack-volume"

inherit cargo_bin

do_unpack() {
    install -d "${S}" "${DSTACK_ROOTFS_FILES}"
    rsync -a --exclude=".git" --exclude=".worktrees" --exclude="target" \
        "${DSTACK_CORE_SRC}/" "${S}/"
    rsync -a "${DSTACK_ROOTFS_SRC}/" "${DSTACK_ROOTFS_FILES}/"
}

do_unpack[cleandirs] = "${UNPACKDIR}/repo"

# Force the configure task to run every time to detect source changes
do_unpack[nostamp] = "1"

# Add source directory to configure task dependencies
do_unpack[vardeps] += "DSTACK_CORE_SRC DSTACK_ROOTFS_SRC"

do_configure() {
    cargo_bin_do_configure
}

do_compile() {
    cargo_bin_do_compile
}

do_compile[network] = "1"

do_install() {
    install -d ${D}${bindir}
    install -d ${D}${sysconfdir}/systemd/journald.conf.d
    install -m 0755 ${CARGO_BINDIR}/dstack-util ${D}${bindir}
    install -m 0755 ${CARGO_BINDIR}/dstack-guest-agent ${D}${bindir}
    install -m 0755 ${CARGO_BINDIR}/dstack-volume ${D}${bindir}
    install -m 0755 ${DSTACK_ROOTFS_FILES}/dstack-prepare.sh ${D}${bindir}
    install -m 0755 ${DSTACK_ROOTFS_FILES}/ephemeral-docker.sh ${D}${bindir}
    install -m 0755 ${DSTACK_ROOTFS_FILES}/app-compose.sh ${D}${bindir}
    install -m 0644 ${DSTACK_ROOTFS_FILES}/journald.conf ${D}${sysconfdir}/systemd/journald.conf.d/dstack.conf

    install -d ${D}${sysconfdir}/
    install -m 0644 ${DSTACK_ROOTFS_FILES}/tdx-attest.conf ${D}${sysconfdir}/tdx-attest.conf

    install -d ${D}${sysconfdir}/sysctl.d
    install -m 0644 ${DSTACK_ROOTFS_FILES}/sysctl.d/99-dstack.conf ${D}${sysconfdir}/sysctl.d/99-dstack.conf

    if ${@bb.utils.contains('DISTRO_FEATURES', 'systemd', 'true', 'false', d)}; then
        install -d ${D}${systemd_system_unitdir} \
                   ${D}${sysconfdir}/systemd/resolved.conf.d

        install -m 0644 ${DSTACK_ROOTFS_FILES}/dstack-guest-agent.service ${D}${systemd_system_unitdir}
        install -m 0644 ${DSTACK_ROOTFS_FILES}/dstack-prepare.service ${D}${systemd_system_unitdir}
        install -m 0644 ${DSTACK_ROOTFS_FILES}/app-compose.service ${D}${systemd_system_unitdir}
        install -m 0644 ${DSTACK_ROOTFS_FILES}/dstack-gateway-checker.service ${D}${systemd_system_unitdir}
        install -m 0644 ${DSTACK_ROOTFS_FILES}/dstack-guest-agent.socket ${D}${systemd_system_unitdir}
        install -m 0644 ${DSTACK_ROOTFS_FILES}/llmnr.conf ${D}${sysconfdir}/systemd/resolved.conf.d
        # Drop-ins the image ships are vendor configuration, so they belong
        # beside the units in ${systemd_system_unitdir}. /etc is the operator's
        # layer and `systemctl revert` deletes <unit>.d/ below it wholesale.
        install -d ${D}${systemd_system_unitdir}/docker.service.d
        install -m 0644 ${DSTACK_ROOTFS_FILES}/docker.service.d/* ${D}${systemd_system_unitdir}/docker.service.d/

        install -d ${D}${systemd_system_unitdir}/containerd.service.d
        install -m 0644 ${DSTACK_ROOTFS_FILES}/containerd.service.d/* ${D}${systemd_system_unitdir}/containerd.service.d/
    fi
}

FILES:${PN} += " \
    ${systemd_system_unitdir}/docker.service.d/dstack-guest-agent.conf \
    ${systemd_system_unitdir}/docker.service.d/dstack-prepare.conf \
    ${systemd_system_unitdir}/containerd.service.d/dstack-prepare.conf \
"

# Cargo embeds build paths into binaries; allow TMPDIR references.
INSANE_SKIP:${PN} += "buildpaths"
INSANE_SKIP:${PN}-dbg += "buildpaths"
