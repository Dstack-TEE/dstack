SUMMARY = "Development-only TEE ABI simulator for dstack"
DESCRIPTION = "Extensible TEE-platform simulator whose default TDX backend lets the development guest image exercise the production TDX userspace path on a non-TEE QEMU VM"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COREBASE}/meta/files/common-licenses/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

inherit systemd

# Stage the monorepo core workspace only. The public Rust SDK lives in its own
# Cargo workspace and is not needed to build dstack-tee-simulator.
DSTACK_MONOREPO_ROOT ?= "${@os.path.realpath(os.path.join(d.getVar('THISDIR'), '../../../../../..'))}"
DSTACK_CORE_SRC ?= "${DSTACK_MONOREPO_ROOT}/dstack"

S = "${UNPACKDIR}/repo/dstack"

DEPENDS += "rsync-native cmake-native"
RDEPENDS:${PN} += "dstack-guest fuse3-utils swtpm tpm2-tools libtss2-tcti-device openssl"
do_unpack[depends] += "rsync-native:do_populate_sysroot"

# aws-lc-sys cannot detect this Yocto cross build reliably with its default
# cc builder. Its supported CMake builder does not execute target binaries.
export AWS_LC_SYS_CMAKE_BUILDER = "1"

SYSTEMD_SERVICE:${PN} = "dstack-tee-simulator.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"
EXTRA_CARGO_FLAGS = "-p dstack-tee-simulator"

inherit cargo_bin

do_unpack() {
    install -d "${S}"
    rsync -a --exclude=".git" --exclude=".worktrees" --exclude="target" \
        "${DSTACK_CORE_SRC}/" "${S}/"
}

do_unpack[cleandirs] = "${UNPACKDIR}/repo"
do_unpack[nostamp] = "1"
do_unpack[vardeps] += "DSTACK_CORE_SRC"

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
    install -m 0644 ${THISDIR}/files/dstack-tee-simulator.service \
        ${D}${systemd_system_unitdir}

    install -d ${D}${systemd_system_unitdir}/dstack-prepare.service.d
    install -m 0644 ${THISDIR}/files/tee-simulator.conf \
        ${D}${systemd_system_unitdir}/dstack-prepare.service.d/tee-simulator.conf
}

# Unit/drop-in live next to this recipe; include them in task checksums.
do_install[file-checksums] += "\
    ${THISDIR}/files/dstack-tee-simulator.service:True \
    ${THISDIR}/files/tee-simulator.conf:True \
"

FILES:${PN} += "${systemd_system_unitdir}/dstack-prepare.service.d/tee-simulator.conf"

# Cargo embeds build paths into binaries; allow TMPDIR references.
INSANE_SKIP:${PN} += "buildpaths"
INSANE_SKIP:${PN}-dbg += "buildpaths"
