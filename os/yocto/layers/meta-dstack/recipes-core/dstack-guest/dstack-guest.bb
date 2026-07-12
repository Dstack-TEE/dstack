SUMMARY = "Guest binaries for dstack, a decentralized computing stack"
DESCRIPTION = "${SUMMARY}"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COREBASE}/meta/COPYING.MIT;md5=3da9cfbcb788c80a0384361b4de20420"

inherit systemd

REPO_ROOT = "${THISDIR}/../../.."

SRC_DIR = '${REPO_ROOT}/dstack'

S = "${UNPACKDIR}/dstack"

RDEPENDS:${PN} += "bash"

DEPENDS += "rsync-native"

# Ensure rsync-native is built before unpack runs
do_unpack[depends] += "rsync-native:do_populate_sysroot"

DSTACK_SERVICES = "dstack-guest-agent.service dstack-guest-agent.socket dstack-prepare.service app-compose.service wg-checker.service"
SYSTEMD_PACKAGES = "${@bb.utils.contains('DISTRO_FEATURES','systemd','${PN}','',d)}"
SYSTEMD_SERVICE:${PN} = "${@bb.utils.contains('DISTRO_FEATURES','systemd','${DSTACK_SERVICES}','',d)}"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"
EXTRA_CARGO_FLAGS = "-p dstack-guest-agent -p dstack-util"

inherit cargo_bin

do_unpack() {
    mkdir -p ${S}
    rsync -a --exclude="target" ${SRC_DIR}/ ${S}/
}

# Force the configure task to run every time to detect source changes
do_unpack[nostamp] = "1"

# Add source directory to configure task dependencies
do_unpack[vardeps] += "SRC_DIR"

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
    install -m 0755 ${S}/basefiles/dstack-prepare.sh ${D}${bindir}
    install -m 0755 ${S}/basefiles/ephemeral-docker.sh ${D}${bindir}
    install -m 0755 ${S}/basefiles/wg-checker.sh ${D}${bindir}
    install -m 0755 ${S}/basefiles/app-compose.sh ${D}${bindir}
    install -m 0644 ${S}/basefiles/journald.conf ${D}${sysconfdir}/systemd/journald.conf.d/dstack.conf

    install -d ${D}${sysconfdir}/
    install -m 0644 ${S}/basefiles/tdx-attest.conf ${D}${sysconfdir}/tdx-attest.conf

    install -d ${D}${sysconfdir}/sysctl.d
    install -m 0644 ${S}/basefiles/sysctl.d/99-dstack.conf ${D}${sysconfdir}/sysctl.d/99-dstack.conf

    if ${@bb.utils.contains('DISTRO_FEATURES', 'systemd', 'true', 'false', d)}; then
        install -d ${D}${systemd_system_unitdir} \
                   ${D}${sysconfdir}/systemd/resolved.conf.d

        install -m 0644 ${S}/basefiles/dstack-guest-agent.service ${D}${systemd_system_unitdir}
        install -m 0644 ${S}/basefiles/dstack-prepare.service ${D}${systemd_system_unitdir}
        install -m 0644 ${S}/basefiles/app-compose.service ${D}${systemd_system_unitdir}
        install -m 0644 ${S}/basefiles/wg-checker.service ${D}${systemd_system_unitdir}
        install -m 0644 ${S}/basefiles/dstack-guest-agent.socket ${D}${systemd_system_unitdir}
        install -m 0644 ${S}/basefiles/llmnr.conf ${D}${sysconfdir}/systemd/resolved.conf.d
        install -d ${D}${sysconfdir}/systemd/system/docker.service.d
        install -m 0644 ${S}/basefiles/docker.service.d/* ${D}${sysconfdir}/systemd/system/docker.service.d/

        install -d ${D}${sysconfdir}/systemd/system/containerd.service.d
        install -m 0644 ${S}/basefiles/containerd.service.d/* ${D}${sysconfdir}/systemd/system/containerd.service.d/
    fi
}

FILES:${PN} += " \
    ${sysconfdir}/systemd/system/docker.service.d/dstack-guest-agent.conf \
    ${sysconfdir}/systemd/system/docker.service.d/dstack-prepare.conf \
    ${sysconfdir}/systemd/system/containerd.service.d/dstack-prepare.conf \
"

# Cargo embeds build paths into binaries; allow TMPDIR references.
INSANE_SKIP:${PN} += "buildpaths"
INSANE_SKIP:${PN}-dbg += "buildpaths"
