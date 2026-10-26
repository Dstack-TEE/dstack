SUMMARY = "Lazy-pulling eStargz snapshotter for containerd"
HOMEPAGE = "https://github.com/containerd/stargz-snapshotter"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

SRC_URI = "https://github.com/containerd/stargz-snapshotter/releases/download/v${PV}/stargz-snapshotter-v${PV}-linux-amd64.tar.gz;subdir=${BP} \
           file://containerd-stargz-grpc.service \
"
SRC_URI[sha256sum] = "515a3c3af0012f192ace31fb79e910597977c77227e976680aeaaef6e9ae50a9"

S = "${UNPACKDIR}/${BP}"

inherit systemd

COMPATIBLE_HOST = "x86_64.*-linux"
INHIBIT_PACKAGE_DEBUG_SPLIT = "1"
INSANE_SKIP:${PN} += "already-stripped"

SYSTEMD_SERVICE:${PN} = "containerd-stargz-grpc.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"

RDEPENDS:${PN} += "containerd-config fuse3-utils"

do_install() {
    install -d ${D}${bindir} ${D}${systemd_system_unitdir}
    install -m 0755 ${S}/containerd-stargz-grpc ${D}${bindir}/containerd-stargz-grpc
    install -m 0755 ${S}/ctr-remote ${D}${bindir}/ctr-remote
    install -m 0644 ${UNPACKDIR}/containerd-stargz-grpc.service ${D}${systemd_system_unitdir}/containerd-stargz-grpc.service
}
