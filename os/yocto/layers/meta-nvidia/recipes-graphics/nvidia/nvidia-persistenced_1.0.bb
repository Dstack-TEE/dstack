SUMMARY = "NVidia Persistenced systemd service"
LICENSE = "CLOSED"

SRC_URI += "\
    file://nvidia-persistenced.service \
"

S = "${UNPACKDIR}"

inherit systemd

RDEPENDS:${PN} += "nvidia-gpu-detect kmod"

SYSTEMD_PACKAGES = "${PN}"
SYSTEMD_SERVICE:${PN} = "nvidia-persistenced.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"

do_install() {
    install -d ${D}${systemd_unitdir}/system
    install -m 0644 ${UNPACKDIR}/nvidia-persistenced.service ${D}${systemd_unitdir}/system
}
