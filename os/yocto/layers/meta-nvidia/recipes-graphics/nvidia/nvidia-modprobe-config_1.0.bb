SUMMARY = "NVIDIA kernel module configuration"
DESCRIPTION = "Configuration for NVIDIA kernel modules with dynamic settings based on kernel command line"
LICENSE = "CLOSED"

SRC_URI = "\
    file://nvidia.conf \
"

S = "${UNPACKDIR}"

do_install() {
    install -d ${D}${sysconfdir}/modprobe.d
    install -m 0644 ${UNPACKDIR}/nvidia.conf ${D}${sysconfdir}/modprobe.d/
}

FILES:${PN} = "${sysconfdir}/modprobe.d/nvidia.conf"

RDEPENDS:${PN} = "bash"
