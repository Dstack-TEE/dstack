DESCRIPTION = "Create containerd config"
LICENSE = "CLOSED"

# FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
SRC_URI = "file://config.toml"

S = "${UNPACKDIR}"

do_install:append() {
    install -d ${D}${sysconfdir}/containerd
    install -m 0644 ${UNPACKDIR}/config.toml ${D}${sysconfdir}/containerd/
}

RDEPENDS:${PN}:append = " containerd-opencontainers"
FILES:${PN}:append = "${sysconfdir}/containerd/config.toml"
