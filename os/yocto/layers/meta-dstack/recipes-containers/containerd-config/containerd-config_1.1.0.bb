SUMMARY = "dstack containerd configuration"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://config.toml"

do_install() {
    install -d ${D}${sysconfdir}/containerd
    install -m 0644 ${UNPACKDIR}/config.toml ${D}${sysconfdir}/containerd/config.toml
}

FILES:${PN} = "${sysconfdir}/containerd/config.toml"
