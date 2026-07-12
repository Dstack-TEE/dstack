FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI += "file://disable-password-auth.conf"

do_install:append() {
    install -d ${D}${sysconfdir}/ssh/sshd_config.d
    install -m 0644 ${UNPACKDIR}/disable-password-auth.conf ${D}${sysconfdir}/ssh/sshd_config.d/
}

FILES:${PN}-sshd += "${sysconfdir}/ssh/sshd_config.d/"
