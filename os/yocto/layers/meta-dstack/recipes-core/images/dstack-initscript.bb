SUMMARY = "dstack initramfs files"

LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COREBASE}/meta/COPYING.MIT;md5=3da9cfbcb788c80a0384361b4de20420"

SRC_URI = "file://init"

FILES:${PN} = "*"

inherit allarch

UNPACKDIR = "${WORKDIR}/sources"
S = "${UNPACKDIR}"

do_install() {
    install -d ${D}/
    install -d ${D}/scripts
    install -d ${D}/${bindir}
    install -m 0755 ${S}/init ${D}/init
}
