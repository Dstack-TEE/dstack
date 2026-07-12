FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI += "file://dstack-motd"

do_install:append() {
    if [ -f ${UNPACKDIR}/dstack-motd ];then
        bbnote "Installing custom dstack motd file"
        install -m 0644 ${UNPACKDIR}/dstack-motd ${D}${sysconfdir}/motd
    else
        bbwarn "Custom dstack-motd file not found in ${UNPACKDIR}"
        ls -la ${UNPACKDIR}
    fi
}
