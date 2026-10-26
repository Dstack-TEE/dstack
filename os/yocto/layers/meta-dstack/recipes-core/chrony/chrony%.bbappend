FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

DEPENDS += "gnutls"
PACKAGECONFIG:append = " nts"
