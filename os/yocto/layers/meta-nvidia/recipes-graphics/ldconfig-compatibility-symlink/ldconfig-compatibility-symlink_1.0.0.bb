DESCRIPTION = "Create symlink from /sbin/ldconfig.real to /sbin/ldconfig"
LICENSE = "CLOSED"

# This recipe does not fetch source code from anywhere
SRC_URI = ""

# Since we're not downloading or unpacking anything, skip those tasks
do_unpack[noexec] = "1"
do_configure[noexec] = "1"
do_compile[noexec] = "1"

inherit allarch

# Add a task to create the symlink
do_install() {
    install -d ${D}${base_sbindir}
    ln -s ldconfig ${D}${base_sbindir}/ldconfig.real
}

# Ensure that the package is always installed
PACKAGES = "${PN}"
FILES:${PN}:append = "${base_sbindir}/ldconfig.real"
