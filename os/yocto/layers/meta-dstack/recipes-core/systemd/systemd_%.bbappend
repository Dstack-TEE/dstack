FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI:append = " file://0001-core-suppress-ephemeral-status-output.patch"

do_install:append() {
    # Remove systemd-vconsole-setup entirely (no virtual console needed)
    rm -f ${D}${systemd_system_unitdir}/sysinit.target.wants/systemd-vconsole-setup.service
    rm -f ${D}${systemd_system_unitdir}/systemd-vconsole-setup.service
    rm -f ${D}${rootlibexecdir}/systemd/systemd-vconsole-setup
    rm -f ${D}${nonarch_libdir}/udev/rules.d/90-vconsole.rules

    # Disable EFI System Partition automount (not needed, causes UNSUPP error)
    rm -f ${D}${nonarch_libdir}/systemd/system-generators/systemd-gpt-auto-generator

    # Ensure systemd-resolved waits for /var/volatile tmpfs and tmpfiles setup
    install -d ${D}${systemd_system_unitdir}/systemd-resolved.service.d
    cat <<'EOF' > ${D}${systemd_system_unitdir}/systemd-resolved.service.d/10-var-volatile.conf
[Unit]
After=systemd-tmpfiles-setup.service var-volatile.mount
Requires=var-volatile.mount
EOF
}

SYSTEMD_SERVICE:${PN}-vconsole-setup = ""
PACKAGECONFIG:remove = "sysvinit logind"


# Create a minimal package with only systemd-socket-proxyd
# This avoids pulling in all of systemd-extra-utils
PACKAGES =+ "${PN}-socket-proxyd"
FILES:${PN}-socket-proxyd = "${nonarch_libdir}/systemd/systemd-socket-proxyd"
RDEPENDS:${PN}-socket-proxyd = "${PN}"
