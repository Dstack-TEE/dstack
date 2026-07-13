FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# Only start the fabric manager when NVSwitch hardware is present, so the
# service is silently skipped (not failed) on non-NVSwitch instances.
SRC_URI += "file://nvidia-fabricmanager-nvswitch-condition.conf"

RDEPENDS:${PN} += "nvidia-gpu-detect kmod"

do_install:append() {
    install -d ${D}${systemd_system_unitdir}/nvidia-fabricmanager.service.d
    install -m 0644 ${UNPACKDIR}/nvidia-fabricmanager-nvswitch-condition.conf \
        ${D}${systemd_system_unitdir}/nvidia-fabricmanager.service.d/10-nvswitch-condition.conf
}

FILES:${PN} += "${systemd_system_unitdir}/nvidia-fabricmanager.service.d/10-nvswitch-condition.conf"
