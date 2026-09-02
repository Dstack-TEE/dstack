SUMMARY = "NVIDIA kernel module configuration"
DESCRIPTION = "Generates NVIDIA kernel module options at boot from the GPU \
topology the guest was given, so one image serves Hopper Protected PCIe, \
Blackwell multi-GPU and single-GPU tenants without a per-shape command line."
LICENSE = "CLOSED"

# The payload shared with the mkosi backend lives in os/common/nvidia so neither
# image backend reaches into the other's tree. See os/common/README.md.
FILESEXTRAPATHS:prepend := "${THISDIR}/../../../../../common/nvidia:"

SRC_URI = "\
    file://nvidia-module-options \
    file://nvidia-module-options.service \
    file://nvidia-blacklist.conf \
"

S = "${UNPACKDIR}"

inherit systemd

RDEPENDS:${PN} += "nvidia-gpu-detect"

SYSTEMD_PACKAGES = "${PN}"
SYSTEMD_SERVICE:${PN} = "nvidia-module-options.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${UNPACKDIR}/nvidia-module-options ${D}${bindir}/nvidia-module-options
    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${UNPACKDIR}/nvidia-module-options.service ${D}${systemd_system_unitdir}
    # Vendor configuration lives under ${nonarch_libdir}; /etc/modprobe.d stays
    # free for operator overrides and /run/modprobe.d holds the generated file.
    install -d ${D}${nonarch_libdir}/modprobe.d
    install -m 0644 ${UNPACKDIR}/nvidia-blacklist.conf ${D}${nonarch_libdir}/modprobe.d/
}

FILES:${PN} = "\
    ${bindir}/nvidia-module-options \
    ${systemd_system_unitdir}/nvidia-module-options.service \
    ${nonarch_libdir}/modprobe.d/nvidia-blacklist.conf \
"
