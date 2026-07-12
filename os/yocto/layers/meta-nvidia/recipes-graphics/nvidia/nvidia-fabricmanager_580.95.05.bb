SUMMARY = "NVIDIA Fabric Manager for NVSwitch systems"
DESCRIPTION = "NVIDIA Fabric Manager provides NVSwitch management for NVIDIA HGX and DGX systems"
HOMEPAGE = "https://developer.nvidia.com/"
LICENSE = "NVIDIA-Proprietary"
LIC_FILES_CHKSUM = "file://LICENSE;md5=2cc00be68c1227a7c42ff3620ef75d05"

SRC_URI = "https://developer.download.nvidia.com/compute/nvidia-driver/redist/fabricmanager/linux-x86_64/fabricmanager-linux-x86_64-${PV}-archive.tar.xz"
SRC_URI[md5sum] = "a6568aa288cb4784b85ba6826463f918"
SRC_URI[sha256sum] = "f0220bfb67d04b4107acf00cc95abe5a9268fd8f8b5bae26971f4df232e4369c"

S = "${UNPACKDIR}/fabricmanager-linux-x86_64-${PV}-archive"

DEPENDS = ""
RDEPENDS:${PN} = "bash zlib"

INSANE_SKIP:${PN} = "already-stripped ldflags"

do_configure[noexec] = "1"
do_compile[noexec] = "1"

inherit systemd

SYSTEMD_AUTO_ENABLE = "enable"
SYSTEMD_SERVICE:${PN} = "nvidia-fabricmanager.service"

do_install() {
    # Create directories
    install -d ${D}${bindir}
    install -d ${D}${libdir}
    install -d ${D}${datadir}/nvidia/nvswitch
    install -d ${D}${systemd_system_unitdir}

    # Install binaries
    install -m 0755 ${S}/bin/nv-fabricmanager ${D}${bindir}
    install -m 0755 ${S}/bin/nvidia-fabricmanager-start.sh ${D}${bindir}
    install -m 0755 ${S}/bin/nvswitch-audit ${D}${bindir}

    # Install libraries
    install -m 0644 ${S}/lib/libnvfm.so.1 ${D}${libdir}
    ln -sf libnvfm.so.1 ${D}${libdir}/libnvfm.so

    # Install config + topology files (glob picks up new SKUs in future archives)
    install -m 0644 ${S}/etc/fabricmanager.cfg ${D}${datadir}/nvidia/nvswitch/
    install -m 0644 ${S}/etc/fabricmanager_multinode.cfg ${D}${datadir}/nvidia/nvswitch/
    for f in ${S}/share/nvidia/nvswitch/*; do
        [ -f "$f" ] && install -m 0644 "$f" ${D}${datadir}/nvidia/nvswitch/
    done

    # Install systemd service
    install -m 0644 ${S}/systemd/nvidia-fabricmanager.service ${D}${systemd_system_unitdir}
}

FILES:${PN} = "\
    ${bindir}/nv-fabricmanager \
    ${bindir}/nvidia-fabricmanager-start.sh \
    ${bindir}/nvswitch-audit \
    ${libdir}/libnvfm.so.1 \
    ${libdir}/libnvfm.so \
    ${datadir}/nvidia/nvswitch/* \
    ${systemd_system_unitdir}/nvidia-fabricmanager.service \
"
