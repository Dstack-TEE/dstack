SUMMARY = "NVIDIA NSCQ library"
DESCRIPTION = "NVIDIA NSCQ (NVIDIA System Communication Queue) library for NVIDIA GPU systems"
HOMEPAGE = "https://developer.nvidia.com/"
LICENSE = "NVIDIA-Proprietary"
LIC_FILES_CHKSUM = "file://LICENSE;md5=2cc00be68c1227a7c42ff3620ef75d05"

SRC_URI = "https://developer.download.nvidia.cn/compute/nvidia-driver/redist/libnvidia_nscq/linux-x86_64/libnvidia_nscq-linux-x86_64-${PV}-archive.tar.xz"
SRC_URI[md5sum] = "5b559a614f2c2c79b6eb796b68b6fb0f"
SRC_URI[sha256sum] = "1c008787111fc55a7fc1d3521a6d41c2523b8949354e5651eadb4498554e5469"

S = "${UNPACKDIR}/libnvidia_nscq-linux-x86_64-${PV}-archive"

INSANE_SKIP:${PN} = "already-stripped ldflags"

do_configure[noexec] = "1"
do_compile[noexec] = "1"

do_install() {
    install -d ${D}${libdir}

    install -m 0755 ${S}/lib/libnvidia-nscq.so.${PV} ${D}${libdir}
    ln -sf libnvidia-nscq.so.${PV} ${D}${libdir}/libnvidia-nscq.so.2.0
    ln -sf libnvidia-nscq.so.2.0 ${D}${libdir}/libnvidia-nscq.so.2
    ln -sf libnvidia-nscq.so.2 ${D}${libdir}/libnvidia-nscq.so
}

FILES:${PN} = "\
    ${libdir}/libnvidia-nscq.so.${PV} \
    ${libdir}/libnvidia-nscq.so.2.0 \
    ${libdir}/libnvidia-nscq.so.2 \
    ${libdir}/libnvidia-nscq.so \
"
