SUMMARY = "NVIDIA NSCQ library"
DESCRIPTION = "NVIDIA NSCQ (NVIDIA System Communication Queue) library for NVIDIA GPU systems"
HOMEPAGE = "https://developer.nvidia.com/"
LICENSE = "NVIDIA-Proprietary"
LIC_FILES_CHKSUM = "file://LICENSE;md5=2cc00be68c1227a7c42ff3620ef75d05"

SRC_URI = "https://developer.download.nvidia.cn/compute/nvidia-driver/redist/libnvidia_nscq/linux-x86_64/libnvidia_nscq-linux-x86_64-${PV}-archive.tar.xz"
SRC_URI[sha256sum] = "71086dc7d9c97ac20a7d14de2a119e3b2ee97a08da452d63c2c4f5a71d80e19a"

S = "${UNPACKDIR}/libnvidia_nscq-linux-x86_64-${PV}-archive"

INSANE_SKIP:${PN} = "already-stripped ldflags"

do_configure[noexec] = "1"
do_compile[noexec] = "1"

do_install() {
    # Create directories
    install -d ${D}${libdir}

    # Install libraries
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
