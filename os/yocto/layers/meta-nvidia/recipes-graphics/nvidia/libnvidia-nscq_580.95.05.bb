SUMMARY = "NVIDIA NSCQ library"
DESCRIPTION = "NVIDIA NSCQ (NVIDIA System Communication Queue) library for NVIDIA GPU systems"
HOMEPAGE = "https://developer.nvidia.com/"
LICENSE = "NVIDIA-Proprietary"
LIC_FILES_CHKSUM = "file://LICENSE;md5=2cc00be68c1227a7c42ff3620ef75d05"

SRC_URI = "https://developer.download.nvidia.cn/compute/nvidia-driver/redist/libnvidia_nscq/linux-x86_64/libnvidia_nscq-linux-x86_64-${PV}-archive.tar.xz"
SRC_URI[md5sum] = "6bc20061ebdae98fadd7a76110b44430"
SRC_URI[sha256sum] = "c2285c12f10ec2afc0ad2949f7fcc282b6fd37f32165c1df241451ccabb1067a"

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
