SUMMARY = "NVidia Graphics Driver"
LICENSE = "NVIDIA-Proprietary"
LIC_FILES_CHKSUM = "file://../LICENSE;md5=92aa2e2af6aa0bcba1c3fe49da021937"

NVIDIA_ARCHIVE_NAME = "NVIDIA-Linux-${TARGET_ARCH}-${PV}"
NVIDIA_SRC = "${WORKDIR}/${NVIDIA_ARCHIVE_NAME}"
SRC_URI = " \
    https://us.download.nvidia.com/tesla/${PV}/${NVIDIA_ARCHIVE_NAME}.run \
"
SRC_URI[md5sum] = "8d98a183bf994af0ff19980e0ef430f2"
SRC_URI[sha256sum] = "8c0d4f967b7932c4ab5714272aee8103392b0a702c92afa555176d36205829f9"

RDEPENDS:${PN} = "nvidia-modprobe-config"

do_unpack() {
	chmod +x ${DL_DIR}/${NVIDIA_ARCHIVE_NAME}.run
	rm -rf ${NVIDIA_SRC}
	${DL_DIR}/${NVIDIA_ARCHIVE_NAME}.run -x --target ${NVIDIA_SRC}
}

do_make_scripts[noexec] = "1"

include nvidia-kernel-module.inc
include nvidia-libs.inc
