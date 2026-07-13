SUMMARY = "NVidia Graphics Driver"
LICENSE = "NVIDIA-Proprietary"
LIC_FILES_CHKSUM = "file://../LICENSE;md5=92aa2e2af6aa0bcba1c3fe49da021937"

NVIDIA_ARCHIVE_NAME = "NVIDIA-Linux-${TARGET_ARCH}-${PV}"
NVIDIA_SRC = "${UNPACKDIR}/${NVIDIA_ARCHIVE_NAME}"
SRC_URI = " \
    https://us.download.nvidia.com/tesla/${PV}/${NVIDIA_ARCHIVE_NAME}.run \
"
SRC_URI[sha256sum] = "d9c6e8188672f3eb74dd04cfa69dd58479fa1d0162c8c28c8d17625763293475"

RDEPENDS:${PN} = "nvidia-modprobe-config"

do_unpack() {
	chmod +x ${DL_DIR}/${NVIDIA_ARCHIVE_NAME}.run
	rm -rf ${NVIDIA_SRC}
	${DL_DIR}/${NVIDIA_ARCHIVE_NAME}.run -x --target ${NVIDIA_SRC}
}

do_make_scripts[noexec] = "1"

include nvidia-kernel-module.inc
include nvidia-libs.inc
