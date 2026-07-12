DESCRIPTION = "libnvidia-container"
HOMEPAGE = "https://github.com/NVIDIA/libnvidia-container"
LICENSE = "Apache-2.0"
# LIC_FILES_CHKSUM = "file://LICENSE;md5=3b83ef96387f14655fc854ddc3c6bd57"

LIC_FILES_CHKSUM = "\
    file://LICENSE;md5=3b83ef96387f14655fc854ddc3c6bd57 \
    file://deps/src/nvidia-modprobe-${NVIDIA_MODPROBE_VERSION}/modprobe-utils/nvidia-modprobe-utils.c;endline=22;md5=2ee73384f2a7a7e246230f8a2e2d4b30 \
    file://deps/src/nvidia-modprobe-${NVIDIA_MODPROBE_VERSION}/modprobe-utils/pci-enum.h;endline=29;md5=ca948b6fabc48e616fccbf17247feebf \
    file://deps/src/nvidia-modprobe-${NVIDIA_MODPROBE_VERSION}/modprobe-utils/pci-sysfs.c;endline=25;md5=0449248350efd54938e7f8d25af965cb \
"

ELF_TOOLCHAIN_VERSION = "0.7.1"
NVIDIA_MODPROBE_VERSION = "580.105.08"
LIBTIRPC_VERSION = "1.3.4"

SRC_URI = "git://github.com/NVIDIA/libnvidia-container.git;protocol=https;name=libnvidia;branch=main \
           git://github.com/NVIDIA/nvidia-modprobe.git;protocol=https;branch=main;name=modprobe;destsuffix=nvidia-modprobe \
           file://0001-build-fix.patch \
           file://0002-secomp-fix.patch \
           file://0003-fix-remove-buildpath-for-package-qa.patch \
           "


# SRCREV = "a4ef85ebc86688eeef667271abbc7cd4f1110cf6"
SRCREV_libnvidia = "889a3bb5408c195ed7897ba2cb8341c7d249672f"
# Nvidia modprobe version 495.44
SRCREV_modprobe = "0c7433d5b04ce4a97036a939c076416d47427675"
SRCREV_FORMAT = "libnvidia_modprobe"

DEPENDS = " \
            curl-native ca-certificates-native go-native \
            coreutils-native \
            pkgconfig-native \
            libcap \
            elfutils \
            libtirpc134 \
            ldconfig-native \
            "
RDEPENDS:${PN}:append = " ldconfig-compatibility-symlink containerd-config"