DESCRIPTION = "NVIDIA Container Toolkit"
HOMEPAGE = "https://github.com/NVIDIA/nvidia-container-toolkit"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://src/${GO_IMPORT}/LICENSE;md5=3b83ef96387f14655fc854ddc3c6bd57"

SRC_URI = "git://github.com/NVIDIA/nvidia-container-toolkit.git;protocol=https;branch=main;destsuffix=${BP}/src/${GO_IMPORT}"
SRCREV = "c748619c592030519361274a2fdd43f2c2ced73a"

SRC_URI += "file://config.toml"
GO_IMPORT = "github.com/NVIDIA/nvidia-container-toolkit"

DEPENDS = " \
            curl-native ca-certificates-native go-native \
            coreutils-native \
            "
