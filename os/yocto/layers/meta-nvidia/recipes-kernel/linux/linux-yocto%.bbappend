
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI += "file://nvidia.cfg \
            file://nvidia.scc"

KERNEL_FEATURES:append = " nvidia.scc"
