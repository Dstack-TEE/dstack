SUMMARY = "Detect NVIDIA GPU / NVSwitch presence for conditional systemd services"
DESCRIPTION = "Small sysfs-based helper used as a systemd ExecCondition= so that \
GPU-only services (nvidia-persistenced, nvidia-fabricmanager) skip cleanly on \
instances without a GPU or without NVSwitch, allowing a single merged image."
LICENSE = "CLOSED"

SRC_URI = "file://nvidia-gpu-detect"

S = "${UNPACKDIR}"

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${UNPACKDIR}/nvidia-gpu-detect ${D}${bindir}/nvidia-gpu-detect
}

FILES:${PN} = "${bindir}/nvidia-gpu-detect"
