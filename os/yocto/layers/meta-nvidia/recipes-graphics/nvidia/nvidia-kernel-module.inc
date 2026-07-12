inherit module

S = "${NVIDIA_SRC}/kernel-open"

do_compile[depends] += "virtual/kernel:do_shared_workdir"
EXTRA_OEMAKE:append = " SYSSRC=${STAGING_KERNEL_DIR} KERNEL_OUTPUT=${STAGING_KERNEL_BUILDDIR}"

export ARCH = "${@bb.utils.contains('TARGET_ARCH', 'x86_64', 'x86_64', '', d)}"

RPROVIDES:${PN} += " \
    kernel-module-nvidia-${KERNEL_VERSION} \
    kernel-module-nvidia-drm-${KERNEL_VERSION} \
    kernel-module-nvidia-modeset-${KERNEL_VERSION} \
    kernel-module-nvidia-peermem-${KERNEL_VERSION} \
    kernel-module-nvidia-uvm-${KERNEL_VERSION} \
"