NVIDIA_GROUP = "acpid \
    nvidia \
    nvidia-firmware \
    nvidia-gpu-detect \
    nvidia-persistenced \
    nvidia-fabricmanager \
    libnvidia-nscq \
    nvattest \
    nvidia-container-toolkit \
    kernel-module-video \
    numactl \
"
# Do not autoload NVIDIA modules on every boot. The default image also runs on
# GPU-less hosts, so GPU services load these modules only after hardware
# detection succeeds.
KERNEL_MODULE_AUTOLOAD:append = " video"
IMAGE_INSTALL:append = " ${NVIDIA_GROUP}"

DOCKER_DAEMON_JSON = "${THISDIR}/files/docker-daemon-nvidia.json"
