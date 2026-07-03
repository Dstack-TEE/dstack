inherit core-image

IMAGE_BASENAME = "${PN}"

IMAGE_INSTALL = "\
    ${VIRTUAL-RUNTIME_base-utils} \
    ${ROOTFS_BOOTSTRAP_INSTALL} \
    base-files \
    base-passwd \
    systemd \
    netbase \
    iptables \
    nftables \
    docker-moby \
    docker-compose \
    dstack-guest \
    kata-agent-coco \
    coco-guest-components \
    wireguard-tools \
    cryptsetup \
    curl \
    jq \
    chrony \
    chronyc \
    dstack-zfs \
    dstack-sysbox \
    kernel-module-tun \
    kernel-module-fuse \
    kernel-module-br-netfilter \
    kernel-module-xt-mark \
    kernel-module-xt-connmark \
    kernel-module-xt-comment \
    kernel-module-xt-multiport \
    kernel-module-xt-statistic \
    kernel-module-xt-redirect \
    kernel-module-xt-tcpmss \
    kernel-module-xt-ct \
    kernel-module-xt-log \
    kernel-module-xt-limit \
    kernel-module-nf-tables \
    kernel-module-nft-compat \
    kernel-module-nft-nat \
    kernel-module-nft-chain-nat \
    kernel-module-nft-masq \
    kernel-module-nft-redir \
    kernel-module-nft-ct \
    kernel-module-nft-log \
    kernel-module-nft-limit \
    kernel-module-nft-reject \
    kernel-module-nft-reject-inet \
    kernel-module-nft-hash \
    kernel-module-ip-set \
    kernel-module-ip-set-hash-ip \
    kernel-module-ip-set-hash-net \
    kernel-module-ip-set-hash-ipport \
    kernel-module-ip-set-hash-ipportip \
    kernel-module-ip-set-hash-ipportnet \
    kernel-module-ip-set-hash-netiface \
    kernel-module-ip-set-bitmap-ip \
    kernel-module-ip-set-bitmap-port \
    kernel-module-ip-set-list-set \
    kernel-module-xt-set \
    kernel-module-xt-nflog \
    kernel-module-xt-physdev \
    fuse3 \
    fuse3-utils \
    pigz \
    xfsprogs \
    e2fsprogs \
    e2fsprogs-resize2fs \
    gptfdisk \
    parted \
    tpm2-tools \
"

IMAGE_NAME_SUFFIX ?= ""
IMAGE_LINGUAS = ""
INITRAMFS_MAXSIZE = "1000000"

LICENSE = "MIT"

IMAGE_CLASSES += "dm-verity-img"

DM_VERITY_IMAGE = "${PN}"
DM_VERITY_IMAGE_TYPE = "squashfs"
DM_VERITY_SEPARATE_HASH = "0"
DM_VERITY_REPRODUCIBLE = "1"

IMAGE_FSTYPES = "cpio squashfs"
CONVERSIONTYPES += "verity"
IMAGE_TYPES += "squashfs.verity"

EXTRA_IMAGE_FEATURES = "read-only-rootfs"

IMAGE_ROOTFS_SIZE = "8192"
IMAGE_ROOTFS_EXTRA_SPACE = "0"

# Use the same restriction as initramfs-live-install
COMPATIBLE_HOST = "x86_64.*-linux"

# Remove sysvinit related files in a postprocess function
ROOTFS_POSTPROCESS_COMMAND += "remove_sysvinit_files;"
ROOTFS_POSTPROCESS_COMMAND += "symlink_lib64;"
IMAGE_FEATURES[validitems] += "nologin"
ROOTFS_POSTPROCESS_COMMAND += '${@bb.utils.contains_any("IMAGE_FEATURES", [ 'nologin' ], "disable_login", "",d)}'
ROOTFS_POSTPROCESS_COMMAND += "install_docker_config;"
ROOTFS_POSTPROCESS_COMMAND += "mkdirs;"


remove_sysvinit_files() {
    # Remove /etc/init.d directory and its contents
    rm -rf ${IMAGE_ROOTFS}${sysconfdir}/init.d

    # Remove /etc/rc*.d directories and their contents
    for d in ${IMAGE_ROOTFS}${sysconfdir}/rc*.d; do
        rm -rf $d
    done

    # Remove other sysvinit specific files
    rm -f ${IMAGE_ROOTFS}${sysconfdir}/inittab
}

symlink_lib64() {
    ln -s lib ${IMAGE_ROOTFS}/lib64
}

disable_login() {
    for srv in getty getty-pre; do
        rm -f ${IMAGE_ROOTFS}/etc/systemd/system/${srv}.target
        rm -f ${IMAGE_ROOTFS}/usr/lib/systemd/system/${srv}.target
    done
    for srv in autovt container-getty console-getty getty-generator serial-getty getty; do
        rm -f ${IMAGE_ROOTFS}/etc/systemd/system/${srv}.service
        rm -f ${IMAGE_ROOTFS}/etc/systemd/system/${srv}@.service
        rm -f ${IMAGE_ROOTFS}/usr/lib/systemd/system/${srv}.service
        rm -f ${IMAGE_ROOTFS}/usr/lib/systemd/system/${srv}@.service
    done

    # Login/console related
    rm -rf ${IMAGE_ROOTFS}/usr/sbin/getty
    rm -rf ${IMAGE_ROOTFS}/usr/sbin/agetty
    rm -rf ${IMAGE_ROOTFS}/usr/bin/login
    rm -rf ${IMAGE_ROOTFS}/usr/bin/loginctl
    rm -rf ${IMAGE_ROOTFS}/etc/systemd/system/getty.target.wants

    # Console fonts and keymaps
    rm -rf ${IMAGE_ROOTFS}/usr/share/consolefonts
    rm -rf ${IMAGE_ROOTFS}/usr/share/keymaps

    # Systemd components we don't need
    rm -rf ${IMAGE_ROOTFS}/usr/bin/systemd-tty-ask-password-agent
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/system/debug-shell.service
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/system/suspend.target
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/system/systemd-hibernate.service
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/system/systemd-suspend-then-hibernate.service
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/systemd-hibernate-resume
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/system-generators/systemd-getty-generator
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/systemd-logind
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/system/systemd-logind.service
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/system/multi-user.target.wants/systemd-logind.service
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/logind.conf.d
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/system/graphical.target.wants
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/user/graphical-session.target
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/user/graphical-session-pre.target
    rm -rf ${IMAGE_ROOTFS}/usr/lib/systemd/user/bluetooth.target

    # Polkit
    rm -rf ${IMAGE_ROOTFS}/usr/share/polkit-1

    # Factory defaults
    rm -rf ${IMAGE_ROOTFS}/usr/share/factory

    > ${IMAGE_ROOTFS}/etc/securetty
}

DOCKER_DAEMON_JSON ?= "${THISDIR}/files/docker-daemon.json"

install_docker_config() {
    install -d ${IMAGE_ROOTFS}${sysconfdir}/docker
    install -m 0644 ${DOCKER_DAEMON_JSON} ${IMAGE_ROOTFS}${sysconfdir}/docker/daemon.json
}

mkdirs() {
    mkdir -p ${IMAGE_ROOTFS}/dev
    mkdir -p ${IMAGE_ROOTFS}/proc
    mkdir -p ${IMAGE_ROOTFS}/sys
    mkdir -p ${IMAGE_ROOTFS}/run
    mkdir -p ${IMAGE_ROOTFS}/dstack
    mkdir -p ${IMAGE_ROOTFS}/etc/wireguard
    mkdir -p ${IMAGE_ROOTFS}/var/lib/docker
    mkdir -p ${IMAGE_ROOTFS}/var/lib/containerd
    ln -sf dstack ${IMAGE_ROOTFS}/tapp
}
