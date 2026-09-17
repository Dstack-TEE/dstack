# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Toolchain image for building an out-of-tree kernel module against one dstack
# guest OS image. It carries the exported kernel build tree of that image plus
# a compiler from the same pinned Debian snapshot the guest kernel was built
# with, so a module built here matches the guest kernel's vermagic and
# Module.symvers and loads in the CVM.
#
# Build context is the directory holding the kernel-devel tarball:
#
#   docker build -f os/image/kernel-builder/Dockerfile \
#     --build-arg DEBIAN_SNAPSHOT=<snapshot> \
#     --build-arg KERNEL_RELEASE=<release> \
#     --build-arg KERNEL_DEVEL_TARBALL=dstack-<version>-kernel-devel.tar.gz \
#     -t dstack-kernel-builder:<version> <dist-dir>

ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE}

# The snapshot is what pins the compiler, which is the part that has to match
# the guest kernel build; the base image tag only provides the file layout.
ARG DEBIAN_SNAPSHOT
ARG KERNEL_RELEASE
ARG KERNEL_DEVEL_TARBALL
ARG IMAGE_VERSION=unknown
ARG OS_IMAGE_HASH=unknown
ARG GIT_REVISION=unknown

# Trixie ships deb822 sources in /etc/apt/sources.list.d/, so rewriting
# sources.list alone leaves the live mirror active and the toolchain drifts on
# every rebuild. Wipe both layouts, as dstack/build/shared/pin-packages.sh does.
RUN set -eux; \
    test -n "${DEBIAN_SNAPSHOT}"; \
    suite=$(. /etc/os-release && echo "${VERSION_CODENAME}"); \
    rm -f /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s %s main\n' \
      "${DEBIAN_SNAPSHOT}" "${suite}" > /etc/apt/sources.list; \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10no-check-valid-until; \
    apt-get update; \
    apt-get install --yes --no-install-recommends \
      bc \
      bison \
      build-essential \
      flex \
      kmod \
      libelf-dev \
      libssl-dev \
      python3 \
      xz-utils; \
    rm -rf /var/lib/apt/lists/*

COPY ${KERNEL_DEVEL_TARBALL} /tmp/kernel-devel.tar.gz

# The archive's own metadata is the authority on which kernel it belongs to, so
# a mismatch with the requested release fails the build instead of producing an
# image whose KDIR silently points at a different kernel.
RUN set -eux; \
    test -n "${KERNEL_RELEASE}"; \
    mkdir -p /usr/src; \
    tar -C /usr/src --strip-components=1 -xzf /tmp/kernel-devel.tar.gz; \
    rm /tmp/kernel-devel.tar.gz; \
    declared=$(python3 -c 'import json;print(json.load(open("/usr/src/kernel-devel.json"))["kernel_release"])'); \
    test "${declared}" = "${KERNEL_RELEASE}"; \
    test -f "/usr/src/linux-headers-${KERNEL_RELEASE}/Module.symvers"; \
    mkdir -p "/lib/modules/${KERNEL_RELEASE}"; \
    ln -s "/usr/src/linux-headers-${KERNEL_RELEASE}" "/lib/modules/${KERNEL_RELEASE}/build"

# Pass KDIR explicitly; uname -r inside a container still names the host kernel.
# The /lib/modules symlink is for consumers using the target KERNEL_RELEASE.
ENV KDIR="/usr/src/linux-headers-${KERNEL_RELEASE}"
ENV KERNEL_RELEASE="${KERNEL_RELEASE}"

LABEL org.opencontainers.image.title="dstack kernel module builder" \
      org.opencontainers.image.description="Kernel build tree and toolchain for dstack guest OS ${IMAGE_VERSION}" \
      org.opencontainers.image.source="https://github.com/Dstack-TEE/dstack" \
      org.opencontainers.image.revision="${GIT_REVISION}" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      network.phala.dstack.kernel-release="${KERNEL_RELEASE}" \
      network.phala.dstack.os-image-hash="${OS_IMAGE_HASH}"

WORKDIR /work
