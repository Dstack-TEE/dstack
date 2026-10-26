# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Toolchain image for building out-of-tree modules against one dstack guest OS
# kernel: its exported build tree plus a compiler from the same pinned Debian
# snapshot the kernel was built with. Built by build.sh.

ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE}

ARG DEBIAN_SNAPSHOT
ARG KERNEL_RELEASE
ARG IMAGE_VERSION=unknown
ARG GIT_REVISION=unknown

# Pin apt to the snapshot; trixie also ships deb822 sources that must go.
RUN set -eux; \
    suite=$(. /etc/os-release && echo "${VERSION_CODENAME}"); \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT:?} ${suite} main" \
      > /etc/apt/sources.list; \
    apt-get update; \
    apt-get install --yes --no-install-recommends \
      bc bison build-essential flex kmod libelf-dev libssl-dev; \
    rm -rf /var/lib/apt/lists/*

ENV KERNEL_RELEASE=${KERNEL_RELEASE}
ENV KDIR=/usr/src/linux-headers-${KERNEL_RELEASE}

ADD kernel-devel.tar.gz /tmp/
RUN set -eux; \
    mv /tmp/*-kernel-devel/linux-headers-* /usr/src/; \
    rm -rf /tmp/*-kernel-devel; \
    test "$(cat "$KDIR/include/config/kernel.release")" = "${KERNEL_RELEASE:?}"; \
    mkdir -p "/lib/modules/${KERNEL_RELEASE}"; \
    ln -s "$KDIR" "/lib/modules/${KERNEL_RELEASE}/build"

LABEL org.opencontainers.image.title="dstack kernel module builder" \
      org.opencontainers.image.source="https://github.com/Dstack-TEE/dstack" \
      org.opencontainers.image.revision="${GIT_REVISION}" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      network.phala.dstack.kernel-release="${KERNEL_RELEASE}"

WORKDIR /work
