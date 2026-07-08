# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      software-properties-common \
    && add-apt-repository -y ppa:kobuk-team/tdx-release && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      bash \
      coreutils \
      curl \
      iproute2 \
      iptables \
      iputils-ping \
      jq \
      netcat-openbsd \
      openssl \
      procps \
      python3 \
      qemu-system-x86 \
      qemu-utils \
      socat \
      tini \
      wireguard-tools \
      xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /suite
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash"]
