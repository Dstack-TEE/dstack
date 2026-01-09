# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.92.0@sha256:48851a839d6a67370c9dbe0e709bedc138e3e404b161c5233aedcf2b717366e4 AS kms-builder
COPY ./shared /build
ARG DSTACK_REV
ARG DSTACK_SRC_URL=https://github.com/Dstack-TEE/dstack.git
WORKDIR /build
RUN ./pin-packages.sh ./kms-pinned-packages.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    build-essential \
    musl-tools \
    libssl-dev \
    protobuf-compiler \
    libprotobuf-dev \
    clang \
    libclang-dev
RUN git clone ${DSTACK_SRC_URL} && \
    cd dstack && \
    git checkout ${DSTACK_REV}
RUN rustup target add x86_64-unknown-linux-musl
RUN cd dstack && cargo build --release -p dstack-kms --target x86_64-unknown-linux-musl

FROM debian:bookworm@sha256:0d8498a0e9e6a60011df39aab78534cfe940785e7c59d19dfae1eb53ea59babe
COPY ./shared /build
WORKDIR /build
ARG QEMU_REV=dbcec07c0854bf873d346a09e87e4c993ccf2633
RUN ./pin-packages.sh ./qemu-pinned-packages.txt && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    libslirp-dev \
    python3-pip \
    ninja-build \
    pkg-config \
    libglib2.0-dev \
    python3-sphinx \
    python3-sphinx-rtd-theme \
    build-essential \
    flex \
    bison && \
    rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache
RUN git clone https://github.com/kvinwang/qemu-tdx.git --depth 1 --branch dstack-qemu-9.2.1 --single-branch && \
    cd qemu-tdx && git fetch --depth 1 origin ${QEMU_REV} && \
    git checkout ${QEMU_REV} && \
    ../config-qemu.sh ./build /usr/local && \
    cd build && \
    ninja && \
    strip qemu-system-x86_64 && \
    install -m 755 qemu-system-x86_64 /usr/local/bin/dstack-acpi-tables && \
    cd ../ && \
    install -d /usr/local/share/qemu && \
    install -m 644 pc-bios/efi-virtio.rom /usr/local/share/qemu/ && \
    install -m 644 pc-bios/kvmvapic.bin /usr/local/share/qemu/ && \
    install -m 644 pc-bios/linuxboot_dma.bin /usr/local/share/qemu/ && \
    cd .. && rm -rf qemu-tdx
COPY --from=kms-builder /build/dstack/target/x86_64-unknown-linux-musl/release/dstack-kms /usr/local/bin/dstack-kms
COPY .GIT_REV /etc/.GIT_REV
CMD ["dstack-kms"]
