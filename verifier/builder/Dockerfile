# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.86.0@sha256:300ec56abce8cc9448ddea2172747d048ed902a3090e6b57babb2bf19f754081 AS verifier-builder
COPY builder/shared /build/shared
ARG DSTACK_REV
ARG DSTACK_SRC_URL=https://github.com/Dstack-TEE/dstack.git
WORKDIR /build
RUN ./shared/pin-packages.sh ./shared/builder-pinned-packages.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    build-essential \
    musl-tools \
    libssl-dev \
    protobuf-compiler \
    libprotobuf-dev \
    clang \
    libclang-dev \
    pkg-config \
    ca-certificates \
    curl && \
    rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache
RUN git clone ${DSTACK_SRC_URL} && \
    cd dstack && \
    git checkout ${DSTACK_REV}
RUN rustup target add x86_64-unknown-linux-musl
RUN cd dstack && cargo build --release -p dstack-verifier --target x86_64-unknown-linux-musl
RUN echo "${DSTACK_REV}" > /build/.GIT_REV

FROM debian:bookworm@sha256:0d8498a0e9e6a60011df39aab78534cfe940785e7c59d19dfae1eb53ea59babe AS acpi-builder
COPY builder/shared /build
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

FROM debian:bookworm@sha256:0d8498a0e9e6a60011df39aab78534cfe940785e7c59d19dfae1eb53ea59babe
COPY builder/shared /build
WORKDIR /build
RUN ./pin-packages.sh ./pinned-packages.txt && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libglib2.0-0 \
    libslirp0 \
    && rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache
COPY --from=verifier-builder /build/dstack/target/x86_64-unknown-linux-musl/release/dstack-verifier /usr/local/bin/dstack-verifier
COPY --from=verifier-builder /build/.GIT_REV /etc/
COPY --from=acpi-builder /usr/local/bin/dstack-acpi-tables /usr/local/bin/dstack-acpi-tables
COPY --from=acpi-builder /usr/local/share/qemu /usr/local/share/qemu
RUN mkdir -p /etc/dstack
COPY dstack-verifier.toml /etc/dstack/dstack-verifier.toml
WORKDIR /var/lib/dstack-verifier
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dstack-verifier"]
CMD ["--config", "/etc/dstack/dstack-verifier.toml"]
