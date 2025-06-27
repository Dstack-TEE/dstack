ARG GIT_REV=main
FROM rust:1.86.0@sha256:300ec56abce8cc9448ddea2172747d048ed902a3090e6b57babb2bf19f754081 AS kms-builder
ARG GIT_REV
COPY ./shared /build
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
RUN git clone https://github.com/Dstack-TEE/dstack.git && \
    cd dstack && \
    git checkout ${GIT_REV}
RUN rustup target add x86_64-unknown-linux-musl
RUN cd dstack && cargo build --release -p dstack-kms --target x86_64-unknown-linux-musl

FROM debian:bookworm@sha256:0d8498a0e9e6a60011df39aab78534cfe940785e7c59d19dfae1eb53ea59babe
COPY ./shared /build
WORKDIR /build
RUN ./pin-packages.sh ./qemu-pinned-packages.txt
RUN apt-get update && \
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
    bison

RUN git clone https://github.com/kvinwang/qemu-tdx.git --depth 1 --branch passthrough-dump-acpi && \
    cd qemu-tdx && \
    mkdir build && \
    cd build && \
    CFLAGS="-DDUMP_ACPI_TABLES" ../configure --prefix=/usr --target-list=x86_64-softmmu && \
    ninja && make install && \
    mv /usr/bin/qemu-system-x86_64 /usr/bin/dstack-acpi-tables && \
    cd ../.. && rm -rf qemu-tdx
COPY --from=kms-builder /build/dstack/target/x86_64-unknown-linux-musl/release/dstack-kms /usr/local/bin/dstack-kms
