# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.92.0@sha256:48851a839d6a67370c9dbe0e709bedc138e3e404b161c5233aedcf2b717366e4 AS kms-builder
COPY --from=build-shared /pin-packages.sh /build/
COPY ./shared/*-pinned-packages.txt /build/
ARG DSTACK_REV
ARG DSTACK_SRC_URL=https://github.com/Dstack-TEE/dstack.git
WORKDIR /build
RUN ./pin-packages.sh ./builder-pinned-packages.txt
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
RUN git clone ${DSTACK_SRC_URL} repo && \
    cd repo && \
    git checkout ${DSTACK_REV}
RUN rustup target add x86_64-unknown-linux-musl
RUN cd repo/dstack && cargo build --release -p dstack-kms --target x86_64-unknown-linux-musl
RUN echo "${DSTACK_REV}" > /build/.GIT_REV

FROM debian:bookworm@sha256:0d8498a0e9e6a60011df39aab78534cfe940785e7c59d19dfae1eb53ea59babe
COPY --from=kms-builder /build/repo/dstack/target/x86_64-unknown-linux-musl/release/dstack-kms /usr/local/bin/dstack-kms
COPY --from=kms-builder /build/.GIT_REV /etc/
CMD ["dstack-kms"]
