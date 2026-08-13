# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.92.0-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2 AS verifier-builder
COPY --from=build-shared pin-packages.sh /build/
COPY builder/shared/*-pinned-packages.txt /build/
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
    libclang-dev \
    pkg-config \
    ca-certificates \
    curl && \
    rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache
RUN git clone ${DSTACK_SRC_URL} repo && \
    cd repo && \
    git checkout ${DSTACK_REV}
RUN rustup target add x86_64-unknown-linux-musl
RUN cd repo/dstack && cargo build --release -p dstack-verifier --target x86_64-unknown-linux-musl
RUN echo "${DSTACK_REV}" > /build/.GIT_REV

FROM debian:bookworm@sha256:0d8498a0e9e6a60011df39aab78534cfe940785e7c59d19dfae1eb53ea59babe
COPY --from=build-shared pin-packages.sh /build/
COPY builder/shared/pinned-packages.txt /build/
WORKDIR /build
RUN ./pin-packages.sh ./pinned-packages.txt && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache
COPY --from=verifier-builder /build/repo/dstack/target/x86_64-unknown-linux-musl/release/dstack-verifier /usr/local/bin/dstack-verifier
COPY --from=verifier-builder /build/.GIT_REV /etc/
RUN mkdir -p /etc/dstack
COPY dstack-verifier.toml /etc/dstack/dstack-verifier.toml
WORKDIR /var/lib/dstack-verifier
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dstack-verifier"]
CMD ["--config", "/etc/dstack/dstack-verifier.toml"]
