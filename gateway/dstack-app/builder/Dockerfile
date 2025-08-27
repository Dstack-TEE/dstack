# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.86.0@sha256:300ec56abce8cc9448ddea2172747d048ed902a3090e6b57babb2bf19f754081 AS gateway-builder
COPY ./shared /build
ARG DSTACK_REV
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
RUN git clone https://github.com/Dstack-TEE/dstack.git && \
    cd dstack && \
    git checkout ${DSTACK_REV}
RUN rustup target add x86_64-unknown-linux-musl
RUN cd dstack && cargo build --release -p dstack-gateway --target x86_64-unknown-linux-musl
RUN echo "${DSTACK_REV}" > /build/.GIT_REV

FROM debian:bookworm@sha256:731dd1380d6a8d170a695dbeb17fe0eade0e1c29f654cf0a3a07f372191c3f4b
COPY ./shared /build
WORKDIR /build
RUN ./pin-packages.sh ./pinned-packages.txt && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    wireguard-tools \
    iproute2 \
    jq \
    && rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache
COPY --from=gateway-builder /build/dstack/target/x86_64-unknown-linux-musl/release/dstack-gateway /usr/local/bin/dstack-gateway
COPY --from=gateway-builder /build/.GIT_REV /etc/
WORKDIR /app
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["dstack-gateway"]
