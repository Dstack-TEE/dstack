# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN git init helios && cd helios \
    && git remote add origin https://github.com/a16z/helios \
    && git fetch --depth 1 origin d20aa4f4de5886b6c78004447ee197a1cf744362 \
    && git checkout --detach FETCH_HEAD
WORKDIR /build/helios
COPY helios.patch /build/helios.patch
RUN git apply --check /build/helios.patch && git apply /build/helios.patch
COPY fixtures/phala-signed-commitment.json opstack/tests/fixtures/phala-signed-commitment.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/helios/target \
    cargo test --locked -p helios-opstack --lib \
    && cargo build --locked --release -p helios-cli -p helios-opstack --bins \
    && install -D target/release/helios /out/helios \
    && install -D target/release/opstack-server /out/opstack-server

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 helios
COPY --from=build /out/ /usr/local/bin/
USER helios
ENV HOME=/home/helios
CMD ["helios", "opstack", "--network", "phala"]
