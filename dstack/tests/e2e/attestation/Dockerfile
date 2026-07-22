# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.92-bookworm AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --locked \
    -p dstack-tee-simulator \
    -p mock-attestation \
    -p dstack-util \
    -p dstack-verifier \
    -p dstack-mr \
 && mkdir -p /out \
 && cp target/debug/dstack-tee-simulator target/debug/dstack-mock-attestation \
       target/debug/dstack-util target/debug/dstack-verifier target/debug/dstack-mr /out/ \
 && strip /out/*

FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl fuse3 jq kmod openssl swtpm tpm2-tools xxd \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/ /usr/local/bin/
COPY cc-eventlog/samples/tpm_eventlog.bin /usr/local/share/dstack/tpm_eventlog.bin
COPY verifier/fixtures/tdx-lite-getquote.json /usr/local/share/dstack/tdx-lite-getquote.json
COPY verifier/fixtures/sev-snp-attestation.json /usr/local/share/dstack/sev-snp-attestation.json
ENTRYPOINT ["/usr/local/bin/run-platform"]
