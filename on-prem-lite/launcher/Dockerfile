# dstack-lite-launcher: KMS-less "on-prem-lite" launcher. Serves a plain-HTTP
# courier API (reached via the operator's IAP tunnel), verifies a signed License,
# HPKE-opens the image CEK, pulls the JWE-encrypted workload image by digest,
# decrypts it (ocicrypt native JWE), runs it via docker compose, and enforces the
# License expiry with a watchdog.
# Build context: workspace root.
#   docker build -f on-prem-lite/launcher/Dockerfile -t cr.kvin.wang/lite-launcher:latest .

FROM rust:1.92-slim-bookworm AS builder
RUN apt-get update && apt-get install -y \
    build-essential libssl-dev protobuf-compiler libprotobuf-dev \
    clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p dstack-lite-launcher

# ubuntu 24.04 ships skopeo 1.13.x with solid ocicrypt JWE support (debian
# bookworm's 1.9.3 is older). glibc 2.39 runs the bookworm-built binary fine.
FROM ubuntu:24.04
# skopeo (ocicrypt JWE decrypt), docker CLI + compose plugin (manage the
# workload containers via the host docker socket). curl is used for the GCP
# metadata-server registry token. No keyprovider/python: JWE decryption is built
# into skopeo/ocicrypt and driven by --decryption-key.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates skopeo docker.io curl \
    && rm -rf /var/lib/apt/lists/*
# docker compose v2 plugin (not in debian repos) — fetch the static binary
RUN mkdir -p /usr/local/lib/docker/cli-plugins && \
    curl -fsSL "https://github.com/docker/compose/releases/download/v2.32.4/docker-compose-linux-x86_64" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
COPY --from=builder /build/target/release/dstack-lite-launcher /usr/local/bin/dstack-lite-launcher
# the dstack host dockerd requires docker API >= 1.44
ENV DOCKER_API_VERSION=1.44 LITE_PORT=9000
EXPOSE 9000
CMD ["dstack-lite-launcher"]
