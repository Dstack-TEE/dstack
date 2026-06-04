# dstack launcher: fetches the decryption keyring from the KMS key-broker
# (mTLS), pulls the JWE-encrypted workload image by digest, decrypts it with the
# leased private keys (ocicrypt native JWE), and runs it via docker compose.
# Build context: workspace root.
#   docker build -f on-prem/launcher/Dockerfile -t cr.kvin.wang/launcher:latest .

FROM rust:1.92-slim-bookworm AS builder
RUN apt-get update && apt-get install -y \
    build-essential libssl-dev protobuf-compiler libprotobuf-dev \
    clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p launcher

# ubuntu 24.04 ships skopeo 1.13.x with solid ocicrypt JWE support (debian
# bookworm's 1.9.3 is older). glibc 2.39 runs the bookworm-built launcher binary
# fine (forward-compatible).
FROM ubuntu:24.04
# skopeo (ocicrypt JWE decrypt), docker CLI + compose plugin (manage the
# workload containers via the host docker socket). No keyprovider/python: JWE
# decryption is built into skopeo/ocicrypt and driven by --decryption-key.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates skopeo docker.io curl \
    && rm -rf /var/lib/apt/lists/*
# docker compose v2 plugin (not in debian repos) — fetch the static binary
RUN mkdir -p /usr/local/lib/docker/cli-plugins && \
    curl -fsSL "https://github.com/docker/compose/releases/download/v2.32.4/docker-compose-linux-x86_64" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
COPY --from=builder /build/target/release/launcher /usr/local/bin/launcher
# the dstack host dockerd requires docker API >= 1.44
ENV DOCKER_API_VERSION=1.44
CMD ["launcher"]
