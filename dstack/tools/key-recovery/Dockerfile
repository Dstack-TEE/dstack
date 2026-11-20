# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Pinned build: the source is cloned at DSTACK_REV, base images are pinned by
# digest, and Cargo.lock is enforced. The release workflow passes the tag
# commit as DSTACK_REV.
#
#   docker build \
#     --build-arg DSTACK_REV="$(git rev-parse HEAD)" \
#     -f dstack/tools/key-recovery/Dockerfile \
#     dstack/tools/key-recovery

FROM rust:1.92.0-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2 AS build

ARG DSTACK_REV
ARG DSTACK_SRC_URL=https://github.com/Dstack-TEE/dstack.git

RUN apt-get update \
 && apt-get install -y --no-install-recommends git musl-tools ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /src
RUN git clone "${DSTACK_SRC_URL}" repo \
 && cd repo \
 && git checkout "${DSTACK_REV}"
RUN cd repo/dstack \
 && cargo build --release --locked -p dstack-key-recovery --target x86_64-unknown-linux-musl
RUN echo "${DSTACK_REV}" > /src/.GIT_REV

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/repo/dstack/target/x86_64-unknown-linux-musl/release/dstack-key-recovery /dstack-key-recovery
COPY --from=build /src/.GIT_REV /.GIT_REV

# In a container the app reaches the sidecar over the compose network, so listen
# on all interfaces and skip the Unix socket.
ENTRYPOINT ["/dstack-key-recovery"]
CMD ["serve", "--addr", "0.0.0.0:8099", "--no-socket"]
