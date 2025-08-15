# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.86.0@sha256:300ec56abce8cc9448ddea2172747d048ed902a3090e6b57babb2bf19f754081 AS gateway-builder
ARG DSTACK_REV
WORKDIR /src

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    build-essential \
    libssl-dev \
    protobuf-compiler \
    libprotobuf-dev \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone and checkout specific revision
RUN git clone https://github.com/Dstack-TEE/dstack.git && \
    cd dstack && \
    git checkout ${DSTACK_REV}

# Build the gateway binary
WORKDIR /src/dstack
RUN cargo build --release -p dstack-gateway

# Runtime stage
FROM debian:bookworm@sha256:ced9eb5eca0a3ba2e29d0045513863b3baaee71cd8c2eed403c9f7d3eaccfd2b
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wireguard-tools \
    iproute2 \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary
COPY --from=gateway-builder /src/dstack/target/release/dstack-gateway /usr/local/bin/dstack-gateway

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Store git revision for reproducibility
ARG DSTACK_REV
RUN echo "${DSTACK_REV}" > /etc/.GIT_REV

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["dstack-gateway"]
