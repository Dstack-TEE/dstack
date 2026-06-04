# Build context: workspace root (docker build -f on-prem/key-broker/Dockerfile .)
# bookworm-based to match the debian:bookworm-slim runtime glibc (2.36)
FROM rust:1.92-slim-bookworm AS builder
RUN apt-get update && apt-get install -y \
    build-essential libssl-dev protobuf-compiler libprotobuf-dev \
    clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p key-broker

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/key-broker /usr/local/bin/key-broker
ENV PORT=8001 PORT_MTLS=8002 KMS_VOLUME=/kms
EXPOSE 8001 8002
CMD ["key-broker"]
