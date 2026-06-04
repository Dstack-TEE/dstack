# dstack-verifier built from THIS repo's source (local tree), with the QEMU-based
# `dstack-acpi-tables` helper that dstack-mr needs to compute RTMR0 expected MRs.
# Mirrors verifier/builder/Dockerfile but builds the verifier from the local
# workspace (COPY .) instead of git-cloning, and skips package pinning.
#
# Build context: workspace root (docker build -f on-prem/verifier/Dockerfile .)

# ── stage 1: build dstack-verifier from local source ─────────────────────────
FROM rust:1.92-slim-bookworm AS verifier-builder
RUN apt-get update && apt-get install -y \
    build-essential libssl-dev protobuf-compiler libprotobuf-dev \
    clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p dstack-verifier

# ── stage 2: build qemu-tdx → dstack-acpi-tables (ACPI table dumper) ──────────
FROM debian:bookworm AS acpi-builder
WORKDIR /build
COPY build/shared/config-qemu.sh /build/config-qemu.sh
ARG QEMU_REV=dbcec07c0854bf873d346a09e87e4c993ccf2633
RUN apt-get update && apt-get install -y --no-install-recommends \
    git libslirp-dev python3-pip ninja-build pkg-config libglib2.0-dev \
    python3-sphinx python3-sphinx-rtd-theme build-essential flex bison \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/kvinwang/qemu-tdx.git --depth 1 --branch dstack-qemu-9.2.1 --single-branch && \
    cd qemu-tdx && git fetch --depth 1 origin ${QEMU_REV} && \
    git checkout ${QEMU_REV} && \
    ../config-qemu.sh ./build /usr/local && \
    cd build && ninja && \
    strip qemu-system-x86_64 && \
    install -m 755 qemu-system-x86_64 /usr/local/bin/dstack-acpi-tables && \
    cd ../ && \
    install -d /usr/local/share/qemu && \
    install -m 644 pc-bios/efi-virtio.rom /usr/local/share/qemu/ && \
    install -m 644 pc-bios/kvmvapic.bin /usr/local/share/qemu/ && \
    install -m 644 pc-bios/linuxboot_dma.bin /usr/local/share/qemu/

# ── stage 3: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libglib2.0-0 libslirp0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=verifier-builder /build/target/release/dstack-verifier /usr/local/bin/dstack-verifier
COPY --from=acpi-builder /usr/local/bin/dstack-acpi-tables /usr/local/bin/dstack-acpi-tables
COPY --from=acpi-builder /usr/local/share/qemu /usr/local/share/qemu
EXPOSE 8080
# config via DSTACK_VERIFIER_* env (see verifier/dstack-verifier.toml)
CMD ["dstack-verifier"]
