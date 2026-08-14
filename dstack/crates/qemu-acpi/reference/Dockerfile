# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:24.04 AS builder

ARG QEMU_REPOSITORY=https://github.com/kvinwang/qemu-tdx.git
ARG QEMU_REVISION=9de6fdfff3a84103b83ca6b2e8c4fb8e05cf9195

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates git ninja-build pkg-config python3 python3-venv \
        build-essential libglib2.0-dev libpixman-1-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --filter=blob:none "${QEMU_REPOSITORY}" /src/qemu \
    && git -C /src/qemu checkout "${QEMU_REVISION}"

WORKDIR /src/qemu/build-acpi
RUN CFLAGS='-O2 -DDUMP_ACPI_TABLES -Wno-builtin-macro-redefined -D__DATE__="" -D__TIME__="" -D__TIMESTAMP__=""' \
    LDFLAGS='-Wl,--build-id=none' \
    ../configure \
        --target-list=x86_64-softmmu \
        --disable-werror \
        --disable-docs \
        --disable-gtk \
        --disable-sdl \
        --disable-vnc \
        --disable-curses \
        --disable-tools \
        --disable-user \
    && ninja qemu-system-x86_64

FROM ubuntu:24.04

ARG QEMU_REVISION=9de6fdfff3a84103b83ca6b2e8c4fb8e05cf9195
LABEL org.opencontainers.image.source="https://github.com/kvinwang/qemu-tdx" \
      org.opencontainers.image.revision="${QEMU_REVISION}" \
      org.opencontainers.image.licenses="GPL-2.0-or-later"

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libglib2.0-0 libpixman-1-0 zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/qemu/build-acpi/qemu-system-x86_64 /usr/local/bin/dstack-acpi-tables
COPY --from=builder /src/qemu/pc-bios /usr/share/qemu

ENTRYPOINT ["/usr/local/bin/dstack-acpi-tables", "-L", "/usr/share/qemu", "-bios", "/usr/share/qemu/bios-256k.bin"]
