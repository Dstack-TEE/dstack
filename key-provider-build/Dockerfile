# SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Stage 1: Build
FROM gramineproject/gramine:1.9-jammy@sha256:84b3d222e0bd9ab941f0078a462af0dbc5518156b99b147c10a7b83722ac0c38 AS builder

RUN apt-get update && apt-get install -y \
        git \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain 1.85 -y
ENV PATH="/root/.cargo/bin:${PATH}"

ENV SGX=1 DEBUG=0 DEV_MODE=0 RUST_LOG=info

RUN git clone https://github.com/MoeMahhouk/gramine-sealing-key-provider && \
    cd gramine-sealing-key-provider && \
    git checkout 180ff4691dce5aae7cd7d6c1344c3e1ec872f174

WORKDIR /gramine-sealing-key-provider
COPY Cargo.lock .

RUN make target/release/gramine-sealing-key-provider && \
    gramine-sgx-gen-private-key && \
    make RUST_LOG=info

# Stage 2: Runtime
# Same base image = same /lib/x86_64-linux-gnu/ (except libgcc-s1 from build-essential)
FROM gramineproject/gramine:1.9-jammy@sha256:84b3d222e0bd9ab941f0078a462af0dbc5518156b99b147c10a7b83722ac0c38

# libgcc-s1: only /lib/x86_64-linux-gnu/ addition from build-essential, needed for manifest hash match
# libsgx-dcap-default-qpl: not in base image, needed by aesmd for DCAP
RUN curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
        | gpg --dearmor -o /usr/share/keyrings/intel-sgx-deb.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' \
        > /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install -y \
        libgcc-s1 \
        libsgx-dcap-default-qpl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /gramine-sealing-key-provider/target/release/gramine-sealing-key-provider /gramine-sealing-key-provider/target/release/gramine-sealing-key-provider
COPY --from=builder /gramine-sealing-key-provider/gramine-sealing-key-provider.manifest.sgx /gramine-sealing-key-provider/
COPY --from=builder /gramine-sealing-key-provider/gramine-sealing-key-provider.sig /gramine-sealing-key-provider/

WORKDIR /gramine-sealing-key-provider

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3443

ENTRYPOINT ["/entrypoint.sh"]
