#!/bin/sh

# SPDX-FileCopyrightText: © 2025-2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -eu

echo "Waiting for AESM socket to be available..."
AESM_SOCKET="/var/run/aesmd/aesm.socket"
for i in $(seq 1 30); do
    if [ -S "$AESM_SOCKET" ]; then
        echo "AESM socket is available."
        break
    fi
    echo "Waiting for AESM socket ($i/30)..."
    sleep 1
done

if [ ! -S "$AESM_SOCKET" ]; then
    echo "Error: AESM socket is not available after 30 seconds."
    exit 1
fi

echo "Enclave info:"
gramine-sgx-sigstruct-view --output-format json local-key-provider.sig

echo "Starting dstack Local Key Provider"
exec gramine-sgx local-key-provider
