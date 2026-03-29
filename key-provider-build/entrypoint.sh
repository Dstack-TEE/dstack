#!/bin/sh

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -e

# Start AESM service in background
echo "Starting AESM service..."
mkdir -p /var/run/aesmd
chmod 755 /var/run/aesmd
export AESM_PATH=/opt/intel/sgx-aesm-service/aesm
export LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm
/opt/intel/sgx-aesm-service/aesm/aesm_service --no-daemon &
AESM_PID=$!

# Clean up aesmd on exit
trap "kill $AESM_PID 2>/dev/null; exit" INT TERM EXIT

# Wait for AESM socket
echo "Waiting for AESM socket..."
AESM_SOCKET="/var/run/aesmd/aesm.socket"
while [ ! -S "$AESM_SOCKET" ]; do
    if ! kill -0 "$AESM_PID" 2>/dev/null; then
        echo "Error: AESM service exited unexpectedly"
        exit 1
    fi
    sleep 1
done
echo "AESM socket is available."

# Show enclave info
echo "Enclave info:"
gramine-sgx-sigstruct-view --output-format json gramine-sealing-key-provider.sig

# Replace shell with gramine-sgx so it receives signals directly as PID 1
echo "Starting Gramine Sealing Key Provider"
exec gramine-sgx gramine-sealing-key-provider
