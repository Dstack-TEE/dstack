#!/bin/sh

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

echo "Starting AESM service..."
# Make sure the AESM directory exists with proper permissions
mkdir -p /var/run/aesmd
chmod 755 /var/run/aesmd

# Start the AESM service
export AESM_PATH=/opt/intel/sgx-aesm-service/aesm
export LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm
/opt/intel/sgx-aesm-service/aesm/aesm_service --no-daemon
