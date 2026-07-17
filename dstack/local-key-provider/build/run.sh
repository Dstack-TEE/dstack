#!/bin/bash

# SPDX-FileCopyrightText: © 2025-2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

echo "Starting all SGX services using docker-compose..."
docker compose up --build -d

echo "=========================="
echo "Services started!"
echo "=========================="
echo "Key provider endpoint: tcp://127.0.0.1:3443"
echo "  - Using shared socket with AESM service"
echo "  - Socket location: /var/run/aesmd/aesm.socket"
echo
echo "Check logs with:"
echo "  docker compose logs -f aesmd"
echo "  docker compose logs -f local-key-provider"
echo "=========================="
