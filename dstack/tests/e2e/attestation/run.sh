#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
docker compose build
for platform in dstack-tdx-legacy dstack-tdx-lite gcp-tdx amd-sev-snp aws-nitro-enclave aws-nitro-tpm; do
  echo "=== $platform ==="
  docker compose run --rm "$platform"
done
docker compose down --remove-orphans
