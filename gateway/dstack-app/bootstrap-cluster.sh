#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Bootstrap the gateway admin API with ACME config, DNS credentials, and ZT-Domain.
# This only needs to run once per cluster — additional nodes sync config automatically.
#
# Usage:
#   bash bootstrap-cluster.sh                  # Uses GATEWAY_ADMIN_RPC_ADDR from .env
#   bash bootstrap-cluster.sh <admin-addr>     # Explicit admin address (e.g., 127.0.0.1:19603)

# Load .env if present
if [ -f ".env" ]; then
  set -a
  source .env
  set +a
fi

ADMIN_ADDR="${1:-${GATEWAY_ADMIN_RPC_ADDR:-127.0.0.1:9203}}"

echo "Waiting for gateway admin API at $ADMIN_ADDR..."
max_retries=60
retry=0
while [ $retry -lt $max_retries ]; do
  if curl -sf "http://$ADMIN_ADDR/prpc/Status" >/dev/null 2>&1; then
    break
  fi
  retry=$((retry + 1))
  sleep 5
done

if [ $retry -eq $max_retries ]; then
  echo "ERROR: admin API not ready after $max_retries retries"
  echo "You can configure the gateway manually via the Web UI at http://$ADMIN_ADDR"
  exit 1
fi

echo "Admin API ready, bootstrapping configuration..."

# Set ACME URL
if [ "$ACME_STAGING" = "yes" ]; then
  ACME_URL="https://acme-staging-v02.api.letsencrypt.org/directory"
else
  ACME_URL="https://acme-v02.api.letsencrypt.org/directory"
fi

echo "Setting certbot config (ACME URL: $ACME_URL)..."
curl -sf -X POST "http://$ADMIN_ADDR/prpc/SetCertbotConfig" \
  -H "Content-Type: application/json" \
  -d '{"acme_url":"'"$ACME_URL"'","renew_interval_secs":3600,"renew_before_expiration_secs":864000,"renew_timeout_secs":300}' >/dev/null \
  && echo "  Certbot config set" || echo "  WARN: failed to set certbot config"

# Create DNS credential if CF_API_TOKEN is provided and no credentials exist yet
if [ -n "$CF_API_TOKEN" ]; then
  existing=$(curl -sf "http://$ADMIN_ADDR/prpc/ListDnsCredentials" 2>/dev/null)
  cred_count=$(echo "$existing" | jq -r '.credentials | length' 2>/dev/null || echo "0")

  if [ "$cred_count" = "0" ]; then
    echo "Creating default DNS credential..."
    curl -sf -X POST "http://$ADMIN_ADDR/prpc/CreateDnsCredential" \
      -H "Content-Type: application/json" \
      -d '{"name":"cloudflare","provider_type":"cloudflare","cf_api_token":"'"$CF_API_TOKEN"'","set_as_default":true}' >/dev/null \
      && echo "  DNS credential created" || echo "  WARN: failed to create DNS credential"
  else
    echo "  DNS credentials already exist ($cred_count), skipping"
  fi
else
  echo "  WARN: CF_API_TOKEN not set, skipping DNS credential creation"
fi

# Add ZT-Domain if SRV_DOMAIN is provided and domain doesn't exist yet
if [ -n "$SRV_DOMAIN" ]; then
  existing=$(curl -sf "http://$ADMIN_ADDR/prpc/ListZtDomains" 2>/dev/null)
  has_domain=$(echo "$existing" | jq -r '.domains[]? | select(.domain=="'"$SRV_DOMAIN"'") | .domain' 2>/dev/null)

  if [ -z "$has_domain" ]; then
    echo "Adding ZT-Domain: $SRV_DOMAIN..."
    curl -sf -X POST "http://$ADMIN_ADDR/prpc/AddZtDomain" \
      -H "Content-Type: application/json" \
      -d '{"domain":"'"$SRV_DOMAIN"'","port":443,"priority":100}' >/dev/null \
      && echo "  ZT-Domain added" || echo "  WARN: failed to add ZT-Domain"
  else
    echo "  ZT-Domain $SRV_DOMAIN already exists, skipping"
  fi
fi

echo "Bootstrap complete"
echo "Gateway Web UI: http://$ADMIN_ADDR"
