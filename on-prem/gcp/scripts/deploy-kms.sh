#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Deploy / configure dstack-kms + key-broker on the CUSTOMER's TDX Confidential
# VM. Renders the compose (host networking, dstack.sock mount, AUTHORITY_PUBKEY
# for AuthBundle signature verification) and kms.toml, ships them to the CVM,
# pulls images and (re)creates the containers.
#
# The CVM is a dstack-cloud OS image (TDX). It reaches cr.kvin.wang via Cloud NAT
# (egress only). The compose lives at /dstack/docker-compose.yaml and the KMS
# config + state at /dstack/persistent/kms/.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

AUTHORITY_PUBKEY="${AUTHORITY_PUBKEY:-}"
[[ -z "$AUTHORITY_PUBKEY" && -f "$HERE/.authority-pubkey" ]] && AUTHORITY_PUBKEY="$(cat "$HERE/.authority-pubkey")"
[[ -n "$AUTHORITY_PUBKEY" ]] || c_die "AUTHORITY_PUBKEY not set (run deploy-authority.sh first)"

KMS_DIR=/dstack/persistent/kms
COMPOSE=/dstack/docker-compose.yaml
TMP_COMPOSE="$(mktemp)"; TMP_TOML="$(mktemp)"
trap 'rm -f "$TMP_COMPOSE" "$TMP_TOML"' EXIT

c_step "rendering KMS + key-broker compose (AUTHORITY_PUBKEY=${AUTHORITY_PUBKEY:0:16}…)"
cat > "$TMP_COMPOSE" <<EOF
services:
  kms:
    image: ${KMS_IMAGE}
    restart: unless-stopped
    network_mode: host
    volumes:
      - ${KMS_DIR}:/kms
    command: dstack-kms -c /kms/kms.toml

  key-broker:
    image: ${KEY_BROKER_IMAGE}
    restart: unless-stopped
    network_mode: host
    volumes:
      - ${KMS_DIR}:/kms
      - /var/run/dstack.sock:/var/run/dstack.sock   # guest agent → TDX Attest
    environment:
      - PORT=8001
      - PORT_MTLS=8002
      - KMS_VOLUME=/kms
      - AUTHORITY_PUBKEY=${AUTHORITY_PUBKEY}           # enables AuthBundle sig verify
EOF

# kms.toml: host networking → webhook on loopback; cert_dir on the shared volume;
# enforce_self_authorization=false (KMS root comes from the authority via courier).
cp "$ROOT/kms.toml" "$TMP_TOML"

c_step "shipping config to ${KMS_VM}"
kms_ssh "mkdir -p ${KMS_DIR}"
kms_put "$TMP_COMPOSE" "$COMPOSE"
kms_put "$TMP_TOML" "${KMS_DIR}/kms.toml"
c_ok "wrote ${COMPOSE} and ${KMS_DIR}/kms.toml"

c_step "pulling images + (re)creating containers"
kms_ssh "docker compose -f ${COMPOSE} pull 2>&1 | tail -2
docker compose -f ${COMPOSE} up -d --force-recreate 2>&1 | tail -4
sleep 3
docker ps --format 'table {{.Names}}\t{{.Status}}'
echo -n 'key-broker healthz: '; curl -s http://localhost:8001/healthz; echo"

c_ok "deployed. key-broker should read 'waiting for root key' until provisioned."
echo "Next: ./provision-kms.sh"
