#!/bin/bash

USE_HEAD=${USE_HEAD:-yes}
TEEPOD_RPC=${TEEPOD_RPC}
CF_API_TOKEN=${CF_API_TOKEN}
CF_ZONE_ID=${CF_ZONE_ID}
SRV_DOMAIN=${SRV_DOMAIN}
PUBLIC_IP=${PUBLIC_IP}
TPROXY_APP_ID=${TPROXY_APP_ID}

TPROXY_RPC_PORT=9030
TPROXY_ADMIN_RPC_PORT=9031
TPROXY_SERVING_PORT=9033
TAPPD_PORT=9032
WG_PORT=9030

required_env_vars=(
  "TEEPOD_RPC"
  "CF_API_TOKEN"
  "CF_ZONE_ID"
  "SRV_DOMAIN"
  "PUBLIC_IP"
  "TPROXY_APP_ID"
)

for var in "${required_env_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Please set env variable $var"
    exit 1
  fi
done

CLI="../../teepod/src/teepod-cli.py --url $TEEPOD_RPC"

COMPOSE_TMP=$(mktemp)

if [ "$USE_HEAD" = "yes" ]; then
  CURRENT_REV=$(git rev-parse HEAD)
else
  CURRENT_REV=86290e4038aba067d784b088532c129d7ad4c828
fi
sed "s/git checkout TPROXY_REV/git checkout ${CURRENT_REV}/g" docker-compose.yaml > "$COMPOSE_TMP"

$CLI compose \
    --docker-compose "$COMPOSE_TMP" \
    --name tproxy \
    --kms \
    --public-logs \
    --public-sysinfo \
    --output .app-compose.json

# Remove the temporary file as it is no longer needed
rm "$COMPOSE_TMP"

cat <<EOF > .env
CF_API_TOKEN=$CF_API_TOKEN
CF_ZONE_ID=$CF_ZONE_ID
SRV_DOMAIN=$SRV_DOMAIN
WG_ENDPOINT=$PUBLIC_IP:$WG_PORT
EOF

$CLI deploy \
    --name tproxy \
    --app-id "$TPROXY_APP_ID" \
    --compose .app-compose.json \
    --env-file .env \
    --image dstack-0.4.0 \
    --port tcp:0.0.0.0:$TPROXY_RPC_PORT:8000 \
    --port tcp:127.0.0.1:$TPROXY_ADMIN_RPC_PORT:8001 \
    --port tcp:0.0.0.0:$TPROXY_SERVING_PORT:443 \
    --port tcp:127.0.0.1:$TAPPD_PORT:8090 \
    --port udp:0.0.0.0:$WG_PORT:51820 \
    --vcpu 8 \
    --memory 8G \
    --disk 50G
