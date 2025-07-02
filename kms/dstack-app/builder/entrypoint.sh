#!/bin/sh
set -e

cat <<EOF > ./kms.toml
[rpc]
address = "0.0.0.0"
port = 8000

[rpc.tls]
key = "/kms/certs/rpc.key"
certs = "/kms/certs/rpc.crt"

[rpc.tls.mutual]
ca_certs = "/kms/certs/tmp-ca.crt"
mandatory = false

[core]
cert_dir = "/kms/certs"
admin_token_hash = ""

[core.image]
verify = true
cache_dir = "/kms/images"
download_url = "${IMAGE_DOWNLOAD_URL}"
download_timeout = "2m"

[core.auth_api]
type = "${AUTH_TYPE}"

[core.auth_api.webhook]
url = "${AUTH_RPC_URL}"

[core.auth_api.dev]
gateway_app_id = "any"

[core.onboard]
enabled = true
auto_bootstrap_domain = "${DEV_DOMAIN}"
quote_enabled = ${QUOTE_ENABLED}
address = "0.0.0.0"
port = 8000
EOF

exec "$@"
