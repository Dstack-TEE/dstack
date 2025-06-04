#!/bin/sh
set -e

cat <<EOF > ./kms.toml
[core]
admin_token_hash = "${ADMIN_TOKEN_HASH}"

[core.image]
verify = ${VERIFY_IMAGE}
cache_dir = "./images"
download_url = "${IMAGE_DOWNLOAD_URL}"
download_timeout = "2m"
EOF

exec dstack-kms -c ./kms.toml
