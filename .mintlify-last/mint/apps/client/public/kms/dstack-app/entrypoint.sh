#!/bin/sh
set -e

cat <<EOF > ./kms.toml
[core.image]
verify = true
cache_dir = "./images"
download_url = "${IMAGE_DOWNLOAD_URL}"
download_timeout = "2m"
EOF

exec dstack-kms -c ./kms.toml
