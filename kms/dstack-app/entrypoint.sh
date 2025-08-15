#!/bin/sh

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
# SPDX-FileCopyrightText: © 2025 Test in Prod <contact@testinprod.io>
#
# SPDX-License-Identifier: Apache-2.0

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
