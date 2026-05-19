#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Wraps `cargo publish -p $1` so that "already exists on crates.io" is treated
# as success. Lets a partially-failed release be retried by pushing the same
# tag, without getting stuck on the first crate.

set -euo pipefail

crate=${1:?missing crate name}

if output=$(cargo publish -p "$crate" 2>&1); then
    echo "$output"
    exit 0
fi

echo "$output"

if grep -q "already exists on crates.io index" <<<"$output"; then
    echo "::notice::$crate is already published at this version; treating as success"
    exit 0
fi

exit 1
