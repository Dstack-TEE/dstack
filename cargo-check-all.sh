#!/bin/sh

# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: BUSL-1.1

find . -name Cargo.toml -exec dirname {} \; | while read dir; do
    echo "Checking $dir..."
    (cd "$dir" && cargo check)
done
