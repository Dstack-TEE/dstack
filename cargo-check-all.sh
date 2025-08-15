#!/bin/sh

# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

find . -name Cargo.toml -exec dirname {} \; | while read dir; do
    echo "Checking $dir..."
    (cd "$dir" && cargo check)
done
