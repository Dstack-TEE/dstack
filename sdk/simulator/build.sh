#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

cd $(dirname $0)
cargo build --release -p dstack-guest-agent-simulator
cp ../../target/release/dstack-simulator .

