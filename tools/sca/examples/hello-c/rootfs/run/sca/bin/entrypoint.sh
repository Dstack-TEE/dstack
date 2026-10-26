#!/bin/sh
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
# runs inside the CVM under systemd (sca.service)
set -e
echo "hello-c: starting self-contained server"
exec /run/sca/bin/app
