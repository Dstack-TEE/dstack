#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Compatibility wrapper: the driver now takes a --phase, and the upgrade
# scenario is one of them.
set -euo pipefail
exec "$(dirname -- "${BASH_SOURCE[0]}")/run-e2e.sh" --phase upgrade "$@"
