#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Build the four drivers and feed every case in `cases.json` to all of them.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SDK="$(cd "$HERE/../.." && pwd -P)"

(cd "$HERE/rustdriver" && cargo build)
(cd "$HERE/godriver" && go build -o pdiff-go .)
(cd "$SDK/js" && npm run --silent build)

exec python3 "$HERE/run.py"
