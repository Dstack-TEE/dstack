#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root/dstack"

export CARGO_PROFILE_RELEASE_OPT_LEVEL=z
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_PANIC=abort
export CARGO_PROFILE_RELEASE_STRIP=true

cargo build --target wasm32-unknown-unknown --release -p dstack-verifier-wasm

wasm="$root/dstack/target/wasm32-unknown-unknown/release/dstack_verifier_wasm.wasm"
if [[ ! -f "$wasm" ]]; then
  echo "missing wasm artifact: $wasm" >&2
  exit 1
fi

node "$root/sdk/verifier-wasm/scripts/embed-wasm.mjs" "$wasm" "$root/sdk/verifier-wasm/src/wasm-bytes.js"

python3 - "$wasm" <<'PY'
import gzip, sys
from pathlib import Path
path = Path(sys.argv[1])
raw = path.stat().st_size
gz = len(gzip.compress(path.read_bytes(), compresslevel=9))
print(f"wasm raw={raw} gzip={gz}")
PY
