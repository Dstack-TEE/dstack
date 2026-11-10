#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root/dstack"

add_remap() {
  local from=$1
  local to=$2
  if [[ ! -d "$from" ]]; then
    return 0
  fi
  local logical physical
  logical=$(cd "$from" && pwd)
  physical=$(cd "$from" && pwd -P)
  remap+=("--remap-path-prefix=${logical}=${to}")
  if [[ $logical != "$physical" ]]; then
    remap+=("--remap-path-prefix=${physical}=${to}")
  fi
}

commit=$(rustc -vV | sed -n 's/^commit-hash: //p')
sysroot=$(rustc --print sysroot)

# More specific prefixes first: rust-src lives under the sysroot (and thus
# rustup). Without rust-src, rustc already emits /rustc/<commit>/...; with it,
# remap the local sources to that same virtual path so both toolchains match.
remap=()
add_remap "$sysroot/lib/rustlib/src/rust" "/rustc/${commit}"
add_remap "${CARGO_HOME:-$HOME/.cargo}" /cargo
add_remap "${RUSTUP_HOME:-$HOME/.rustup}" /rustup
add_remap "$root" /source

# Encode so paths with spaces survive. Keep any caller RUSTFLAGS.
encoded=()
if [[ -n ${CARGO_ENCODED_RUSTFLAGS:-} ]]; then
  IFS=$'\x1f' read -r -a encoded <<<"$CARGO_ENCODED_RUSTFLAGS"
elif [[ -n ${RUSTFLAGS:-} ]]; then
  # shellcheck disable=SC2206
  encoded=($RUSTFLAGS)
fi
encoded+=("${remap[@]}")
export CARGO_ENCODED_RUSTFLAGS
CARGO_ENCODED_RUSTFLAGS=$(printf '%s\x1f' "${encoded[@]}")
CARGO_ENCODED_RUSTFLAGS=${CARGO_ENCODED_RUSTFLAGS%$'\x1f'}
unset RUSTFLAGS

export CARGO_INCREMENTAL=0
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

python3 - "$wasm" "$root/sdk/verifier-wasm/src/wasm-bytes.js" <<'PY'
import base64, gzip, hashlib, re, sys
from pathlib import Path

wasm = Path(sys.argv[1]).read_bytes()
js = Path(sys.argv[2]).read_text()
match = re.search(r"wasmBase64 = '([^']+)'", js)
if not match:
    raise SystemExit("wasm-bytes.js has no wasmBase64")
decoded = base64.b64decode(match.group(1))
if decoded != wasm:
    raise SystemExit("embedded wasm does not match the .wasm file")
print(f"wasm raw={len(wasm)} gzip={len(gzip.compress(wasm, compresslevel=9))}")
print(f"wasm sha256={hashlib.sha256(wasm).hexdigest()}")
print(f"wasm-bytes.js sha256={hashlib.sha256(js.encode()).hexdigest()}")
PY
