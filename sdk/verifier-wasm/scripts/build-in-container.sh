#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible wasm build. Runs scripts/build.sh inside a digest-pinned
# linux/amd64 Rust image so host toolchain binaries cannot affect codegen.
set -euo pipefail

# Official rust:1.92.0-bookworm, linux/amd64 platform manifest.
# https://hub.docker.com/layers/library/rust/1.92.0-bookworm
IMAGE=${DSTACK_WASM_IMAGE:-docker.io/library/rust:1.92.0-bookworm@sha256:5c38a9e735664861e84ce6918e98ce7f05dbac210230d45381bcf870b2d58083}
PLATFORM=linux/amd64
EXPECTED_RELEASE=1.92.0
EXPECTED_COMMIT_PREFIX=ded5c06cf

root=$(cd "$(dirname "$0")/../../.." && pwd)

wasm_sha() {
  local js=$1
  local b64
  b64=$(sed -n "s/^export const wasmBase64 = '\\(.*\\)'$/\\1/p" "$js")
  if [ -z "$b64" ]; then
    echo "no wasmBase64 in $js" >&2
    exit 1
  fi
  printf '%s' "$b64" | base64 -d | sha256sum | awk '{print $1}'
}

ensure_toolchain() {
  local ver commit
  ver=$(rustc -vV | sed -n 's/^release: //p')
  commit=$(rustc -vV | sed -n 's/^commit-hash: //p')
  if [ "$ver" != "$EXPECTED_RELEASE" ] || [ "${commit#"$EXPECTED_COMMIT_PREFIX"}" = "$commit" ]; then
    rustup toolchain install 1.92.0 --profile minimal --no-self-update
    rustup default 1.92.0
  fi
  ver=$(rustc -vV | sed -n 's/^release: //p')
  commit=$(rustc -vV | sed -n 's/^commit-hash: //p')
  if [ "$ver" != "$EXPECTED_RELEASE" ]; then
    echo "rustc release $ver, expected $EXPECTED_RELEASE" >&2
    exit 1
  fi
  case "$commit" in
    "${EXPECTED_COMMIT_PREFIX}"*) ;;
    *)
      echo "rustc commit $commit, expected prefix $EXPECTED_COMMIT_PREFIX" >&2
      exit 1
      ;;
  esac
  rustup target add wasm32-unknown-unknown
}

if [ "${1:-}" = --inner ]; then
  # Repo rust-toolchain.toml pulls extra targets/components. Use the image
  # toolchain; rustc under qemu-user SIGSEGV'd while rustup installed that overlay.
  cd /tmp
  export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-$(rustc -vV | sed -n 's/^release: //p')}
  cd /work
  ensure_toolchain
  export CARGO_TARGET_DIR=/tmp/dstack-wasm-target
  bash /work/sdk/verifier-wasm/scripts/build.sh
  hash1=$(wasm_sha /work/sdk/verifier-wasm/src/wasm-bytes.js)
  echo "build1 wasm sha256=$hash1"

  if [ "${REPRO_CHECK:-0}" = 1 ]; then
    second=/tmp/repro-src
    cargo2=/tmp/repro-cargo
    rm -rf "$second" "$cargo2"
    mkdir -p "$second" "$cargo2"
    cp -a /work/. "$second/"
    rm -rf "$second/dstack/target"
    src_cargo="${CARGO_HOME:-/usr/local/cargo}"
    if [ -d "$src_cargo/registry" ]; then
      cp -a "$src_cargo/registry" "$cargo2/registry"
    fi
    CARGO_HOME="$cargo2" CARGO_TARGET_DIR=/tmp/dstack-wasm-target-2 \
      bash "$second/sdk/verifier-wasm/scripts/build.sh"
    hash2=$(wasm_sha "$second/sdk/verifier-wasm/src/wasm-bytes.js")
    echo "build2 wasm sha256=$hash2"
    if [ "$hash1" != "$hash2" ]; then
      echo "wasm bytes differ across CARGO_HOME and checkout path" >&2
      exit 1
    fi
  fi

  if [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then
    chown "$HOST_UID:$HOST_GID" /work/sdk/verifier-wasm/src/wasm-bytes.js
  fi
  exit 0
fi

if command -v docker >/dev/null 2>&1; then
  engine=docker
elif command -v podman >/dev/null 2>&1; then
  engine=podman
else
  echo "need docker or podman" >&2
  exit 1
fi

run_args=(
  --rm --platform "$PLATFORM"
  -v "$root:/work"
  -w /work
  -e REPRO_CHECK="${REPRO_CHECK:-0}"
  -e HOST_UID="$(id -u)"
  -e HOST_GID="$(id -g)"
)
if [ -n "${RUST_MIN_STACK:-}" ]; then
  run_args+=(-e "RUST_MIN_STACK=$RUST_MIN_STACK")
fi
"$engine" run "${run_args[@]}" "$IMAGE" \
  bash /work/sdk/verifier-wasm/scripts/build-in-container.sh --inner
