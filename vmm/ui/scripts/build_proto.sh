#!/bin/bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="${ROOT}/../rpc/proto"
OUT_DIR="${ROOT}/src/proto"
PBJS="${ROOT}/node_modules/.bin/pbjs"
PBTS="${ROOT}/node_modules/.bin/pbts"

if [ ! -x "${PBJS}" ] || [ ! -x "${PBTS}" ]; then
  echo "protobufjs CLI not found. Run 'npm install' first." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

generate_proto() {
  local name="$1"
  echo "[proto] Generating ${name} bindings..."
  "${PBJS}" --keep-case -w commonjs -t static-module --path "${PROTO_DIR}" "${PROTO_DIR}/${name}.proto" -o "${OUT_DIR}/${name}.js"
  "${PBTS}" -o "${OUT_DIR}/${name}.d.ts" "${OUT_DIR}/${name}.js"
}

generate_proto "vmm_rpc"
generate_proto "prpc"

echo "[proto] Done."
