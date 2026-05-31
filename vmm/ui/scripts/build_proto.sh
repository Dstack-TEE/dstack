#!/bin/bash

# SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="${ROOT}/../rpc/proto"
OUT_DIR="${ROOT}/src/proto"
PBJS="${ROOT}/node_modules/.bin/pbjs"
JSDOC="${ROOT}/node_modules/.bin/jsdoc"
PBTS_CONFIG="${ROOT}/node_modules/protobufjs-cli/lib/tsd-jsdoc.json"

if [ ! -x "${PBJS}" ] || [ ! -x "${JSDOC}" ]; then
  echo "protobufjs CLI not found. Run 'npm install' first." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

generate_proto() {
  local name="$1"
  echo "[proto] Generating ${name} bindings..."
  "${PBJS}" --keep-case -w commonjs -t static-module --path "${PROTO_DIR}" "${PROTO_DIR}/${name}.proto" -o "${OUT_DIR}/${name}.js"
  tmp_file=$(mktemp)
  "${JSDOC}" -c "${PBTS_CONFIG}" -q "module=null&comments=true" "${OUT_DIR}/${name}.js" > "${tmp_file}"
  {
    echo 'import * as $protobuf from "protobufjs";'
    echo 'import Long = require("long");'
    cat "${tmp_file}"
  } > "${OUT_DIR}/${name}.d.ts"
  rm -f "${tmp_file}"
}

generate_proto "vmm_rpc"
generate_proto "prpc"

echo "[proto] Done."
