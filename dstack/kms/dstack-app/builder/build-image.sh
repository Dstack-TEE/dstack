#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
CONTEXT_DIR="$SCRIPT_DIR"
SHARED_DIR="$SCRIPT_DIR/shared"
DOCKERFILE="$SCRIPT_DIR/Dockerfile"
export CONTEXT_DIR DOCKERFILE

# shellcheck source=/dev/null
source "$REPO_ROOT/dstack/build/shared/build-lib.sh"

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <image-name>[:<tag>]..." >&2
    exit 1
fi
TAGS=$(printf '%s\n' "$@")

NO_CACHE=${NO_CACHE:-}
GIT_REV=${GIT_REV:-HEAD}
GIT_REV=$(git -C "$REPO_ROOT" rev-parse "$GIT_REV")
DSTACK_SRC_URL=${DSTACK_SRC_URL:-https://github.com/Dstack-TEE/dstack.git}

ensure_buildkit

touch "$SHARED_DIR/builder-pinned-packages.txt"
touch "$SHARED_DIR/pinned-packages.txt"

METADATA=$(image_metadata \
    "dstack-kms" \
    "Key management service for dstack confidential applications" \
    "dstack/kms" \
    "dstack/kms/README.md")

docker_build "$TAGS" "" "$SHARED_DIR/pinned-packages.txt" "$METADATA"
docker_build "kms-builder-temp" "kms-builder" "$SHARED_DIR/builder-pinned-packages.txt"

check_clean_tree "$SHARED_DIR"
