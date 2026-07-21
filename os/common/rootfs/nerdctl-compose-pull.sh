#!/bin/bash

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Register Compose images for lazy pulling. ctr-remote adds the remote snapshot
# annotations that containerd's generic transfer service does not provide.
set -euo pipefail

compose_file=${1:?usage: nerdctl-compose-pull.sh COMPOSE_FILE [NAMESPACE]}
namespace=${2:-dstack}
docker_config=${DOCKER_CONFIG:-/root/.docker}/config.json

registry_for_image() {
    local first_component=${1%%/*}
    case "$first_component" in
    *.*|*:*|localhost) printf '%s\n' "$first_component" ;;
    *) printf '%s\n' docker.io ;;
    esac
}

auth_for_registry() {
    local registry=$1
    [ -r "$docker_config" ] || return 0
    jq -r --arg registry "$registry" '
        .auths[$registry].auth //
        (if $registry == "docker.io" then
            .auths["https://index.docker.io/v1/"].auth
         else empty end) // empty
    ' "$docker_config"
}

pull_image() {
    local image=$1 registry auth
    local -a auth_args=()
    registry=$(registry_for_image "$image")
    auth=$(auth_for_registry "$registry")
    if [ -n "$auth" ]; then
        auth_args=(--user "$(printf '%s' "$auth" | base64 -d)")
    fi
    ctr-remote --namespace "$namespace" images rpull \
        --snapshotter stargz "${auth_args[@]}" "$image"
}

while IFS= read -r image; do
    [ -n "$image" ] && pull_image "$image"
done < <(docker compose -f "$compose_file" config --images)
