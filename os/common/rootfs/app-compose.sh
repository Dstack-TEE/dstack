#!/bin/bash

# SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HOST_SHARED_DIR="/dstack/.host-shared"
SYS_CONFIG_FILE="$HOST_SHARED_DIR/.sys-config.json"
APP_COMPOSE_FILE="${APP_COMPOSE_FILE:-app-compose.json}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yaml}"
NERDCTL_NAMESPACE="${NERDCTL_NAMESPACE:-dstack}"
ACTION="${1:-start}"

CFG_PCCS_URL=$([ -f "$SYS_CONFIG_FILE" ] && jq -r '.pccs_url//""' "$SYS_CONFIG_FILE" || echo "")
export PCCS_URL=${PCCS_URL:-$CFG_PCCS_URL}

runner=$(jq -r '.runner' "$APP_COMPOSE_FILE")
snapshotter=$(jq -r '.snapshotter // "overlayfs"' "$APP_COMPOSE_FILE")

ensure_compose_file() {
    if ! [ -f "$COMPOSE_FILE" ]; then
        jq -r '.docker_compose_file' "$APP_COMPOSE_FILE" >"$COMPOSE_FILE"
    fi
}

validate_runner() {
    case "$runner" in
    docker-compose)
        if jq -e 'has("snapshotter")' "$APP_COMPOSE_FILE" >/dev/null; then
            echo "ERROR: snapshotter is only supported by the nerdctl-compose runner" >&2
            exit 1
        fi
        ;;
    nerdctl-compose)
        case "$snapshotter" in
        overlayfs|stargz) ;;
        *)
            echo "ERROR: unsupported snapshotter for nerdctl-compose: $snapshotter" >&2
            exit 1
            ;;
        esac
        ;;
    bash) ;;
    *)
        echo "ERROR: unsupported runner: $runner" >&2
        exit 1
        ;;
    esac
}

compose_start() {
    ensure_compose_file
    case "$runner" in
    docker-compose)
        docker compose -f "$COMPOSE_FILE" up --remove-orphans -d --build
        ;;
    nerdctl-compose)
        if docker compose -f "$COMPOSE_FILE" config --format json | jq -e \
            'any(.services[]; has("build"))' >/dev/null; then
            echo "ERROR: nerdctl-compose requires pre-built images; Compose build sections are not supported" >&2
            return 1
        fi
        if [ "$snapshotter" = stargz ]; then
            # containerd's transfer-service pull path does not add the remote
            # snapshot annotations required by stargz. Register every Compose
            # image with ctr-remote before nerdctl creates the containers.
            while IFS= read -r image; do
                [ -n "$image" ] || continue
                auth_args=()
                registry=${image%%/*}
                case "$registry" in
                *.*|*:*|localhost) ;;
                *) registry="docker.io" ;;
                esac
                if [ -r /root/.docker/config.json ]; then
                    auth=$(jq -r --arg registry "$registry" '
                        .auths[$registry].auth //
                        (if $registry == "docker.io" then .auths["https://index.docker.io/v1/"].auth else empty end) // empty
                    ' /root/.docker/config.json)
                    if [ -n "$auth" ]; then
                        auth_args=(--user "$(printf '%s' "$auth" | base64 -d)")
                    fi
                fi
                ctr-remote --namespace "$NERDCTL_NAMESPACE" images rpull \
                    --snapshotter "$snapshotter" "${auth_args[@]}" "$image"
            done < <(docker compose -f "$COMPOSE_FILE" config --images)
        fi
        compose_args=(up --remove-orphans -d)
        if [ "$snapshotter" = stargz ]; then
            compose_args+=(--pull never)
        fi
        nerdctl --namespace "$NERDCTL_NAMESPACE" --snapshotter "$snapshotter" \
            compose -f "$COMPOSE_FILE" "${compose_args[@]}"
        ;;
    esac
}

compose_stop() {
    [ -f "$COMPOSE_FILE" ] || return 0
    case "$runner" in
    docker-compose)
        docker compose -f "$COMPOSE_FILE" stop
        ;;
    nerdctl-compose)
        nerdctl --namespace "$NERDCTL_NAMESPACE" --snapshotter "$snapshotter" \
            compose -f "$COMPOSE_FILE" stop
        ;;
    esac
}

validate_runner

case "$ACTION" in
start)
    if [ "$(jq 'has("pre_launch_script")' "$APP_COMPOSE_FILE")" = true ]; then
        echo "Running pre-launch script"
        dstack-util notify-host -e "boot.progress" -d "pre-launch" || true
        # shellcheck disable=SC1090
        source <(jq -r '.pre_launch_script' "$APP_COMPOSE_FILE")
    fi

    case "$runner" in
    docker-compose|nerdctl-compose)
        echo "Starting containers with runner=$runner snapshotter=$snapshotter"
        dstack-util notify-host -e "boot.progress" -d "starting containers" || true
        if ! compose_start; then
            dstack-util notify-host -e "boot.error" -d "failed to start containers"
            exit 1
        fi
        if [ "$runner" = docker-compose ]; then
            echo "Pruning unused Docker images and volumes"
            docker image prune -af
            docker volume prune -f
        else
            echo "Pruning unused containerd images"
            nerdctl --namespace "$NERDCTL_NAMESPACE" --snapshotter "$snapshotter" image prune -af
        fi
        ;;
    bash)
        echo "Running main script"
        dstack-util notify-host -e "boot.progress" -d "running main script" || true
        jq -r '.bash_script' "$APP_COMPOSE_FILE" | bash
        ;;
    esac
    dstack-util notify-host -e "boot.progress" -d "done" || true
    ;;
stop)
    compose_stop
    ;;
*)
    echo "Usage: $0 [start|stop]" >&2
    exit 2
    ;;
esac
