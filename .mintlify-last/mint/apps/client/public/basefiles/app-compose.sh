#!/bin/bash

HOST_SHARED_DIR="/dstack/.host-shared"
SYS_CONFIG_FILE="$HOST_SHARED_DIR/.sys-config.json"
CFG_PCCS_URL=$([ -f "$SYS_CONFIG_FILE" ] && jq -r '.pccs_url//""' "$SYS_CONFIG_FILE" || echo "")
export PCCS_URL=${PCCS_URL:-$CFG_PCCS_URL}

if [ $(jq 'has("pre_launch_script")' app-compose.json) == true ]; then
    echo "Running pre-launch script"
    dstack-util notify-host -e "boot.progress" -d "pre-launch" || true
    source <(jq -r '.pre_launch_script' app-compose.json)
fi

RUNNER=$(jq -r '.runner' app-compose.json)
case "$RUNNER" in
"docker-compose")
    echo "Starting containers"
    dstack-util notify-host -e "boot.progress" -d "starting containers" || true
    if ! [ -f docker-compose.yaml ]; then
        jq -r '.docker_compose_file' app-compose.json >docker-compose.yaml
    fi
    dstack-util remove-orphans -f docker-compose.yaml || true
    chmod +x /usr/bin/containerd-shim-runc-v2
    systemctl restart docker

    if ! docker compose up --remove-orphans -d --build; then
        dstack-util notify-host -e "boot.error" -d "failed to start containers"
        exit 1
    fi
    echo "Pruning unused images"
    docker image prune -af
    echo "Pruning unused volumes"
    docker volume prune -f
    ;;
"bash")
    chmod +x /usr/bin/containerd-shim-runc-v2
    echo "Running main script"
    dstack-util notify-host -e "boot.progress" -d "running main script" || true
    jq -r '.bash_script' app-compose.json | bash
    ;;
*)
    echo "ERROR: unsupported runner: $RUNNER" >&2
    dstack-util notify-host -e "boot.error" -d "unsupported runner: $RUNNER"
    exit 1
    ;;
esac

dstack-util notify-host -e "boot.progress" -d "done" || true
