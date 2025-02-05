#!/bin/bash

if [ $(jq 'has("pre_launch_script")' app-compose.json) == true ]; then
    echo "Running pre-launch script"
    tdxctl notify-host -e "boot.progress" -d "pre-launch" || true
    source <(jq -r '.pre_launch_script' app-compose.json)
fi

RUNNER=$(jq -r '.runner' app-compose.json)
case "$RUNNER" in
"docker-compose")
    echo "Starting containers"
    tdxctl notify-host -e "boot.progress" -d "starting containers" || true
    if ! [ -f docker-compose.yaml ]; then
        jq -r '.docker_compose_file' app-compose.json >docker-compose.yaml
    fi
    tdxctl remove-orphans -f docker-compose.yaml || true
    chmod +x /usr/bin/containerd-shim-runc-v2
    systemctl restart docker

    if ! docker compose up --remove-orphans -d; then
        tdxctl notify-host -e "boot.error" -d "failed to start containers"
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
    tdxctl notify-host -e "boot.progress" -d "running main script" || true
    jq -r '.bash_script' app-compose.json | bash
    ;;
*)
    echo "ERROR: unsupported runner: $RUNNER" >&2
    tdxctl notify-host -e "boot.error" -d "unsupported runner: $RUNNER"
    exit 1
    ;;
esac

tdxctl notify-host -e "boot.progress" -d "done" || true
