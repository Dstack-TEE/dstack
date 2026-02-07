#!/bin/bash
# ephemeral-docker.sh - Run docker commands in a temporary dockerd environment
# Usage: ephemeral-docker.sh <docker-command> [args...]
# Example: ephemeral-docker.sh run --rm hello-world
#
# This script creates an isolated temporary docker environment that:
# - Uses a unique temporary directory for all state
# - Cleans up completely on exit

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <docker-command> [args...]" >&2
    echo "Example: $0 run --rm hello-world" >&2
    exit 1
fi

TMPDIR=$(mktemp -d)
CONTAINERD_PID=""
DOCKERD_PID=""
EXIT_CODE=0

cleanup() {
    local exit_code=$?
    set +e  # Don't exit on error during cleanup

    # Stop dockerd first (it depends on containerd)
    if [ -n "$DOCKERD_PID" ] && kill -0 $DOCKERD_PID 2>/dev/null; then
        kill -TERM $DOCKERD_PID 2>/dev/null
        # Wait with timeout
        for i in $(seq 1 50); do
            kill -0 $DOCKERD_PID 2>/dev/null || break
            sleep 0.1
        done
        # Force kill if still running
        kill -9 $DOCKERD_PID 2>/dev/null || true
        wait $DOCKERD_PID 2>/dev/null || true
    fi

    # Stop containerd
    if [ -n "$CONTAINERD_PID" ] && kill -0 $CONTAINERD_PID 2>/dev/null; then
        kill -TERM $CONTAINERD_PID 2>/dev/null
        for i in $(seq 1 50); do
            kill -0 $CONTAINERD_PID 2>/dev/null || break
            sleep 0.1
        done
        kill -9 $CONTAINERD_PID 2>/dev/null || true
        wait $CONTAINERD_PID 2>/dev/null || true
    fi

    # Unmount any netns that docker created
    if [ -d "$TMPDIR/docker-exec/netns" ]; then
        find "$TMPDIR/docker-exec/netns" -type f 2>/dev/null | while read ns; do
            umount "$ns" 2>/dev/null || true
        done
    fi

    # Remove temporary directory
    rm -rf "$TMPDIR"

    exit ${EXIT_CODE:-$exit_code}
}
trap cleanup EXIT INT TERM

# Create all directories
mkdir -p "$TMPDIR"/{containerd,containerd-state,docker-data,docker-exec}

# Start temporary containerd with isolated state
containerd \
    --root "$TMPDIR/containerd" \
    --state "$TMPDIR/containerd-state" \
    --address "$TMPDIR/containerd.sock" \
    &>/dev/null &
CONTAINERD_PID=$!

# Wait for containerd socket with timeout
TIMEOUT=100  # 10 seconds
for i in $(seq 1 $TIMEOUT); do
    [ -S "$TMPDIR/containerd.sock" ] && break
    if ! kill -0 $CONTAINERD_PID 2>/dev/null; then
        echo "Error: containerd exited unexpectedly" >&2
        exit 1
    fi
    sleep 0.1
done
if [ ! -S "$TMPDIR/containerd.sock" ]; then
    echo "Error: Timeout waiting for containerd socket" >&2
    exit 1
fi

# Start temporary dockerd with isolated state
dockerd \
    --data-root "$TMPDIR/docker-data" \
    --exec-root "$TMPDIR/docker-exec" \
    --pidfile "$TMPDIR/docker.pid" \
    --host "unix://$TMPDIR/docker.sock" \
    --containerd "$TMPDIR/containerd.sock" \
    &>/dev/null &
DOCKERD_PID=$!

# Wait for docker socket with timeout
for i in $(seq 1 $TIMEOUT); do
    [ -S "$TMPDIR/docker.sock" ] && break
    if ! kill -0 $DOCKERD_PID 2>/dev/null; then
        echo "Error: dockerd exited unexpectedly" >&2
        exit 1
    fi
    sleep 0.1
done
if [ ! -S "$TMPDIR/docker.sock" ]; then
    echo "Error: Timeout waiting for docker socket" >&2
    exit 1
fi

# Run the docker command and capture exit code
docker -H "unix://$TMPDIR/docker.sock" "$@" || EXIT_CODE=$?

# Cleanup happens via trap
