#!/bin/sh
# the whole "app" is this script — no compiled binary, no toolchain needed.
# it reads an interval from an embedded config file and logs a heartbeat.
set -e
INTERVAL=$(cat /etc/heartbeat/interval 2>/dev/null || echo 5)
echo "heartbeat: starting (interval=${INTERVAL}s)"
i=0
while true; do
    echo "heartbeat: alive $i"
    i=$((i + 1))
    sleep "$INTERVAL"
done
