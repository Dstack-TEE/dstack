#!/bin/sh
# runs inside the CVM under systemd (sca.service)
set -e
echo "hello-c: starting self-contained server"
exec /run/sca/bin/app
