#!/bin/sh
# compile the static server into the rootfs, then build app-compose.json.
# requires musl-gcc (apt install musl-tools). produces a ~30 KB static binary.
set -e
cd "$(dirname "$0")"

echo "==> compiling static server (musl, -static)"
musl-gcc -static -Os -s -o rootfs/run/sca/bin/app src/server.c
chmod +x rootfs/run/sca/bin/app

echo "==> building app-compose.json"
../../sca.py build

cat <<'EOF'

next:
  add the printed compose-hash to your on-chain DstackApp whitelist, then:
    ./vmm-cli.py deploy --name hello-c --image dstack-0.5.11 \
        --compose app-compose.json --vcpu 1 --memory 1G --disk 3G
  the app listens on :8080; reach it via the gateway ingress
    https://<instance-id>-8080.<gateway-domain>
EOF
