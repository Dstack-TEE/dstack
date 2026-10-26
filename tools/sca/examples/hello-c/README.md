# hello-c

A ~30 KB **static C HTTP server** embedded into `app-compose.json` and exposed
through dstack-gateway. No docker, no registry pull.

This example uses `key_provider: kms` + `gateway_enabled: true` (the gateway
requires a KMS identity).

## layout

```
config.json                          key_provider kms + gateway enabled
src/server.c                         the server source
build.sh                             compile (musl) -> rootfs, then sca build
rootfs/
  run/sca/bin/entrypoint.sh          execs /run/sca/bin/app
  run/sca/bin/app                    <-- produced by build.sh (gitignored)
  etc/systemd/system/sca.service     Restart=always
```

## build

```sh
./build.sh        # needs musl-gcc (apt install musl-tools)
```

This compiles `src/server.c` into `rootfs/run/sca/bin/app` and writes
`app-compose.json`, printing the compose-hash / app-id.

## deploy

```sh
# add the compose-hash to your on-chain DstackApp whitelist first, then:
./vmm-cli.py deploy --name hello-c --image dstack-0.5.11 \
    --compose app-compose.json --vcpu 1 --memory 1G --disk 3G
```

The app listens on `:8080`. Reach it via the gateway ingress (note the `-8080`
port suffix; the default app URL points at a different port):

```
https://<instance-id>-8080.<gateway-domain>
```
