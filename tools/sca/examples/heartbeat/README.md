# heartbeat

The simplest possible self-contained app: **no compiler, no binary**. The
service is the shell script `entrypoint.sh` itself, which logs a heartbeat to
the journal using an interval read from an embedded config file
(`/etc/heartbeat/interval`) — demonstrating multi-file rootfs packing.

No gateway, no KMS (`key_provider: none`).

## layout

```
config.json
rootfs/
  run/sca/bin/entrypoint.sh          the "app" (a logging loop)
  etc/heartbeat/interval             config: seconds between heartbeats
  etc/systemd/system/sca.service     Restart=always
```

## build & deploy

```sh
../../sca.py build
./vmm-cli.py deploy --name heartbeat --image dstack-0.5.11 \
    --compose app-compose.json --vcpu 1 --memory 512M --disk 2G
```

Check it ran via the boot events / logs:

```sh
./vmm-cli.py info <vm-id> | grep sca:
./vmm-cli.py logs <vm-id> | grep heartbeat
```
