# sca — self-contained dstack app builder

`sca` packages an application **directly into `app-compose.json`** so a dstack
CVM can run it with **no docker and no registry pull**. You lay out a `rootfs/`
tree that mirrors the CVM filesystem; `sca build` packs the whole tree
(deterministic `tar.gz` + base64) into the compose file. At boot, a generated
`bash_script` extracts the tree onto the CVM and starts your **systemd**
service, which supervises the app the way docker would.

Because the entire `app-compose.json` (including the embedded rootfs) is hashed
into the **compose-hash** and extended to **RTMR3**, the exact bytes you ship
are covered by remote attestation and gated by the on-chain whitelist.

## Why

For small, self-contained apps that don't need a container image: ship a static
binary (or scripts/assets) inline instead of pulling from a Docker registry.
No dockerd, no image pull, smaller TCB, and the payload is measured.

## How it works

```
sca build                         at CVM boot (runner: bash)
─────────                         ──────────────────────────
rootfs/  ──tar.gz+base64──►  app-compose.json
                                   │  app-compose.sh runs .bash_script:
                                   │    jq .sca_rootfs | openssl base64 -d
                                   │      | tar -xz -C /         (extract tree)
                                   │    systemctl start <svc>    (systemd runs app)
                                   ▼
                            your app, supervised by systemd (Restart=always)
```

## Requirements

- **Build side:** Python 3 (stdlib only — no pip installs). Bring your own
  compiler if your app is a binary.
- **CVM side (already present in dstack guest images, verified on a live CVM):**
  busybox `openssl`, `tar`, `gzip`, `jq`, and systemd. Note the guest busybox
  has **no `base64`**, which is why decoding uses `openssl`.

## Quick start

```bash
# 1. scaffold a project (optionally set compose options inline)
./sca.py new myapp --key-provider kms --gateway

# 2. drop your prebuilt binary into the rootfs
cp ./my-static-binary myapp/rootfs/run/sca/bin/app

# 3. build app-compose.json (prints compose-hash + app-id)
cd myapp && ../sca.py build

# 4. add the compose-hash to your on-chain DstackApp whitelist, then deploy
./vmm-cli.py deploy --name myapp --image dstack-0.5.11 \
    --compose app-compose.json --vcpu 1 --memory 1G --disk 3G
```

## Subcommands

### `sca new <dir>`
Scaffolds a project:

```
config.json                          build config
rootfs/                              mirrors the CVM filesystem (packed whole)
  run/sca/bin/entrypoint.sh          what the service runs (edit/extend)
  run/sca/bin/app                    <-- drop your prebuilt binary here
  etc/systemd/system/sca.service     the systemd unit (Restart=always)
README.md
```

Anything under `rootfs/` lands at the same path inside the CVM. File modes are
preserved (keep executables `chmod +x`). Paths like `/run`, `/etc`, `/usr` are
writable in the guest.

### `sca build`
Packs `rootfs/` and writes `app-compose.json`, printing the size, **compose-hash**
and **app-id** (first 20 bytes of the hash). The build is reproducible: tar
metadata is normalized (sorted entries, `mtime=0`, uid/gid=0, modes forced to
0644/0755 by exec bit) and the tar format is pinned, so identical content yields
an identical compose-hash.

## config.json

```json
{
  "name": "myapp",
  "manifest_version": 2,
  "rootfs": "rootfs",
  "services": ["sca.service"],
  "compose": {
    "key_provider": "none",
    "gateway_enabled": false,
    "public_logs": true,
    "public_sysinfo": true,
    "secure_time": false,
    "no_instance_id": false,
    "allowed_envs": [],
    "key_provider_id": ""
  }
}
```

- `services` — systemd units to `systemctl start` after the rootfs is extracted.
- `key_provider` — `none | kms | local | tpm` (dstack's `KeyProviderKind`).
  Replaces the legacy `kms_enabled` / `local_key_provider_enabled` booleans.
- `gateway_enabled` — expose the app via dstack-gateway. **Requires
  `key_provider: kms`** (the gateway needs a KMS identity, otherwise the CVM
  fails boot with `Missing allowed dstack-gateway app id`).

## CLI options

Every `compose` option is settable on **both** `new` (baked into config.json)
and `build` (overrides config; precedence is defaults < config.json < CLI):

```
--key-provider none|kms|local|tpm   key provider (gateway requires kms)
--gateway / --no-gateway            expose via dstack-gateway
--public-logs / --no-public-logs
--public-sysinfo / --no-public-sysinfo
--secure-time / --no-secure-time
--no-instance-id / --instance-id
--allowed-env NAME                  (repeatable)
--key-provider-id HEX
```

## Security model

- The embedded `sca_rootfs` and the generated `bash_script` are part of
  `app-compose.json`, so they're measured into the compose-hash → RTMR3. The
  exact bytes you run are attested; changing any file changes the app-id and
  requires re-whitelisting on-chain.
- The boot script runs as **root**; service unit names in `services` are
  validated against a strict pattern and shell-quoted before use.
- Don't add heavy systemd sandboxing (`ProtectSystem=strict`, etc.) to your unit
  if the app needs the guest-agent socket at `/var/run/dstack.sock` (for quotes
  / key derivation).

## Size limits

`app-compose.json` must stay under **50 MiB** (the in-guest copy cap). The rootfs
is gzip'd before base64, so the practical budget is roughly the *compressed*
tree. Note there are **other limits in front of the VMM** that a large compose
can hit independently:

| Layer | Typical limit | Where |
| ----- | ------------- | ----- |
| reverse proxy (nginx) | `client_max_body_size` (default ~1 MiB) | in front of the VMM |
| pRPC payload | 10 MiB default per method | dstack-vmm |
| in-guest copy | 50 MiB | dstack-util `HostShared::copy` |

For small self-contained apps (a stripped static binary is tens of KB to a few
MB) none of these are a problem.

## Examples

See [`examples/`](examples/):

- [`hello-c/`](examples/hello-c/) — a ~30 KB static C HTTP server, exposed via
  the gateway (key_provider kms). Compile + build + deploy; reachable over HTTPS.
- [`heartbeat/`](examples/heartbeat/) — the simplest possible app: the service
  is a shell script (no compiler needed), plus an extra config file to show
  multi-file packing. No gateway/KMS.
