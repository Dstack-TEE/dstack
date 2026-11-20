# dstack-key-recovery

Recover an application key from an older KMS root epoch.

## First, the two guest APIs

dstack changed its guest API in **0.6.0**. The tool needs to know which one your
app used, because the same name produces a different key on each:

| Your guest OS | API your app called | Internal name | Tool flag |
|---|---|---|---|
| **0.5.x** | `getKey(path, purpose, algorithm)` | v0 | `--api v0` |
| **0.6.x** | `getKey(domain, algorithm)` | v1 | `--api v1` |

- **0.5.x API (v0)**: one `path` string, optional `purpose`, optional
  `algorithm`. The key is `HKDF-SHA256(salt="RATLS", app_root, path)`. `purpose`
  does not change the key; it only changes the signature chain.
- **0.6.x API (v1)**: one `domain` string and a required `algorithm`. The key is
  `HKDF-SHA256(salt="dstack-guest-v1", app_root, LP(tag)||LP(algorithm)||LP(domain))`.
  It is deliberately **not** the same key as v0 for the same name.

`--api auto` (the default) reads the guest OS version and picks the right one:
0.5.x → v0, 0.6.x → v1. You can force either with `--api v0` / `--api v1`.

## Why you need this tool

The guest agent only serves its **boot (current) epoch**. After a KMS root-key
rotation, `getKey` returns a key derived from the new root, and the old key is no
longer reachable through the agent. This tool asks the KMS for the app root of a
chosen epoch (default `0`, the original root) and re-applies the same derivation
your app used, so you get the old key back.

It reads everything from the guest, so no KMS URL or CA has to be passed:

- `/dstack/.host-shared/.appkeys.json` — KMS URL, pinned CA, current epochs
- `/dstack/.host-shared/.sys-config.json` — launch ticket, collateral URLs

It must run **inside the CVM**, because it needs the platform quote to
authenticate to the KMS. Normally that means a sidecar container; see
[Run in a container](#run-in-a-container).

## Passthroughs

| Path | Why | Mode |
|---|---|---|
| `/dstack/.host-shared` | `.appkeys.json`, `.sys-config.json` | `ro` |
| `/run/log/dstack` | runtime RTMR3 events for the quote | `ro` |
| `/sys/firmware/acpi/tables/data/CCEL` → `/ccel.bin` | boot event log | `ro` |
| `/etc/tdx-attest.conf` | vsock QGS port | `ro` |
| `/dev/tdx_guest` | TDX report / quote ioctl | device |
| `/dev/vsock` | host vsock transport for the QGS quote service | device |
| `/sys/kernel/config/tsm/report` | alternative quote path on newer kernels | `rw` |
| network | KMS egress | — |

Two things that are easy to miss:

- **CCEL must not be mounted into `/sys`.** A sysfs file cannot be bind-mounted
  over the container's sysfs. Mount it to a normal path and set
  `DSTACK_CCEL_FILE` to that path.
- **AF_VSOCK needs `security_opt: ["seccomp=unconfined"]`.** The default Docker
  seccomp profile refuses the vsock connect with `Operation not permitted`.
  A custom profile that allows `AF_VSOCK` works too.

If the CCEL file lives elsewhere, set `DSTACK_CCEL_FILE` to its absolute path.

## Run in a container

### Sidecar (recommended)

The sidecar holds the privileged passthrough; the app only talks HTTP. See
[`docker-compose.example.yaml`](docker-compose.example.yaml).

```yaml
services:
  key-recovery:
    image: ghcr.io/dstack-tee/dstack-key-recovery:0.6.5
    restart: unless-stopped
    command: ["serve", "--addr", "0.0.0.0:8099", "--no-socket"]
    security_opt: ["seccomp=unconfined"]
    environment:
      DSTACK_CCEL_FILE: /ccel.bin
    volumes:
      - /dstack/.host-shared:/dstack/.host-shared:ro
      - /run/log/dstack:/run/log/dstack:ro
      - /sys/firmware/acpi/tables/data/CCEL:/ccel.bin:ro
      - /etc/tdx-attest.conf:/etc/tdx-attest.conf:ro
    devices:
      - /dev/tdx_guest:/dev/tdx_guest
      - /dev/vsock:/dev/vsock

  app:
    image: your-app
    depends_on: [key-recovery]
    environment:
      KEY_RECOVERY_URL: http://key-recovery:8099
```

### Call it from the app

The sidecar is reachable at `http://key-recovery:8099` on the compose network.
The app just makes an HTTP request:

```bash
# auto: 0.5.x returns the old getKey(path) key, 0.6.x the getKey(domain, algo) key
curl "$KEY_RECOVERY_URL/key?name=derive-path"

# force a surface
curl "$KEY_RECOVERY_URL/v0/key?path=derive-path&purpose=signing"
curl "$KEY_RECOVERY_URL/v1/key?domain=derive-path&algorithm=secp256k1"

# epochs (default 0 = the original root)
curl "$KEY_RECOVERY_URL/key?name=derive-path&root_epoch=0&app_epoch=0"

# what epochs exist and whether epoch 0 is still served
curl "$KEY_RECOVERY_URL/info"

# POST works too
curl -X POST "$KEY_RECOVERY_URL/key" \
  -H 'content-type: application/json' \
  -d '{"name":"derive-path","algorithm":"secp256k1","root_epoch":0}'
```

The response is the same JSON as `key --json`:

```json
{
  "api": "v0",
  "key": "1459f09e…",
  "public_key": "03d8aeae…",
  "signature_chain": ["eb10549f…", "3d9adc81…"],
  "root_epoch": 0,
  "app_epoch": 0
}
```

Pin the image by digest in production. The release workflow publishes
`ghcr.io/dstack-tee/dstack-key-recovery` with build provenance and an SBOM.

### Embed in your image

Copy the binary from the published image in a build stage:

```dockerfile
FROM ghcr.io/dstack-tee/dstack-key-recovery:0.6.5 AS key-recovery
FROM your-app
COPY --from=key-recovery /dstack-key-recovery /usr/local/bin/
```

Then call it directly from the app, no server needed:

```bash
dstack-key-recovery key derive-path --json
```

The app container needs the same mounts, devices, `seccomp=unconfined` and
`DSTACK_CCEL_FILE` as the table above.

To build the tool yourself, from the `dstack/` workspace root:

```bash
docker build -f tools/key-recovery/Dockerfile -t dstack-key-recovery .
```

### Run directly in the guest (dev/SSH only)

Production CVMs usually have no SSH. For a dev image you can copy the static
binary in:

```bash
phala cp target/x86_64-unknown-linux-musl/release/dstack-key-recovery cvm-name:/tmp/
phala ssh cvm-name -- "chmod +x /tmp/dstack-key-recovery"
```

## Build the binary

Build from **v0.6.5+** (the KMS must be 0.6.4+ for epochs). The binary is static
musl, so it also runs on a 0.5.15 guest:

```bash
cd dstack
rustup target add x86_64-unknown-linux-musl
cargo build --release -p dstack-key-recovery --target x86_64-unknown-linux-musl
# target/x86_64-unknown-linux-musl/release/dstack-key-recovery
```

## Commands

```text
dstack-key-recovery <COMMAND>

Commands:
  key    Derive one key and print it
  info   Show the CVM's current epochs and whether epoch 0 is available
  serve  Serve the same operations over HTTP
```

---

## `key`

```text
Usage: dstack-key-recovery key [OPTIONS] <NAME>

Arguments:
  <NAME>  Key name: the old 0.5.x path, or the 0.6.x domain

Options:
      --api <API>              auto | v0 | v1                  [default: auto]
      --purpose <PURPOSE>      0.5.x purpose, affects chain[0] [default: ""]
      --algorithm <ALGORITHM>  secp256k1 | ed25519             [default: secp256k1]
      --root-epoch <N>         KMS root epoch                  [default: 0]
      --app-epoch <N>          app epoch                       [default: 0]
      --keys-file <PATH>       .appkeys.json                   [default: /dstack/.host-shared/.appkeys.json]
      --sys-config <PATH>      .sys-config.json                [default: /dstack/.host-shared/.sys-config.json]
      --json                   Print JSON
```

### 0.5.x app: old `getKey(path)` key at epoch 0

```bash
dstack-key-recovery key derive-path
```

```text
api:        v0
root_epoch: 0
app_epoch:  0
key:        1459f09e1bbfc08fffdb99cd7024a8efd2b980c29b38a558b37af667320cb2d8
public_key: 03d8aeae1aea83d4cd5a025a421fd1177f0e31d73f942a407bed4a1028ac70ffb6
signature_chain:
  [0] eb10549f58097920cc102f30d6e6d549d39cd9180741e0ab8c33f975424fbe522cf412779721765ff5eaa16443dee09a0d9a33005084e06df6b824e5d375b7eb01
  [1] 3d9adc81a2212dddb24ecb38a9b52185d2e53deb63f0ebb17780ef7edc74be002ac831aa46cbc99442e5f0adb6bfa0875329391a2ad2ccbe83692f4089d2ebd201
```

### 0.6.x app: old `getKey(domain, algorithm)` key at epoch 0

```bash
dstack-key-recovery key derive-path --api v1
```

```text
api:        v1
root_epoch: 0
app_epoch:  0
key:        cb76d09171f7ad06e061687e9bd3c3939728b859440688d3472e8d5eefb9d88a
public_key: 0259f3174c282392984b5b5f4cd3e39800aa6941e4af20cfe2f9d1e5c412f7c754
signature_chain:
  [0] 8b1337c7ab541181d503c84ba576cec312f2455aac3c89ab8038e7b53c031da2298e73e4806f9dea0409d3ea9b88de78036cfdd351126cceb2db092445cac75801
  [1] 3d9adc81a2212dddb24ecb38a9b52185d2e53deb63f0ebb17780ef7edc74be002ac831aa46cbc99442e5f0adb6bfa0875329391a2ad2ccbe83692f4089d2ebd201
```

### Sanity check: current epoch must match the agent

```bash
dstack-key-recovery key derive-path --api v0 --root-epoch 1
```

```text
api:        v0
root_epoch: 1
app_epoch:  0
key:        87ae122fd5f1196b91fc06a6d4ef69980d280d1b91bf98ab4d4856864dbfd188
public_key: 03bc3a7bc83ebe38dca95b88c67f66cd7e7f6ad5bab5b0a5b926198b377ffc3dc4
signature_chain:
  [0] 2bdcd6a2bae6d7d44da4af743124c5b0c33eda571e8cd9cd88a2cec9af5645f433fecbfc60114a2cd7730d079a6ced25df306052ba739695559b7f87bc47ba5c00
  [1] e1af019362eff0771e7431d0f6ce4c3d8e92b1e3d40b09e038a6f5d51e3264317d77dd965241f8a31497261c3c787e38eecb05af6c4a43fc40ac5b7e201d727901
```

The 0.5.x agent on the same CVM returns exactly this:

```json
{"key":"87ae122fd5f1196b91fc06a6d4ef69980d280d1b91bf98ab4d4856864dbfd188",
 "signature_chain":["2bdcd6a2…5c00","e1af0193…7901"]}
```

### JSON output

```bash
dstack-key-recovery key derive-path --json
```

```json
{
  "api": "v0",
  "key": "1459f09e1bbfc08fffdb99cd7024a8efd2b980c29b38a558b37af667320cb2d8",
  "public_key": "03d8aeae1aea83d4cd5a025a421fd1177f0e31d73f942a407bed4a1028ac70ffb6",
  "signature_chain": [
    "eb10549f58097920cc102f30d6e6d549d39cd9180741e0ab8c33f975424fbe522cf412779721765ff5eaa16443dee09a0d9a33005084e06df6b824e5d375b7eb01",
    "3d9adc81a2212dddb24ecb38a9b52185d2e53deb63f0ebb17780ef7edc74be002ac831aa46cbc99442e5f0adb6bfa0875329391a2ad2ccbe83692f4089d2ebd201"
  ],
  "root_epoch": 0,
  "app_epoch": 0
}
```

### ed25519

```bash
dstack-key-recovery key derive-path --algorithm ed25519 --json
```

```json
{
  "api": "v0",
  "key": "1459f09e1bbfc08fffdb99cd7024a8efd2b980c29b38a558b37af667320cb2d8",
  "public_key": "6acbd81c95393c59906c969344956c713b3d4d9d99b13f588455d005f8769add",
  "signature_chain": ["…", "…"],
  "root_epoch": 0,
  "app_epoch": 0
}
```

The 0.5.x KDF ignores the algorithm, so the 32 private-key bytes are the same as
the secp256k1 key above; only the public-key encoding and the chain claim
differ.

### `purpose` (0.5.x only)

`purpose` is not part of the KDF. It only changes `signature_chain[0]`:

```bash
dstack-key-recovery key derive-path --purpose signing
```

The `key` is identical to the call without `--purpose`.

### App epoch

```bash
dstack-key-recovery key derive-path --root-epoch 2 --app-epoch 1
```

Root and app epochs are independent. Omitted means `0` (the recovery target),
not "current" — pass the current numbers explicitly if you want them.

---

## `info`

```text
Usage: dstack-key-recovery info [OPTIONS]

Options:
      --keys-file <PATH>   .appkeys.json
      --sys-config <PATH>  .sys-config.json
      --json               Print JSON
```

```bash
dstack-key-recovery info
```

```text
guest_version:       0.5.15
api:                 v0
kms_url:             https://kms.dstack-pha-prod2.phala.network/prpc
current_root_epoch:  1
current_app_epoch:   0
epoch0_available:    true
```

```bash
dstack-key-recovery info --json
```

```json
{
  "guest_version": "0.5.15",
  "api": "v0",
  "kms_url": "https://kms.dstack-pha-prod2.phala.network/prpc",
  "current_root_epoch": 1,
  "current_app_epoch": 0,
  "root_epochs": [0, 1],
  "app_epochs": [0],
  "epoch0_available": true,
  "epoch0_error": null
}
```

`guest_version` is `0.5.15`, so `api` is `v0`. On a 0.6.x guest it would be
`0.6.5` / `v1`. `epoch0_available` probes the KMS once and caches the result; if
the old roots are gone it is `false` and `epoch0_error` carries the KMS error.

---

## `serve`

```text
Usage: dstack-key-recovery serve [OPTIONS]

Options:
      --socket <PATH>      Unix socket        [default: /var/run/dstack-key-recovery.sock]
      --no-socket          Disable the Unix socket
      --addr <ADDR>        TCP address        [default: 127.0.0.1:8099]
      --no-addr            Disable TCP
      --keys-file <PATH>   .appkeys.json
      --sys-config <PATH>  .sys-config.json
```

```bash
dstack-key-recovery serve
# listening on unix:/var/run/dstack-key-recovery.sock
# listening on http://127.0.0.1:8099
```

In a container, listen on the compose network instead:

```bash
dstack-key-recovery serve --addr 0.0.0.0:8099 --no-socket
```

The app then calls `http://key-recovery:8099/...`.

### Endpoints

| Method | Path | API |
|---|---|---|
| GET | `/health` | — |
| GET | `/info` | — |
| GET | `/key` | auto (0.5.x → v0, 0.6.x → v1) |
| GET | `/v0/key` | 0.5.x `getKey(path, purpose, algorithm)` |
| GET | `/v1/key` | 0.6.x `getKey(domain, algorithm)` |
| POST | `/key` | auto, JSON body |

Query/body fields:

| Field | Default | Meaning |
|---|---|---|
| `name` / `path` / `domain` | — | key name |
| `purpose` | `""` | 0.5.x only |
| `algorithm` | `secp256k1` | `secp256k1` or `ed25519` |
| `root_epoch` | `0` | KMS root epoch |
| `app_epoch` | `0` | app epoch |

### Examples

```bash
curl --unix-socket /var/run/dstack-key-recovery.sock http://localhost/health
# {"ok":true}

curl --unix-socket /var/run/dstack-key-recovery.sock http://localhost/info
# {"guest_version":"0.5.15","api":"v0",…,"epoch0_available":true}

curl --unix-socket /var/run/dstack-key-recovery.sock \
  'http://localhost/key?name=derive-path'
```

```json
{
  "api": "v0",
  "key": "1459f09e1bbfc08fffdb99cd7024a8efd2b980c29b38a558b37af667320cb2d8",
  "public_key": "03d8aeae1aea83d4cd5a025a421fd1177f0e31d73f942a407bed4a1028ac70ffb6",
  "signature_chain": ["eb10549f…eb01", "3d9adc81…d201"],
  "root_epoch": 0,
  "app_epoch": 0
}
```

```bash
curl 'http://127.0.0.1:8099/v1/key?domain=derive-path&algorithm=secp256k1&root_epoch=0'
```

```json
{
  "api": "v1",
  "key": "cb76d09171f7ad06e061687e9bd3c3939728b859440688d3472e8d5eefb9d88a",
  "public_key": "0259f3174c282392984b5b5f4cd3e39800aa6941e4af20cfe2f9d1e5c412f7c754",
  "signature_chain": ["8b1337c7…5801", "3d9adc81…d201"],
  "root_epoch": 0,
  "app_epoch": 0
}
```

```bash
curl -X POST http://127.0.0.1:8099/key \
  -H 'content-type: application/json' \
  -d '{"name":"derive-path","algorithm":"ed25519","root_epoch":0}'
```

Errors are `400` with the message as the body:

```json
{"error":"failed to get the keys of root epoch 0 …"}
```

The server hands out private keys. Keep it on the Unix socket or localhost; in
the sidecar setup it is only reachable on the compose network.

---

## Notes

- If the current keys are already at the requested epochs, no KMS call is made.
- The KMS must still hold the epoch (`root epoch N is not held by this KMS`
  otherwise), and the current image/compose must still be allowed in that
  epoch's policy row.
- The historical `ca_cert` in the response is not used as transport trust; the
  connection stays pinned to the CA recorded in `.appkeys.json`.
- Fetched app roots are cached in memory per `(root_epoch, app_epoch)`.
- The **disk** key is instance-bound and is not recovered here. App keys are
  instance-independent, so a new CVM gets the same app key as the old one.

## Test

```bash
cargo test -p dstack-key-recovery
```

Pins the 0.5.x vector from the guest-agent tests and the 0.6.x vector from
`docs/guest-api-v1.md`.
