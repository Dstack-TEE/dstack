# dstack-auth Operations Guide

> **This guide is for self-hosted deployments** on your own TDX hardware. For cloud deployments, see [Quickstart](./quickstart.md).

> [!WARNING]
> `dstack-auth` is intended for development, testing and evaluation only. Do not
> use it to protect production keys; use [auth-eth](../dstack/kms/auth-eth/) or
> an equivalent production-grade authorization service instead.

`dstack-auth` is the file-based KMS authorization webhook. It allowlists OS
images, KMS instances and apps in one JSON file. For on-chain governance, use
[auth-eth](../dstack/kms/auth-eth/) instead
(see [On-Chain Governance](./onchain-governance.md)).

This guide covers running `dstack-auth` and managing apps and devices with it.
For initial deployment setup, see [Deployment Guide](./deployment.md).

## Overview

The allowlist file whitelists:
- **OS images** - Which guest OS versions can boot
- **KMS nodes** - Which KMS instances can bootstrap, serve and onboard (`mrAggregated`, devices)
- **Apps** - Which applications can boot (appId, composeHash, devices)
- **Platform state (opt-in)** - Which TCB statuses and security advisories are acceptable

The file is re-read on every request, so changes take effect immediately without restart.
A missing or invalid file denies every request.

---

## Running dstack-auth

### Installed by dstackup

`dstackup` installs `dstack-auth` as the `dstack-auth.service` systemd unit,
listening on `127.0.0.1:8001`, and writes the allowlist to
`auth-allowlist.json` in its config directory. `dstack run` adds the compose
hash of each app it deploys. Edit that file to change the policy.

### Running the binary yourself

Build it from the repository:

```bash
cd dstack
cargo build --release -p dstack-auth
./target/release/dstack-auth --config /path/to/auth-config.json --port 3001
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | `/var/lib/dstack/auth-allowlist.json` | Allowlist JSON file |
| `--address` | `127.0.0.1` | Bind address |
| `--port` | `8001` | Bind port |

A KMS CVM on QEMU user-mode networking reaches the host loopback at `10.0.2.2`,
so the default address is enough for a KMS on the same host: point the KMS at
`http://10.0.2.2:<port>`. Bind `--address 0.0.0.0` only when the KMS reaches the
host over a real network, and restrict access to that port.

Point the KMS at it in `kms.toml`:

```toml
[core.auth_api]
type = "webhook"

[core.auth_api.webhook]
url = "http://10.0.2.2:3001"
```

---

## Config File Structure

```json
{
  "osImages": ["0x..."],
  "gatewayAppId": "0x...",
  "kmsContractAddr": "0x<kms-app-id>",
  "kms": {
    "mrAggregated": ["0x..."],
    "devices": ["0x..."],
    "allowAnyDevice": true
  },
  "apps": {
    "0x<app-id>": {
      "composeHashes": ["0x..."],
      "devices": ["0x..."],
      "allowAnyDevice": true
    }
  },
  "rootEpochs": [{"caPubkey": "0x...", "k256Pubkey": "0x..."}],
  "currentRootEpoch": 0
}
```

> **Note:** `osImages` is always required for apps. For KMS authorization, you must also populate `kms.mrAggregated`; if it is left empty, dstack-auth denies all KMS boots. Add `gatewayAppId` after deploying the Gateway. Add `apps` entries as you deploy applications.

Hex values are compared case-insensitively, with or without a `0x` prefix.

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `osImages` | Yes | Allowed OS image hashes (from `digest.txt`). Empty denies every app. |
| `gatewayAppId` | No | Gateway app ID (add after Gateway deployment). Several gateways: join their IDs with commas. |
| `kmsContractAddr` | For `/authorize*` | The attested app ID of the KMS. Every operation except `kms_bootstrap` is denied while it is unset, and a caller is accepted only on the endpoint matching its app ID (`/authorizeKms` for this ID, `/authorizeApp` for any other). Reported by `GET /`. |
| `chainId` | No | Informational, reported by `GET /` (default `0`). |
| `appImplementation` | No | Informational, reported by `GET /` as `appImplementation` and `appAuthImplementation`. |
| `allowedTcbStatuses` | No | When set, deny unless the verifier-derived `tcbStatus` is listed; `[]` denies everything. **Absent: not checked.** See [TCB and advisory policy](#tcb-and-advisory-policy). |
| `allowedAdvisoryIds` | No | When set, deny any reported advisory ID that is not listed; `[]` denies any advisory. **Absent: not checked.** |
| `kms.mrAggregated` | Yes | Allowed KMS early aggregate MR values (boot-mr-done). Empty denies every KMS. |
| `kms.devices` | No | Allowed KMS device IDs. Empty denies all unless `kms.allowAnyDevice` is true. |
| `kms.allowAnyDevice` | No | If true, skip the device ID check for KMS |
| `apps.<appId>.composeHashes` | No | Allowed compose hashes for this app |
| `apps.<appId>.devices` | No | Allowed device IDs for this app. Empty denies all unless `allowAnyDevice` is true. |
| `apps.<appId>.allowAnyDevice` | No | If true, skip the device ID check for this app |
| `apps.<appId>.currentAppEpoch` | No | Current app key epoch (default `0`), served by `GET /app/<appId>`. A non-zero epoch denies the legacy `/bootAuth/app` route. |
| `rootEpochs` | No | KMS root public keys of each root epoch, indexed by epoch, `[{"caPubkey": "0x...", "k256Pubkey": "0x..."}]`. Epoch 0 is the original roots. Append only. `GET /` reports the current epoch as `rootEpoch` with its chain hash as `rootEpochHash`; the last entry is reported as `latestRootEpoch`, and entries beyond `currentRootEpoch` are pending activation. |
| `currentRootEpoch` | No | Root epoch KMS instances serve (default 0). Key-issuing operations (`kms_serve`, `app_get_key`, `app_get_cert`) may request up to this epoch; KMS key handover (`kms_export_keys`, `kms_import_keys`) may request any registered epoch, so the other KMS nodes can onboard from the rotated one while the new epoch is pending. Raise it only once every KMS node holds that epoch. |

### Validation Logic

KMS (`/authorizeKms`, `/bootAuth/kms`):

1. `tcbStatus` must be in `allowedTcbStatuses`, if set
2. Every `advisoryIds` entry must be in `allowedAdvisoryIds`, if set
3. `mrAggregated` must be in `kms.mrAggregated`
4. `deviceId` must be in `kms.devices` unless `kms.allowAnyDevice` is true

Apps (`/authorizeApp`, `/bootAuth/app`):

1. `tcbStatus` must be in `allowedTcbStatuses`, if set
2. Every `advisoryIds` entry must be in `allowedAdvisoryIds`, if set
3. `osImageHash` must be in `osImages`
4. `appId` must exist in `apps`
5. `composeHash` must be in the app's `composeHashes`
6. `deviceId` must be in the app's `devices` unless `allowAnyDevice` is true

KMS requests are not matched against `osImages`: `mrAggregated` already pins
the OS image measurements. The `/authorize*` endpoints and legacy `/bootAuth/*`
routes also enforce root epochs, see the
[KMS authorization protocol](../dstack/kms/README.md#authorization-protocol).

---

## TCB and Advisory Policy

By default `dstack-auth` does not check the platform TCB status or security
advisories. In the single-operator model the operator controls and trusts the
host, and real TDX hosts routinely report a non-`UpToDate` TCB when microcode or
the TDX module lags behind, so a hard TCB gate there adds friction without
adding trust.

Deployments where the host operator is not the party relying on the policy
(a KMS serving other users, AWS, SEV-SNP) should enforce it explicitly:

```json
{
  "allowedTcbStatuses": ["UpToDate"],
  "allowedAdvisoryIds": [],
  "osImages": ["0x..."],
  "kms": { "mrAggregated": ["0x..."], "allowAnyDevice": true },
  "apps": {}
}
```

With this, any status other than `UpToDate` and any advisory ID denies. To
accept a known state temporarily, list it explicitly, for example
`"allowedTcbStatuses": ["UpToDate", "SWHardeningNeeded"]` or
`"allowedAdvisoryIds": ["INTEL-SA-00837"]`.

AWS NitroTPM has no TDX/SNP-style TCB advisory surface, so the KMS normalizes a
verified NitroTPM attestation to `tcbStatus: "UpToDate"` before calling the
webhook; the policy above works unchanged there.

---

## Migrating from auth-simple

`auth-simple` (the Bun/TypeScript server in `dstack/kms/auth-simple`) has been
removed. `dstack-auth` reads the same config file format, so an existing
`auth-config.json` loads unchanged. To switch:

1. Keep auth-simple's strict platform defaults by adding them explicitly, unless
   your config already sets them:

   ```json
   "allowedTcbStatuses": ["UpToDate"],
   "allowedAdvisoryIds": []
   ```

   Without these fields, dstack-auth accepts any TCB status and advisory.
2. Set `kmsContractAddr` to the attested KMS app ID if it is not set. auth-simple
   defaulted it to the zero address and did not check it; dstack-auth denies
   every `/authorize*` operation except `kms_bootstrap` without it.
3. Replace the start command. `PORT` and `AUTH_CONFIG_PATH` become flags, and
   auth-simple listened on all interfaces while dstack-auth binds to loopback
   by default:

   ```bash
   # before
   PORT=3001 AUTH_CONFIG_PATH=/path/to/auth-config.json bun run start
   # after
   dstack-auth --config /path/to/auth-config.json --port 3001
   ```

   Add `--address 0.0.0.0` if the KMS reaches the webhook over a real network
   rather than `10.0.2.2`.

Other differences: KMS requests are no longer matched against `osImages` (see
[Validation Logic](#validation-logic)), `GET /` no longer reports `configPath`,
and rejection reasons are lowercase (for example `root epoch not registered`).

---

## Adding an App

### Step 1: Generate App ID

App IDs are typically the contract address (for on-chain) or a unique identifier you choose.

For dstack-auth, you can use any unique hex string (40 characters / 20 bytes):

```bash
# Generate a random app ID
openssl rand -hex 20
# Output: 7a3b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b
```

### Step 2: Get Compose Hash

The compose hash is computed from the normalized docker-compose file. The VMM displays it when deploying:

```
Docker compose file:
...
Compose hash: 0x700a50336df7c07c82457b116e144f526c29f6d8...
```

Or query from a running CVM:

```bash
curl -s --unix-socket /var/run/dstack.sock http://localhost/Info | \
  jq -r '"0x" + (.tcb_info | fromjson | .compose_hash)'
```

> **Note:** The VMM normalizes YAML to JSON before hashing. For exact hash, use the value shown during deployment.

### Step 3: Add to Config

Edit your allowlist file:

```json
{
  "apps": {
    "0x7a3b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b": {
      "composeHashes": [
        "0x700a50336df7c07c82457b116e144f526c29f6d8..."
      ],
      "devices": [],
      "allowAnyDevice": true
    }
  }
}
```

### Step 4: Deploy via VMM

Use the App ID when deploying through VMM:

```bash
./vmm-cli.py deploy \
  --app-id 7a3b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b \
  --compose docker-compose.yaml \
  ...
```

---

## Updating an App

When you change your docker-compose.yaml, a new compose hash is generated.

### Add New Hash (Keep Old Running)

Add the new hash to the `composeHashes` array:

```json
{
  "apps": {
    "0x<app-id>": {
      "composeHashes": [
        "0x<old-hash>",
        "0x<new-hash>"
      ]
    }
  }
}
```

### Replace Hash (Force Upgrade)

Remove the old hash to prevent old versions from booting:

```json
{
  "apps": {
    "0x<app-id>": {
      "composeHashes": [
        "0x<new-hash>"
      ]
    }
  }
}
```

---

## Device Management

Devices are identified by their TDX device ID (hardware-specific).

### Get Device ID

The `deviceId` is sent by the booting app/KMS in its auth request. dstack-auth
logs it with each decision (`journalctl -u dstack-auth` when installed by
`dstackup`):

```
authorize AppGetKey app=7a3b... compose=700a... mr=... os=0b32... device=e5a0... tcb=UpToDate advisories=[] -> authorized=true ()
```

> **Tip:** Use `allowAnyDevice: true` initially, then restrict to specific devices after capturing IDs from logs.

### Restrict App to Specific Devices

```json
{
  "apps": {
    "0x<app-id>": {
      "composeHashes": ["0x..."],
      "devices": [
        "0xe5a0c70bb6503de2d31c11d85914fe3776ed5b33a078ed856327c371a60fe0fd"
      ],
      "allowAnyDevice": false
    }
  }
}
```

### Allow Any Device

For initial testing or when device restriction isn't needed:

```json
{
  "apps": {
    "0x<app-id>": {
      "allowAnyDevice": true
    }
  }
}
```

---

## Removing an App

Delete the app entry from the `apps` object. Running instances continue until
restarted; new key requests are rejected.

---

## Setting the Gateway App (After Gateway Deployment)

The `gatewayAppId` field is **optional** during initial KMS deployment. Add it after deploying the Gateway.

The Gateway is a special app that routes traffic to other apps. Once deployed, add its App ID to your config:

```json
{
  "gatewayAppId": "0x75537828f2ce51be7289709686A69CbFDbB714F1",
  "apps": {
    "0x75537828f2ce51be7289709686A69CbFDbB714F1": {
      "composeHashes": ["0x..."],
      "allowAnyDevice": true
    }
  }
}
```

The `gatewayAppId` is returned in authorization responses and used by KMS for key derivation.

To trust several gateways, join their App IDs with commas (`"0xaaa...,0xbbb..."`). CVMs accept a gateway whose App ID is contained in this value.

---

## KMS Onboarding (Multi-Node)

To allow additional KMS nodes to onboard (receive root keys from the primary KMS), whitelist their `mrAggregated` value.

### Get mrAggregated

1. **Initial setup**: capture the first KMS measurement with `Onboard.GetAttestationInfo` and add it to `kms.mrAggregated` before bootstrap. An empty array denies all KMS boots.
2. **From dstack-auth logs**: every KMS request is logged with its measurement:
   ```
   authorize KmsBootstrap app=... compose=... mr=<mr-aggregated> os=... device=... -> authorized=false (kms mrAggregated not allowed)
   ```

### Add to Config

```json
{
  "kms": {
    "mrAggregated": ["0x<mr-aggregated-hash>"],
    "allowAnyDevice": true
  }
}
```

> **Note:** All KMS nodes using the same OS image and compose will have the same mrAggregated, so you only need to capture it once.

---

## Verification

### Check Config is Valid

```bash
curl -s http://127.0.0.1:3001/ | jq
```

Returns `status`, `gatewayAppId`, `kmsContractAddr` and, once `rootEpochs` is
configured, `rootEpoch` and `rootEpochHash`. An invalid `rootEpochs`
configuration returns HTTP 503.

### Test Boot Authorization

```bash
curl -s -X POST http://127.0.0.1:3001/bootAuth/app \
  -H "Content-Type: application/json" \
  -d '{
    "appId": "0x<app-id>",
    "composeHash": "0x<compose-hash>",
    "osImageHash": "0x<os-image-hash>",
    "deviceId": "0x<device-id>",
    "tcbStatus": "UpToDate",
    "advisoryIds": []
  }' | jq
```

Expected responses:
- `{"isAllowed": true, ...}` - App is authorized
- `{"isAllowed": false, "reason": "app not registered", ...}` - App ID not in config
- `{"isAllowed": false, "reason": "compose hash not allowed", ...}` - Hash not whitelisted
- `{"isAllowed": false, "reason": "tcb status not allowed", ...}` - `tcbStatus` not in `allowedTcbStatuses`

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Health check and info (`kmsContractAddr`, `gatewayAppId`, `chainId`, `appImplementation`, `rootEpoch`, `rootEpochHash`) |
| `POST /authorizeKms`, `POST /authorizeApp` | Epoch-aware authorization; return an `AuthorizationResult`. See the [KMS authorization protocol](../dstack/kms/README.md#authorization-protocol). |
| `GET /app/<appId>` | `{"currentAppEpoch": N}`; 404 for an app that is not configured |
| `POST /bootAuth/kms`, `POST /bootAuth/app` | Legacy boot authorization for older KMS binaries; return `{isAllowed, reason, gatewayAppId}` |

---

## See Also

- [Deployment Guide](./deployment.md) - Initial setup
- [On-Chain Governance](./onchain-governance.md) - Smart contract-based alternative
