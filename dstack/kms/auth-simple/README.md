# dstack auth-simple

A config-based auth server for dstack KMS webhook authorization. Validates boot requests against a JSON configuration file.

## When to Use

| Auth Server | Use Case |
|-------------|----------|
| **auth-simple** | Production deployments with config-file-based whitelisting |
| auth-eth | Production deployments with on-chain governance |
| auth-mock | Development and testing only |

## Installation

```bash
bun install
```

## Configuration

Create `auth-config.json` (see `auth-config.example.json`).

For KMS deployment, you must allowlist the OS image hash and at least one KMS
identity value via `kms.mrAggregated` (the early/boot-mr-done aggregate MR,
same pinning model as bare TDX). App compose hashes still use
`apps.<appId>.composeHashes`.

```json
{
  "osImages": ["0x0b327bcd642788b0517de3ff46d31ebd3847b6c64ea40bacde268bb9f1c8ec83"],
  "kms": {
    "mrAggregated": ["0x<kms-early-mr-aggregated>"],
    "allowAnyDevice": true
  },
  "apps": {}
}
```

Add more fields as you deploy Gateway and apps:

```json
{
  "osImages": ["0x..."],
  "allowedTcbStatuses": ["UpToDate"],
  "allowedAdvisoryIds": [],
  "gatewayAppId": "0x...",
  "kms": {
    "mrAggregated": ["0x..."],
    "devices": [],
    "allowAnyDevice": true
  },
  "apps": {
    "0xYourAppId": {
      "composeHashes": ["0xabc...", "0xdef..."],
      "devices": [],
      "allowAnyDevice": true
    }
  }
}
```

### AWS NitroTPM Example

AWS NitroTPM has no TDX/SNP-style TCB advisory surface, so the KMS normalizes a
verified NitroTPM attestation to `tcbStatus: "UpToDate"` before calling
auth-simple. Pin KMS via early `mrAggregated` (boot-mr-done snapshot), same as
bare TDX. Prefer a stable AMI/`os_image_hash` and empty TPM key-provider id so
that early MR is precomputable.

```json
{
  "osImages": ["0x<aws-os-image-hash>"],
  "allowedAdvisoryIds": [],
  "kms": {
    "mrAggregated": ["0x<kms-early-mr-aggregated>"],
    "devices": [],
    "allowAnyDevice": true
  },
  "apps": {
    "0x<app-id>": {
      "composeHashes": ["0x<app-compose-hash>"],
      "devices": [],
      "allowAnyDevice": true
    }
  }
}
```

The verifier that calls auth-simple must already have verified the NitroTPM
Attestation Document, AWS NitroTPM PKI chain, boot PCRs, PCR14 launch-event
replay (the authoritative app-identity binding), and any recipient public key
used for encrypted key release. The PCR8 `MrConfig` V2 config commitment is an
optional shortcut for verifiers that skip PCR14 replay, not a required check.
auth-simple authorizes the resulting canonical `BootInfo`; it does not verify
raw NitroTPM evidence by itself.

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `osImages` | Yes | Allowed OS image hashes (from `digest.txt`) |
| `gatewayAppId` | No | Gateway app ID (add after Gateway deployment) |
| `allowedTcbStatuses` | No | Allowed verifier-derived TCB status strings. Defaults to `["UpToDate"]`; non-up-to-date SNP/TDX statuses remain fail-closed unless explicitly allowlisted for testing. |
| `allowedAdvisoryIds` | No | Advisory IDs permitted in `advisoryIds`. Defaults to `[]`, which rejects any advisory. |
| `kms.mrAggregated` | Yes | Allowed KMS early aggregate MR values (boot-mr-done). |
| `kms.devices` | No | Allowed KMS device IDs |
| `kms.allowAnyDevice` | No | If true, skip device ID check for KMS |
| `apps.<appId>.composeHashes` | No | Allowed compose hashes for this app |
| `apps.<appId>.devices` | No | Allowed device IDs for this app |
| `apps.<appId>.allowAnyDevice` | No | If true, skip device ID check for this app |

For experimental AMD SEV-SNP dry-run authorization, keep the default fail-closed TCB policy unless you intentionally want the auth webhook to accept non-up-to-date verifier-derived SNP `BootInfo`. To exercise the dry-run path without enabling key release, allowlist the recomputed SNP `mrAggregated`, `osImageHash`, app/compose identity, device/chip identity, and any non-default `allowedTcbStatuses`/`allowedAdvisoryIds` values explicitly. KMS still rejects SNP before returning app keys, KMS keys, or app certificates.

### Getting Hash Values

**OS Image Hash:**
```bash
# From meta-dstack build output
cat images/digest.txt
```

**Compose Hash:**
```bash
sha256sum .app-compose.json | awk '{print "0x"$1}'
```

## Usage

### Development

```bash
# Run with hot reload
bun run dev
```

### Production

```bash
# Run directly
bun run start

# Or build first
bun run build
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | Server port |
| `AUTH_CONFIG_PATH` | ./auth-config.json | Path to config file |

## API Endpoints

### GET /

Health check and server info.

**Response:**
```json
{
  "status": "ok",
  "configPath": "./auth-config.json",
  "gatewayAppId": "0x..."
}
```

### POST /bootAuth/app

App boot authorization.

**Request:**
```json
{
  "attestationMode": "dstack-tdx",
  "mrAggregated": "0x...",
  "osImageHash": "0x...",
  "appId": "0x...",
  "composeHash": "0x...",
  "instanceId": "0x...",
  "deviceId": "0x...",
  "tcbStatus": "UpToDate",
  "advisoryIds": []
}
```

**Response:**
```json
{
  "isAllowed": true,
  "reason": "",
  "gatewayAppId": "0x..."
}
```

### POST /bootAuth/kms

KMS boot authorization.

**Request:** Same as `/bootAuth/app`

**Response:** Same as `/bootAuth/app`

## Validation Logic

### KMS Boot Validation

1. `tcbStatus` must be listed in `allowedTcbStatuses` (default: only `"UpToDate"`). AWS NitroTPM is normalized to `"UpToDate"` by the KMS before it reaches auth-simple.
2. Every `advisoryIds` entry must be listed in `allowedAdvisoryIds` (default: none allowed)
3. `osImageHash` must be in `osImages` array
4. At least one KMS identity allowlist must be configured:
   - `kms.mrAggregated` early/boot-mr-done aggregate MR (required)
6. `deviceId` must be in `kms.devices` unless `allowAnyDevice` is true

### App Boot Validation

1. `tcbStatus` must be listed in `allowedTcbStatuses` (default: only `"UpToDate"`). AWS NitroTPM is normalized to `"UpToDate"` by the KMS before it reaches auth-simple.
2. Every `advisoryIds` entry must be listed in `allowedAdvisoryIds` (default: none allowed)
3. `osImageHash` must be in `osImages` array
4. `appId` must exist in `apps` object
5. `composeHash` must be in app's `composeHashes` array
6. `deviceId` must be in app's `devices` (unless `allowAnyDevice` is true)

## Hot Reload

The config file is re-read on every request. No restart required after config changes.

## Integration with KMS

Configure KMS to use webhook auth pointing to this server:

```toml
[core.auth_api]
type = "webhook"

[core.auth_api.webhook]
url = "http://localhost:3000"
```

## Testing

```bash
# Run tests
bun run test

# Run once
bun run test:run
```

## See Also

- [auth-eth](../auth-eth/) - On-chain governance auth server
- [auth-mock](../auth-mock/) - Development/testing auth server (always allows)
- [Deployment Guide](../../../docs/deployment.md) - Full deployment instructions
