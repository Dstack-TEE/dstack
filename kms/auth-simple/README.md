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

For initial KMS deployment, you only need the OS image hash:

```json
{
  "osImages": ["0x0b327bcd642788b0517de3ff46d31ebd3847b6c64ea40bacde268bb9f1c8ec83"],
  "kms": {
    "allowAnyDevice": true
  },
  "apps": {}
}
```

Add more fields as you deploy Gateway and apps:

```json
{
  "osImages": ["0x..."],
  "gatewayAppId": "0x...",
  "kms": {
    "mrAggregated": [],
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

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `osImages` | Yes | Allowed OS image hashes (from `digest.txt`) |
| `gatewayAppId` | No | Gateway app ID (add after Gateway deployment) |
| `kms.mrAggregated` | No | Allowed KMS aggregated MR values |
| `kms.devices` | No | Allowed KMS device IDs |
| `kms.allowAnyDevice` | No | If true, skip device ID check for KMS |
| `apps.<appId>.composeHashes` | No | Allowed compose hashes for this app |
| `apps.<appId>.devices` | No | Allowed device IDs for this app |
| `apps.<appId>.allowAnyDevice` | No | If true, skip device ID check for this app |

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
  "mrAggregated": "0x...",
  "osImageHash": "0x...",
  "appId": "0x...",
  "composeHash": "0x...",
  "instanceId": "0x...",
  "deviceId": "0x...",
  "tcbStatus": "UpToDate"
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

1. `tcbStatus` must be "UpToDate"
2. `osImageHash` must be in `osImages` array
3. `mrAggregated` must be in `kms.mrAggregated` (if non-empty)
4. `deviceId` must be in `kms.devices` (unless `allowAnyDevice` is true)

### App Boot Validation

1. `tcbStatus` must be "UpToDate"
2. `osImageHash` must be in `osImages` array
3. `appId` must exist in `apps` object
4. `composeHash` must be in app's `composeHashes` array
5. `deviceId` must be in app's `devices` (unless `allowAnyDevice` is true)

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
- [Deployment Guide](../../docs/deployment.md) - Full deployment instructions
