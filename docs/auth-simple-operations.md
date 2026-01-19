# auth-simple Operations Guide

This guide covers day-to-day operations for managing apps and devices with auth-simple.

For initial deployment setup, see [Deployment Guide](./deployment.md).

## Overview

auth-simple uses a JSON config file to whitelist:
- **OS images** - Which guest OS versions can boot
- **KMS nodes** - Which KMS instances can onboard (mrAggregated, devices)
- **Apps** - Which applications can boot (appId, composeHash, devices)

The config is re-read on each request, so changes take effect immediately without restart.

---

## Config File Structure

```json
{
  "osImages": ["0x..."],
  "gatewayAppId": "0x...",
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
  }
}
```

> **Note:** Only `osImages` is required. Add `gatewayAppId` after deploying the Gateway. Add `apps` entries as you deploy applications.

---

## Adding an App

### Step 1: Generate App ID

App IDs are typically the contract address (for on-chain) or a unique identifier you choose.

For auth-simple, you can use any unique hex string (40 characters / 20 bytes):

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

Edit your `auth-config.json`:

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

The `deviceId` is sent by the booting app/KMS in its auth request. Check auth-simple logs:

```
app boot auth request: { appId: '0x...', deviceId: '0x...', ... }
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

Delete the app entry from the `apps` object:

```json
{
  "apps": {
    // "0x<removed-app-id>": { ... }  <- deleted
  }
}
```

Running instances will continue until restarted. New boot requests will be rejected.

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

The `gatewayAppId` is returned in boot responses and used by KMS for key derivation.

---

## KMS Onboarding (Multi-Node)

To allow additional KMS nodes to onboard (receive root keys from the primary KMS), whitelist their `mrAggregated` value.

### Get mrAggregated

The `mrAggregated` is sent by the booting KMS in its auth request. To get this value:

1. **From auth-simple logs**: When a KMS boots, auth-simple logs the mrAggregated:
   ```
   KMS boot auth request: { osImageHash: '0x...', mrAggregated: '0x...', ... }
   ```

2. **Initial setup**: Leave `kms.mrAggregated` empty for the first KMS (empty array allows any). After it boots, check the logs and add the value.

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
curl -s http://localhost:3001/ | jq
```

Returns current config status including `gatewayAppId`.

### Test Boot Authorization

```bash
# Test app boot
curl -s -X POST http://localhost:3001/bootAuth/app \
  -H "Content-Type: application/json" \
  -d '{
    "appId": "0x<app-id>",
    "composeHash": "0x<compose-hash>",
    "osImageHash": "0x<os-image-hash>",
    "deviceId": "0x<device-id>",
    "mrAggregated": "0x...",
    "instanceId": "0x...",
    "tcbStatus": "UpToDate"
  }' | jq
```

Expected responses:
- `{"isAllowed": true, ...}` - App is authorized
- `{"isAllowed": false, "reason": "app not registered", ...}` - App ID not in config
- `{"isAllowed": false, "reason": "compose hash not allowed", ...}` - Hash not whitelisted

---

## See Also

- [Deployment Guide](./deployment.md) - Initial setup
- [auth-simple README](../kms/auth-simple/README.md) - Developer reference
- [On-Chain Governance](./onchain-governance.md) - Smart contract-based alternative
