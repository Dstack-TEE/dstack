---
title: "Troubleshooting: Gateway Deployment"
description: "Solutions for common issues during gateway build, configuration, and CVM deployment"
section: "Troubleshooting"
stepNumber: null
totalSteps: null
isAppendix: true
tags:
  - troubleshooting
  - gateway
  - deployment
  - cvm
  - wireguard
  - letsencrypt
difficulty: intermediate
estimatedTime: "reference"
lastUpdated: 2026-03-06
---

# Troubleshooting: Gateway Deployment

This appendix consolidates troubleshooting content from the Gateway Deployment tutorials. For inline notes and warnings, see the individual tutorials.

---

## Gateway Build & Configuration Issues

### Contract transaction reverts

If `deployAndRegisterApp` reverts, check:

1. **App implementation not set:** The KMS contract owner must call `setAppImplementation` before apps can be deployed
   ```bash
   cast call "$KMS_CONTRACT_ADDR" \
     "appImplementation()(address)" \
     --rpc-url "$ETH_RPC_URL"
   ```
   Should return a non-zero address.

2. **Insufficient funds:** Your wallet needs Sepolia ETH for gas
   ```bash
   cast balance $(cast wallet address --private-key $PRIVATE_KEY) --rpc-url "$ETH_RPC_URL"
   ```

### Compose hash mismatch

If deployment later fails with "compose hash not allowed":

1. Regenerate app-compose.json and recalculate the hash
2. Whitelist the new hash on-chain (Step 8)
3. The hash changes whenever docker-compose.yaml or .app_env contents change

### vmm-cli.py compose errors

**"Connection refused"** — VMM is not running:
```bash
sudo systemctl restart dstack-vmm
```

**"Authentication required"** — Set the auth token:
```bash
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)
```

### KMS shows wrong gateway app ID

**Symptom:** `curl -sk https://localhost:9100/prpc/KMS.GetMeta | jq '.gateway_app_id'` returns the wrong app ID, an empty string, or KMS is unreachable.

**Cause:** The KMS auth-eth service queries the blockchain directly (via `eth_call`) — it does not cache state. If KMS was deployed with a different `ETH_RPC_URL` or the KMS CVM is having connectivity issues, it may fail to read on-chain changes. Alternatively, you may need to redeploy KMS after port binding changes from the KMS tutorial.

**Solution:** Redeploy the KMS CVM:

```bash
cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)

# Get KMS VM ID and remove it
KMS_ID=$(./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm --json | jq -r '.[] | select(.name=="kms") | .id')
./src/vmm-cli.py --url http://127.0.0.1:9080 stop --force "$KMS_ID"
./src/vmm-cli.py --url http://127.0.0.1:9080 remove "$KMS_ID"

# Redeploy
./src/vmm-cli.py --url http://127.0.0.1:9080 deploy \
  --name kms \
  --image dstack-0.5.7 \
  --compose ~/kms-deploy/app-compose.json \
  --vcpu 2 \
  --memory 4096 \
  --disk 20 \
  --port tcp:0.0.0.0:9100:9100
```

Wait for KMS to come back up:

```bash
until curl -sk https://localhost:9100/prpc/KMS.GetMeta > /dev/null 2>&1; do
  echo "Waiting for KMS..."
  sleep 5
done
echo "KMS is ready"
```

Verify the gateway app ID is now correct:

```bash
curl -sk https://localhost:9100/prpc/KMS.GetMeta | jq '.gateway_app_id'
```

---

## Gateway CVM Deployment Issues

### "Port mapping is not allowed for udp:9202"

The VMM's port mapping whitelist in `/etc/dstack/vmm.toml` doesn't include UDP ports. The gateway needs UDP for WireGuard.

**Solution:** Add a UDP range to the port mapping configuration:

```bash
sudo sed -i '/{ protocol = "tcp", from = 1, to = 20000 },/a\    { protocol = "udp", from = 1, to = 20000 },' /etc/dstack/vmm.toml
sudo systemctl restart dstack-vmm
```

See [Gateway CVM Preparation: Step 1](/tutorial/gateway-build-configuration#step-1-verify-prerequisites) for details.

### "OS image is not allowed"

**Symptom:** CVM reboots with `Boot denied: OS image is not allowed` in the logs.

**Cause:** The OS image hash isn't whitelisted on the KMS contract. Each dstack guest image has a unique SHA256 digest (stored in `digest.txt`) that must be explicitly whitelisted.

**Solution:**

```bash
# Read the actual OS image digest
OS_IMAGE_HASH=$(cat /var/lib/dstack/images/dstack-0.5.7/digest.txt)
echo "OS image hash: 0x$OS_IMAGE_HASH"

# Whitelist it on the KMS contract
export KMS_CONTRACT_ADDR=$(cat ~/.dstack/secrets/kms-contract-address)
cast send "$KMS_CONTRACT_ADDR" \
  "addOsImageHash(bytes32)" \
  "0x$OS_IMAGE_HASH" \
  --rpc-url "https://ethereum-sepolia-rpc.publicnode.com" \
  --private-key "$(cat ~/.dstack/secrets/sepolia-private-key)"
```

The CVM will retry automatically on its next reboot cycle.

> **Common mistake:** Do not whitelist `bytes32(0)` (all zeros). The VMM reads the actual digest from the image's `digest.txt` file and passes it to KMS. You must whitelist that specific hash.

### CVM fails to start

Check VMM status and logs:

```bash
systemctl status dstack-vmm
journalctl -u dstack-vmm -n 50
```

Common causes:
- **Insufficient resources:** The gateway requests 32 vCPUs and 32G RAM. Ensure the host has enough free resources.
- **Image not found:** Verify `dstack-0.5.7` exists in VMM images directory.

### CVM exits immediately or reboots in a loop

Same root cause as KMS CVM — the `dstack-prepare` service fails to fetch SGX quote collateral from PCCS.

Check the CVM logs:

```bash
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=false&ansi=false&lines=500" | grep -A3 "Failed to get sealing key"
```

See [KMS CVM Deployment: CVM Exits Immediately](/tutorial/troubleshooting-kms-deployment#cvm-exits-immediately-or-reboots-in-a-loop) for the full solution.

### Compose hash not allowed

**Symptom:** CVM starts but the gateway container fails with an attestation error.

**Cause:** The `app-compose.json` hash doesn't match what's whitelisted on-chain.

**Solution:** Recalculate and whitelist the hash:

```bash
COMPOSE_HASH=$(sha256sum ~/gateway-deploy/app-compose.json | cut -d' ' -f1)
echo "Hash: 0x$COMPOSE_HASH"

# Check if it's already whitelisted
cast call "$(cat ~/.dstack/secrets/gateway-app-id)" \
  "allowedComposeHashes(bytes32)(bool)" \
  "0x$COMPOSE_HASH" \
  --rpc-url "https://ethereum-sepolia-rpc.publicnode.com"

# If false, add it
cast send "$(cat ~/.dstack/secrets/gateway-app-id)" \
  "addComposeHash(bytes32)" \
  "0x$COMPOSE_HASH" \
  --rpc-url "https://ethereum-sepolia-rpc.publicnode.com" \
  --private-key "$(cat ~/.dstack/secrets/sepolia-private-key)"
```

### Admin API unreachable

**Symptom:** `curl http://127.0.0.1:9203/prpc/Status` returns "Connection refused"

1. **CVM not fully booted:** Wait 1-2 minutes and retry. Check logs for progress.
2. **Port mapping wrong:** Verify the deploy command included `--port tcp:127.0.0.1:9203:8001`
3. **Gateway crashed:** Check CVM logs for errors:
   ```bash
   curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
     "http://127.0.0.1:9080/logs?id=VM_ID&follow=false&ansi=false&lines=100"
   ```

### Let's Encrypt rate limits

**Symptom:** Certificate requests fail with ACME errors mentioning "too many certificates" or "rate limit". The gateway can't serve browser-trusted TLS traffic.

**Root cause:** The gateway stores its Let's Encrypt certificates in WaveKV, a persistent key-value store inside the CVM. Here's what triggers — and doesn't trigger — a new certificate request:

| Action | New cert request? | Why |
|--------|:-:|-----|
| Container restart (within running CVM) | No | Docker named volume preserves WaveKV data |
| CVM destroy + recreate | **Yes** | Docker volume is destroyed, WaveKV store is wiped, no cached cert exists |
| `SetCertbotConfig` with new ACME URL | **Yes** | Renewal loop detects the change and requests from the new CA |
| Normal renewal (cert approaching expiry) | Yes | Expected behavior, well within rate limits |

Let's Encrypt production allows **10 duplicate certificates per 3 hours per IP**. During iterative testing where you destroy and recreate the CVM multiple times, each redeployment burns one request. Ten redeployments in 3 hours exhausts the limit.

**How to check if you're rate-limited:**

```bash
VM_ID=$(cd ~/dstack/vmm && ./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm --json | jq -r '.[] | select(.name=="dstack-gateway") | .id')
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=$VM_ID&follow=false&ansi=false&lines=200" | grep -i "rate\|too many\|acme.*error"
```

**Recovery:**

1. **If already rate-limited on production:** You must wait for the 3-hour window to expire. Switch to staging in the meantime so the gateway can still function (with browser-untrusted staging certs):
   ```bash
   curl -sf -X POST "http://127.0.0.1:9203/prpc/SetCertbotConfig" \
     -H "Content-Type: application/json" \
     -d '{
       "acme_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
       "renew_interval_secs": 3600,
       "renew_before_expiration_secs": 864000,
       "renew_timeout_secs": 300
     }' && echo "Switched to staging"
   ```

2. **Avoid the problem entirely:** Follow the staging-first workflow in this tutorial. Use staging during [Step 4a](#4a-set-certbot-configuration), verify everything works, then switch to production once in [Step 6](#step-6-switch-to-production-certificates). This uses exactly one production cert request per stable deployment.

3. **Minimize redeployments:** If you need to debug the gateway, restart the container inside the CVM rather than destroying and recreating the entire CVM. Container restarts preserve the WaveKV store and don't trigger new cert requests.

### Certbot fails to issue certificates

**Symptom:** Applications get TLS errors; certbot debug logs show failures.

1. **DNS credential not set:** Verify with `curl -sf http://127.0.0.1:9203/prpc/ListDnsCredentials`
2. **Cloudflare token invalid:** Test the token directly:
   ```bash
   curl -s -H "Authorization: Bearer YOUR_CF_TOKEN" \
     "https://api.cloudflare.com/client/v4/user/tokens/verify" | jq .
   ```
3. **Rate limits:** See [Let's Encrypt rate limits](#lets-encrypt-rate-limits) above.

### KMS connectivity issues

**Symptom:** Gateway CVM logs show "Connection refused" errors to KMS, or the CVM reboots in a loop with KMS-related failures.

**Common causes:**

1. **Only one `--kms-url` was passed.** The CVM can't reach KMS at `127.0.0.1:9100` — that's the CVM's own localhost. You need a second `--kms-url` with the KMS domain name.

2. **TLS certificate mismatch.** If you use an IP address (e.g., `10.0.2.2`) instead of the KMS domain name, TLS verification fails because the KMS cert is only valid for the domain set by `KMS_DOMAIN` in the KMS docker-compose. Use `https://kms.yourdomain.com:9100` instead.

3. **KMS bound to localhost only.** If KMS was deployed with `--port tcp:127.0.0.1:9100:9100`, gateway CVMs cannot reach it. Redeploy KMS with `--port tcp:0.0.0.0:9100:9100` (see [KMS CVM Deployment](/tutorial/kms-cvm-deployment)).

**Solution:** Redeploy with two `--kms-url` flags using the KMS domain name:

```bash
--kms-url "https://127.0.0.1:9100" \
--kms-url "https://kms.yourdomain.com:9100" \
```

The first URL is for host-side encryption by `vmm-cli.py`. The second uses the KMS domain (matching its TLS cert) and is passed into the CVM for runtime KMS access.

If KMS itself is not running:

```bash
# Test KMS from host
curl -sk https://localhost:9100/prpc/KMS.GetMeta | jq '{chain_id}'

# Verify KMS CVM is running
cd ~/dstack/vmm
./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm
```

If KMS is not running, redeploy it first. See [KMS CVM Deployment](/tutorial/kms-cvm-deployment).

### WireGuard endpoint unreachable from app CVMs

**Symptom:** App CVMs can't establish WireGuard tunnels to the gateway.

1. **UDP port not forwarded:** Verify `sudo ss -ulnp | grep 9202` shows the port
2. **Firewall blocking UDP:** Check `sudo ufw status` or `sudo iptables -L -n`
3. **PUBLIC_IP wrong:** The WG_ENDPOINT in `.app_env` must be your host's actual public IP
