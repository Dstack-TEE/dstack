---
title: "KMS CVM Deployment"
description: "Deploy dstack KMS as a Confidential Virtual Machine for TDX attestation"
section: "KMS Deployment"
stepNumber: 3
totalSteps: 3
lastUpdated: 2026-01-09
prerequisites:
  - kms-build-configuration
  - gramine-key-provider
  - local-docker-registry
tags:
  - dstack
  - kms
  - cvm
  - tdx
  - vmm
  - deployment
difficulty: "advanced"
estimatedTime: "20 minutes"
---

# KMS CVM Deployment

This tutorial guides you through deploying the dstack KMS as a Confidential Virtual Machine (CVM). Running KMS inside a CVM enables TDX attestation, providing cryptographic proof that the KMS keys were generated in a genuine Intel TDX environment.

## Why Deploy KMS in a CVM?

Running KMS inside a CVM provides significant security benefits:

| Benefit | Description |
|---------|-------------|
| **TDX Attestation** | Generate cryptographic quotes proving keys were created in genuine TDX |
| **Memory Encryption** | Root keys protected by TDX hardware encryption, not just file permissions |
| **Verifiable Integrity** | Anyone can verify KMS integrity via attestation quote |
| **Consistent Model** | KMS deployed the same way as other dstack applications |

## Prerequisites

Before starting, ensure you have:

- Completed [KMS Build & Configuration](/tutorial/kms-build-configuration)
- Completed [Gramine Key Provider](/tutorial/gramine-key-provider) - Required for CVM boot
- Completed [Local Docker Registry](/tutorial/local-docker-registry) - With KMS image cached
- Completed [TDX & SGX Verification](/tutorial/tdx-sgx-verification) - SGX must be working for attestation
- KMS image pushed to local registry (`registry.yourdomain.com/dstack-kms:fixed`)
- dstack VMM running (`systemctl status dstack-vmm`)
- VMM web interface available at http://localhost:9080

> **Why SGX is required:** The KMS uses Intel SGX to generate TDX attestation quotes via the `local_key_provider`. SGX Auto MP Registration must be enabled in BIOS so your platform is registered with Intel's Provisioning Certification Service (PCS). Without this registration, KMS cannot generate valid attestation quotes, and bootstrap will fail.

> **Why local registry?** The KMS Docker image is cached in your [Local Docker Registry](/tutorial/local-docker-registry) for reliable, fast access from CVMs. The auth-eth service inside the container requires `ETH_RPC_URL` and `KMS_CONTRACT_ADDR` environment variables — these are passed via docker-compose, not baked into the image.


## What Gets Deployed

When you deploy KMS as a CVM, the following happens:

1. **CVM Creation** - VMM creates a TDX-protected virtual machine
2. **Container Start** - Docker container runs inside the CVM
3. **Onboard Mode** - KMS starts a plain HTTP server, waiting for bootstrap
4. **Manual Bootstrap** - You trigger key generation via an RPC call
5. **TDX Quote** - KMS generates attestation quote proving TDX environment
6. **Service Ready** - KMS transitions to TLS and starts accepting connections

### Generated Artifacts

Inside the CVM at `/etc/kms/certs/`:

| File | Purpose |
|------|---------|
| `root-ca.crt` | Root Certificate Authority (self-signed) |
| `root-ca.key` | Root CA signing key (P256 ECDSA) |
| `rpc.crt` | TLS certificate for RPC server |
| `rpc.key` | RPC server private key |
| `tmp-ca.crt` | Temporary CA for mutual TLS |
| `tmp-ca.key` | Temporary CA private key |
| `root-k256.key` | Ethereum signing key (secp256k1) |
| `bootstrap-info.json` | Public keys and TDX attestation quote |

---

## Manual Deployment

If you prefer to deploy manually, follow these steps.

### Step 1: Verify Prerequisites

Check that all required components are ready.

#### Verify KMS image in local registry

```bash
curl -sk https://registry.yourdomain.com/v2/dstack-kms/tags/list
```

Expected output shows the `:fixed` tag:
```json
{"name":"dstack-kms","tags":["fixed","latest"]}
```

If missing, complete the [Local Docker Registry](/tutorial/local-docker-registry) tutorial first.

#### Verify Gramine Key Provider is running

```bash
docker ps | grep gramine-sealing-key-provider
```

Should show the container running. If not, complete the [Gramine Key Provider](/tutorial/gramine-key-provider) tutorial.

#### Verify VMM is running

```bash
systemctl status dstack-vmm
```

The VMM must be active and running.

### Step 2: Create Deployment Directory

```bash
mkdir -p ~/kms-deploy
cd ~/kms-deploy
```

### Step 3: Create docker-compose.yaml

> **Replace placeholders:** If you haven't already personalized the tutorials with your domain names, see [DNS Configuration: Personalize Tutorials](/tutorial/dns-configuration#personalize-tutorial-commands). You **must** replace `registry.yourdomain.com` and `kms.yourdomain.com` with your actual domains.

Create the compose file with your registry domain and configuration:

```bash
cat > docker-compose.yaml << 'EOF'
services:
  kms:
    image: registry.yourdomain.com/dstack-kms:fixed
    ports:
      - "9100:9100"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - kms-certs:/etc/kms/certs
    environment:
      - RUST_LOG=info
      - KMS_DOMAIN=kms.yourdomain.com
      - PORT=9200
      - ETH_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
      - KMS_CONTRACT_ADDR=YOUR_CONTRACT_ADDRESS
    configs:
      - source: kms_config
        target: /etc/kms/kms.toml
    restart: unless-stopped

volumes:
  kms-certs:

configs:
  kms_config:
    content: |
      [rpc]
      address = "0.0.0.0"
      port = 9100

      [rpc.tls]
      key = "/etc/kms/certs/rpc.key"
      certs = "/etc/kms/certs/rpc.crt"

      [rpc.tls.mutual]
      ca_certs = "/etc/kms/certs/tmp-ca.crt"
      mandatory = false

      [core]
      cert_dir = "/etc/kms/certs"
      pccs_url = "https://pccs.phala.network/sgx/certification/v4"

      [core.image]
      verify = true
      cache_dir = "/etc/kms/images"
      download_url = "https://download.dstack.org/os-images/mr_{OS_IMAGE_HASH}.tar.gz"
      download_timeout = "2m"

      [core.auth_api]
      type = "webhook"

      [core.auth_api.webhook]
      url = "http://127.0.0.1:9200"

      [core.onboard]
      enabled = true
      auto_bootstrap_domain = ""
      address = "0.0.0.0"
      port = 9100
EOF
```

Replace the placeholder values with your actual configuration:

```bash
# Registry domain (must match your local Docker registry)
sed -i 's|registry.yourdomain.com|registry.your-actual-domain.com|g' docker-compose.yaml

# KMS domain (for the KMS_DOMAIN env var)
sed -i 's|kms.yourdomain.com|kms.your-actual-domain.com|g' docker-compose.yaml

# KMS contract address (from contract deployment tutorial)
sed -i "s|YOUR_CONTRACT_ADDRESS|$(cat ~/.dstack/secrets/kms-contract-address)|g" docker-compose.yaml
```

This docker-compose uses a Docker `configs` section to inject a complete `kms.toml` into the container at `/etc/kms/kms.toml`, overriding the config baked into the image. This approach lets you change KMS configuration without rebuilding the Docker image.

**Key configuration sections in `kms.toml`:**

| Section | Purpose |
|---------|---------|
| `[rpc]` | RPC server address and port (9100) |
| `[rpc.tls]` | TLS certificate paths for HTTPS |
| `[core.image]` | OS image verification — downloads images from `download.dstack.org` to compute expected TDX measurements |
| `[core.auth_api]` | Authentication via auth-eth webhook on localhost:9200 |
| `[core.onboard]` | Bootstrap settings — `auto_bootstrap_domain` is empty so KMS enters onboard mode for manual bootstrap |

> **Why manual bootstrap?** With `auto_bootstrap_domain` left empty, KMS starts in "onboard mode" — a plain HTTP server on port 9100 that waits for you to trigger bootstrap via an RPC call. This ensures `bootstrap-info.json` (containing the TDX attestation quote and public keys) is written to disk. You'll need this file later to register the KMS on-chain.

**Environment variables explained:**

| Variable | Required | Description |
|----------|----------|-------------|
| `RUST_LOG` | Yes | KMS log level (`info`, `debug`, etc.) |
| `KMS_DOMAIN` | Yes | KMS domain name (used by start-kms.sh for reference) |
| `PORT` | Yes | auth-eth listen port — **must be `9200`** to match kms.toml webhook URL |
| `ETH_RPC_URL` | Yes | Ethereum Sepolia RPC endpoint |
| `KMS_CONTRACT_ADDR` | Yes | Your deployed KMS contract address |

> **Getting your values:**
> ```bash
> # Your KMS contract address (from contract deployment tutorial)
> cat ~/.dstack/secrets/kms-contract-address
> ```
>
> For `ETH_RPC_URL`, the tutorials use the free `https://ethereum-sepolia-rpc.publicnode.com` endpoint. For production, consider a dedicated RPC provider.

**Other important settings:**
- `image`: Must use your local registry with the `:fixed` tag
- `/var/run/dstack.sock`: Required for TDX attestation
- `configs`: Injects `kms.toml` at runtime — the `start-kms.sh` entrypoint reads from `/etc/kms/kms.toml`

### Step 4: Deploy via vmm-cli.py

Use the VMM CLI tool to deploy the CVM:

```bash
# Navigate to dstack VMM directory
cd ~/dstack/vmm

# Set VMM auth from saved token
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)

# Generate app-compose.json with local key provider enabled
./src/vmm-cli.py --url http://127.0.0.1:9080 compose \
  --name kms \
  --docker-compose ~/kms-deploy/docker-compose.yaml \
  --local-key-provider \
  --output ~/kms-deploy/app-compose.json

# Deploy the CVM
./src/vmm-cli.py --url http://127.0.0.1:9080 deploy \
  --name kms \
  --image dstack-0.5.7 \
  --compose ~/kms-deploy/app-compose.json \
  --vcpu 2 \
  --memory 4096 \
  --disk 20 \
  --port tcp:0.0.0.0:9100:9100
```

**Key flags explained:**
- `--local-key-provider`: Enables Gramine key provider for CVM boot
- `--image dstack-0.5.7`: Guest image from VMM images directory
- `--port tcp:0.0.0.0:9100:9100`: Maps host port 9100 to CVM port 9100 on all interfaces

> **Why `0.0.0.0` and not `127.0.0.1`?** Gateway CVMs use QEMU user-mode networking and reach the host via its public IP. If KMS is bound to localhost only, gateway CVMs cannot connect. KMS authentication uses TDX attestation, not network isolation, so public accessibility is safe.

> **Note:** Do NOT use `--secure-time` flag - it causes CVM to hang during boot waiting for time sync.

### Step 5: Monitor Deployment

List VMs to get the ID, then view the boot logs:

```bash
# List VMs to get the ID
./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm
```

View CVM boot logs using curl (replace `VM_ID` with the actual ID from `lsvm`):

```bash
# View recent logs
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=false&ansi=false&lines=100"

# Follow logs in real-time
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=true&ansi=false"
```

> **Note:** The VMM logs endpoint requires Bearer token authentication. The `vmm-cli.py logs` command may not work with token auth — use curl directly as shown above.

Look for these log messages indicating KMS entered onboard mode:
```
KMS CVM booting...
Docker container starting...
KMS initializing...
Onboarding
```

> **Important:** KMS is now in onboard mode — a plain HTTP server waiting for bootstrap. It will **not** serve TLS or respond to `KMS.GetMeta` until you complete the next step.
>
> **Critical prerequisite:** before bootstrap can succeed, the KMS must already be authorized by your auth backend.
>
> - For `auth-simple`, add the KMS `mrAggregated` to `kms.mrAggregated`
> - For `auth-eth`, add the KMS `mrAggregated` on-chain with `addKmsAggregatedMr(...)`
>
> You can fetch the value before bootstrap with:
>
> ```bash
> curl -s -X POST \
>   -H "Content-Type: application/json" \
>   -d '{}' \
>   "http://localhost:9100/prpc/Onboard.GetAttestationInfo?json" | jq .
> ```
>
> If you skip this step, `Onboard.Bootstrap` will fail with a KMS authorization error and the KMS will not enter normal service.
>
> **Pre-bootstrap checklist:**
>
> 1. `Onboard.GetAttestationInfo` returns the current KMS measurement
> 2. that `mrAggregated` has been allowlisted in your auth backend
> 3. the auth backend is reachable from the KMS CVM
> 4. you are still calling the onboard HTTP endpoint, not the post-bootstrap TLS endpoint

### Step 6: Bootstrap KMS

With KMS in onboard mode, trigger key generation by calling the Bootstrap RPC endpoint. This generates root keys, a TDX attestation quote, and writes `bootstrap-info.json`:

```bash
# Inspect the KMS measurement before bootstrap
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{}' \
  "http://localhost:9100/prpc/Onboard.GetAttestationInfo?json" | jq .

# Replace kms.yourdomain.com with your actual KMS domain
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"domain":"kms.yourdomain.com"}' \
  "http://localhost:9100/prpc/Onboard.Bootstrap?json" | tee ~/kms-deploy/bootstrap-info.json | jq .
```

> **Note:** This uses plain `http://` — KMS is still in onboard mode (no TLS yet). The `tee` command saves the response to `bootstrap-info.json` while also displaying it. You'll need this file later to register KMS on-chain. If this call fails with a KMS authorization error, allowlist the `mrAggregated` value first and retry.

Expected response:

```json
{
  "ca_pubkey": "3059301306072a8648ce3d0201...",
  "k256_pubkey": "0304c6bfe0ecd9bfa8b8c3450c...",
  "attestation": "04000200810000000..."
}
```

Now signal KMS to exit onboard mode and start the main TLS service:

```bash
curl -s "http://localhost:9100/finish"
```

Wait a few seconds for KMS to transition from onboard mode to the main TLS service:

```bash
sleep 5
```

### Step 7: Verify KMS is Running

Test connectivity to the KMS RPC server (now using TLS):

```bash
curl -sk https://localhost:9100/prpc/KMS.GetMeta?json | jq .
```

**Important:** Use `https://` — KMS now serves TLS after exiting onboard mode.

Expected response:

```json
{
  "ca_cert": "-----BEGIN CERTIFICATE-----...",
  "allow_any_upgrade": false,
  "k256_pubkey": "0304c6bfe0ecd9bfa8b8c3450c8fb49f52d6234522bd4e42c0736db852da8c871e",
  "bootstrap_info": {
    "ca_pubkey": "3059301306072a8648ce3d0201...",
    "k256_pubkey": "0304c6bfe0ecd9bfa8b8c3450c...",
    "attestation": "04000200810000000..."
  },
  "is_dev": false,
  "gateway_app_id": "",
  "kms_contract_address": "0xe6c23bfE4686E28DcDA15A1996B1c0C549656E26",
  "chain_id": 11155111,
  "app_auth_implementation": "0xc308574F9A0c7d144d7AD887785D25C386D32B54"
}
```

Key fields to verify:
- `bootstrap_info`: Contains public keys and TDX attestation quote (not null)
- `bootstrap_info.attestation`: Non-empty — proves keys were generated in genuine TDX
- `ca_cert`: Root CA certificate was generated
- `k256_pubkey`: Ethereum signing key was generated
- `chain_id`: 11155111 indicates Sepolia testnet
- `kms_contract_address`: Your deployed KMS contract address

### Step 8: Test Response Time

Verify the RPC responds quickly (not hanging):

```bash
time curl -sk https://localhost:9100/prpc/KMS.GetMeta?json > /dev/null
```

Expected: Response in < 1 second. If it takes > 10 seconds or hangs, see Troubleshooting section below.

---

## Verifying TDX Attestation

With KMS running in a CVM, the TDX quote provides cryptographic proof of integrity.

### View the TDX Quote

```bash
# Extract the attestation quote from bootstrap_info
curl -sk https://localhost:9100/prpc/KMS.GetMeta?json | jq -r '.bootstrap_info.attestation'
```

This returns a hex-encoded TDX quote. A non-empty value confirms KMS generated a valid attestation during bootstrap.

### Quote Contents

The TDX quote contains:
- **MRTD** - Measurement of the TDX environment
- **RTMR** - Runtime measurements
- **Report Data** - KMS public keys bound to the quote
- **Signature** - Intel's attestation signature

### Verification Options

The TDX quote can be verified by:

1. **Intel PCCS** - Platform Configuration and Certification Service
2. **On-chain verification** - Smart contract quote validation
3. **Third-party services** - Independent attestation verification

---

## Architecture

### CVM-based KMS Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     TDX Host                            │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              dstack-vmm                          │   │
│  │                                                  │   │
│  │  ┌─────────────────────────────────────────┐   │   │
│  │  │           KMS CVM (TDX Protected)        │   │   │
│  │  │                                          │   │   │
│  │  │  ┌──────────────────────────────────┐   │   │   │
│  │  │  │     Docker Container              │   │   │   │
│  │  │  │                                   │   │   │   │
│  │  │  │  ┌─────────┐   ┌──────────────┐  │   │   │   │
│  │  │  │  │  KMS    │◄──│  auth-eth    │  │   │   │   │
│  │  │  │  └────┬────┘   └──────┬───────┘  │   │   │   │
│  │  │  │       │               │          │   │   │   │
│  │  │  │       ▼               ▼          │   │   │   │
│  │  │  │  /etc/kms/certs   Ethereum RPC   │   │   │   │
│  │  │  └──────────────────────────────────┘   │   │   │
│  │  │                                          │   │   │
│  │  │  guest-agent (/var/run/dstack.sock)     │   │   │
│  │  └─────────────────────────────────────────┘   │   │
│  │                                                  │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Port 9100 ◄─── External connections                   │
└─────────────────────────────────────────────────────────┘
```

### Key Differences from Host-based KMS

| Aspect | Host-based KMS | CVM-based KMS |
|--------|----------------|---------------|
| TDX Attestation | Not available | Full attestation with quotes |
| Memory Protection | OS-level only | TDX hardware encryption |
| Key Security | File permissions | Hardware-protected memory |
| Verification | Physical security | Cryptographic proof |
| Deployment | systemd service | VMM-managed CVM |

---

## Troubleshooting

For detailed solutions, see the [KMS Deployment Troubleshooting Guide](/tutorial/troubleshooting-kms-deployment#kms-cvm-deployment-issues):

- [CVM fails to start](/tutorial/troubleshooting-kms-deployment#cvm-fails-to-start)
- [CVM Exits Immediately or Reboots in a Loop](/tutorial/troubleshooting-kms-deployment#cvm-exits-immediately-or-reboots-in-a-loop)
- [Bootstrap hangs](/tutorial/troubleshooting-kms-deployment#bootstrap-hangs)
- [Port 9100 not accessible](/tutorial/troubleshooting-kms-deployment#port-9100-not-accessible)
- [TDX quote not generated](/tutorial/troubleshooting-kms-deployment#tdx-quote-not-generated)
- [CVM Fails with "QGS error code: 0x12001"](/tutorial/troubleshooting-kms-deployment#cvm-fails-with-qgs-error-code-0x12001)
- [GetMeta Returns "Connection refused" on Port 9200](/tutorial/troubleshooting-kms-deployment#getmeta-returns-connection-refused-on-port-9200)
- [GetMeta Returns "missing field `status`"](/tutorial/troubleshooting-kms-deployment#getmeta-returns-missing-field-status)
- [GetMeta Hangs or Times Out](/tutorial/troubleshooting-kms-deployment#getmeta-hangs-or-times-out)
- [CVM Hangs at "Waiting for time to be synchronized"](/tutorial/troubleshooting-kms-deployment#cvm-hangs-at-waiting-for-time-to-be-synchronized)

---

## Certificate Persistence

### Understanding Storage

CVM certificates are stored in a Docker named volume (`kms-certs`). This provides:

- **Container restart persistence** - Certificates survive container restarts
- **CVM restart consideration** - Depending on VMM configuration, volumes may or may not persist

### Backup Recommendations

After successful bootstrap, backup the bootstrap info:

```bash
# Save bootstrap info (contains public keys and TDX attestation quote)
curl -sk https://localhost:9100/prpc/KMS.GetMeta?json | jq '.bootstrap_info' > ~/kms-bootstrap-info-$(date +%Y%m%d).json

# The private keys remain inside the CVM for security
# For full backup, use the VMM console to export the CVM state
```

Store backup information securely offline.

---

## Next Steps

With KMS deployed as a CVM, proceed to set up the Gateway:

- [Gateway Build & Configuration](/tutorial/gateway-build-configuration) - Build and configure the dstack gateway

## Additional Resources

- [Intel TDX Attestation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [dstack GitHub Repository](https://github.com/Dstack-TEE/dstack)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
