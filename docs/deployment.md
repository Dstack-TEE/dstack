# Deploying dstack

This guide covers deploying dstack on bare metal TDX hosts.

## Overview

dstack can be deployed in two ways:

- **Dev Deployment**: All components run directly on the host. For local development and testing only - no security guarantees.
- **Production Deployment**: KMS and Gateway run as CVMs with hardware-rooted security. Uses auth server for authorization and OS image whitelisting. Required for any deployment where security matters.

## Prerequisites

**Hardware:**
- Bare metal TDX server ([setup guide](https://github.com/canonical/tdx))
- At least 16GB RAM, 100GB free disk space
- Public IPv4 address
- Optional: NVIDIA H100 or Blackwell GPU for [Confidential Computing](https://www.nvidia.com/en-us/data-center/solutions/confidential-computing/) workloads

**Network:**
- Domain with DNS access (for Gateway TLS)

> **Note:** See [Hardware Requirements](https://docs.phala.network/dstack/hardware-requirements) for server recommendations.

---

## Dev Deployment

This approach runs all components directly on the host for local development and testing.

> **Warning:** Dev deployment uses KMS in dev mode with no security guarantees. Do NOT use for production.

### Install Dependencies

```bash
# Ubuntu 24.04
sudo apt install -y build-essential chrpath diffstat lz4 wireguard-tools xorriso

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build Configuration

```bash
git clone https://github.com/Dstack-TEE/meta-dstack.git --recursive
cd meta-dstack/
mkdir build && cd build
../build.sh hostcfg
```

Edit the generated `build-config.sh` for your environment. The minimal required changes are:

| Variable | Description |
|----------|-------------|
| `KMS_DOMAIN` | DNS domain for KMS RPC (e.g., `kms.example.com`) |
| `GATEWAY_DOMAIN` | DNS domain for Gateway RPC (e.g., `gateway.example.com`) |
| `GATEWAY_PUBLIC_DOMAIN` | Public base domain for app routing (e.g., `apps.example.com`) |

**TLS Certificates:**

The Gateway requires TLS certificates. Configure Certbot with Cloudflare:

```bash
CERTBOT_ENABLED=true
CF_API_TOKEN=<your-cloudflare-token>
```

The certificates will be obtained automatically via ACME DNS-01 challenge. The KMS auto-generates its own certificates during bootstrap.

Other variables like ports and CID pool settings have sensible defaults.

```bash
vim ./build-config.sh
../build.sh hostcfg
```

### Download Guest Image

```bash
../build.sh dl 0.5.5
```

### Run Components

Start in separate terminals:

1. **KMS**: `./dstack-kms -c kms.toml`
2. **Gateway**: `sudo ./dstack-gateway -c gateway.toml`
3. **VMM**: `./dstack-vmm -c vmm.toml`

> **Note:** This deployment uses KMS in dev mode without an auth server. For production deployments with proper security, see [Production Deployment](#production-deployment) below.

---

## Production Deployment

For production, deploy KMS and Gateway as CVMs with hardware-rooted security. Production deployments require:
- KMS running in a CVM (not on the host)
- Auth server for authorization (webhook mode)

### Production Checklist

**Required:**

1. Set up TDX host with dstack-vmm
2. Deploy KMS as CVM (with auth server)
3. Deploy Gateway as CVM

**Optional Add-ons:**

4. [Zero Trust HTTPS](#4-zero-trust-https-optional)
5. [Certificate Transparency monitoring](#5-certificate-transparency-monitoring-optional)
6. [Multi-node deployment](#6-multi-node-deployment-optional)
7. [On-chain governance](./onchain-governance.md) - Smart contract-based authorization

---

### 1. Set Up TDX Host

Clone and build dstack-vmm:

```bash
git clone https://github.com/Dstack-TEE/dstack
cd dstack
cargo build --release -p dstack-vmm -p supervisor
mkdir -p vmm-data
cp target/release/dstack-vmm vmm-data/
cp target/release/supervisor vmm-data/
cd vmm-data/
```

Create `vmm.toml`:

```toml
address = "tcp:0.0.0.0:9080"
reuse = true
image_path = "./images"
run_path = "./run/vm"

[cvm]
kms_urls = []
gateway_urls = []
cid_start = 30000
cid_pool_size = 1000

[cvm.port_mapping]
enabled = true
address = "127.0.0.1"
range = [
    { protocol = "tcp", from = 1, to = 20000 },
    { protocol = "udp", from = 1, to = 20000 },
]

[host_api]
address = "vsock:2"
port = 10000
```

Download guest images from [meta-dstack releases](https://github.com/Dstack-TEE/meta-dstack/releases) and extract to `./images/`.

> For reproducible builds and verification, see [Security Guide](./security-guide/security-guide.md).

Start VMM:

```bash
./dstack-vmm -c vmm.toml
```

---

### 2. Deploy KMS as CVM

Production KMS requires:
- **KMS**: The key management service inside a CVM
- **Auth server**: Webhook server that validates boot requests and returns authorization decisions

#### Auth Server Options

| Server | Use Case | Configuration |
|--------|----------|---------------|
| [auth-simple](../kms/auth-simple/) | Config-file-based whitelisting | JSON config file |
| [auth-eth](../kms/auth-eth/) | On-chain governance via smart contracts | Ethereum RPC + contract |
| Custom | Your own authorization logic | Implement webhook interface |

All auth servers implement the same webhook interface:
- `GET /` - Health check
- `POST /bootAuth/app` - App boot authorization
- `POST /bootAuth/kms` - KMS boot authorization

#### Using auth-simple (Config-Based)

auth-simple validates boot requests against a JSON config file.

Create `auth-config.json` for initial KMS deployment:

```json
{
  "osImages": ["0x<os-image-hash>"],
  "kms": { "allowAnyDevice": true },
  "apps": {}
}
```

Run auth-simple:

```bash
cd kms/auth-simple
bun install
PORT=3001 AUTH_CONFIG_PATH=/path/to/auth-config.json bun run start
```

For adding Gateway, apps, and other config fields, see [auth-simple Operations Guide](./auth-simple-operations.md).

#### Using auth-eth (On-Chain)

For decentralized governance via smart contracts, see [On-Chain Governance](./onchain-governance.md).

#### Getting OS Image Hash

The OS image hash is in the `digest.txt` file inside the guest image tarball:

```bash
# Extract hash from release tarball
tar -xzf dstack-0.5.5.tar.gz
cat dstack-0.5.5/digest.txt
# Output: 0b327bcd642788b0517de3ff46d31ebd3847b6c64ea40bacde268bb9f1c8ec83
```

Add `0x` prefix for auth-simple config: `0x0b327bcd...`

#### Deploy KMS CVM

Choose the deployment script based on your auth server:

**For auth-simple (external webhook):**

auth-simple runs on your infrastructure, outside the CVM.

```bash
cd dstack/kms/dstack-app/
```

Edit `.env.simple`:

```bash
VMM_RPC=http://127.0.0.1:9080
AUTH_WEBHOOK_URL=http://your-auth-server:3001
KMS_RPC_ADDR=0.0.0.0:9201
GUEST_AGENT_ADDR=127.0.0.1:9205
OS_IMAGE=dstack-0.5.5
IMAGE_DOWNLOAD_URL=https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.5/dstack-0.5.5.tar.gz
```

Then run:

```bash
./deploy-simple.sh
```

**For auth-eth (on-chain governance):**

> See [On-Chain Governance Guide](./onchain-governance.md) for deploying KMS with smart contract-based authorization.

**Monitor startup:**

```bash
tail -f ../../vmm-data/run/vm/<vm-id>/serial.log
```

Wait for `[  OK  ] Finished App Compose Service.`

#### Bootstrap KMS

Open `http://127.0.0.1:9201/` in your browser.

1. Click **Bootstrap**
2. Enter the domain for your KMS (e.g., `kms.example.com`)
3. Click **Finish setup**

![KMS Bootstrap](assets/kms-bootstrap.png)

The KMS will display its public key and TDX quote:

![KMS Bootstrap Result](assets/kms-bootstrap-result.png)

---

### 3. Deploy Gateway as CVM

#### Prerequisites

Before deploying Gateway:
1. Register the Gateway app in your auth server config (add to `apps` section in `auth-config.json`)
2. Note the App ID you assign - you'll need it for the `.env` file

For on-chain governance, see [On-Chain Governance](./onchain-governance.md#register-gateway-app) for registration steps.

#### Deploy Gateway CVM

```bash
cd dstack/gateway/dstack-app/
./deploy-to-vmm.sh
```

Edit `.env` with required variables:

```bash
# VMM connection (use TCP if VMM is on same host, or remote URL)
VMM_RPC=http://127.0.0.1:9080

# Cloudflare (for DNS-01 ACME challenge)
CF_API_TOKEN=your_cloudflare_api_token

# Domain configuration
SRV_DOMAIN=example.com
PUBLIC_IP=$(curl -s ifconfig.me)

# Gateway app ID (from registration above)
GATEWAY_APP_ID=32467b43BFa67273FC7dDda0999Ee9A12F2AaA08

# Gateway URLs
MY_URL=https://gateway.example.com:9202
BOOTNODE_URL=https://gateway.example.com:9202

# WireGuard (uses same port as RPC)
WG_ADDR=0.0.0.0:9202

# Network settings
SUBNET_INDEX=0
ACME_STAGING=no  # Set to 'yes' for testing
OS_IMAGE=dstack-0.5.5
```

**Note on hex formats:**
- Gateway `.env` file: Use raw hex without `0x` prefix (e.g., `GATEWAY_APP_ID=32467b43...`)
- auth-simple config: Use `0x` prefix (e.g., `"0x32467b43..."`). The server normalizes both formats.

Run the script again:

```bash
./deploy-to-vmm.sh
```

The script will display the compose file and compose hash, then prompt for confirmation:

```
Docker compose file:
...
Compose hash: 0x700a50336df7c07c82457b116e144f526c29f6d8...
Configuration:
...
Continue? [y/N]
```

**Before pressing 'y'**, add the compose hash to your auth server whitelist:
- For auth-simple: Add to `composeHashes` array in `auth-config.json`
- For auth-eth: Use `app:add-hash` (see [On-Chain Governance](./onchain-governance.md#register-gateway-app))

Then return to the first terminal and press 'y' to deploy.

#### Update VMM Configuration

After Gateway is running, update `vmm.toml` with KMS and Gateway URLs:

```toml
[cvm]
kms_urls = ["https://kms.example.com:9201"]
gateway_urls = ["https://gateway.example.com:9202"]
```

Restart dstack-vmm to apply changes.

---

### 4. Zero Trust HTTPS (Optional)

Generate TLS certificates inside the TEE with automatic CAA record management.

Configure in `build-config.sh`:

```bash
GATEWAY_CERT=${CERTBOT_WORKDIR}/live/cert.pem
GATEWAY_KEY=${CERTBOT_WORKDIR}/live/key.pem
CF_API_TOKEN=<your-cloudflare-token>
ACME_URL=https://acme-v02.api.letsencrypt.org/directory
```

Run certbot:

```bash
RUST_LOG=info,certbot=debug ./certbot renew -c certbot.toml
```

This will:
- Create an ACME account
- Set CAA DNS records on Cloudflare
- Request and auto-renew certificates

---

### 5. Certificate Transparency Monitoring (Optional)

Monitor for unauthorized certificates issued to your domain.

```bash
cargo build --release -p ct_monitor
./target/release/ct_monitor \
  --gateway-uri https://<gateway-domain> \
  --domain <your-domain>
```

**How it works:**
1. Fetches known public keys from Gateway (`/acme-info` endpoint)
2. Queries crt.sh for certificates issued to your domain
3. Verifies each certificate's public key matches the known keys
4. Logs errors (❌) when certificates are issued to unknown public keys

The monitor runs in a loop, checking every 60 seconds. Integrate with your alerting system by monitoring stderr for error messages.

---

### 6. Multi-Node Deployment (Optional)

Scale by adding VMM nodes and KMS replicas for high availability.

#### Adding VMM Nodes

On each additional TDX host:
1. Set up dstack-vmm (see step 1)
2. Configure `vmm.toml` with existing KMS/Gateway URLs
3. Start VMM

```toml
[cvm]
kms_urls = ["https://kms.example.com:9201"]
gateway_urls = ["https://gateway.example.com:9202"]
```

#### Adding KMS Replicas (Onboarding)

Additional KMS instances can onboard from an existing KMS to share the same root keys. This enables:
- High availability (multiple KMS nodes)
- Geographic distribution
- Load balancing

**How it works:**

1. New KMS starts in onboard mode (empty `auto_bootstrap_domain`)
2. New KMS calls `GetTempCaCert` on source KMS
3. New KMS generates RA-TLS certificate with TDX quote
4. New KMS calls `GetKmsKey` with mTLS authentication
5. Source KMS verifies attestation via `bootAuth/kms` webhook
6. If approved, source KMS returns root keys
7. Both KMS instances now derive identical keys

**Configure new KMS for onboarding:**

```toml
[core.onboard]
enabled = true
auto_bootstrap_domain = ""   # Empty = onboard mode
quote_enabled = true         # Require TDX attestation
address = "0.0.0.0"
port = 9203                  # HTTP port for onboard UI
```

**Trigger onboard via API:**

```bash
curl -X POST http://<new-kms>:9203/prpc/Onboard.Onboard?json \
  -H "Content-Type: application/json" \
  -d '{"source_url": "https://<existing-kms>:9201/prpc", "domain": "kms2.example.com"}'
```

**Finish and restart:**

```bash
curl http://<new-kms>:9203/finish
# Restart KMS - it will now serve as a full KMS with shared keys
```

> **Note:** For KMS onboarding with `quote_enabled = true`, add the KMS mrAggregated hash to your auth server's `kms.mrAggregated` whitelist.

---

## Deploying Apps

After setup, deploy apps via the VMM dashboard or CLI.

### Register App

Before deploying, register your app in your auth server:
- For auth-simple: See [auth-simple Operations Guide](./auth-simple-operations.md#adding-an-app)
- For auth-eth: See [On-Chain Governance](./onchain-governance.md#register-apps-on-chain)

### Deploy via UI

Open `http://localhost:9080`:

![App Deploy](assets/app-deploy.png)

- Select the OS image
- Enter the App ID (from registration above)
- Upload your `docker-compose.yaml`

After startup, click **Dashboard** to view:

![App Board](assets/app-board.png)

---

## Troubleshooting

### Error: vhost-vsock: unable to set guest cid: Address already in use

The CID range conflicts with existing VMs.

1. Find used CIDs: `ps aux | grep 'guest-cid='`
2. Update `vmm.toml`:
   ```toml
   [cvm]
   cid_start = 33000
   cid_pool_size = 1000
   ```

### Error: Operation not permitted when building guest image

Ubuntu 23.10+ restricts unprivileged user namespaces:

```bash
sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0
```
