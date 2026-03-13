---
title: "Hello World Application"
description: "Deploy your first application to a dstack Confidential Virtual Machine"
section: "First Application"
stepNumber: 1
totalSteps: 2
lastUpdated: 2026-03-06
prerequisites:
  - gateway-service-setup
tags:
  - dstack
  - cvm
  - deployment
  - docker-compose
  - hello-world
difficulty: "intermediate"
estimatedTime: "30 minutes"
---

# Hello World Application

This tutorial guides you through deploying your first application to a dstack Confidential Virtual Machine (CVM). You'll deploy a simple nginx web server that runs inside a TDX-protected environment with full gateway integration, verifying that your entire dstack infrastructure is working correctly end-to-end.

## What You'll Deploy

| Component | Description |
|-----------|-------------|
| **nginx:alpine** | Lightweight web server running inside a CVM |
| **KMS attestation** | TDX-verified app identity via on-chain compose hash |
| **Gateway routing** | HTTPS access via WireGuard tunnel with Let's Encrypt certificate |

## How CVM Deployment Works

When you deploy an application to dstack:

1. **vmm-cli.py compose** generates an encrypted deployment manifest (`app-compose.json`)
2. **On-chain registration** whitelists the compose hash so KMS will attest the app
3. **vmm-cli.py deploy** creates a TDX-protected CVM with the manifest
4. **Guest OS** boots, Docker containers start, and the app contacts KMS for attestation
5. **Gateway registration** — with `--gateway` flag, the app CVM establishes a WireGuard tunnel to the gateway
6. **HTTPS routing** — the gateway provisions a Let's Encrypt certificate and routes traffic to the app

```
Client HTTPS Request
       │
       ▼
┌──────────────────┐
│  HAProxy (:443)  │
│  SNI routing     │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     WireGuard      ┌──────────────┐
│  Gateway CVM     │ ◄────────────────► │   App CVM    │
│  TLS termination │     tunnel         │  nginx :80   │
│  Let's Encrypt   │                    │  TDX protected│
└──────────────────┘                    └──────────────┘
```

## Prerequisites

### Server

- Completed [Gateway CVM Deployment](/tutorial/gateway-service-setup) — gateway running and admin API bootstrapped
- KMS CVM running on port 9100
- VMM running (`systemctl status dstack-vmm`)
- Python cryptography libraries for `vmm-cli.py`:
  ```bash
  pip3 install --break-system-packages cryptography eth-keys eth-utils "eth-hash[pycryptodome]"
  ```

### Local machine

- Foundry toolchain installed (`cast` command available)
- Wallet private key at `~/.dstack/secrets/sepolia-private-key`
- KMS contract address at `~/.dstack/secrets/kms-contract-address`

Verify the infrastructure is ready:

```bash
# KMS is responding
curl -sk https://localhost:9100/prpc/KMS.GetMeta | jq '{chain_id}' && echo "KMS: OK"

# Gateway admin API is responding
curl -sf http://127.0.0.1:9203/prpc/Status > /dev/null && echo "Gateway: OK"

# VMM is running
systemctl is-active dstack-vmm && echo "VMM: OK"
```

## Step 1: Create Application Directory

```bash
mkdir -p ~/hello-world-deploy
cd ~/hello-world-deploy
```

## Step 2: Create Docker Compose File

Create a minimal compose file. The app runs inside a CVM, so there is no access to the host filesystem — do not use local volume mounts.

```bash
cat > docker-compose.yaml << 'EOF'
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    restart: always
EOF
```

| Setting | Description |
|---------|-------------|
| `image: nginx:alpine` | Lightweight nginx image, pulled from Docker Hub at boot |
| `ports: "80:80"` | Expose port 80 inside the CVM |
| `restart: always` | Restart container if it crashes |

> **No local volumes:** Unlike a traditional Docker setup, CVMs don't have access to host directories. The default nginx welcome page is served automatically. To serve custom content, you would bake it into a custom Docker image.

## Step 3: Register App On-Chain

> **Run on your local machine.** This step uses `cast` (Foundry) and your wallet private key, which live on your local machine — not on the server.

The app needs an on-chain identity so KMS can attest it and the gateway can route traffic to it.

### Load wallet credentials

```bash
export PRIVATE_KEY=$(cat ~/.dstack/secrets/sepolia-private-key)
export ETH_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
export KMS_CONTRACT_ADDR=$(cat ~/.dstack/secrets/kms-contract-address)
```

### Deploy and register the app

```bash
HELLO_APP_ID=$(cast send "$KMS_CONTRACT_ADDR" \
  "deployAndRegisterApp(address,bool,bool,bytes32,bytes32)" \
  "$(cast wallet address --private-key $PRIVATE_KEY)" \
  false \
  true \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --json | jq -r '.logs[-1].topics[1]' | sed 's/0x000000000000000000000000/0x/')

echo "Hello World App ID: $HELLO_APP_ID"
```

Verify the app was created:

```bash
cast call "$HELLO_APP_ID" "owner()(address)" --rpc-url "$ETH_RPC_URL"
```

This should return your wallet address.

### Save the app ID

```bash
echo "$HELLO_APP_ID" > ~/.dstack/secrets/hello-world-app-id
```

### Copy the app ID to the server

The server needs the app ID for Step 6 (CVM deployment). Copy it over:

```bash
# Replace user@your-server with your actual server SSH target
scp ~/.dstack/secrets/hello-world-app-id user@your-server:~/.dstack/secrets/
```

SSH back into the server before continuing:

```bash
ssh user@your-server
```

## Step 4: Generate Deployment Manifest

Use `vmm-cli.py compose` to generate the encrypted deployment manifest. The `--gateway` and `--kms` flags enable gateway registration and KMS attestation.

```bash
cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)

./src/vmm-cli.py --url http://127.0.0.1:9080 compose \
  --docker-compose ~/hello-world-deploy/docker-compose.yaml \
  --name hello-world \
  --gateway \
  --kms \
  --public-logs \
  --output ~/hello-world-deploy/app-compose.json
```

**Key flags:**

| Flag | Purpose |
|------|---------|
| `--gateway` | Enable gateway integration — the CVM will register with the gateway and establish a WireGuard tunnel |
| `--kms` | Enable KMS attestation — the CVM will contact KMS for TDX verification |
| `--public-logs` | Allow log access via VMM API (useful for debugging) |

### Get the compose hash for Step 5

The compose hash is needed on your local machine for on-chain whitelisting. Display it and copy the value:

```bash
COMPOSE_HASH=$(sha256sum ~/hello-world-deploy/app-compose.json | cut -d' ' -f1)
echo "Compose hash: 0x$COMPOSE_HASH"
```

Copy the full `0x...` hash value — you'll paste it into Step 5 on your local machine.

## Step 5: Whitelist Compose Hash On-Chain

> **Run on your local machine.** This step uses `cast` and your wallet private key.

The KMS contract verifies that the exact compose configuration is authorized. Use the compose hash from Step 4 and register it on-chain.

If you're in a new shell since Step 3, re-load your wallet credentials:

```bash
export PRIVATE_KEY=$(cat ~/.dstack/secrets/sepolia-private-key)
export ETH_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
export KMS_CONTRACT_ADDR=$(cat ~/.dstack/secrets/kms-contract-address)
```

Set the compose hash (paste the value displayed in Step 4):

```bash
COMPOSE_HASH="<paste-hash-from-step-4-without-0x-prefix>"

HELLO_APP_ID=$(cat ~/.dstack/secrets/hello-world-app-id)

cast send "$HELLO_APP_ID" \
  "addComposeHash(bytes32)" \
  "0x$COMPOSE_HASH" \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$PRIVATE_KEY"
```

Verify:

```bash
cast call "$HELLO_APP_ID" \
  "allowedComposeHashes(bytes32)(bool)" \
  "0x$COMPOSE_HASH" \
  --rpc-url "$ETH_RPC_URL"
```

Expected output: `true`

> **Important:** If you modify `docker-compose.yaml` and regenerate `app-compose.json`, the hash changes. You must whitelist the new hash before deploying.

SSH back into the server before continuing:

```bash
ssh user@your-server
```

## Step 6: Deploy the CVM

```bash
cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)

SRV_DOMAIN=$(grep ^SRV_DOMAIN ~/gateway-deploy/.env | cut -d= -f2)
KMS_DOMAIN=$(grep ^KMS_DOMAIN ~/gateway-deploy/.env | cut -d= -f2)

./src/vmm-cli.py --url http://127.0.0.1:9080 deploy \
  --name hello-world \
  --app-id "$(cat ~/.dstack/secrets/hello-world-app-id)" \
  --compose ~/hello-world-deploy/app-compose.json \
  --gateway-url "https://gateway.$SRV_DOMAIN" \
  --kms-url "https://$KMS_DOMAIN:9100" \
  --image dstack-0.5.7 \
  --vcpu 2 \
  --memory 2G \
  --port tcp:0.0.0.0:9300:80
```

**Key flags:**

| Flag | Value | Purpose |
|------|-------|---------|
| `--app-id` | Hello World app ID | Links CVM to on-chain app identity |
| `--gateway-url` | `https://gateway.$SRV_DOMAIN` | Gateway RPC endpoint (uses port 443 via HAProxy passthrough) |
| `--kms-url` (1st) | `https://127.0.0.1:9100` | Host-side KMS for env encryption |
| `--kms-url` (2nd) | `https://$KMS_DOMAIN:9100` | CVM-side KMS (domain must match TLS cert) |
| `--port` | `tcp:0.0.0.0:9300:80` | Direct port mapping for testing (optional) |

> **Why two `--kms-url` values?** Same reason as the gateway — the first is for host-side encryption, the second is for CVM-side runtime access. See [Gateway CVM Deployment](/tutorial/gateway-service-setup#step-2-deploy-the-gateway-cvm) for details.

## Step 7: Monitor Boot Logs

List VMs and get the hello-world ID:

```bash
./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm
```

Follow the boot logs (replace `VM_ID` with the actual ID):

```bash
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=true&ansi=false"
```

Watch for these key log messages:

```
Docker container starting...
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
```

And if gateway integration is working:

```
Registering with gateway...
WireGuard tunnel established
```

The CVM typically boots in 1-2 minutes.

## Step 8: Verify via Gateway (HTTPS)

Once the CVM registers with the gateway, it's accessible via an HTTPS URL. The gateway automatically provisions a Let's Encrypt certificate.

Find your app's gateway URL. If you've deployed multiple times, the `hosts` array may contain stale entries from previous deployments. Use the most recent `latest_handshake` to identify the active instance:

```bash
# Get the most recently active app instance
curl -sf http://127.0.0.1:9203/prpc/Status | jq '.hosts | sort_by(.latest_handshake) | reverse | .[0]'
```

The `instance_id` and `base_domain` fields determine the app URL: `https://<instance_id>-80.gateway.<base_domain>`.

Access the app:

```bash
# Replace with your actual instance_id and base_domain from the output above
curl -s "https://<instance_id>-80.gateway.<base_domain>/"
```

You should see the default nginx welcome page HTML. The Let's Encrypt certificate is automatically provisioned, so this works without `-k`.

Verify the certificate:

```bash
echo | openssl s_client -connect <instance_id>-80.gateway.<base_domain>:443 -servername <instance_id>-80.gateway.<base_domain> 2>/dev/null | openssl x509 -noout -issuer -subject
```

The issuer should be `Let's Encrypt` (not `STAGING`).

## Step 9: Verify via Direct Port Mapping

As an alternative to gateway access, you can test directly via the mapped port:

```bash
curl -s http://YOUR_SERVER_IP:9300/
```

This bypasses the gateway and hits nginx directly. You should see the same nginx welcome page.

> **Note:** Direct port access is unencrypted HTTP. In production, use the gateway HTTPS URL.

## Managing the Application

Navigate to the VMM directory:

```bash
cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)
```

### List running VMs

```bash
./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm
```

### View logs

```bash
VM_ID=$(./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm --json | jq -r '.[] | select(.name=="hello-world") | .id')
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=$VM_ID&follow=false&ansi=false&lines=50"
```

### Stop and remove

```bash
VM_ID=$(./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm --json | jq -r '.[] | select(.name=="hello-world") | .id')
./src/vmm-cli.py --url http://127.0.0.1:9080 stop --force "$VM_ID"
./src/vmm-cli.py --url http://127.0.0.1:9080 remove "$VM_ID"
```

### Redeploy

To redeploy after changes:

1. Remove the existing CVM (see above)
2. If you changed `docker-compose.yaml`, regenerate `app-compose.json` (Step 4) and whitelist the new hash (Step 5)
3. Re-run the deploy command (Step 6)

---

## Troubleshooting

For detailed solutions, see the [First Application Troubleshooting Guide](/tutorial/troubleshooting-first-application#hello-world-app-issues):

- [CVM fails to start](/tutorial/troubleshooting-first-application#cvm-fails-to-start)
- ["OS image is not allowed"](/tutorial/troubleshooting-first-application#os-image-is-not-allowed)
- [CVM boots but no gateway registration](/tutorial/troubleshooting-first-application#cvm-boots-but-no-gateway-registration)
- [Application not accessible via gateway](/tutorial/troubleshooting-first-application#application-not-accessible-via-gateway)
- [Cannot pull Docker images](/tutorial/troubleshooting-first-application#cannot-pull-docker-images)

---

## Verification Checklist

Before proceeding, verify:

- [ ] App registered on-chain with `deployAndRegisterApp`
- [ ] Compose hash whitelisted on app contract
- [ ] CVM deployed and running (`lsvm` shows status)
- [ ] CVM registered with gateway (WireGuard tunnel established)
- [ ] Application accessible via gateway HTTPS URL (valid Let's Encrypt cert)
- [ ] Application accessible via direct port mapping (optional)

---

## What's Running Inside Your CVM

```
┌─────────────────────────────────────────────────────────────┐
│                         CVM (TDX Protected)                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                   Docker Container                     │  │
│  │  ┌─────────────┐                                      │  │
│  │  │   nginx     │                                      │  │
│  │  │   :80       │                                      │  │
│  │  └─────────────┘                                      │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    Guest Agent                         │  │
│  │  - TDX attestation via /var/run/dstack.sock           │  │
│  │  - Docker lifecycle management                        │  │
│  │  - WireGuard tunnel to gateway                        │  │
│  │  - Log forwarding to VMM                              │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                   TDX Protection                       │  │
│  │  - Encrypted memory (hardware-enforced)               │  │
│  │  - Measured boot chain (MRTD, RTMRs)                  │  │
│  │  - Isolated from host OS                              │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Next Steps

Your Hello World application is running inside a TDX-protected CVM with full gateway integration. From here you can:

- Deploy more complex applications with multiple containers
- Use the tappd socket (`/var/run/tappd.sock`) for TDX attestation from your application
- Build custom Docker images with your own application code

## Additional Resources

- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [nginx Documentation](https://nginx.org/en/docs/)
- [dstack GitHub Repository](https://github.com/Dstack-TEE/dstack)
- [dstack Examples Repository](https://github.com/Dstack-TEE/dstack-examples)
