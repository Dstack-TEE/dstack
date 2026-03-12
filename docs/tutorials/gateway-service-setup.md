---
title: "Gateway CVM Deployment"
description: "Deploy the dstack gateway as a CVM, bootstrap the admin API, and verify operation"
section: "Gateway Deployment"
stepNumber: 2
totalSteps: 2
lastUpdated: 2026-02-21
prerequisites:
  - gateway-build-configuration
tags:
  - dstack
  - gateway
  - cvm
  - deployment
  - admin-api
  - wireguard
difficulty: "advanced"
estimatedTime: "25 minutes"
---

# Gateway CVM Deployment

This tutorial deploys the dstack gateway as a Confidential Virtual Machine and bootstraps its admin API. After deployment, the gateway will handle TLS termination, WireGuard tunnels to application CVMs, and automatic certificate provisioning via Let's Encrypt.

## Prerequisites

Before starting, ensure you have:

- Completed [Gateway CVM Preparation](/tutorial/gateway-build-configuration)
- All deployment artifacts in `~/gateway-deploy/`:
  - `docker-compose.yaml`
  - `.env`
  - `.app_env`
  - `app-compose.json`
- Compose hash whitelisted on-chain
- KMS CVM running on port 9100
- Python cryptography libraries installed (`sudo apt install -y python3-pip && pip3 install --break-system-packages cryptography eth-keys eth-utils "eth-hash[pycryptodome]"`)


## What Gets Deployed

When you deploy the gateway CVM, the following happens:

1. **CVM Creation** — VMM creates a TDX-protected virtual machine with user-mode networking
2. **Container Start** — Docker container runs inside the CVM in privileged mode
3. **Config Generation** — Entrypoint script generates `gateway.toml` and WireGuard keys
4. **WireGuard Setup** — WireGuard interface created inside the CVM
5. **TLS Bootstrap** — Gateway contacts KMS for TDX-attested TLS certificates
6. **Service Ready** — RPC server (port 8000) and admin API (port 8001) start accepting connections

### Port Mappings

The CVM uses user-mode networking with explicit port forwarding from host to container:

| Host Port | Container Port | Protocol | Purpose |
|-----------|---------------|----------|---------|
| 0.0.0.0:9202 | 8000 | TCP | Gateway RPC (public) |
| 127.0.0.1:9203 | 8001 | TCP | Admin API (localhost only) |
| 127.0.0.1:9206 | 8090 | TCP | Guest agent |
| 0.0.0.0:9202 | 51820 | UDP | WireGuard tunnel |
| 0.0.0.0:9204 | 443 | TCP | HTTPS proxy (app traffic) |

> **Security note:** The admin API (port 9203) is bound to localhost only. It is not accessible from the internet.

---

## Manual Deployment

### Step 1: Verify Prerequisites

```bash
# Check KMS is reachable
curl -sk https://localhost:9100/prpc/KMS.GetMeta | jq '{chain_id}' && echo "KMS: OK"

# Check deployment artifacts exist
ls ~/gateway-deploy/app-compose.json && echo "Compose: OK"
```

### Step 2: Deploy the Gateway CVM

Load environment variables and deploy:

```bash
cd ~/gateway-deploy
set -a; source .env; set +a

cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)

./src/vmm-cli.py --url http://127.0.0.1:9080 deploy \
  --name dstack-gateway \
  --app-id "$(cat ~/.dstack/secrets/gateway-app-id)" \
  --compose ~/gateway-deploy/app-compose.json \
  --env-file ~/gateway-deploy/.app_env \
  --kms-url "https://127.0.0.1:9100" \
  --kms-url "https://kms.dstack.yourdomain.com:9100" \
  --image dstack-0.5.7 \
  --vcpu 32 \
  --memory 32G \
  --port tcp:0.0.0.0:9202:8000 \
  --port tcp:127.0.0.1:9203:8001 \
  --port tcp:127.0.0.1:9206:8090 \
  --port udp:0.0.0.0:9202:51820 \
  --port tcp:0.0.0.0:9204:443
```

**Key flags explained:**

| Flag | Value | Purpose |
|------|-------|---------|
| `--app-id` | Gateway app ID | Links CVM to on-chain app identity |
| `--kms-url` (1st) | https://127.0.0.1:9100 | KMS endpoint for host-side env encryption |
| `--kms-url` (2nd) | https://kms.dstack.yourdomain.com:9100 | KMS endpoint accessible from inside the CVM (must match KMS TLS cert domain) |
| `--vcpu 32` | 32 vCPUs | Gateway needs resources for TLS + proxy workload |
| `--memory 32G` | 32 GB RAM | Memory for connection handling and WireGuard |
| `--port` | Various | User-mode networking port mappings (see table above) |

> **Why two `--kms-url` values?** The first URL (`127.0.0.1:9100`) is used by `vmm-cli.py` on the host to encrypt environment variables before passing them to the CVM. The second URL uses the KMS domain name and is passed into the CVM so the gateway can reach KMS at runtime. The domain must match the KMS TLS certificate (set by `KMS_DOMAIN` in the KMS docker-compose). Inside a CVM with user-mode networking, `127.0.0.1` refers to the CVM itself, not the host — so the CVM resolves the KMS domain via DNS to reach the host's public IP.

### Step 3: Monitor Deployment

List VMs to get the gateway's ID:

```bash
./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm
```

View boot logs (replace `VM_ID` with the actual ID from `lsvm`):

```bash
# View recent logs
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=false&ansi=false&lines=100"

# Follow logs in real-time
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=true&ansi=false"
```

Look for these log messages indicating successful startup:

```
Configuration file generated: /data/gateway/gateway.toml
WG_IP: 10.240.0.1/12
Gateway starting...
RPC server listening on 0.0.0.0:8000
Admin API listening on 0.0.0.0:8001
```

Wait for the admin API to become reachable (may take 1-2 minutes):

```bash
until curl -sf http://127.0.0.1:9203/prpc/Status > /dev/null 2>&1; do
  echo "Waiting for admin API..."
  sleep 5
done
echo "Admin API is ready"
```

### Step 4: Bootstrap Admin API

The admin API must be configured with certbot settings, DNS credentials, and the service domain before the gateway can issue TLS certificates for applications.

```bash
ADMIN_ADDR="127.0.0.1:9203"
```

#### 4a. Set certbot configuration

> **Why does the gateway need its own certificates?** The host machine may already have a wildcard cert for `*.yourdomain.com`, but the gateway runs inside a CVM with user-mode networking — it has no access to the host filesystem. The gateway requests its own Let's Encrypt wildcard certificate from inside the CVM, and this cert is stored in the CVM's WaveKV persistent store (not on the host). This is by design: certificates generated inside the CVM are tied to the TDX attestation chain, providing zero-trust HTTPS. Container restarts within a running CVM preserve the cert data (Docker named volumes survive restarts), but destroying and recreating the CVM wipes the WaveKV store and triggers a fresh certificate request.

Configure Let's Encrypt ACME settings. We start with the **staging** environment to avoid hitting production rate limits during initial setup and testing:

```bash
curl -sf -X POST "http://$ADMIN_ADDR/prpc/SetCertbotConfig" \
  -H "Content-Type: application/json" \
  -d '{
    "acme_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "renew_interval_secs": 3600,
    "renew_before_expiration_secs": 864000,
    "renew_timeout_secs": 300
  }' && echo "Certbot config set (STAGING)"
```

| Setting | Value | Description |
|---------|-------|-------------|
| `acme_url` | Let's Encrypt **staging** | ACME directory URL (staging has 30,000 cert limit vs production's 10 per 3 hours) |
| `renew_interval_secs` | 3600 (1 hour) | How often to check for renewal |
| `renew_before_expiration_secs` | 864000 (10 days) | Renew this far before expiry |
| `renew_timeout_secs` | 300 (5 min) | Timeout for renewal attempts |

> **Staging vs production:** Staging certificates are signed by a fake CA and will show browser warnings — this is expected. The staging environment exists specifically for testing and has much higher rate limits. After verifying the gateway works correctly in [Step 6](#step-6-switch-to-production-certificates), you'll switch to the production ACME URL to get browser-trusted certificates.

#### 4b. Create DNS credential

Add your Cloudflare API token for DNS-01 challenges:

```bash
CF_API_TOKEN=$(grep CF_API_TOKEN ~/gateway-deploy/.env | cut -d= -f2)

curl -sf -X POST "http://$ADMIN_ADDR/prpc/CreateDnsCredential" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "cloudflare",
    "provider_type": "cloudflare",
    "cf_api_token": "'"$CF_API_TOKEN"'",
    "set_as_default": true
  }' && echo "DNS credential created"
```

Verify the credential was stored:

```bash
curl -sf "http://$ADMIN_ADDR/prpc/ListDnsCredentials" | jq '.credentials'
```

#### 4c. Add ZT-Domains

Register the service domains for zero-trust application routing. You need **two** domains:

1. `$SRV_DOMAIN` — covers `*.$SRV_DOMAIN` (e.g., `vmm.dstack.yourdomain.com`)
2. `gateway.$SRV_DOMAIN` — covers `*.gateway.$SRV_DOMAIN` (e.g., `<id>-<port>.gateway.dstack.yourdomain.com`)

The second domain is required because app URLs are two levels deep (`<id>-<port>.gateway.$SRV_DOMAIN`), and a wildcard cert for `*.$SRV_DOMAIN` does not cover subdomains of subdomains.

> **Important:** ZT domains must be added **after** the DNS credential is set as default (Step 4b). The gateway uses the default credential for DNS-01 challenges when requesting certificates for these domains.

```bash
SRV_DOMAIN=$(grep SRV_DOMAIN ~/gateway-deploy/.env | cut -d= -f2)

# Add the base service domain
curl -sf -X POST "http://$ADMIN_ADDR/prpc/AddZtDomain" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "'"$SRV_DOMAIN"'",
    "port": 443,
    "priority": 100
  }' && echo "ZT-Domain added: $SRV_DOMAIN"

# Add the gateway subdomain (for app URLs like <id>-<port>.gateway.$SRV_DOMAIN)
curl -sf -X POST "http://$ADMIN_ADDR/prpc/AddZtDomain" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "gateway.'"$SRV_DOMAIN"'",
    "port": 443,
    "priority": 100
  }' && echo "ZT-Domain added: gateway.$SRV_DOMAIN"
```

Verify both domains were registered:

```bash
curl -sf "http://$ADMIN_ADDR/prpc/ListZtDomains" | jq '.domains'
```

You should see both domains listed.

### Step 5: Verify Gateway Operation

#### Check admin API status

```bash
curl -sf http://127.0.0.1:9203/prpc/Status | jq .
```

Expected output shows gateway status with node information (node ID, WireGuard key, connections).

#### Check public RPC port

Verify TLS is working on the public endpoint:

```bash
curl -sk https://localhost:9202/ -o /dev/null -w '%{http_code}\n'
```

A `404` response confirms the HTTPS listener is active. This port uses a TDX-attested `Dstack App CA` certificate for internal CVM communication — this is correct and expected.

#### Verify WireGuard is running inside the CVM

The WireGuard interface runs inside the CVM, not on the host. You can verify it's listening by checking the UDP port:

```bash
sudo ss -ulnp | grep 9202
```

Expected output shows the UDP port mapped to the CVM:

```
UNCONN 0      0         0.0.0.0:9202      0.0.0.0:*
```

#### Test external RPC access

From another machine (or using your domain), verify the public endpoint is reachable:

```bash
curl -sk https://gateway.dstack.yourdomain.com:9202/ -o /dev/null -w '%{http_code}\n'
```

A `404` response confirms the gateway is accepting HTTPS connections from external clients.

### Step 6: Switch to Production Certificates

Now that the gateway is verified and working with staging certificates, switch to Let's Encrypt production to get browser-trusted certificates. This only needs to happen once per stable deployment.

Update the ACME URL to production:

```bash
ADMIN_ADDR="127.0.0.1:9203"

curl -sf -X POST "http://$ADMIN_ADDR/prpc/SetCertbotConfig" \
  -H "Content-Type: application/json" \
  -d '{
    "acme_url": "https://acme-v02.api.letsencrypt.org/directory",
    "renew_interval_secs": 3600,
    "renew_before_expiration_secs": 864000,
    "renew_timeout_secs": 300
  }' && echo "Certbot config set (PRODUCTION)"
```

After switching the ACME URL, the renewal loop may report "does not need renewal" because the staging cert is still valid. Force a renewal for each ZT domain to get production certificates immediately:

```bash
SRV_DOMAIN=$(grep SRV_DOMAIN ~/gateway-deploy/.env | cut -d= -f2)

# Force renewal for the base service domain
curl -sf -X POST "http://$ADMIN_ADDR/prpc/Admin.RenewZtDomainCert" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "'"$SRV_DOMAIN"'",
    "force": true
  }' && echo "Forced renewal: $SRV_DOMAIN"

# Force renewal for the gateway subdomain
curl -sf -X POST "http://$ADMIN_ADDR/prpc/Admin.RenewZtDomainCert" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "gateway.'"$SRV_DOMAIN"'",
    "force": true
  }' && echo "Forced renewal: gateway.$SRV_DOMAIN"
```

Verify the certificates were issued by checking the admin API:

```bash
curl -sf http://127.0.0.1:9203/prpc/ListZtDomains | jq '.domains[] | {
  domain: .config.domain,
  has_cert: .cert_status.has_cert,
  loaded: .cert_status.loaded_in_memory,
  issued: (.cert_status.issued_at | todate),
  expires: (.cert_status.not_after | todate)
}'
```

Expected output shows both domains with `has_cert: true` and expiry dates ~90 days from issuance (Let's Encrypt's standard validity period):

```json
{
  "domain": "dstack.yourdomain.com",
  "has_cert": true,
  "loaded": true,
  "issued": "2026-03-08T22:44:09Z",
  "expires": "2026-06-06T21:45:37Z"
}
```

> **Why not verify with `openssl s_client`?** The gateway has two TLS endpoints with different certificates. Port 9202 (RPC) always serves a TDX-attested `Dstack App CA` certificate for internal CVM-to-CVM communication. Port 9204 (HTTPS proxy) serves the Let's Encrypt certificates, but only when application traffic arrives for a registered app. With no apps deployed yet, the proxy port accepts TCP connections but doesn't present a certificate. Full TLS verification happens automatically when you deploy your [first application](/tutorial/hello-world-app).

If the cert status shows `has_cert: false`, check the gateway logs for ACME errors:

```bash
VM_ID=$(cd ~/dstack/vmm && ./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm --json | jq -r '.[] | select(.name=="dstack-gateway") | .id')
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=$VM_ID&follow=false&ansi=false&lines=50" | grep -i "cert\|renew\|acme"
```

> **In production deployments**, you deploy the gateway once and it requests a single production cert. Redeployments are rare and each only burns one rate-limited request — well within limits. The staging-first workflow is specifically for the initial setup phase where iterative testing is expected.

### Step 7: Verify HAProxy Configuration

If you followed the [HAProxy Setup](/tutorial/haproxy-setup) tutorial, your HAProxy configuration already includes the SNI routing rules needed for the gateway. Verify the configuration has the correct 3-rule SNI routing:

```bash
grep -A2 "use_backend\|gateway" /etc/haproxy/haproxy.cfg
```

Your `https_front` frontend should have these three rules in order:

1. **`vmm.dstack.yourdomain.com`** → `local_https_backend` (TLS termination → VMM on port 9080)
2. **`gateway.dstack.yourdomain.com`** → `gateway_rpc_passthrough` (TLS passthrough → port 9202, gateway RPC)
3. **`*.dstack.yourdomain.com`** → `gateway_passthrough` (TLS passthrough → port 9204, gateway HTTPS proxy)

The `gateway_rpc_passthrough` rule is critical: when app CVMs use `--gateway-url https://gateway.dstack.yourdomain.com` (port 443), HAProxy forwards that traffic to the gateway RPC on port 9202. Without this rule, CVM registration fails because the traffic would hit the gateway proxy (port 9204) instead.

If any rules are missing, update your HAProxy config per the [HAProxy Setup tutorial](/tutorial/haproxy-setup#step-4-create-haproxy-configuration), then reload:

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
```

---

## CVM Management

### Common VMM Commands

Navigate to the VMM directory first:

```bash
cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)
```

| Action | Command |
|--------|---------|
| List VMs | `./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm` |
| View logs | `curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" "http://127.0.0.1:9080/logs?id=VM_ID&follow=false&ansi=false&lines=100"` |
| Follow logs | `curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" "http://127.0.0.1:9080/logs?id=VM_ID&follow=true&ansi=false"` |
| Remove VM | `./src/vmm-cli.py --url http://127.0.0.1:9080 remove VM_ID` |

> **Note:** Replace `VM_ID` with the actual VM ID from `lsvm`.

### Redeploying

> **Certificate impact:** Destroying a CVM wipes its WaveKV store, which contains cached Let's Encrypt certificates. The next deployment will trigger a fresh ACME certificate request. If you're doing iterative redeployments during testing, use the staging ACME URL in [Step 4a](#4a-set-certbot-configuration) to avoid hitting production rate limits (10 certs / 3 hours / IP). See [Troubleshooting: Let's Encrypt rate limits](/tutorial/troubleshooting-gateway-deployment#lets-encrypt-rate-limits) for details.

To redeploy the gateway (e.g., after configuration changes):

1. Remove the existing CVM:
   ```bash
   VM_ID=$(./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm --json | jq -r '.[] | select(.name=="dstack-gateway") | .id')
   ./src/vmm-cli.py --url http://127.0.0.1:9080 remove "$VM_ID"
   ```
2. If you changed docker-compose.yaml or .app_env, regenerate app-compose.json and whitelist the new hash (see Preparation tutorial Steps 7-8)
3. Re-run the deploy command (Step 2 above)
4. Re-run the admin API bootstrap (Step 4 above) — use staging ACME if still iterating, or production if this is a final deployment

---

## Architecture

### Request Flow

```
Client HTTPS Request (*.dstack.yourdomain.com)
       │
       ▼
┌──────────────────────────────────────────────────┐
│  HAProxy (:443)                                  │
│  SNI: *.dstack.yourdomain.com                    │
│  TCP passthrough → 127.0.0.1:9204                │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│  Gateway CVM                                     │
│  ┌────────────────────────────────────────────┐  │
│  │  HTTPS Proxy (:443 inside CVM)             │  │
│  │  1. TLS Termination (Let's Encrypt cert)   │  │
│  │  2. Domain Parsing (app-id.domain.com)     │  │
│  │  3. CVM Lookup                             │  │
│  │  4. Forward via WireGuard                  │  │
│  └────────────────────┬───────────────────────┘  │
│                       │                          │
│  ┌────────────────────▼───────────────────────┐  │
│  │  WireGuard (wg-ds-gw :51820)              │  │
│  │  10.240.0.0/16 subnet                     │  │
│  └────────────────────┬───────────────────────┘  │
└───────────────────────┼──────────────────────────┘
                        │
            ┌───────────┼───────────┐
            ▼           ▼           ▼
      ┌──────────┐ ┌──────────┐ ┌──────────┐
      │ App CVM  │ │ App CVM  │ │ App CVM  │
      │10.240.0.2│ │10.240.0.3│ │10.240.0.4│
      └──────────┘ └──────────┘ └──────────┘
```

---

## Troubleshooting

For detailed solutions, see the [Gateway Deployment Troubleshooting Guide](/tutorial/troubleshooting-gateway-deployment#gateway-cvm-deployment-issues):

- ["Port mapping is not allowed for udp:9202"](/tutorial/troubleshooting-gateway-deployment#port-mapping-is-not-allowed-for-udp9202)
- ["OS image is not allowed"](/tutorial/troubleshooting-gateway-deployment#os-image-is-not-allowed)
- [CVM fails to start](/tutorial/troubleshooting-gateway-deployment#cvm-fails-to-start)
- [CVM exits immediately or reboots in a loop](/tutorial/troubleshooting-gateway-deployment#cvm-exits-immediately-or-reboots-in-a-loop)
- [Compose hash not allowed](/tutorial/troubleshooting-gateway-deployment#compose-hash-not-allowed)
- [Admin API unreachable](/tutorial/troubleshooting-gateway-deployment#admin-api-unreachable)
- [Let's Encrypt rate limits](/tutorial/troubleshooting-gateway-deployment#lets-encrypt-rate-limits)
- [Certbot fails to issue certificates](/tutorial/troubleshooting-gateway-deployment#certbot-fails-to-issue-certificates)
- [KMS connectivity issues](/tutorial/troubleshooting-gateway-deployment#kms-connectivity-issues)
- [WireGuard endpoint unreachable from app CVMs](/tutorial/troubleshooting-gateway-deployment#wireguard-endpoint-unreachable-from-app-cvms)

---

## Phase Complete

Congratulations! You have completed Gateway Deployment:

1. **Gateway CVM Preparation** — Docker compose, environment configuration, on-chain registration
2. **Gateway CVM Deployment** — CVM deployment, admin API bootstrap, verification

Your dstack infrastructure now has:
- **KMS CVM** — Key management with TDX attestation (port 9100)
- **Gateway CVM** — Reverse proxy with WireGuard tunnels and auto-TLS (RPC: 9202, HTTPS: 9204)
- **VMM** — Virtual machine manager (port 9080)
- **HAProxy** — External traffic routing (ports 80, 443)

## Next Steps

With the gateway running, you're ready to deploy your first application to a CVM:

- Deploy a Hello World application through the gateway
- Verify end-to-end TLS with automatic certificate provisioning
- Test WireGuard tunnel connectivity from an app CVM to the gateway
