---
title: "HAProxy Setup"
description: "Install and configure HAProxy as the unified TLS entry point for dstack services"
section: "Prerequisites"
stepNumber: 3
totalSteps: 7
lastUpdated: 2026-01-22
prerequisites:
  - ssl-certificate-setup
tags:
  - haproxy
  - tls
  - proxy
  - prerequisites
difficulty: intermediate
estimatedTime: "15 minutes"
---

# HAProxy Setup

This tutorial guides you through installing and configuring HAProxy as the unified TLS entry point for all dstack services. HAProxy provides a critical capability: mixed-mode TLS handling that can terminate TLS for some backends while passing through encrypted traffic for others.

## Why HAProxy?

| Capability | Description |
|------------|-------------|
| **SNI-based routing** | Route requests based on domain without decrypting |
| **TLS termination** | Handle HTTPS for services without native TLS |
| **TLS passthrough** | Forward encrypted traffic to services with native TLS |
| **Mixed mode** | Both modes on the same port (443) |

The dstack gateway has native TLS passthrough capability (the `*s.` subdomain pattern). HAProxy preserves this by forwarding encrypted traffic directly to the gateway, while terminating TLS for other services like the Docker registry.

## Architecture Overview

```
                           Internet
                              │
                              ▼
                    ┌─────────────────┐
                    │   HAProxy :443  │
                    │     :80         │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
   ┌────────▼───────┐ ┌──────▼──────┐ ┌──────▼──────┐
   │  TLS Terminate │ │TLS Terminate│ │TLS Passthru │
   │   registry.*   │ │  vmm.*      │ │  *.dstack.* │
   └────────┬───────┘ └──────┬──────┘ └──────┬──────┘
            │                │                │
            ▼                ▼                ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │  Registry     │ │   VMM API     │ │   Gateway     │
    │ localhost:5000│ │ localhost:9080│ │ localhost:9204│
    └───────────────┘ └───────────────┘ └───────────────┘
```

## Prerequisites

Before starting, ensure you have:

- Completed [SSL Certificate Setup](/tutorial/ssl-certificate-setup) - Certificates obtained
- SSH access to your TDX server
- Root or sudo privileges


## Manual Setup

If you prefer to configure manually, follow these steps.

### Step 1: Install HAProxy

```bash
sudo apt update
sudo apt install -y haproxy
```

Verify installation:

```bash
haproxy -v
```

### Step 2: Create Certificate Directory

HAProxy requires certificates in a combined format (cert + key in one file):

```bash
sudo mkdir -p /etc/haproxy/certs
```

### Step 3: Prepare Certificates

Combine Let's Encrypt certificates into HAProxy format:

```bash
# Registry certificate
sudo cat /etc/letsencrypt/live/registry.yourdomain.com/fullchain.pem \
         /etc/letsencrypt/live/registry.yourdomain.com/privkey.pem \
         | sudo tee /etc/haproxy/certs/registry.pem > /dev/null

# Wildcard certificate (for *.dstack.yourdomain.com)
sudo cat /etc/letsencrypt/live/dstack.yourdomain.com/fullchain.pem \
         /etc/letsencrypt/live/dstack.yourdomain.com/privkey.pem \
         | sudo tee /etc/haproxy/certs/wildcard.pem > /dev/null

# Secure the certificates
sudo chmod 600 /etc/haproxy/certs/*.pem
```

### Step 4: Create HAProxy Configuration

```bash
sudo tee /etc/haproxy/haproxy.cfg > /dev/null <<'EOF'
# HAProxy Configuration for dstack Services
# Provides SNI-based routing with mixed TLS termination/passthrough

global
    log /dev/log local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # Modern TLS settings
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

# =============================================================================
# FRONTEND: HTTP (port 80) - Redirect to HTTPS
# =============================================================================
frontend http_front
    bind *:80
    mode http
    option httplog

    # Redirect all HTTP to HTTPS
    http-request redirect scheme https code 301

# =============================================================================
# FRONTEND: HTTPS (port 443) - SNI-based routing
# =============================================================================
frontend https_front
    bind *:443
    mode tcp
    option tcplog

    # Inspect SNI for routing decisions
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }

    # TLS Termination: VMM management interface (must be before gateway rules)
    use_backend local_https_backend if { req_ssl_sni -i vmm.dstack.yourdomain.com }

    # TLS Passthrough: Gateway RPC (CVM registration uses port 443 via --gateway-url)
    use_backend gateway_rpc_passthrough if { req_ssl_sni -i gateway.dstack.yourdomain.com }

    # TLS Passthrough: Gateway proxy handles all other *.dstack.* subdomains (app traffic)
    use_backend gateway_passthrough if { req_ssl_sni -m end .dstack.yourdomain.com }

    # TLS Termination: Everything else goes to local termination frontend
    default_backend local_https_backend

# =============================================================================
# BACKEND: Gateway RPC TLS Passthrough
# When app CVMs use --gateway-url https://gateway.dstack.yourdomain.com (port 443),
# HAProxy must forward that traffic to the gateway RPC port (9202) so CVM
# registration works without requiring clients to specify port 9202 directly.
# =============================================================================
backend gateway_rpc_passthrough
    mode tcp
    option tcp-check
    server gateway-rpc 127.0.0.1:9202 check

# =============================================================================
# BACKEND: Gateway Proxy TLS Passthrough (app traffic)
# =============================================================================
backend gateway_passthrough
    mode tcp
    option tcp-check
    server gateway 127.0.0.1:9204 check

# =============================================================================
# BACKEND: Route to TLS Termination Frontend
# =============================================================================
backend local_https_backend
    mode tcp
    server loopback 127.0.0.1:8444 send-proxy

# =============================================================================
# FRONTEND: TLS Termination (internal)
# =============================================================================
frontend https_terminate
    bind 127.0.0.1:8444 ssl crt /etc/haproxy/certs/ accept-proxy
    mode http
    option httplog

    # Route based on Host header after TLS termination
    use_backend registry_backend if { hdr(host) -i registry.yourdomain.com }
    use_backend vmm_backend if { hdr(host) -m end .dstack.yourdomain.com }

    # Default backend
    default_backend vmm_backend

# =============================================================================
# HTTP BACKENDS
# =============================================================================
backend registry_backend
    mode http
    option httpchk GET /v2/
    http-check expect status 200
    http-request set-header X-Forwarded-Proto https
    server registry 127.0.0.1:5000 check

backend vmm_backend
    mode http
    option httpchk GET /
    http-request set-header X-Forwarded-Proto https
    server vmm 127.0.0.1:9080 check

# =============================================================================
# STATS (localhost only)
# =============================================================================
listen stats
    bind 127.0.0.1:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
EOF
```

**Update `yourdomain.com`** throughout the configuration to your actual domain.

### Step 5: Update Domain in Configuration

```bash
# Replace placeholder with your actual domain
sudo sed -i 's/yourdomain\.com/YOUR_ACTUAL_DOMAIN/g' /etc/haproxy/haproxy.cfg
```

### Step 6: Test Configuration

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
```

Expected output:

```
Configuration file is valid
```

### Step 7: Enable and Start HAProxy

```bash
sudo systemctl enable haproxy
sudo systemctl restart haproxy
```

### Step 8: Verify HAProxy is Running

```bash
sudo systemctl status haproxy
```

Check HAProxy is listening:

```bash
sudo ss -tlnp | grep haproxy
```

Expected output shows ports 80, 443, 8444, and 8404.

---

## Certificate Renewal Hook

When Let's Encrypt renews certificates, HAProxy needs to reload them.

### Create Renewal Hook

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-haproxy.sh > /dev/null <<'EOF'
#!/bin/bash
# Reload HAProxy certificates after Let's Encrypt renewal

# Combine certificates for HAProxy
cat /etc/letsencrypt/live/registry.yourdomain.com/fullchain.pem \
    /etc/letsencrypt/live/registry.yourdomain.com/privkey.pem \
    > /etc/haproxy/certs/registry.pem

cat /etc/letsencrypt/live/dstack.yourdomain.com/fullchain.pem \
    /etc/letsencrypt/live/dstack.yourdomain.com/privkey.pem \
    > /etc/haproxy/certs/wildcard.pem

chmod 600 /etc/haproxy/certs/*.pem

# Reload HAProxy
systemctl reload haproxy

echo "HAProxy certificates updated: $(date)"
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-haproxy.sh
```

**Update the domain names** in the script to match your certificates.

### Test Renewal Hook

```bash
sudo /etc/letsencrypt/renewal-hooks/deploy/reload-haproxy.sh
```

---

## Configuration Reference

### Directory Structure

```
/etc/haproxy/
├── haproxy.cfg           # Main configuration
├── certs/
│   ├── registry.pem      # Registry cert+key combined
│   └── wildcard.pem      # Wildcard cert+key combined
└── errors/               # Error pages
```

### Service Commands

| Command | Description |
|---------|-------------|
| `sudo systemctl start haproxy` | Start HAProxy |
| `sudo systemctl stop haproxy` | Stop HAProxy |
| `sudo systemctl restart haproxy` | Restart HAProxy |
| `sudo systemctl reload haproxy` | Reload config without dropping connections |
| `sudo haproxy -c -f /etc/haproxy/haproxy.cfg` | Test configuration syntax |

### View Logs

```bash
# Follow HAProxy logs
sudo journalctl -u haproxy -f

# Check syslog for HAProxy entries
sudo tail -f /var/log/syslog | grep haproxy
```

### Stats Page

HAProxy provides a stats page on `127.0.0.1:8404`:

```bash
curl http://127.0.0.1:8404/stats
```

Or open in browser via SSH tunnel:

```bash
ssh -L 8404:127.0.0.1:8404 user@your-server
# Then open http://localhost:8404/stats in browser
```

---

## How SNI Routing Works

HAProxy inspects the TLS ClientHello message to read the SNI (Server Name Indication) field without decrypting the traffic:

```
Client Request: https://app123s.dstack.example.com
    │
    ▼
HAProxy sees SNI = "app123s.dstack.example.com"
    │
    ▼ (matches .dstack.example.com pattern)
    │
TCP Passthrough to gateway:9204
    │
    ▼
Gateway receives original TLS handshake
    │
    ▼ (gateway sees "s" suffix = passthrough mode)
    │
Gateway passes encrypted stream to CVM:443
```

For TLS-terminated services:

```
Client Request: https://registry.example.com
    │
    ▼
HAProxy sees SNI = "registry.example.com"
    │
    ▼ (no .dstack. pattern match, goes to default)
    │
Routes to internal TLS termination frontend
    │
    ▼
HAProxy terminates TLS using registry.pem
    │
    ▼
HTTP proxy to localhost:5000
```

---

## Troubleshooting

For detailed solutions, see the [Prerequisites Troubleshooting Guide](/tutorial/troubleshooting-prerequisites#haproxy-setup-issues):

- [Port 443 Already in Use](/tutorial/troubleshooting-prerequisites#port-443-already-in-use)
- [Configuration Test Fails](/tutorial/troubleshooting-prerequisites#configuration-test-fails)
- [Certificate Errors](/tutorial/troubleshooting-prerequisites#certificate-errors)
- [Backend Health Check Failing](/tutorial/troubleshooting-prerequisites#backend-health-check-failing)
- [Gateway Not Receiving Traffic](/tutorial/troubleshooting-prerequisites#gateway-not-receiving-traffic)

---

## Next Steps

With HAProxy installed, proceed to configure services that use it:

- [Local Docker Registry](/tutorial/local-docker-registry) - Registry behind HAProxy
- [Management Interface Setup](/tutorial/management-interface-setup) - VMM management via HAProxy
- [Gateway Service Setup](/tutorial/gateway-service-setup) - Gateway with HAProxy passthrough

## Additional Resources

- [HAProxy Documentation](https://www.haproxy.org/documentation/)
- [HAProxy Configuration Manual](https://cbonte.github.io/haproxy-dconv/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
