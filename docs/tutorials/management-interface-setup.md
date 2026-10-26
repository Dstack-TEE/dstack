---
title: "Management Interface Setup"
description: "Configure secure remote access to dstack VMM management interface via HAProxy"
section: "dstack Installation"
stepNumber: 6
totalSteps: 8
lastUpdated: 2026-01-22
prerequisites:
  - vmm-service-setup
  - haproxy-setup
  - ssl-certificate-setup
tags:
  - haproxy
  - reverse-proxy
  - tls
  - management
  - security
difficulty: intermediate
estimatedTime: "10 minutes"
---

# Management Interface Setup

This tutorial guides you through verifying secure remote access to the dstack VMM management interface. By default, the VMM API listens on `127.0.0.1:9080`, which is only accessible from the server itself. HAProxy (configured in [HAProxy Setup](/tutorial/haproxy-setup)) proxies requests from `vmm.dstack.yourdomain.com` to the VMM API.

## Architecture Overview

```
External Request                 Internal
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  vmm.dstack.yourdomain.com:443  →  HAProxy  →  localhost:9080   │
│                   (TLS)            (proxy)      (VMM API)       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

The VMM API requires authentication tokens, providing an additional layer of security beyond TLS.

## Prerequisites

Before starting, ensure you have:

- Completed [VMM Service Setup](/tutorial/vmm-service-setup) - VMM running on localhost:9080
- Completed [HAProxy Setup](/tutorial/haproxy-setup) - HAProxy installed and configured
- Completed [SSL Certificate Setup](/tutorial/ssl-certificate-setup) - Wildcard certificate for `*.dstack.yourdomain.com`
- VMM authentication token (generated during VMM configuration)

## Security Considerations

### Authentication

The VMM API requires an authentication token for all requests. This token was generated during [VMM Configuration](/tutorial/vmm-configuration) and saved to `~/.dstack/secrets/vmm-auth-token`. API requests include it via:

```bash
curl -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" ...
```

### Firewall

Ensure your firewall allows HTTPS traffic:

```bash
# Check current rules
sudo ufw status

# Allow HTTPS if needed
sudo ufw allow 443/tcp
```

---

## Verify HAProxy Configuration

HAProxy is already configured to proxy VMM requests. Verify the configuration includes the VMM backend:

```bash
grep -A5 "vmm_backend" /etc/haproxy/haproxy.cfg
```

Expected output shows the VMM backend configuration:

```
backend vmm_backend
    mode http
    option httpchk GET /
    http-request set-header X-Forwarded-Proto https
    server vmm 127.0.0.1:9080 check
```

## Verify Remote Access

### Step 1: Test VMM is Running Locally

```bash
curl -s http://127.0.0.1:9080/ | head -5
```

Should return the VMM web interface HTML.

### Step 2: Test External Access

Test the management interface through HAProxy:

```bash
# Replace with your domain
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "https://vmm.dstack.yourdomain.com/prpc/Status?json" | jq .
```

Expected response:

```json
{
  "vms": [],
  "port_mapping_enabled": true,
  "total": 0
}
```

> **Note:** The `vms` list will be empty until you deploy CVMs in later tutorials. The key point is that you get a valid JSON response through HAProxy, confirming TLS termination, routing, and VMM authentication are all working.

### Step 3: Access Web Interface

Open in your browser:

```
https://vmm.dstack.yourdomain.com
```

You should see the VMM Management Console. API requests require the auth token in the `Authorization` header.

---

## Troubleshooting

For detailed solutions, see the [dstack Installation Troubleshooting Guide](/tutorial/troubleshooting-dstack-installation#management-interface-setup-issues):

- [502 Bad Gateway](/tutorial/troubleshooting-dstack-installation#502-bad-gateway)
- [Connection Refused](/tutorial/troubleshooting-dstack-installation#connection-refused)
- [DNS Not Resolving](/tutorial/troubleshooting-dstack-installation#dns-not-resolving)
- [Authentication Failed](/tutorial/troubleshooting-dstack-installation#authentication-failed)
- [Backend Marked as DOWN](/tutorial/troubleshooting-dstack-installation#backend-marked-as-down)

---

## Next Steps

With secure remote access configured, proceed to:

- [Guest OS Image Setup](/tutorial/guest-image-setup) - Download and configure guest images

## Additional Resources

- [HAProxy Documentation](https://www.haproxy.org/documentation/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
