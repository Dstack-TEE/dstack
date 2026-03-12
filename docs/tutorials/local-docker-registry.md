---
title: "Local Docker Registry"
description: "Deploy a local Docker registry behind HAProxy for reliable CVM image pulls"
section: "Prerequisites"
stepNumber: 4
totalSteps: 7
lastUpdated: 2026-01-22
prerequisites:
  - haproxy-setup
  - ssl-certificate-setup
tags:
  - docker
  - registry
  - haproxy
  - prerequisites
difficulty: intermediate
estimatedTime: "20 minutes"
---

# Local Docker Registry

This tutorial guides you through deploying a local Docker registry behind HAProxy. The registry runs on localhost:5000 and HAProxy handles TLS termination, providing secure external access via `registry.yourdomain.com`.

## Why Local Registry?

| Challenge | Solution |
|-----------|----------|
| Docker Hub rate limits | Local registry has no pull limits |
| Network reliability | Local pulls are fast and consistent |
| CVM boot timing | Registry must respond quickly during boot |
| Image availability | Cached images always available |

When a CVM boots, it pulls Docker images. If this fails, the CVM fails to start. A local registry with proper SSL ensures reliable deployments.

## Architecture Overview

```
External Request                 Internal
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  registry.yourdomain.com:443  →  HAProxy  →  localhost:5000  │
│                   (TLS)          (proxy)     (registry)      │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

HAProxy handles:
- TLS termination using Let's Encrypt certificates
- SNI-based routing to the registry on localhost:5000
- Unified configuration with other services (VMM management, gateway, etc.)

## Prerequisites

Before starting, ensure you have:

- Completed [HAProxy Setup](/tutorial/haproxy-setup) - HAProxy installed and configured
- Completed [SSL Certificate Setup](/tutorial/ssl-certificate-setup) - Registry certificate obtained
- Docker installed and running

Verify the DNS record:

```bash
dig +short registry.yourdomain.com
```

Should return your server's IP address.

---


## Manual Deployment

If you prefer to deploy manually, follow these steps.

> **Note:** HAProxy and SSL certificates must already be set up. If you haven't completed [HAProxy Setup](/tutorial/haproxy-setup) and [SSL Certificate Setup](/tutorial/ssl-certificate-setup), do those first. HAProxy is already configured to proxy `registry.yourdomain.com` to `localhost:5000`.

### Step 1: Create Registry Storage Directory

```bash
sudo mkdir -p /var/lib/registry
```

### Step 2: Deploy Registry Container

The registry runs on localhost:5000 (not exposed externally). HAProxy handles external TLS connections.

```bash
docker run -d \
  --name registry \
  --restart always \
  -p 127.0.0.1:5000:5000 \
  -v /var/lib/registry:/var/lib/registry \
  registry:2
```

### Step 3: Verify Registry is Running Locally

```bash
docker ps | grep registry
```

Expected output shows container running:
```
abc123   registry:2   ...   Up 2 minutes   127.0.0.1:5000->5000/tcp   registry
```

Test the registry API locally (without TLS):

```bash
curl -s http://127.0.0.1:5000/v2/
```

An empty response or `{}` indicates success - the registry is running.

### Step 4: Verify External Access

Test the registry through HAProxy:

```bash
curl -s https://registry.yourdomain.com/v2/
```

An empty response or `{}` indicates success.

Check the catalog (empty initially):

```bash
curl -s https://registry.yourdomain.com/v2/_catalog
```

Expected response: `{"repositories":[]}` (no images pushed yet)

---

## About KMS Images

The KMS Docker image is **built from source** and pushed to your local registry during Phase 4 (KMS Build & Configuration). This is handled by:

- Follow the [KMS Build & Configuration](/tutorial/kms-build-configuration) tutorial.

**Do not attempt to pull KMS images from Docker Hub.** The tutorial workflow builds everything from source to ensure you have a verifiable, reproducible deployment.

### Verify Registry is Ready

At this point, your registry should be running but empty:

```bash
curl -sk https://registry.yourdomain.com/v2/_catalog
```

Expected response:
```json
{"repositories":[]}
```

Images will appear here after completing the KMS build phase.

---

## Verification Summary

Run this verification script:

```bash
# Replace with your registry domain
DOMAIN="registry.yourdomain.com"

echo "Registry Container: $(docker ps --format '{{.Names}}' | grep -q registry && echo 'running' || echo 'not running')"
echo "Local Port 5000: $(ss -tln | grep -q 127.0.0.1:5000 && echo 'listening' || echo 'not listening')"
echo "HAProxy Port 443: $(ss -tln | grep -q :443 && echo 'listening' || echo 'not listening')"
echo "SSL Certificate: $(openssl s_client -connect $DOMAIN:443 -servername $DOMAIN </dev/null 2>/dev/null | grep -q 'Verify return code: 0' && echo 'valid' || echo 'invalid or expired')"
echo "Local Registry: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/v2/ | grep -q '200' && echo 'responding' || echo 'not responding')"
echo "External via HAProxy: $(curl -s -o /dev/null -w '%{http_code}' https://$DOMAIN/v2/ | grep -q '200' && echo 'responding' || echo 'not responding')"
echo "Repositories: $(curl -s https://$DOMAIN/v2/_catalog)"
```

All checks should show positive status. The repositories list will be empty until you complete the KMS build phase.

---

## Troubleshooting

For detailed solutions, see the [Prerequisites Troubleshooting Guide](/tutorial/troubleshooting-prerequisites#local-docker-registry-issues):

- [Certificate Verification Failed](/tutorial/troubleshooting-prerequisites#certificate-verification-failed)
- [503 Service Unavailable from HAProxy](/tutorial/troubleshooting-prerequisites#503-service-unavailable-from-haproxy)
- [502 Bad Gateway from HAProxy](/tutorial/troubleshooting-prerequisites#502-bad-gateway-from-haproxy)
- [DNS Not Resolving (Docker Registry)](/tutorial/troubleshooting-prerequisites#dns-not-resolving-docker-registry)
- [Registry Container Not Starting](/tutorial/troubleshooting-prerequisites#registry-container-not-starting)
- [HAProxy Configuration Error](/tutorial/troubleshooting-prerequisites#haproxy-configuration-error)

---

## Next Steps

With the local Docker registry running, proceed to:

- [Contract Deployment](/tutorial/contract-deployment) - Deploy KMS contracts to Sepolia
- [KMS Build & Configuration](/tutorial/kms-build-configuration) - Prepare KMS for CVM deployment

## Additional Resources

- [Docker Registry Documentation](https://docs.docker.com/registry/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Certbot Documentation](https://certbot.eff.org/docs/)
