---
title: "Troubleshooting: First Application"
description: "Solutions for common issues during Hello World deployment and attestation verification"
section: "Troubleshooting"
stepNumber: null
totalSteps: null
isAppendix: true
tags:
  - troubleshooting
  - hello-world
  - attestation
  - deployment
  - cvm
difficulty: intermediate
estimatedTime: "reference"
lastUpdated: 2026-03-06
---

# Troubleshooting: First Application

This appendix consolidates troubleshooting content from the First Application tutorials. For inline notes and warnings, see the individual tutorials.

---

## Hello World App Issues

### CVM fails to start

Check VMM status and logs:

```bash
systemctl status dstack-vmm
journalctl -u dstack-vmm -n 50
```

Common causes:
- **Insufficient resources:** Reduce `--vcpu` or `--memory`
- **Image not found:** Verify `dstack-0.5.7` exists: `ls /var/lib/dstack/images/`
- **Compose hash not whitelisted:** See Step 5

### "OS image is not allowed"

The OS image hash isn't whitelisted on the KMS contract. See [KMS CVM Deployment: OS image not allowed](/tutorial/troubleshooting-kms-deployment#os-image-is-not-allowed) for the solution.

### CVM boots but no gateway registration

Check the CVM logs for gateway-related errors:

```bash
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=false&ansi=false&lines=200" | grep -i "gateway\|wireguard\|wg"
```

Common causes:
- **`--gateway` flag missing** from `vmm-cli.py compose` — regenerate `app-compose.json` with `--gateway`
- **`--gateway-url` missing** from `vmm-cli.py deploy` — redeploy with the correct URL
- **Gateway RPC unreachable** — verify `curl -sk https://gateway.dstack.yourdomain.com:9202/prpc/Status` works from the host
- **HAProxy missing `gateway_rpc_passthrough` rule** — see [HAProxy Setup](/tutorial/haproxy-setup)

### Application not accessible via gateway

1. Check if the app registered: `curl -sf http://127.0.0.1:9203/prpc/Status | jq '.hosts'`
2. Check if Let's Encrypt cert was issued (look for certbot logs in CVM output)
3. Try direct port access first: `curl http://YOUR_SERVER_IP:9300/`
4. Check the [Gateway Deployment Troubleshooting Guide](/tutorial/troubleshooting-gateway-deployment#gateway-cvm-deployment-issues)

### Cannot pull Docker images

The CVM needs internet access to pull images from Docker Hub. With user-mode networking (default), this should work automatically. If pulls fail:

```bash
# Check CVM logs for pull errors
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=false&ansi=false&lines=200" | grep -i "pull\|image\|error"
```

---

## Attestation Verification Issues

### Attestation data retrieval fails

If `/guest/Info` returns empty or errors, check that the CVM is running:

```bash
cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)
./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm
```

Verify the VM UUID and try the request manually:

```bash
VM_UUID=$(./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm --json 2>/dev/null \
  | jq -r '.[] | select(.name=="hello-world") | .id')

curl -s -u "admin:$DSTACK_VMM_AUTH_PASSWORD" \
  -X POST http://127.0.0.1:9080/guest/Info \
  -H "Content-Type: application/json" \
  -d "{\"id\": \"$VM_UUID\"}" | jq 'keys'
```

If the response is empty, check that tappd is running inside the CVM:

```bash
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=$VM_UUID&follow=false&ansi=false&lines=100" | grep -i tappd
```

### Measurements don't match

Common causes:

**Different VM configuration:**
```bash
# Check actual vCPUs/RAM vs expected (shown in lsvm output)
./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm
```

**Different image version:**
```bash
# Verify image version matches (shown in lsvm output)
./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm
```

**Image was modified:**
```bash
# Verify image integrity
sha256sum /var/lib/dstack/images/dstack-0.5.7/*
```

### RA-TLS certificate issues

If the `app_cert` field is empty or the certificate doesn't contain RA-TLS extensions:

```bash
# Check if app_cert is present in the response
curl -s -u "admin:$DSTACK_VMM_AUTH_PASSWORD" \
  -X POST http://127.0.0.1:9080/guest/Info \
  -H "Content-Type: application/json" \
  -d "{\"id\": \"$VM_UUID\"}" | jq '.app_cert | length'
```

If the certificate is present but extensions are missing, the CVM may still be initializing. Wait for tappd to complete its boot sequence and try again.
