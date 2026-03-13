---
title: "Gramine Key Provider"
description: "Deploy SGX-based Gramine Sealing Key Provider for CVM attestation"
section: "Prerequisites"
stepNumber: 4
totalSteps: 7
lastUpdated: 2026-01-09
prerequisites:
  - docker-setup
tags:
  - gramine
  - sgx
  - attestation
  - key-provider
  - prerequisites
difficulty: advanced
estimatedTime: "30 minutes"
---

# Gramine Key Provider

This tutorial guides you through deploying the Gramine Sealing Key Provider, an SGX-based service that solves the "chicken-and-egg" problem in CVM deployment. The key provider runs on the host and provides attestation-backed sealing keys to CVMs during boot.

## Why You Need This

When deploying a dstack CVM (like the KMS), there's a fundamental bootstrapping problem:

| The Problem | Why It Matters |
|-------------|----------------|
| CVMs need sealing keys to boot | Keys protect secrets inside the CVM |
| KMS is the service that provides keys | But KMS itself is a CVM that needs keys |
| **Chicken-and-egg:** KMS needs keys, but KMS provides keys | Deployment deadlock |

**The Solution:** The Gramine Sealing Key Provider runs on the **host** using Intel SGX (not TDX). It can provide attestation-backed sealing keys to CVMs during their initial boot. Once the KMS CVM boots successfully, it takes over key management for subsequent deployments.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                       TDX Host                               │
│                                                              │
│  ┌──────────────────────────────────────┐                   │
│  │     Gramine Sealing Key Provider     │                   │
│  │          (SGX Enclave)               │                   │
│  │                                      │                   │
│  │  - Runs in Intel SGX enclave         │                   │
│  │  - Listens on 0.0.0.0:3443           │                   │
│  │  - Provides sealing keys via HTTPS   │                   │
│  │  - Verifies TDX quotes from CVMs     │                   │
│  └──────────────────────┬───────────────┘                   │
│                         │                                    │
│                         ▼ (provides keys)                    │
│  ┌──────────────────────────────────────┐                   │
│  │           KMS CVM (TDX)              │                   │
│  │                                      │                   │
│  │  - Boots with sealing key            │                   │
│  │  - Generates TDX attestation quote   │                   │
│  │  - Takes over key management         │                   │
│  └──────────────────────────────────────┘                   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**Key Points:**
- Gramine runs in an SGX enclave (not a TDX CVM)
- Only provides keys to verified TDX CVMs
- Uses PPID (Platform Provisioning ID) verification
- Temporary solution until KMS CVM is running

## Prerequisites

Before starting, ensure you have:

- Completed [TDX & SGX Verification](/tutorial/tdx-sgx-verification) - SGX devices must be present
- Docker installed and running
- SGX devices accessible: `/dev/sgx_enclave`, `/dev/sgx_provision`

### Verify SGX Devices

```bash
ls -la /dev/sgx*
```

Expected output:
```
crw------- 1 root root 10, 125 Dec  8 00:00 /dev/sgx_enclave
crw------- 1 root root 10, 126 Dec  8 00:00 /dev/sgx_provision
crw------- 1 root root 10, 124 Dec  8 00:00 /dev/sgx_vepc
```

If these devices are missing, complete the [TDX BIOS Configuration](/tutorial/tdx-bios-configuration) tutorial first.

---


## Manual Deployment

If you prefer to deploy manually, follow these steps.

### Step 1: Clone dstack Repository

Clone the dstack repository and check out the v0.5.7 release:

```bash
cd ~
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack
git checkout v0.5.7
```

### Step 2: Navigate to Key Provider

```bash
cd ~/dstack/key-provider-build
ls -la
```

You should see:
- `docker-compose.yml` - Container orchestration
- `Dockerfile.aesmd` (or similar) - SGX AESM daemon image
- `Dockerfile.gramine` (or similar) - Gramine key provider image

### Step 3: Create QCNL Configuration

The key provider needs to know where to find a PCCS for quote verification. Create the QCNL configuration file:

```bash
cat > ~/dstack/key-provider-build/sgx_default_qcnl.conf << 'EOF'
{
  "pccs_url": "https://pccs.phala.network/sgx/certification/v4/",
  "use_secure_cert": false,
  "retry_times": 6,
  "retry_delay": 10
}
EOF
```

This configures the key provider to use Phala Network's public PCCS for attestation verification.

### Step 4: Configure Network Binding for CVM Access

The default configuration binds to localhost, but CVMs need to access the key provider via the host's network. Update the port binding:

```bash
# Change from 127.0.0.1:3443 to 0.0.0.0:3443
sed -i 's/"127\.0\.0\.1:3443:3443"/"0.0.0.0:3443:3443"/' ~/dstack/key-provider-build/docker-compose.yaml
```

> **Note:** This makes the key provider accessible from CVMs via the QEMU user-mode networking gateway (`10.0.2.2`). The key provider still verifies TDX quotes, so only legitimate CVMs can obtain keys.

### Step 5: Build Docker Images

```bash
docker compose build
```

This builds two images:
1. **aesmd** - Intel SGX Architectural Enclave Service Manager
2. **gramine-sealing-key-provider** - The actual key provider

### Step 6: Start Services

```bash
docker compose up -d
```

This starts:
- **aesmd container** - Provides SGX enclave services
- **gramine-sealing-key-provider container** - Key provider on port 3443

### Step 7: Verify Services Running

Check container status:

```bash
docker ps | grep -E "(aesmd|gramine)"
```

Expected output shows both containers running:
```
abc123  aesmd                           Up 2 minutes
def456  gramine-sealing-key-provider    Up 2 minutes
```

Check aesmd logs:

```bash
docker logs aesmd 2>&1 | tail -20
```

Look for successful initialization messages.

Check key provider logs:

```bash
docker logs gramine-sealing-key-provider 2>&1 | tail -20
```

Look for messages indicating the enclave is ready and listening.

---

## Verification

### Check Port Binding

```bash
sudo ss -tlnp | grep 3443
```

Expected:
```
LISTEN  0  4096  0.0.0.0:3443  0.0.0.0:*  users:(("node",pid=12345,fd=7))
```

> **Note:** The `-p` flag requires sudo to show process information.

> **Note:** The service binds to `0.0.0.0` to allow access from CVMs via QEMU's user-mode networking (`10.0.2.2` from the CVM's perspective).

### Check SGX Enclave Status

The key provider should show SGX enclave initialization in its logs:

```bash
docker logs gramine-sealing-key-provider 2>&1 | grep -i "enclave\|sgx\|quote"
```

Look for messages like:
- `SGX enclave initialized`
- `Quote provider ready`
- `Listening on 0.0.0.0:3443`

### Test Key Provider Endpoint

The key provider uses HTTPS with a self-signed certificate. Test connectivity:

```bash
curl -sk https://127.0.0.1:3443/
```

An empty response or a brief error message indicates the service is running - the TLS handshake succeeded. The key provider doesn't serve a root endpoint; it only responds to specific API calls from CVMs.

If you get `curl: (7) Failed to connect` or similar connection error, the service is not running.

---

## How CVMs Use the Key Provider

When deploying a CVM with `--local-key-provider` flag, the VMM:

1. CVM boots and needs sealing key
2. CVM generates TDX attestation quote
3. Quote is sent to Gramine Key Provider (127.0.0.1:3443)
4. Key Provider verifies quote authenticity
5. Key Provider returns sealing key to CVM
6. CVM uses key to decrypt/protect secrets

This happens automatically - you don't need to configure anything in the CVM.

---

## Architecture Details

### Container Configuration

```yaml
services:
  aesmd:
    # Intel SGX AESM daemon
    # Provides enclave management services
    devices:
      - /dev/sgx_enclave:/dev/sgx/enclave
      - /dev/sgx_provision:/dev/sgx/provision
    volumes:
      - /var/run/aesmd:/var/run/aesmd

  gramine-sealing-key-provider:
    # Gramine-based key provider
    # Runs inside SGX enclave
    depends_on:
      - aesmd
    ports:
      - "0.0.0.0:3443:3443"  # Accessible from CVMs via 10.0.2.2
    devices:
      - /dev/sgx_enclave:/dev/sgx/enclave
      - /dev/sgx_provision:/dev/sgx/provision
    volumes:
      - /var/run/aesmd:/var/run/aesmd
```

### Security Considerations

| Aspect | Implementation |
|--------|----------------|
| Network binding | `0.0.0.0:3443` - accessible from CVMs via `10.0.2.2` |
| Quote verification | Validates TDX quotes before providing keys |
| Enclave protection | Keys never leave SGX enclave in plaintext |
| PPID verification | Ensures keys only go to legitimate CVMs |

> **Why `0.0.0.0`?** CVMs use QEMU's user-mode networking where the host appears as `10.0.2.2`. Binding to localhost would prevent CVMs from reaching the key provider. Security is maintained through TDX quote verification - only legitimate CVMs with valid attestation can obtain keys.

---

## Troubleshooting

For detailed solutions, see the [Prerequisites Troubleshooting Guide](/tutorial/troubleshooting-prerequisites#gramine-key-provider-issues):

- [Container fails to start: SGX devices not found](/tutorial/troubleshooting-prerequisites#container-fails-to-start-sgx-devices-not-found)
- [Error: AESM service not ready](/tutorial/troubleshooting-prerequisites#error-aesm-service-not-ready)
- [Quote verification failures](/tutorial/troubleshooting-prerequisites#quote-verification-failures)
- [Empty response from curl test](/tutorial/troubleshooting-prerequisites#empty-response-from-curl-test)
- [Port 3443 already in use](/tutorial/troubleshooting-prerequisites#port-3443-already-in-use)
- [SGX enclave initialization timeout](/tutorial/troubleshooting-prerequisites#sgx-enclave-initialization-timeout)

---

## Verification Summary

Run this verification script:

```bash
echo "AESMD Container: $(docker ps --format '{{.Names}}' | grep -q aesmd && echo 'running' || echo 'not running')"
echo "Key Provider Container: $(docker ps --format '{{.Names}}' | grep -q gramine-sealing-key-provider && echo 'running' || echo 'not running')"
echo "Port 3443: $(ss -tln | grep -q :3443 && echo 'listening' || echo 'not listening')"
echo "SGX Devices: $([ -e /dev/sgx_enclave ] && [ -e /dev/sgx_provision ] && echo 'present' || echo 'missing')"
```

All checks should show positive status (running, listening, present).

---

## Next Steps

With the Gramine Key Provider running, proceed to:

- [Local Docker Registry](/tutorial/local-docker-registry) - Set up registry for CVM images

## Additional Resources

- [Gramine Documentation](https://gramine.readthedocs.io/)
- [Intel SGX Developer Guide](https://download.01.org/intel-sgx/sgx-dcap/1.14/linux/docs/)
- [dstack GitHub Repository](https://github.com/Dstack-TEE/dstack)
