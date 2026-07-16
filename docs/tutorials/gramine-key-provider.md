---
title: "Local Key Provider"
description: "Deploy dstack's SGX-backed local key provider for CVM attestation"
section: "Prerequisites"
stepNumber: 4
totalSteps: 7
lastUpdated: 2026-07-16
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

# Local Key Provider

`local-key-provider` is dstack's SGX-based bootstrap key service. It solves the
chicken-and-egg problem in which the KMS runs in a CVM but needs a stable key in
order to boot. The service runs under Gramine on the host, verifies a requesting
CVM's TDX quote, and returns a measurement-bound key encrypted to that CVM.

The implementation is maintained in this repository under
`dstack/local-key-provider`; its build assets live in the `build/` subdirectory,
and the container build does not
clone an external key-provider repository. It currently uses the latest stable
Gramine release, 1.9, on the Ubuntu Noble image.

## Security Flow

1. The guest places an ephemeral X25519 public key in its TDX report data.
2. The VMM forwards the TDX quote to `local-key-provider` over the host-only TCP
   listener.
3. The provider verifies the TDX quote and checks that its SGX quote has the
   same platform identifier.
4. Inside SGX it derives
   `SHA-256(SGX sealing key || MRTD || RTMR0 || RTMR1 || RTMR2 || RTMR3)`.
5. It encrypts the derived key to the guest using the libsodium sealed-box wire
   format.
6. It returns the ciphertext and an SGX quote whose report data binds the
   ciphertext hash.

The guest independently verifies the SGX quote and hash before decrypting the
key. Plaintext key material therefore never leaves either TEE.

## Prerequisites

- Intel SGX and TDX enabled in firmware
- Docker Engine with the Compose plugin
- `/dev/sgx_enclave` and `/dev/sgx_provision`

Verify the devices:

```bash
ls -l /dev/sgx_enclave /dev/sgx_provision
```

If either device is absent, complete the TDX/SGX host setup before continuing.

## Deploy

Clone dstack and enter the build directory:

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack/dstack/local-key-provider/build
```

The bundled `sgx_default_qcnl.conf` points AESM at the Phala PCCS. To use a
different PCCS, edit its `pccs_url` while keeping certificate verification
enabled, and export the provider's base URL as `PCCS_URL` before running
Compose.

Build and start both AESM and the provider:

```bash
docker compose build
docker compose up -d
```

Or use the convenience script:

```bash
./run.sh
```

The Compose configuration publishes port 3443 on `127.0.0.1` only. Keep this
host-only binding: guests send requests through the VMM host API and do not
connect to the provider directly.

## Verify

Check both containers and the listener:

```bash
docker compose ps
docker compose logs --tail=50 aesmd
docker compose logs --tail=50 local-key-provider
ss -tln | grep '127.0.0.1:3443'
```

Expected results:

- `aesmd` and `local-key-provider` are running;
- the provider log includes `local key provider listening`; and
- TCP port 3443 is bound only to localhost.

The endpoint is a length-prefixed JSON protocol over raw TCP, not HTTP or
HTTPS, so `curl` is not a valid health check. An actual provisioning request is
made automatically when a TDX CVM starts with local key provisioning enabled.

## Container Configuration

The relevant Compose structure is:

```yaml
services:
  aesmd:
    devices:
      - /dev/sgx_enclave:/dev/sgx_enclave
      - /dev/sgx_provision:/dev/sgx_provision
    volumes:
      - aesmd:/var/run/aesmd/

  local-key-provider:
    depends_on:
      - aesmd
    devices:
      - /dev/sgx_enclave:/dev/sgx_enclave
      - /dev/sgx_provision:/dev/sgx_provision
    volumes:
      - aesmd:/var/run/aesmd/
    ports:
      - "127.0.0.1:3443:3443"
```

## Troubleshooting

For detailed solutions, see the
[Prerequisites Troubleshooting Guide](/tutorial/troubleshooting-prerequisites#local-key-provider-issues):

- [Container fails to start: SGX devices not found](/tutorial/troubleshooting-prerequisites#container-fails-to-start-sgx-devices-not-found)
- [Error: AESM service not ready](/tutorial/troubleshooting-prerequisites#error-aesm-service-not-ready)
- [Quote verification failures](/tutorial/troubleshooting-prerequisites#quote-verification-failures)
- [Port 3443 already in use](/tutorial/troubleshooting-prerequisites#port-3443-already-in-use)
- [SGX enclave initialization timeout](/tutorial/troubleshooting-prerequisites#sgx-enclave-initialization-timeout)

## Next Steps

With `local-key-provider` running, proceed to
[Local Docker Registry](/tutorial/local-docker-registry).

## Additional Resources

- [Gramine documentation](https://gramine.readthedocs.io/)
- [dstack source](https://github.com/Dstack-TEE/dstack)
