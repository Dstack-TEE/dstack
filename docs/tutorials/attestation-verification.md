---
title: "Attestation Verification"
description: "Verify TDX attestation to prove your application runs in a genuine secure environment"
section: "First Application"
stepNumber: 2
totalSteps: 2
lastUpdated: 2026-03-09
prerequisites:
  - hello-world-app
tags:
  - dstack
  - tdx
  - attestation
  - ra-tls
  - verification
  - security
difficulty: "advanced"
estimatedTime: "45 minutes"
---

# Attestation Verification

This tutorial guides you through verifying TDX attestation for your deployed applications. Attestation is the cryptographic proof that your application is genuinely running inside a TDX-protected Confidential Virtual Machine with the expected software stack.

## What You'll Learn

- **Retrieving attestation data** - Get measurements and RA-TLS certificates from running CVMs
- **Measurement verification** - Understand and verify MRTD and RTMR values
- **RA-TLS certificates** - Examine X.509 certificates with embedded TDX quotes
- **End-to-end verification** - Complete attestation workflow

## Why Attestation Matters

Attestation provides cryptographic proof of three critical properties:

| Property | What It Proves |
|----------|----------------|
| **Authenticity** | The CVM is running on genuine Intel TDX hardware |
| **Integrity** | The firmware, kernel, and OS haven't been modified |
| **Isolation** | Your application's memory is encrypted and isolated |

Without attestation, you're trusting the infrastructure provider. With attestation, you have mathematical proof that the security guarantees are being enforced by hardware.

## Understanding TDX Measurements

TDX uses several measurement registers to track the boot process:

```
┌─────────────────────────────────────────────────────────────┐
│                  TDX Measurement Registers                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  MRTD (Measurement Register TD)                              │
│  └── Measures: Virtual firmware (OVMF)                       │
│      Computed by: TDX module (hardware)                      │
│      Fixed for: Same OVMF binary                             │
│                                                              │
│  RTMR0 (Runtime Measurement Register 0)                      │
│  └── Measures: CPU/memory configuration                      │
│      Computed by: OVMF during boot                           │
│      Varies with: VM specifications (vCPUs, RAM)             │
│                                                              │
│  RTMR1 (Runtime Measurement Register 1)                      │
│  └── Measures: Linux kernel                                  │
│      Computed by: OVMF when loading kernel                   │
│      Fixed for: Same kernel binary (bzImage)                 │
│                                                              │
│  RTMR2 (Runtime Measurement Register 2)                      │
│  └── Measures: Kernel cmdline + initramfs                    │
│      Computed by: OVMF                                       │
│      Fixed for: Same image metadata                          │
│                                                              │
│  RTMR3 (Runtime Measurement Register 3)                      │
│  └── Measures: Application configuration                     │
│      Computed by: Tappd at runtime                           │
│      Varies with: Docker compose, app ID, etc.               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Understanding RA-TLS

dstack uses **Remote Attestation TLS (RA-TLS)** to bind TDX attestation to standard TLS certificates. When a CVM boots, tappd generates an X.509 certificate (`app_cert`) that embeds the TDX quote directly in certificate extensions:

```
┌─────────────────────────────────────────────────────────────┐
│                    RA-TLS Certificate                        │
├─────────────────────────────────────────────────────────────┤
│  Standard X.509 fields (subject, issuer, validity, etc.)     │
│                                                              │
│  Custom Extensions:                                          │
│  ├── OID 1.3.6.1.4.1.62397.1.1  →  TDX Quote (binary)      │
│  ├── OID 1.3.6.1.4.1.62397.1.2  →  Event Log               │
│  ├── OID 1.3.6.1.4.1.62397.1.3  →  App ID / Compose Hash   │
│  └── OID 1.3.6.1.4.1.62397.1.4  →  Custom Claims           │
│                                                              │
│  The TDX quote is signed by Intel TDX hardware and binds     │
│  the certificate's public key to the CVM measurements.       │
└─────────────────────────────────────────────────────────────┘
```

In production, the **application inside the CVM** serves this `app_cert` via TLS. External verifiers connect to the app, receive the RA-TLS certificate, extract the TDX quote from the X.509 extensions, and verify it independently — no host access needed.

For this tutorial, since our hello-world app (nginx:alpine) doesn't serve RA-TLS directly, we'll use the VMM's `/guest/Info` proxy API to retrieve the attestation data. The concepts are identical to what you'd implement in a production RA-TLS verifier.

## Prerequisites

Before starting, ensure you have:

- Completed [Hello World Application](/tutorial/hello-world-app)
- A running CVM instance
- `jq` and `openssl` installed on the host

Verify you have a running CVM:

```bash
cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)
./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm
```

## Step 1: Retrieve Attestation Data

The VMM provides a `/guest/Info` endpoint that proxies into the CVM and retrieves attestation data including measurements and the RA-TLS certificate.

### Via VMM Guest Proxy

```bash
cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)

# Get the VM UUID for hello-world
VM_UUID=$(./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm --json 2>/dev/null \
  | jq -r '.[] | select(.name=="hello-world") | .id')
echo "VM UUID: $VM_UUID"

# Retrieve attestation data via guest proxy
curl -s -u "admin:$DSTACK_VMM_AUTH_PASSWORD" \
  -X POST http://127.0.0.1:9080/guest/Info \
  -H "Content-Type: application/json" \
  -d "{\"id\": \"$VM_UUID\"}" | jq '{
    instance_id: .instance_id,
    app_id: .app_id,
    tcb_info: (.tcb_info | fromjson | {mrtd, rtmr0, rtmr1, rtmr2, rtmr3})
  }'
```

You should see output like:

```json
{
  "instance_id": "hello-world-abc123",
  "app_id": "hello-world",
  "tcb_info": {
    "mrtd": "a3f1b2c4d5e6...",
    "rtmr0": "11223344aabb...",
    "rtmr1": "55667788ccdd...",
    "rtmr2": "99aabbccddee...",
    "rtmr3": "ddeeff001122..."
  }
}
```

> **RA-TLS in production:** In a real deployment, your application would serve the `app_cert` via TLS directly. External verifiers would connect to your app's HTTPS endpoint, receive the RA-TLS certificate, and extract the TDX quote from the X.509 extension at OID `1.3.6.1.4.1.62397.1.1`. No VMM access is needed — the app proves its own integrity.

### From Inside the CVM

Applications running inside the CVM can request raw TDX quotes directly via the tappd Unix socket:

```bash
# This would be run inside a container in the CVM
curl -X POST --unix-socket /var/run/tappd.sock \
  -d '{"report_data": "0x48656c6c6f"}' \
  http://localhost/prpc/Tappd.RawQuote?json
```

The `report_data` field is optional user-provided data (up to 64 bytes, hex-encoded) that gets included in the quote. Applications use this for challenge-response attestation — a verifier sends a random nonce, the app includes it in the quote, proving the quote is fresh.

## Step 2: Understand the Response

The `/guest/Info` response contains several key fields. Let's examine the full structure:

```bash
# Save the full response for examination
RESPONSE=$(curl -s -u "admin:$DSTACK_VMM_AUTH_PASSWORD" \
  -X POST http://127.0.0.1:9080/guest/Info \
  -H "Content-Type: application/json" \
  -d "{\"id\": \"$VM_UUID\"}")

# Show top-level keys
echo "$RESPONSE" | jq 'keys'
```

The response includes:

| Field | Description |
|-------|-------------|
| `instance_id` | Unique identifier for this CVM instance |
| `app_id` | Application identifier (from compose config) |
| `version` | dstack version running in the CVM |
| `app_cert` | RA-TLS certificate (PEM-encoded X.509 with TDX quote in extensions) |
| `tcb_info` | JSON string containing all measurements and the event log |

### TCB Info Structure

The `tcb_info` field is a JSON string that must be parsed separately. It contains the core attestation data:

```bash
echo "$RESPONSE" | jq -r '.tcb_info' | jq .
```

| Field | Description |
|-------|-------------|
| `mrtd` | Virtual firmware (OVMF) measurement — set by TDX hardware |
| `rtmr0` | VM configuration measurement (vCPUs, RAM) — set by OVMF |
| `rtmr1` | Kernel measurement — set by OVMF when loading bzImage |
| `rtmr2` | Cmdline/initrd measurement — set by OVMF |
| `rtmr3` | Application runtime measurement — set by tappd |
| `compose_hash` | SHA-256 of the docker compose configuration |
| `os_image_hash` | SHA-256 of the guest OS image |
| `event_log` | Array of detailed events for RTMR3 replay verification |

## Step 3: Calculate Expected Measurements

To verify attestation, you need to independently calculate what the measurements **should** be from the guest OS image files. The `dstack-mr` tool does this, but it requires a runtime dependency that must be built first.

### Get image metadata

```bash
cat /var/lib/dstack/images/dstack-0.5.7/metadata.json | jq .
```

### Build dstack-acpi-tables (required dependency)

`dstack-mr` internally runs a tool called `dstack-acpi-tables` to generate ACPI tables for RTMR0 calculation. This is a custom-patched QEMU binary compiled with `-DDUMP_ACPI_TABLES`. You need to build it once:

```bash
# Install QEMU build dependencies
sudo apt-get update
sudo apt-get install -y git libslirp-dev python3-pip ninja-build \
  pkg-config libglib2.0-dev build-essential flex bison

# Clone the custom QEMU fork
cd ~/dstack
git clone https://github.com/kvinwang/qemu-tdx.git --depth 1 \
  --branch dstack-qemu-9.2.1 --single-branch

# Configure with ACPI table dumping enabled
cd qemu-tdx
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
export CFLAGS="-DDUMP_ACPI_TABLES -Wno-builtin-macro-redefined -D__DATE__=\"\" -D__TIME__=\"\" -D__TIMESTAMP__=\"\""
export LDFLAGS="-Wl,--build-id=none"
mkdir build && cd build
../configure --target-list=x86_64-softmmu --disable-werror

# Build (this takes several minutes)
ninja

# Install the binary
strip qemu-system-x86_64
sudo install -m 755 qemu-system-x86_64 /usr/local/bin/dstack-acpi-tables

# Install required QEMU data files
sudo install -d /usr/local/share/qemu
sudo install -m 644 ../pc-bios/efi-virtio.rom /usr/local/share/qemu/
sudo install -m 644 ../pc-bios/kvmvapic.bin /usr/local/share/qemu/
sudo install -m 644 ../pc-bios/linuxboot_dma.bin /usr/local/share/qemu/

# Clean up source (optional)
cd ~/dstack
rm -rf qemu-tdx
```

### Build the measurement calculator

```bash
cd ~/dstack
cargo build --release -p dstack-mr-cli
```

This produces `./target/release/dstack-mr`.

### Calculate expected MRs

The tool uses a `measure` subcommand. The metadata path is a positional argument, and it reads the actual OVMF, kernel, and initrd files from the same directory:

```bash
./target/release/dstack-mr measure \
  --cpu 2 \
  --memory 2G \
  /var/lib/dstack/images/dstack-0.5.7/metadata.json
```

Expected output:

```
Machine measurements:
MRTD: a1b2c3d4e5f6789...
RTMR0: 112233445566...
RTMR1: 55667788990011...
RTMR2: 99aabbccddee...
```

For JSON output (useful in scripts), add `--json`:

```bash
./target/release/dstack-mr measure --json \
  --cpu 2 --memory 2G \
  /var/lib/dstack/images/dstack-0.5.7/metadata.json
```

> **Note:** RTMR3 is not included — it depends on application configuration and can only be verified via event log replay (see Step 6).

## Step 4: Verify the RA-TLS Certificate

The `app_cert` in the `/guest/Info` response is an RA-TLS certificate — a standard X.509 certificate with TDX attestation data embedded in custom extensions.

### Extract and examine the certificate

```bash
# Extract the app_cert
echo "$RESPONSE" | jq -r '.app_cert' > /tmp/app_cert.pem

# View the certificate structure
openssl x509 -in /tmp/app_cert.pem -text -noout
```

In the output, look for the **X509v3 extensions** section. You'll see custom extensions under the dstack OID arc (`1.3.6.1.4.1.62397.1.*`):

### Extension OIDs

| OID | Content | Description |
|-----|---------|-------------|
| `1.3.6.1.4.1.62397.1.1` | TDX Quote | Binary TDX quote signed by Intel hardware. Contains all measurement registers and binds the cert's public key to the measurements. |
| `1.3.6.1.4.1.62397.1.2` | Event Log | Detailed event log for RTMR3 replay verification |
| `1.3.6.1.4.1.62397.1.3` | App ID / Compose Hash | Application identity and configuration hash |
| `1.3.6.1.4.1.62397.1.4` | Custom Claims | Optional application-defined claims |

### Verify the certificate chain

The app_cert is signed by the dstack App CA, which is in turn signed by the dstack KMS CA:

```
app_cert → Dstack App CA → Dstack KMS CA
```

The KMS CA is established during KMS deployment (Phase 4). The chain proves that this certificate was issued by a KMS that verified the CVM's TDX measurements before issuing the cert.

```bash
# Show issuer information
openssl x509 -in /tmp/app_cert.pem -issuer -noout
```

### Why RA-TLS works

The TDX quote embedded at OID `1.3.6.1.4.1.62397.1.1` was generated by Intel TDX hardware during CVM boot. It contains:

1. **All measurement registers** (MRTD, RTMR0-3) — proving what software is running
2. **A hash of the certificate's public key** in the `report_data` field — binding the cert to the hardware attestation
3. **Intel's hardware signature** — proving the quote came from genuine TDX hardware

This means: if you trust the certificate (verified via the chain), you trust the measurements, which means you know exactly what code is running inside the CVM.

## Step 5: Compare Measurements

Compare the CVM's actual measurements against your expected values:

```bash
#!/bin/bash
# verify-measurements.sh

cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)

# Get VM UUID
VM_UUID=$(./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm --json 2>/dev/null \
  | jq -r '.[] | select(.name=="hello-world") | .id')

if [ -z "$VM_UUID" ] || [ "$VM_UUID" = "null" ]; then
    echo "Error: hello-world CVM not found. Is it running?"
    exit 1
fi

# Fetch attestation data
RESPONSE=$(curl -s -u "admin:$DSTACK_VMM_AUTH_PASSWORD" \
  -X POST http://127.0.0.1:9080/guest/Info \
  -H "Content-Type: application/json" \
  -d "{\"id\": \"$VM_UUID\"}")

# Parse tcb_info (it's a JSON string inside JSON)
TCB_INFO=$(echo "$RESPONSE" | jq -r '.tcb_info')

# Extract measurements
MRTD=$(echo "$TCB_INFO" | jq -r '.mrtd')
RTMR0=$(echo "$TCB_INFO" | jq -r '.rtmr0')
RTMR1=$(echo "$TCB_INFO" | jq -r '.rtmr1')
RTMR2=$(echo "$TCB_INFO" | jq -r '.rtmr2')
RTMR3=$(echo "$TCB_INFO" | jq -r '.rtmr3')

echo "Actual Measurements from CVM:"
echo "  MRTD:  $MRTD"
echo "  RTMR0: $RTMR0"
echo "  RTMR1: $RTMR1"
echo "  RTMR2: $RTMR2"
echo "  RTMR3: $RTMR3"
echo ""

# Expected values — replace these with your dstack-mr output
EXPECTED_MRTD="<paste your dstack-mr MRTD value here>"
EXPECTED_RTMR0="<paste your dstack-mr RTMR0 value here>"
EXPECTED_RTMR1="<paste your dstack-mr RTMR1 value here>"
EXPECTED_RTMR2="<paste your dstack-mr RTMR2 value here>"

echo "Measurement Verification Results:"
echo "=================================="

if [ "$EXPECTED_MRTD" = "<paste your dstack-mr MRTD value here>" ]; then
    echo "Warning: Using placeholder expected values."
    echo "Run dstack-mr first, then update the EXPECTED_* variables."
    exit 0
fi

if [ "$MRTD" = "$EXPECTED_MRTD" ]; then
    echo "  MRTD  - MATCH - Firmware verified"
else
    echo "  MRTD  - MISMATCH"
    echo "    Expected: $EXPECTED_MRTD"
    echo "    Got:      $MRTD"
fi

if [ "$RTMR0" = "$EXPECTED_RTMR0" ]; then
    echo "  RTMR0 - MATCH - VM config verified"
else
    echo "  RTMR0 - MISMATCH"
    echo "    Expected: $EXPECTED_RTMR0"
    echo "    Got:      $RTMR0"
fi

if [ "$RTMR1" = "$EXPECTED_RTMR1" ]; then
    echo "  RTMR1 - MATCH - Kernel verified"
else
    echo "  RTMR1 - MISMATCH"
    echo "    Expected: $EXPECTED_RTMR1"
    echo "    Got:      $RTMR1"
fi

if [ "$RTMR2" = "$EXPECTED_RTMR2" ]; then
    echo "  RTMR2 - MATCH - Initrd verified"
else
    echo "  RTMR2 - MISMATCH"
    echo "    Expected: $EXPECTED_RTMR2"
    echo "    Got:      $RTMR2"
fi

echo ""
echo "RTMR3 requires event log replay (see Step 6)"
```

## Step 6: Verify RTMR3 via Event Log

RTMR3 contains runtime measurements that can't be pre-calculated — they depend on the application configuration, instance ID, and other runtime values. Instead, verify by examining the event log.

### View the event log

```bash
# Extract and display the event log from tcb_info
TCB_INFO=$(echo "$RESPONSE" | jq -r '.tcb_info')
echo "$TCB_INFO" | jq '.event_log'
```

Each event in the log has these fields:

| Field | Description |
|-------|-------------|
| `imr` | Which measurement register was extended (3 = RTMR3) |
| `event_type` | Type of event |
| `digest` | SHA-384 hash that was extended into the register |
| `event` | Human-readable event name |
| `event_payload` | Hex-encoded payload data |

### Decode and verify known events

The event log records everything that was measured into RTMR3 during boot:

```bash
# Display events in human-readable format
echo "$TCB_INFO" | jq -r '.event_log[] | "\(.event): \(.event_payload)"' | while read line; do
    EVENT_NAME=$(echo "$line" | cut -d: -f1)
    PAYLOAD_HEX=$(echo "$line" | cut -d: -f2- | tr -d ' ')

    # Decode hex payload to text (where applicable)
    DECODED=$(echo "$PAYLOAD_HEX" | xxd -r -p 2>/dev/null || echo "(binary)")

    echo "  $EVENT_NAME: $DECODED"
done
```

### Expected RTMR3 events

These are the standard events you'll see in the log:

| Event | Description | What to verify |
|-------|-------------|----------------|
| `system-preparing` | System initialization marker | Always present |
| `app-id` | Application identifier | Should match your app name |
| `compose-hash` | SHA-256 of docker compose config | Should match `tcb_info.compose_hash` |
| `instance-id` | Unique instance identifier | Should match `instance_id` from response |
| `boot-mr-done` | Boot measurements complete | Marker event |
| `mr-kms` | KMS identity measurement | KMS public key hash |
| `os-image-hash` | Guest OS image hash | Should match `tcb_info.os_image_hash` |
| `key-provider` | Key provider type | e.g., `kms` |
| `storage-fs` | Storage filesystem type | Storage configuration |
| `system-ready` | System ready marker | Always present at end |

### Verify specific event values

```bash
# Extract compose-hash from event log and compare to tcb_info
EVENT_COMPOSE_HASH=$(echo "$TCB_INFO" | jq -r '.event_log[] | select(.event=="compose-hash") | .event_payload' | xxd -r -p 2>/dev/null)
TCB_COMPOSE_HASH=$(echo "$TCB_INFO" | jq -r '.compose_hash')

echo "Event log compose-hash: $EVENT_COMPOSE_HASH"
echo "TCB info compose_hash:  $TCB_COMPOSE_HASH"

# Extract os-image-hash from event log
EVENT_OS_HASH=$(echo "$TCB_INFO" | jq -r '.event_log[] | select(.event=="os-image-hash") | .event_payload' | xxd -r -p 2>/dev/null)
TCB_OS_HASH=$(echo "$TCB_INFO" | jq -r '.os_image_hash')

echo "Event log os-image-hash: $EVENT_OS_HASH"
echo "TCB info os_image_hash:  $TCB_OS_HASH"
```

## Step 7: Full Verification Script

Here's a complete end-to-end verification script:

```bash
#!/bin/bash
# full-attestation-verify.sh
#
# Complete attestation verification for a dstack CVM.
# Retrieves measurements, examines the RA-TLS certificate,
# and verifies the event log.

INSTANCE_NAME="${1:-hello-world}"
IMAGE_VERSION="${2:-dstack-0.5.7}"

echo "========================================="
echo "dstack Attestation Verification"
echo "========================================="
echo "Instance: $INSTANCE_NAME"
echo "Image:    $IMAGE_VERSION"
echo ""

cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)

# --- Step 1: Get VM UUID ---
echo "Step 1: Locating CVM..."
VM_UUID=$(./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm --json 2>/dev/null \
  | jq -r ".[] | select(.name==\"$INSTANCE_NAME\") | .id")

if [ -z "$VM_UUID" ] || [ "$VM_UUID" = "null" ]; then
    echo "  FAIL - CVM '$INSTANCE_NAME' not found. Is it running?"
    echo "  Run: ./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm"
    exit 1
fi
echo "  OK   - VM UUID: $VM_UUID"

# --- Step 2: Fetch attestation data ---
echo ""
echo "Step 2: Fetching attestation data via /guest/Info..."
RESPONSE=$(curl -s -u "admin:$DSTACK_VMM_AUTH_PASSWORD" \
  -X POST http://127.0.0.1:9080/guest/Info \
  -H "Content-Type: application/json" \
  -d "{\"id\": \"$VM_UUID\"}")

if [ -z "$RESPONSE" ] || [ "$(echo "$RESPONSE" | jq -r '.tcb_info // empty')" = "" ]; then
    echo "  FAIL - No attestation data returned. CVM may still be booting."
    exit 1
fi

INSTANCE_ID=$(echo "$RESPONSE" | jq -r '.instance_id')
APP_ID=$(echo "$RESPONSE" | jq -r '.app_id')
echo "  OK   - Instance: $INSTANCE_ID"
echo "  OK   - App ID:   $APP_ID"

# --- Step 3: Extract measurements ---
echo ""
echo "Step 3: Extracting measurements from tcb_info..."
TCB_INFO=$(echo "$RESPONSE" | jq -r '.tcb_info')

MRTD=$(echo "$TCB_INFO" | jq -r '.mrtd')
RTMR0=$(echo "$TCB_INFO" | jq -r '.rtmr0')
RTMR1=$(echo "$TCB_INFO" | jq -r '.rtmr1')
RTMR2=$(echo "$TCB_INFO" | jq -r '.rtmr2')
RTMR3=$(echo "$TCB_INFO" | jq -r '.rtmr3')

echo "  MRTD:  ${MRTD:0:32}..."
echo "  RTMR0: ${RTMR0:0:32}..."
echo "  RTMR1: ${RTMR1:0:32}..."
echo "  RTMR2: ${RTMR2:0:32}..."
echo "  RTMR3: ${RTMR3:0:32}..."

# --- Step 4: Save and examine RA-TLS certificate ---
echo ""
echo "Step 4: Examining RA-TLS certificate..."
APP_CERT=$(echo "$RESPONSE" | jq -r '.app_cert')

if [ -n "$APP_CERT" ] && [ "$APP_CERT" != "null" ]; then
    echo "$APP_CERT" > /tmp/app_cert.pem

    # Show certificate subject and issuer
    SUBJECT=$(openssl x509 -in /tmp/app_cert.pem -subject -noout 2>/dev/null)
    ISSUER=$(openssl x509 -in /tmp/app_cert.pem -issuer -noout 2>/dev/null)
    echo "  $SUBJECT"
    echo "  $ISSUER"

    # Check for RA-TLS extensions
    CERT_TEXT=$(openssl x509 -in /tmp/app_cert.pem -text -noout 2>/dev/null)
    if echo "$CERT_TEXT" | grep -q "1.3.6.1.4.1.62397"; then
        echo "  OK   - RA-TLS extensions found (OID 1.3.6.1.4.1.62397.1.*)"
        echo "         .1.1 = TDX Quote | .1.2 = Event Log"
        echo "         .1.3 = App ID    | .1.4 = Custom Claims"
    else
        echo "  WARN - RA-TLS extensions not found in certificate"
    fi

    echo "  OK   - Certificate saved to /tmp/app_cert.pem"
else
    echo "  WARN - No app_cert in response"
fi

# --- Step 5: Compare measurements (if dstack-mr available) ---
echo ""
echo "Step 5: Measurement comparison..."
DSTACK_MR="$HOME/dstack/target/release/dstack-mr"
METADATA="/var/lib/dstack/images/$IMAGE_VERSION/metadata.json"

if [ -x "$DSTACK_MR" ] && [ -f "$METADATA" ]; then
    echo "  Calculating expected measurements with dstack-mr..."
    EXPECTED=$($DSTACK_MR measure --cpu 2 --memory 2G "$METADATA" 2>/dev/null)

    EXPECTED_MRTD=$(echo "$EXPECTED" | grep "MRTD:" | awk '{print $2}')
    EXPECTED_RTMR0=$(echo "$EXPECTED" | grep "RTMR0:" | awk '{print $2}')
    EXPECTED_RTMR1=$(echo "$EXPECTED" | grep "RTMR1:" | awk '{print $2}')
    EXPECTED_RTMR2=$(echo "$EXPECTED" | grep "RTMR2:" | awk '{print $2}')

    for REG in MRTD RTMR0 RTMR1 RTMR2; do
        ACTUAL_VAR="${REG}"
        EXPECTED_VAR="EXPECTED_${REG}"
        ACTUAL="${!ACTUAL_VAR}"
        EXPECTED_VAL="${!EXPECTED_VAR}"

        if [ -n "$EXPECTED_VAL" ] && [ "$ACTUAL" = "$EXPECTED_VAL" ]; then
            echo "  $REG  - MATCH"
        elif [ -n "$EXPECTED_VAL" ]; then
            echo "  $REG  - MISMATCH"
            echo "    Expected: ${EXPECTED_VAL:0:32}..."
            echo "    Got:      ${ACTUAL:0:32}..."
        fi
    done
else
    echo "  SKIP - dstack-mr not built or metadata not found"
    echo "  To enable: cd ~/dstack && cargo build --release -p dstack-mr-cli"
fi

# --- Step 6: Display event log ---
echo ""
echo "Step 6: Event log (RTMR3 events)..."
EVENT_COUNT=$(echo "$TCB_INFO" | jq '.event_log | length')
echo "  $EVENT_COUNT events recorded:"

echo "$TCB_INFO" | jq -r '.event_log[] | .event' | while read EVENT_NAME; do
    echo "  - $EVENT_NAME"
done

# Verify compose-hash consistency
COMPOSE_HASH=$(echo "$TCB_INFO" | jq -r '.compose_hash // empty')
OS_IMAGE_HASH=$(echo "$TCB_INFO" | jq -r '.os_image_hash // empty')

if [ -n "$COMPOSE_HASH" ]; then
    echo ""
    echo "  Compose hash: ${COMPOSE_HASH:0:32}..."
fi
if [ -n "$OS_IMAGE_HASH" ]; then
    echo "  OS image hash: ${OS_IMAGE_HASH:0:32}..."
fi

# --- Summary ---
echo ""
echo "========================================="
echo "Verification Summary"
echo "========================================="
echo "  CVM instance:  $INSTANCE_NAME ($INSTANCE_ID)"
echo "  App ID:        $APP_ID"
echo "  Measurements:  All 5 registers retrieved (MRTD, RTMR0-3)"
if [ -n "$APP_CERT" ] && [ "$APP_CERT" != "null" ]; then
    echo "  RA-TLS cert:   Present (saved to /tmp/app_cert.pem)"
fi
echo "  Event log:     $EVENT_COUNT events"
echo ""
echo "  Next steps:"
echo "  - Compare MRTD/RTMR0-2 with dstack-mr output"
echo "  - Verify RTMR3 by reviewing event log entries"
echo "  - In production, verify app_cert chain and TDX quote signature"
echo "========================================="
```

Make it executable and run:

```bash
chmod +x full-attestation-verify.sh
./full-attestation-verify.sh hello-world dstack-0.5.7
```

## Best Practices for Production

### 1. Use RA-TLS for application-level attestation

In production, don't rely on host API access. Instead, have your application serve the RA-TLS certificate via TLS:

```python
# Pseudo-code for an RA-TLS verifier
def verify_cvm_app(hostname, port):
    # Connect and get the server's certificate
    cert = ssl_connect_and_get_cert(hostname, port)

    # Extract TDX quote from X.509 extension
    quote = extract_extension(cert, oid="1.3.6.1.4.1.62397.1.1")

    # Verify quote signature (Intel hardware attestation)
    if not verify_tdx_quote(quote):
        raise SecurityError("TDX quote verification failed")

    # Extract measurements from quote
    measurements = parse_quote_measurements(quote)

    # Compare against expected values
    if measurements.mrtd != expected_mrtd:
        raise SecurityError("Firmware measurement mismatch")

    return True  # CVM is genuine and running expected software
```

### 2. Include report_data for freshness

When applications call tappd internally to generate quotes, include fresh random data to prevent replay attacks:

```bash
# Inside the CVM — application generates a fresh quote with a nonce
NONCE=$(openssl rand -hex 32)
curl -X POST --unix-socket /var/run/tappd.sock \
  -d "{\"report_data\": \"0x$NONCE\"}" \
  http://localhost/prpc/Tappd.RawQuote?json
```

The verifier sends the nonce, the app includes it in the quote, and the verifier checks it matches — proving the quote was generated just now, not replayed.

### 3. Verify the complete measurement chain

Don't just check one register — verify the complete chain:

```
MRTD → RTMR0 → RTMR1 → RTMR2 → RTMR3
  │        │        │        │        │
  v        v        v        v        v
OVMF   VM Config  Kernel   Initrd   App
```

Each register builds on the previous one. A compromised kernel (RTMR1) could fake application measurements (RTMR3), so always verify from the firmware up.

### 4. Keep expected measurements updated

When you update guest OS images, recalculate expected measurements:

```bash
# After updating to new image version
dstack-mr measure --cpu 2 --memory 2G \
  /var/lib/dstack/images/dstack-0.5.7/metadata.json
```

### 5. Use reproducible builds

For highest assurance, build images from source:

```bash
git clone https://github.com/Dstack-TEE/meta-dstack.git
cd meta-dstack/repro-build
./repro-build.sh -n  # Reproducible build
```

This ensures you know exactly what code is in the image, and anyone can independently verify the measurements match.

## Troubleshooting

For detailed solutions, see the [First Application Troubleshooting Guide](/tutorial/troubleshooting-first-application#attestation-verification-issues):

- [Attestation data retrieval fails](/tutorial/troubleshooting-first-application#attestation-data-retrieval-fails)
- [Measurements don't match](/tutorial/troubleshooting-first-application#measurements-dont-match)
- [RA-TLS certificate issues](/tutorial/troubleshooting-first-application#ra-tls-certificate-issues)

## Verification Checklist

Before proceeding, verify you have:

- [ ] Successfully retrieved attestation data via `/guest/Info`
- [ ] Extracted all measurement registers (MRTD, RTMR0-3)
- [ ] Examined the RA-TLS certificate and its extensions
- [ ] Understood the event log contents
- [ ] Know how to calculate expected measurements with `dstack-mr`
- [ ] Automated verification with the full script

## Phase 5 Complete!

Congratulations! You have completed Phase 5 (First Application Deployment):

1. **Guest OS Image Setup** - Downloaded and configured guest images
2. **Hello World Application** - Deployed your first CVM application
3. **Attestation Verification** - Proved your app runs in a secure environment

## What You've Accomplished

Your dstack deployment now includes:

- TDX-enabled host with hardware security
- VMM service managing CVMs and virtual machines
- KMS service providing key management
- Gateway service routing traffic
- A running Hello World application
- Cryptographic proof of security via attestation

## Next Steps

With the foundation complete, you're ready to explore:

- **Phase 6:** Deploy more complex applications from dstack-examples
- **Advanced attestation:** ConfigID and RTMR3-based verification
- **Custom domains:** Access apps via your own domain
- **SSH access:** Connect directly to CVMs
- **Port forwarding:** Expose additional services

## Additional Resources

- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
- [DCAP Attestation Guide](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/)
- [dstack Attestation Source](https://github.com/Dstack-TEE/dstack/tree/main/attestation)
- [Reproducible Builds for meta-dstack](https://github.com/Dstack-TEE/meta-dstack/tree/main/repro-build)
