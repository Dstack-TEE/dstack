# Dstack on Google Cloud Platform

Deploy Dstack with Intel TDX Confidential Computing on GCP.

## Prerequisites

- Google Cloud account with billing enabled
- `gcloud` CLI installed and authenticated
- Terraform >= 1.5.0

## Supported Configurations

### Intel TDX (Confidential VM)

| Machine Type | CPU | TEE | Zones |
|--------------|-----|-----|-------|
| `c3-standard-*` | Intel Sapphire Rapids | Intel TDX | us-central1-a/b/c, us-east1-c/d, europe-west4-a/b/c |

### GPU + TEE (NVIDIA H100)

| Machine Type | GPU | TEE | Zones |
|--------------|-----|-----|-------|
| `a3-highgpu-1g` | NVIDIA H100 80GB | Intel TDX + NVIDIA CC | us-central1-a, us-east5-a, europe-west4-c |

## Quick Start

### 1. Authenticate

```bash
gcloud auth login
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
```

### 2. Enable APIs

```bash
gcloud services enable compute.googleapis.com
gcloud services enable dns.googleapis.com
```

### 3. Deploy

```bash
cd deploy/gcp/terraform

# Edit variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# Deploy
terraform init
terraform apply
```

### 4. Verify TDX

```bash
# SSH to VM
ssh -i ~/.ssh/your-key ubuntu@<VM_IP>

# Check TDX device
ls -la /dev/tdx_guest

# Get attestation quote
curl --unix-socket /var/run/dstack.sock "http://./GetQuote?report_data=0x1234"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GCP Confidential VM                       │
│                   (c3-standard-* / a3-highgpu)               │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    Intel TDX                             ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     ││
│  │  │ dstack-vmm  │  │ dstack-kms  │  │   gateway   │     ││
│  │  │   (host)    │  │    (CVM)    │  │    (CVM)    │     ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘     ││
│  │         │                │                │              ││
│  │         └────────────────┴────────────────┘              ││
│  │                    vsock / virtio                        ││
│  └─────────────────────────────────────────────────────────┘│
│                           │                                  │
│                    /dev/tdx_guest                            │
│                  (TDX attestation)                           │
└─────────────────────────────────────────────────────────────┘
```

## Limitations

Per [GCP documentation](https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations):

- No Local SSD support (use pd-balanced)
- No live migration (VMs terminate on host maintenance)
- Longer boot/shutdown times
- No `kdump` support

## GPU Quota

H100 GPUs require quota. Request at:
https://console.cloud.google.com/iam-admin/quotas

Filter: `GPUS_ALL_REGIONS` and request limit of 1+.

## Cost Estimate

| Resource | Hourly Cost |
|----------|-------------|
| c3-standard-8 | ~$0.40 |
| a3-highgpu-1g | ~$3.50 |
| 200GB disk | ~$0.02 |

## Testing

Run the verification script after deployment:

```bash
./test.sh <VM_IP> [SSH_KEY]
```

Example:
```bash
./test.sh 34.123.34.185 ~/.ssh/my-key
```

The test script verifies:
- ✅ SSH connectivity
- ✅ TDX device present (`/dev/tdx_guest`)
- ✅ Docker running
- ✅ Dstack container active
- ✅ Unix sockets present
- ✅ GetQuote API (TDX attestation)
- ✅ DeriveKey API
- ✅ Real TDX (not simulated)

### Manual Verification

```bash
# SSH to VM
ssh ubuntu@<VM_IP>

# Check TDX device
ls -la /dev/tdx_guest

# Check kernel TDX detection
sudo dmesg | grep -i tdx

# Check memory encryption
sudo dmesg | grep "Memory Encryption"

# Generate real TDX quote via kernel TSM interface
dd if=/dev/zero bs=1 count=64 | sudo tee /sys/kernel/config/tsm/report/com.intel.dcap/inblob > /dev/null
sudo cat /sys/kernel/config/tsm/report/com.intel.dcap/outblob | xxd | head -10
```

### Distinguishing Real TDX from Simulation

| Check | Simulated | Real TDX |
|-------|-----------|----------|
| `/dev/tdx_guest` | ❌ Not present | ✅ Present |
| dmesg "tdx: Guest detected" | ❌ Missing | ✅ Present |
| TSM provider | N/A | `tdx_guest` |
| Quote TEE type | N/A | `0x81000000` |
| Quote size | ~10KB (mock) | ~8KB (real) |
| Machine type | Any | `c3-standard-*` |

### Key Evidence of Real TDX

When running on real TDX hardware, you will see:

```
# Kernel messages (at boot)
[    0.000000] tdx: Guest detected
[    1.477222] Memory Encryption Features active: Intel TDX

# TSM provider
$ cat /sys/kernel/config/tsm/report/com.intel.dcap/provider
tdx_guest

# Quote header (first 16 bytes)
00000000: 0400 0200 8100 0000 ...
         └──┘ └──┘ └───────┘
          v4  ECDSA  TDX(0x81)
```

## Cleanup

```bash
terraform destroy
```

Or manually:
```bash
gcloud compute instances delete INSTANCE_NAME --zone=ZONE
```

