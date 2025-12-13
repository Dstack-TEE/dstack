# Dstack on Google Cloud Platform

Deploy Dstack with Intel TDX Confidential Computing on GCP.

## Prerequisites

- Google Cloud account with billing enabled
- `gcloud` CLI authenticated
- Terraform >= 1.5.0

## Supported Machines

| Type | TEE | Zones |
|------|-----|-------|
| `c3-standard-*` | Intel TDX | us-central1-a/b/c, us-east1-c/d, europe-west4-a/b/c |
| `a3-highgpu-1g` | Intel TDX + H100 | us-central1-a, us-east5-a, europe-west4-c |

## Quick Start

```bash
# Authenticate
gcloud auth login
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
gcloud services enable compute.googleapis.com

# Deploy
cd deploy/gcp/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars
terraform init && terraform apply

# Verify
./test.sh <VM_IP> [SSH_KEY]
```

## Verify TDX

```bash
ssh ubuntu@<VM_IP>

# TDX device
ls -la /dev/tdx_guest

# Kernel detection
sudo dmesg | grep tdx

# Memory encryption
sudo dmesg | grep "Memory Encryption"

# TSM quote
dd if=/dev/zero bs=1 count=64 | sudo tee /sys/kernel/config/tsm/report/com.intel.dcap/inblob >/dev/null
sudo cat /sys/kernel/config/tsm/report/com.intel.dcap/outblob | xxd | head -5
```

## Real vs Simulated

| Check | Simulated | Real TDX |
|-------|-----------|----------|
| `/dev/tdx_guest` | Missing | Present |
| `dmesg "tdx: Guest"` | Missing | Present |
| TSM provider | N/A | `tdx_guest` |
| Quote TEE type | N/A | `0x81000000` |

## Limitations

- No Local SSD (use pd-balanced)
- No live migration
- H100 requires quota request

## Cost

| Resource | $/hr |
|----------|------|
| c3-standard-8 | ~$0.40 |
| a3-highgpu-1g | ~$3.50 |

## Cleanup

```bash
terraform destroy
```
