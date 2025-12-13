# PR: Add Google Cloud Platform (GCP) Support with Intel TDX

## Summary

This PR adds support for deploying Dstack on Google Cloud Platform using Intel TDX Confidential Computing. It includes Terraform configurations, deployment scripts, documentation, and a critical bug fix for GCP's event log format.

## Changes

### Bug Fix: GCP TDX Event Log Compatibility

**File:** `cc-eventlog/src/lib.rs`

GCP's TDX implementation uses 0-based IMR indices in some event log entries, while the original code assumed all IMR indices are 1-based (TCG standard). This caused `GetQuote` to fail with "invalid imr index" error.

**Fix:**
```rust
// TCG event logs use 1-based IMR indices (1-4), while TDX RTMRs are 0-based (0-3).
// Standard conversion: TCG IMR 1 → RTMR 0, TCG IMR 2 → RTMR 1, etc.
// However, some cloud platforms (notably GCP) may include events with IMR index 0.
// Rather than failing on these, we pass them through as RTMR 0.
let imr = value.imr_index.saturating_sub(1);
```

This uses `saturating_sub` which handles both cases:
- Standard TCG (IMR 1-4): Converts correctly to RTMR 0-3
- GCP edge case (IMR 0): Maps to RTMR 0 instead of failing

### New Files

#### `deploy/gcp/README.md`
- Comprehensive documentation for GCP deployment
- Supported configurations (Intel TDX, GPU+TEE)
- Quick start guide
- Architecture diagram
- Cost estimates and limitations

#### `deploy/gcp/terraform/main.tf`
- Terraform configuration for GCP Confidential VM
- Creates VPC network with proper firewall rules
- Deploys `c3-standard-8` with Intel TDX enabled
- Startup script for automated Dstack installation

#### `deploy/gcp/terraform/terraform.tfvars.example`
- Example configuration file with all variables documented
- Includes zone recommendations for Intel TDX

#### `deploy/gcp/deploy.sh`
- Interactive deployment script
- Prerequisites checking (gcloud, terraform, auth)
- Deploy and destroy commands

#### `deploy/gcp/test.sh`
- Comprehensive verification script (12 tests)
- Tests SSH, TDX device, Docker, Dstack APIs
- Verifies real TDX attestation (not simulated)

### Modified Files

#### `kms/auth-eth/hardhat.config.ts`
- Added `base-sepolia` network configuration
  - Uses PublicNode RPC endpoint
  - Chain ID: 84532

## Technical Details

### GCP Confidential Computing Configuration

```hcl
confidential_instance_config {
  confidential_instance_type  = "TDX"
  enable_confidential_compute = true
}

scheduling {
  on_host_maintenance = "TERMINATE"  # Required for TDX
}
```

### Supported Zones (Intel TDX on C3)

| Region | Zones |
|--------|-------|
| US | us-central1-a/b/c, us-east1-c/d, us-east4-a/c, us-west1-a/b |
| Europe | europe-west4-a/b/c, europe-west9-a/b |
| Asia | asia-southeast1-a/b/c, asia-northeast1-b, asia-south1-b |

## Testing

Verified on GCP with Intel TDX (`c3-standard-8`):

| Test | Result |
|------|--------|
| SSH connectivity | ✅ |
| TDX device (`/dev/tdx_guest`) | ✅ |
| Kernel TDX detection | ✅ |
| Memory encryption (Intel TDX) | ✅ |
| CPU `tdx_guest` flag | ✅ |
| TSM provider | ✅ |
| Real TDX quote via TSM | ✅ |
| Docker service | ✅ |
| Dstack guest-agent | ✅ |
| Dstack sockets (3) | ✅ |
| Dstack GetQuote API | ✅ |
| Dstack DeriveKey API | ✅ |

**All 12 tests passed.**

### Backward Compatibility

- Phala sample CCEL uses IMR 1-4 (standard format) ✅
- `saturating_sub(1)` is backward compatible ✅
- All existing `cc-eventlog` tests pass ✅
- All `guest-agent` tests pass (15/15) ✅

## Breaking Changes

None. This is additive functionality with a backward-compatible bug fix.

## Dependencies

- Terraform >= 1.5.0
- Google Cloud SDK (gcloud)
- GCP project with Compute Engine API enabled

## Checklist

- [x] Core bug fix for GCP event log compatibility
- [x] Terraform configuration for GCP
- [x] Intel TDX Confidential VM setup
- [x] Startup script for automated Dstack installation
- [x] Network and firewall configuration
- [x] Documentation with architecture diagram
- [x] Base Sepolia network support in Hardhat
- [x] Tested on real GCP infrastructure
- [x] Real TDX attestation verified
- [x] Backward compatibility verified

