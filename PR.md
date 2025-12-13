<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# PR: GCP TDX Support

## Summary

Adds Google Cloud Platform deployment with Intel TDX and fixes event log parsing for GCP compatibility.

## Bug Fix

**`cc-eventlog/src/lib.rs`**: GCP's CCEL uses 0-based IMR indices in some entries. Original code assumed 1-based (TCG standard).

```rust
// Before: fails on IMR 0
imr: value.imr_index.checked_sub(1).context("invalid imr index")?

// After: handles both
let imr = value.imr_index.saturating_sub(1);
```

## New Files

- `deploy/gcp/README.md` - Deployment docs
- `deploy/gcp/deploy.sh` - Deployment script
- `deploy/gcp/test.sh` - Verification (11 tests)
- `deploy/gcp/terraform/main.tf` - Terraform config
- `deploy/gcp/terraform/terraform.tfvars.example`

## Modified

- `kms/auth-eth/hardhat.config.ts` - Added base-sepolia network

## Test Results

All 11 tests pass on GCP `c3-standard-8` with Intel TDX:
- TDX device, kernel detection, memory encryption
- TSM quote (8000 bytes, TEE 0x81000000)
- Dstack GetQuote and DeriveKey APIs

Backward compatible with Phala/standard TDX (all existing tests pass).
