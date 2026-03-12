---
title: "TDX & SGX Verification"
description: "Verify TDX and SGX are properly enabled and registered with Intel"
section: "Host Setup"
stepNumber: 4
totalSteps: 4
lastUpdated: 2025-12-07
prerequisites:
  - tdx-software-installation
tags:
  - tdx
  - sgx
  - verification
  - attestation
difficulty: "beginner"
estimatedTime: "15 minutes"
---

# TDX & SGX Verification

This tutorial verifies that TDX and SGX are properly enabled after BIOS configuration and software installation. Both technologies must be working for dstack KMS attestation.

## Prerequisites

Before starting, ensure you have:

- Completed [TDX Software Installation](/tutorial/tdx-software-installation)
- Rebooted into the TDX-enabled kernel
- SSH access to the server


## Manual Verification

If you prefer to verify manually, or need to troubleshoot specific issues, follow the steps below.

## Part 1: Verify TDX Kernel

First, confirm you're running the TDX-enabled kernel.

### Check Kernel Version

```bash
uname -r
```

**Expected output:**

```
6.8.0-1028-intel
```

The kernel version should contain `intel`. If you see `generic`, the system didn't boot into the TDX kernel - check GRUB configuration.

## Part 2: Verify Memory Encryption (TME/MKTME)

TDX requires Total Memory Encryption (TME) to be enabled.

### Check TME Status

```bash
sudo dmesg | grep -i tme
```

**Expected output:**

```
[    0.000000] x86/tme: enabled by BIOS
[    0.000000] x86/mktme: enabled by BIOS
[    0.000000] x86/mktme: 63 KeyIDs available
```

**What this means:**

| Message | Meaning |
|---------|---------|
| `x86/tme: enabled by BIOS` | Base memory encryption is active |
| `x86/mktme: enabled by BIOS` | Multi-Key TME (TME-MT) is active |
| `63 KeyIDs available` | 63 encryption keys for Trust Domains |

**If TME is not enabled:**

```
[    0.000000] x86/tme: not enabled by BIOS
```

This means BIOS configuration is incomplete. Return to [TDX & SGX BIOS Configuration](/tutorial/tdx-bios-configuration).

## Part 3: Verify TDX Module

Check that the TDX module initialized successfully.

### Check TDX Initialization

```bash
sudo dmesg | grep -i tdx
```

**Expected output:**

```
[   58.680744] virt/tdx: BIOS enabled: private KeyID range [32, 64)
[   58.681739] virt/tdx: Disable ACPI S3. Turn off TDX in the BIOS to use ACPI S3.
[  245.715035] virt/tdx: TDX module: attributes 0x0, vendor_id 0x8086, major_version 1, minor_version 5, build_date 20240725, build_num 784
[  245.715041] virt/tdx: CMR: [0x100000, 0x77800000)
[  245.715044] virt/tdx: CMR: [0x100000000, 0x407a000000)
...
[  249.751098] virt/tdx: 4202516 KB allocated for PAMT
[  249.751110] virt/tdx: module initialized
```

**Key indicators:**

| Message | Meaning |
|---------|---------|
| `BIOS enabled: private KeyID range` | TDX is enabled in BIOS |
| `TDX module: ... major_version 1` | TDX module loaded |
| `CMR: [...]` | Convertible Memory Regions configured |
| `PAMT allocated` | Physical Address Metadata Table ready |
| `module initialized` | TDX is fully operational |

**If TDX output is empty:** BIOS configuration is incomplete or the kernel doesn't have TDX support.

### Check KVM TDX Parameter

```bash
cat /sys/module/kvm_intel/parameters/tdx
```

**Expected output:**

```
Y
```

- `Y` = TDX is enabled in KVM
- `N` = TDX is not enabled (BIOS or kernel issue)

### Check TDX CPU Flags

```bash
grep -o 'tdx[^ ]*' /proc/cpuinfo | sort -u
```

**Expected output:**

```
tdx_host_platform
tdx_pw_mce
```

**What the flags mean:**

| Flag | Meaning |
|------|---------|
| `tdx_host_platform` | System is running as TDX host (correct!) |
| `tdx_pw_mce` | TDX Power Management and Machine Check support |

> **Note:** The `tdx_guest` flag only appears inside TDX guest VMs, not on the host.

## Part 4: Verify SGX

SGX is required for KMS attestation. The KMS uses SGX to generate quotes proving your platform is genuine Intel hardware.

### Check SGX Devices

```bash
ls -la /dev/sgx*
```

**Expected output:**

```
crw-rw---- 1 root sgx  10, 125 Dec  7 10:30 /dev/sgx_enclave
crw------- 1 root root 10, 126 Dec  7 10:30 /dev/sgx_provision
crw-rw---- 1 root sgx  10, 124 Dec  7 10:30 /dev/sgx_vepc
```

**Device purposes:**

| Device | Purpose |
|--------|---------|
| `/dev/sgx_enclave` | Create and run SGX enclaves |
| `/dev/sgx_provision` | Provision attestation keys |
| `/dev/sgx_vepc` | Virtual EPC for SGX VMs |

**If devices are missing:** SGX is not enabled in BIOS. Return to [TDX & SGX BIOS Configuration](/tutorial/tdx-bios-configuration).

### Check SGX CPU Flags

```bash
grep -o 'sgx[^ ]*' /proc/cpuinfo | sort -u
```

**Expected output:**

```
sgx
sgx_lc
```

**Flag meanings:**

| Flag | Meaning |
|------|---------|
| `sgx` | SGX is supported |
| `sgx_lc` | SGX Launch Control is available |

### Check SGX Kernel Messages

```bash
sudo dmesg | grep -i sgx
```

**Expected output:**

```
[    0.428531] sgx: EPC section 0x1020c00000-0x107fffffff
[    0.428535] sgx: EPC section 0x2020c00000-0x207fffffff
```

This shows SGX Enclave Page Cache (EPC) memory is allocated.

## Verification Summary

Run this command for a quick status check:

```bash
echo "=== TDX & SGX Verification Summary ===" && \
echo && \
echo "Kernel: $(uname -r)" && \
echo && \
echo "TME Status:" && \
sudo dmesg | grep -i "x86/tme" | head -1 && \
echo && \
echo "TDX Status:" && \
(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null && echo " (KVM TDX enabled)") || echo "N (KVM TDX not available)" && \
echo && \
echo "SGX Devices:" && \
ls /dev/sgx* 2>/dev/null || echo "Not found"
```

**All checks should pass before proceeding to dstack deployment.**

## Troubleshooting

For detailed solutions, see the [Host Setup Troubleshooting Guide](/tutorial/troubleshooting-host-setup#tdx--sgx-verification-issues):

- [TDX not enabled (dmesg empty)](/tutorial/troubleshooting-host-setup#tdx-not-enabled-dmesg-empty)
- [SGX devices missing](/tutorial/troubleshooting-host-setup#sgx-devices-missing)
- [KVM TDX parameter is N](/tutorial/troubleshooting-host-setup#kvm-tdx-parameter-is-n)

## Next Steps

With TDX and SGX verified, you're ready to proceed with dstack deployment:

- [System Baseline Dependencies](/tutorial/system-baseline-dependencies) - Install system dependencies
- [Rust Toolchain Installation](/tutorial/rust-toolchain-installation) - Install Rust for building dstack

## Additional Resources

- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [Intel SGX Documentation](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html)
- [Canonical TDX Repository](https://github.com/canonical/tdx)
