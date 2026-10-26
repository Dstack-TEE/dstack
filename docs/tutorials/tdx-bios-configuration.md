---
title: "TDX & SGX BIOS Configuration"
description: "Configure BIOS settings for TDX and SGX, including Auto MP Registration for KMS attestation"
section: "Host Setup"
stepNumber: 2
totalSteps: 4
prerequisites:
  - tdx-hardware-verification
tags:
  - tdx
  - sgx
  - bios
  - configuration
  - tme
  - attestation
difficulty: "intermediate"
estimatedTime: "20 minutes"
lastUpdated: 2025-12-07
---

# TDX & SGX BIOS Configuration

This tutorial covers configuring BIOS settings to enable both TDX (Trust Domain Extensions) and SGX (Software Guard Extensions). Both are required for running dstack with KMS attestation.

## Why Both TDX and SGX?

| Technology | Purpose |
|------------|---------|
| **TDX** | Provides hardware-isolated virtual machines (Trust Domains) with encrypted memory |
| **SGX** | Required for KMS attestation - generates cryptographic quotes proving your platform is genuine Intel hardware |

**Important:** SGX Auto MP Registration must be enabled for the KMS to bootstrap with the local key provider. Without this, KMS cannot generate valid attestation quotes.

## Access BIOS/UEFI

You'll need to access your server's BIOS setup utility.

### Option 1: IPMI/BMC (Remote Management)

Most servers have remote management interfaces:

- Dell: iDRAC
- HP: iLO
- Supermicro: IPMI
- Lenovo: XClarity
- OpenMetal: Central Dashboard → IPMI Console

Access the web interface and use the remote console/KVM feature, or use CLI:

```bash
# Example with ipmitool (if you have IPMI credentials)
ipmitool -I lanplus -H YOUR_BMC_IP -U admin -P password sol activate
```

### Option 2: Physical Access

1. Reboot server
2. Press appropriate key during POST:
   - Dell: F2
   - HP: F9 or F10
   - Supermicro: Delete
   - Most others: F2 or Delete

## Required BIOS Settings

Configure all settings in a single BIOS session to avoid multiple reboots.

### Step 0: Disable Physical Address Limit (IMPORTANT!)

**Before enabling TME-MT, you must first disable the CPU physical address limit.**

Navigate to: **Advanced → CPU Configuration** (or **Processor Configuration**)

| Setting | Value | Notes |
|---------|-------|-------|
| **Limit CPU Physical Address to 46 bits** | **Disabled** | May also be labeled "Physical Address Limit" or "Hyper-V Physical Address Limit" |

> **Why this matters:** The 46-bit address limit prevents TME-MT from working. Intel MKTME needs the upper address bits for encryption key IDs. If you don't disable this first, TME-MT will be greyed out and unselectable.

> **Note:** If this setting doesn't exist on your system, it may already be disabled or not applicable. Proceed to the next step.

### Step 1: Memory Encryption Settings

Navigate to: **Advanced → CPU Configuration → Memory Encryption** (or similar path)

| Setting | Value | Notes |
|---------|-------|-------|
| **Total Memory Encryption (TME)** | Enabled | Base memory encryption |
| **Total Memory Encryption Multi-Tenant (TME-MT)** | Enabled | Multi-key encryption for TDX |
| **TME-MT Memory Integrity** | **Disabled** | Impacts performance if enabled |
| **TME-MT/TDX Key Split** | 1 (or higher) | Allocates keys for TDX |

### Step 2: Intel TDX Settings

Navigate to: **Advanced → CPU Configuration** (may be under Security submenu)

| Setting | Value | Notes |
|---------|-------|-------|
| **Trust Domain Extension (TDX)** | Enabled | Main TDX enable |
| **TDX Secure Arbitration Mode Loader (SEAM Loader)** | Enabled | Required for TDX module |

After enabling, you should see key allocation information:

- **TME-MT Keys:** 31 (or similar)
- **TDX Keys:** 32 (or similar)

### Step 3: Intel SGX Settings (REQUIRED for KMS)

**SGX is required for KMS attestation**, even on TDX systems. The KMS uses SGX to generate attestation quotes that prove your platform is genuine Intel hardware registered with Intel's Provisioning Certification Service.

Navigate to: **Advanced → CPU Configuration → Software Guard Extension (SGX)**

Enable these settings:

| Setting | Value | Notes |
|---------|-------|-------|
| **SW Guard Extensions (SGX)** | Enabled | Main SGX enable |
| **SGX Auto MP Registration** | **Enabled** | **CRITICAL** - Registers platform with Intel |
| SGX Factory Reset | Disabled | Don't reset SGX keys |
| **SGX QoS** | Enabled | Quality of Service |
| **PRM Size for SGX** | Auto | Memory allocation (or specific size) |
| **Select Owner EPOCH Input Type** | SGX Owner EPOCH activated | |
| **SGXLEPUBKEYHASHx Write Enable** | Enabled | Allows launch enclave configuration |

> **Why SGX Auto MP Registration is critical:** This setting enables automatic registration of your platform with Intel's Provisioning Certification Service (PCS). On first boot after enabling this setting, your system will register with Intel and obtain Platform Certification Keys (PCKs). Without this registration, the KMS cannot generate valid attestation quotes, and the local_key_provider will fail to bootstrap.

### Step 4: Save and Exit

1. Press **F4** (or navigate to Save & Exit)
2. Confirm save changes
3. System will reboot

> **Having trouble?** See [Host Setup Troubleshooting](/tutorial/troubleshooting-host-setup#tdx-bios-configuration-issues) for common BIOS configuration issues like greyed-out options or settings not persisting.

## Next Steps

After saving BIOS settings and rebooting, continue to:

- [TDX Software Installation](/tutorial/tdx-software-installation) - Install the TDX kernel and software stack

## Additional Resources

- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [Intel SGX Documentation](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html)
- [Canonical TDX Repository](https://github.com/canonical/tdx)
