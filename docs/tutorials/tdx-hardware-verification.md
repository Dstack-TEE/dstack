---
title: "TDX Hardware Verification"
description: "Verify your hardware supports Intel TDX and check memory configuration requirements"
section: "Host Setup"
stepNumber: 1
totalSteps: 4
lastUpdated: 2025-12-07

tags:
  - "tdx"
  - "hardware"
  - "verification"
  - "confidential-computing"
difficulty: "intermediate"
estimatedTime: "15 minutes"
---

# TDX Hardware Verification

This tutorial walks you through verifying your hardware supports Intel Trust Domain Extensions (TDX). TDX is Intel's hardware-based confidential computing technology that allows you to run trusted execution environments (TEEs) for secure, isolated workloads.

## What is Intel TDX?

Intel TDX (Trust Domain Extensions) is a hardware-based technology that creates isolated virtual machine environments called Trust Domains (TDs). These TDs provide:

- **Hardware-level isolation** - VMs are isolated from the hypervisor and other VMs
- **Memory encryption** - All TD memory is encrypted with per-TD keys
- **Remote attestation** - Cryptographic proof of TD integrity
- **Minimal TCB** - Reduced trusted computing base for better security

## Prerequisites Check

Before beginning, verify your hardware supports TDX:

### Supported Processors

Intel TDX is available on:
- **Intel Xeon Scalable (5th Gen)** - Emerald Rapids (2024+)
- **Intel Xeon Scalable (4th Gen)** - Sapphire Rapids (some SKUs)

#### Verify TDX Support on Intel ARK

Before beginning, **verify your specific processor model supports TDX** using Intel ARK:

1. Visit **https://ark.intel.com**
2. Search for your processor model (e.g., "Xeon Gold 6530")
3. Scroll down to **Security & Reliability** section
4. Look for: **Intel® Trust Domain Extensions (Intel® TDX)** → **Yes**

**Example for Intel Xeon Gold 6530:**
- TDX Support: **Yes** ✓
- Generation: 5th Gen (Emerald Rapids)
- Release Date: Q1 2024

#### Check Your Current Processor

Check your CPU model:

```bash
grep "model name" /proc/cpuinfo | head -1
```

**Example output:**
```
model name	: INTEL(R) XEON(R) GOLD 6530
```

The Intel Xeon Gold 6530 is a 5th generation processor (Emerald Rapids), which **does support TDX**.

**Note:** Not all Xeon processors support TDX. Always verify on Intel ARK before proceeding.

### Supported Operating Systems

This tutorial covers:
- **Ubuntu 24.04 LTS (Noble)** - Recommended
- Ubuntu 25.04 (Plucky) - Also supported

**Note:** Ubuntu 24.10 (Oracular) and 23.10 (Mantic) are no longer supported by Canonical's TDX PPA.

### Memory Configuration Requirements

**CRITICAL:** Intel TDX has specific memory configuration requirements that must be met:

#### Memory Channel Requirements

According to Intel's TDX Enabling Guide, your server must have:

- **Minimum:** Memory populated in at least **2 channels per socket**
- **Recommended:** Memory populated in **all available channels** for best performance
- **Configuration:** DIMMs should be identical (same capacity, speed, manufacturer)

**Example valid configurations:**
- ✓ 2 DIMMs per socket (minimum)
- ✓ 4 DIMMs per socket (better)
- ✓ 8 DIMMs per socket (optimal for most systems)

**Invalid configurations:**
- ✗ Single DIMM per socket
- ✗ Mixed DIMM capacities or speeds
- ✗ Asymmetric channel population

#### Verify Your Memory Configuration

Check your current memory configuration:

```bash
sudo dmidecode -t memory | grep -E "Size:|Locator:|Speed:|Type:"
```

**For detailed memory requirements, refer to:**
https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/03/hardware_selection/

**Important:** If your memory configuration doesn't meet these requirements, TDX may fail to initialize even after proper BIOS configuration. Consult with your server vendor if you need to adjust memory configuration.

## Next Steps

Once you've verified your hardware meets all TDX requirements:
- Processor supports TDX (verified on Intel ARK)
- Ubuntu 24.04 LTS installed
- Memory configuration meets requirements (minimum 2 channels per socket)

You're ready to proceed to [TDX & SGX BIOS Configuration](/tutorial/tdx-bios-configuration) where you'll configure BIOS settings for TDX and SGX.

## Additional Resources

- **Intel ARK (Processor Verification):** https://ark.intel.com
- **Intel TDX Enabling Guide:** https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/
- **Canonical TDX Documentation:** https://github.com/canonical/tdx
