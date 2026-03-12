---
title: "Troubleshooting: Host Setup"
description: "Solutions for common issues during TDX BIOS configuration, software installation, and SGX verification"
section: "Troubleshooting"
stepNumber: null
totalSteps: null
isAppendix: true
tags:
  - troubleshooting
  - tdx
  - sgx
  - host-setup
  - next-steps
  - resources
difficulty: intermediate
estimatedTime: "reference"
lastUpdated: 2026-03-07
---

# Troubleshooting: Host Setup

This appendix consolidates troubleshooting content from the Host Setup tutorials. For inline notes and warnings, see the individual tutorials.

---

## TDX BIOS Configuration Issues

Before troubleshooting, verify your current TDX status:

```bash
# Check TDX parameter
cat /sys/module/kvm_intel/parameters/tdx

# Check TME status
sudo dmesg | grep -i tme

# Check TDX initialization
sudo dmesg | grep -i tdx
```

### TDX Still Shows "N" After BIOS Config

**Possible causes:**
1. BIOS settings not saved properly
2. TME not enabled
3. Secure Boot interfering (try disabling)
4. SEAM loader not enabled

**Solution:**
- Re-enter BIOS and verify all settings
- Ensure TME and TME-MT are both enabled
- Check that SEAM Loader is enabled
- Try disabling Secure Boot temporarily

### "x86/tme: not enabled by BIOS"

**Cause:** TME not enabled in BIOS

**Solution:**
- Enter BIOS
- Navigate to CPU Configuration → Memory Encryption
- Enable TME and TME-MT
- Save and reboot

### TME-MT Option Greyed Out/Disabled

**Cause:** CPU Physical Address Limit is enabled (restricts to 46-bit addressing)

**Why this happens:** Intel MKTME (Multi-Key Total Memory Encryption), which TME-MT uses, requires upper address bits for encryption key IDs. The 46-bit physical address limit reserves these bits, preventing TME-MT from functioning. Many server BIOS configurations enable this by default for older OS/hypervisor compatibility.

**Solution:**
1. Enter BIOS
2. Navigate to: **Advanced → CPU Configuration** (or **Processor Configuration**)
3. Find: **"Limit CPU Physical Address to 46 bits"** or **"Physical Address Limit"**
   - May also be labeled: "Hyper-V Physical Address Limit" or "Address Width Limit"
4. **Disable** this setting
5. Save and reboot
6. Re-enter BIOS - TME-MT should now be selectable
7. Enable TME-MT and continue with TDX setup

**Note:** This is documented in Dell, ASUS, and other server vendor documentation. Enabling the 46-bit limit automatically disables TME-MT capabilities.

### No SEAM Firmware After Enabling TDX

**What this actually means:**

If you see your TDX status checks and do NOT see `virt/tdx: module initialized` in dmesg, or you see TDX-related errors during boot, this indicates the SEAM (Secure Arbitration Mode) firmware module failed to load.

**Symptoms:**
- `dmesg | grep -i tdx` shows errors or no "module initialized" message
- `cat /sys/module/kvm_intel/parameters/tdx` returns `N` after enabling TDX in BIOS
- TDX-related error messages in dmesg

**Possible causes:**
1. Server firmware/BIOS needs update
2. Intel TDX SEAM module not installed in firmware
3. BIOS TDX settings not properly saved

**Solution:**
- Update server BIOS/firmware to latest version
- Check with server vendor for TDX support
- Verify BIOS settings were saved and applied (re-enter BIOS to confirm)
- Some early TDX-capable CPUs may need firmware updates

### Kernel Panic After Enabling TDX

**Cause:** Incompatible BIOS settings or outdated firmware

**Solution:**
- Boot into previous kernel from GRUB menu
- Update server BIOS/firmware
- Check Intel and server vendor documentation for specific TDX requirements

### TDX Option Not Visible in BIOS

**Cause:** TME-MT must be enabled first, or CPU doesn't support TDX.

**Solution:**
1. Ensure TME and TME-MT are both enabled first
2. Verify your CPU supports TDX (check [TDX Hardware Verification](/tutorial/tdx-hardware-verification))
3. Update BIOS firmware if TDX should be supported

### SGX Auto MP Registration Not Available

**Cause:** SGX must be enabled first before the registration option appears.

**Solution:**
1. Enable "SW Guard Extensions (SGX)" first
2. Save and reboot if necessary
3. Return to BIOS - the Auto MP Registration option should now appear

### BIOS Settings Don't Persist After Reboot

**Cause:** BIOS battery issue, settings not saved properly, or BIOS reset.

**Solution:**
1. Ensure you're pressing F4 or explicitly selecting "Save & Exit"
2. Check for BIOS firmware updates
3. If settings keep resetting, the CMOS battery may need replacement

---

## TDX Software Installation Issues

### Script fails with permission denied

```bash
sudo chmod +x setup-tdx-host.sh
sudo ./setup-tdx-host.sh
```

### PPA fails to add

Check internet connectivity:

```bash
ping -c 3 ppa.launchpad.net
```

If behind a proxy, configure apt proxy settings.

### Kernel doesn't change after reboot

Verify GRUB configuration:

```bash
grep -r intel /etc/default/grub.d/
```

Manually select kernel in GRUB menu if needed (hold Shift during boot).

### Attestation services fail to start

This is normal before BIOS is configured. Services will start properly after full TDX enablement.

---

## TDX & SGX Verification Issues

### TDX not enabled (dmesg empty)

1. Verify BIOS settings are saved (re-enter BIOS and check)
2. Ensure TME-MT is enabled (prerequisite for TDX)
3. Check that TDX SEAM Loader is enabled

### SGX devices missing

1. Verify SGX is enabled in BIOS
2. Check that SGX Auto MP Registration is enabled
3. Try a cold boot (full power off, not just reboot)

### KVM TDX parameter is N

1. Ensure you're running the Intel kernel (`uname -r` shows `intel`)
2. Check dmesg for TDX initialization errors
3. Verify BIOS TDX settings

---

## Next Steps After TDX Is Enabled

Now that TDX is enabled on your host, you can:

### 1. Create TDX Guest VMs

- Use QEMU/libvirt to launch Trust Domains
- Configure TD guest images with TDX support

### 2. Test TDX Functionality

- Run Canonical's test suite: `cd tests && ./test-tdx.sh`
- Verify TD attestation

### 3. Test TDX Attestation

- Verify attestation quote generation
- Test remote attestation flow
- Validate DCAP configuration

### 4. Deploy dstack

- Install dstack SDK
- Deploy confidential applications to TDX VMs
- Use attestation API for runtime verification

---

## System Requirements Reference

### Hardware

- Intel Xeon Scalable (5th Gen Emerald Rapids or 4th Gen Sapphire Rapids with TDX)
  - Verify TDX support at https://ark.intel.com
- Memory: At least 2 channels populated per socket (identical DIMMs recommended)
- BIOS with TDX support

### Software

- Ubuntu 24.04 LTS (Noble)
- linux-image-intel 6.8.0-1028 or later
- QEMU 8.2.2+tdx1.1 or later
- libvirt 10.0.0+tdx1.2 or later
- OVMF 2024.02+tdx1.0 or later

### BIOS Settings

- TME enabled
- TME-MT enabled
- TDX enabled
- SEAM Loader enabled
- SGX enabled (required for KMS attestation)
- SGX Auto MP Registration enabled (required for KMS)
- **Physical Address Limit: DISABLED** (critical for TME-MT)

---

## Additional Resources

### Official Documentation

- **Intel ARK (Processor Verification):** https://ark.intel.com
- **Intel TDX Enabling Guide:** https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/
- **Canonical TDX Documentation:** https://github.com/canonical/tdx
- **Intel TDX Overview:** https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
- **Ubuntu TDX Wiki:** https://discourse.ubuntu.com/t/intel-tdx-trust-domain-extensions/

### dstack Resources

- **dstack Documentation:** https://docs.phala.com/dstack/overview
- **dstack GitHub:** https://github.com/Phala-Network/dstack

### Getting Help

If you encounter issues not covered in this troubleshooting guide:

1. Check the [Canonical TDX GitHub Issues](https://github.com/canonical/tdx/issues)
2. Review Intel's [TDX Enabling Guide](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/)
3. Consult your server vendor's documentation for TDX-specific guidance
4. Visit the [Ubuntu Discourse TDX Forum](https://discourse.ubuntu.com/t/intel-tdx-trust-domain-extensions/)
