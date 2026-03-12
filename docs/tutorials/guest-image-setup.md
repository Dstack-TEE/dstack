---
title: "Guest OS Image Setup"
description: "Download and configure guest OS images for dstack CVM deployment"
section: "dstack Installation"
stepNumber: 7
totalSteps: 8
lastUpdated: 2025-01-21
prerequisites:
  - vmm-service-setup
  - management-interface-setup
tags:
  - dstack
  - cvm
  - guest-os
  - vmm
  - image
difficulty: "intermediate"
estimatedTime: "30 minutes"
---

# Guest OS Image Setup

This tutorial guides you through setting up guest OS images for deploying Confidential Virtual Machines (CVMs) on your dstack infrastructure. Guest images contain the operating system, kernel, and firmware that run inside the TDX-protected environment.

## What You'll Configure

- **Guest OS images** - Pre-built Yocto-based images for CVMs
- **VMM image directory** - Proper organization for multiple image versions
- **Image verification** - Confirm VMM can access the images

## Understanding Guest OS Images

A dstack guest OS image consists of four core components:

| Component | Description |
|-----------|-------------|
| **OVMF.fd** | Virtual firmware (UEFI BIOS) - boots first, establishes TDX measurements |
| **bzImage** | Linux kernel compiled for TDX guests |
| **initramfs.cpio.gz** | Initial RAM filesystem with early boot scripts |
| **rootfs.cpio** | Root filesystem containing tappd and container runtime |

These components are measured by TDX hardware during boot, creating a cryptographic chain of trust that can be verified through attestation.

## Prerequisites

Before starting, ensure you have:

- Completed [VMM Service Setup](/tutorial/vmm-service-setup)
- VMM service running (with web interface at http://localhost:9080)
- At least 10GB free disk space for images


## Manual Setup

If you prefer to set up guest images manually, follow these steps.

### Step 1: Create Image Directory Structure

Create the directory where guest images will be stored:

```bash
sudo mkdir -p /var/lib/dstack/images
sudo chown root:root /var/lib/dstack/images
sudo chmod 755 /var/lib/dstack/images
```

### Step 2: Download Guest OS Image

Download the dstack guest OS image matching your installed VMM version:

```bash
# Get version from installed VMM
DSTACK_VERSION=$(dstack-vmm --version | grep -oP 'v\K[0-9]+\.[0-9]+\.[0-9]+')
echo "Installing guest images for version: $DSTACK_VERSION"

# Download the image archive
cd /tmp
wget https://github.com/Dstack-TEE/meta-dstack/releases/download/v${DSTACK_VERSION}/dstack-${DSTACK_VERSION}.tar.gz
```

Verify the download:

```bash
ls -lh dstack-${DSTACK_VERSION}.tar.gz
```

Expected output (size varies by version):

```
-rw-r--r-- 1 root root 150M Dec  2 10:00 dstack-0.5.7.tar.gz
```

### Step 3: Extract and Install Image

Extract the image archive (the tarball contains a `dstack-X.Y.Z/` directory):

```bash
# Extract image components (tarball includes versioned directory)
sudo tar -xvf dstack-${DSTACK_VERSION}.tar.gz -C /var/lib/dstack/images/
```

Verify the extracted files:

```bash
ls -la /var/lib/dstack/images/dstack-${DSTACK_VERSION}/
```

Expected output:

```
total 156000
drwxr-xr-x 2 root root     4096 Dec  2 10:05 .
drwxr-xr-x 3 root root     4096 Dec  2 10:05 ..
-rw-r--r-- 1 root root  4194304 Dec  2 10:05 OVMF.fd
-rw-r--r-- 1 root root 12345678 Dec  2 10:05 bzImage
-rw-r--r-- 1 root root 45678901 Dec  2 10:05 initramfs.cpio.gz
-rw-r--r-- 1 root root 98765432 Dec  2 10:05 rootfs.cpio
-rw-r--r-- 1 root root      512 Dec  2 10:05 metadata.json
```

### Step 4: Verify Image Metadata

Check the image metadata to understand its configuration:

```bash
cat /var/lib/dstack/images/dstack-${DSTACK_VERSION}/metadata.json | jq .
```

Expected output:

```json
{
  "version": "dstack-0.5.7",
  "cmdline": "console=hvc0 root=/dev/vda ro rootfstype=squashfs rootflags=loop ...",
  "kernel": "bzImage",
  "initrd": "initramfs.cpio.gz",
  "rootfs": "rootfs.cpio",
  "bios": "OVMF.fd",
  "rootfs_hash": "sha256:abc123...",
  "is_dev": false
}
```

### Metadata Fields Explained

| Field | Description |
|-------|-------------|
| `version` | Image version identifier |
| `cmdline` | Kernel boot parameters including rootfs hash |
| `kernel` | Kernel image filename |
| `initrd` | Initial ramdisk filename |
| `rootfs` | Root filesystem filename |
| `bios` | UEFI firmware filename |
| `rootfs_hash` | Cryptographic hash of rootfs for verification |
| `is_dev` | Whether this is a development image (allows SSH) |

### Step 5: Verify VMM Can Access Images

The VMM service should already be running from the earlier setup. Verify it can see the installed images.

### Check VMM Service Status

```bash
sudo systemctl status dstack-vmm
```

The service should be active and running.

### Verify Images via VMM Web Interface

Open the VMM Management Console in your browser (configured in [Management Interface Setup](/tutorial/management-interface-setup)):

```
https://vmm.dstack.yourdomain.com
```

You should see the installed guest images listed in the interface.

### Verify VMM is Responding

First, verify the VMM web interface is accessible:

```bash
curl -s http://127.0.0.1:9080/ | head -5
```

You should see HTML content from the VMM management interface.

### Verify Images on Disk

Check that image files are present:

```bash
ls -la /var/lib/dstack/images/dstack-*/
```

You should see OVMF.fd, bzImage, initramfs.cpio.gz, rootfs.cpio, and metadata.json.

### Verify Images on Filesystem

List installed images directly:

```bash
ls /var/lib/dstack/images/
```

Expected output:

```
dstack-0.5.7
```

Verify image contents:

```bash
ls /var/lib/dstack/images/dstack-*/
```

Each image directory should contain: OVMF.fd, bzImage, initramfs.cpio.gz, rootfs.cpio, and metadata.json.

### Step 6: Verify VMM Configuration

Ensure VMM is configured to use the correct image path. Check the configuration:

```bash
cat /etc/dstack/vmm.toml | grep -A5 "image"
```

The `image_path` should point to `/var/lib/dstack/images`.

If VMM isn't finding the images, verify the path in the configuration matches where you installed them.

## Managing Multiple Image Versions

You can have multiple image versions installed simultaneously:

```bash
# Download additional version
DSTACK_VERSION="0.5.3"
wget https://github.com/Dstack-TEE/meta-dstack/releases/download/v${DSTACK_VERSION}/dstack-${DSTACK_VERSION}.tar.gz

# Extract to images directory (tarball already contains dstack-X.Y.Z/ folder)
sudo tar -xvf dstack-${DSTACK_VERSION}.tar.gz -C /var/lib/dstack/images/

# Restart VMM to pick up the new image
sudo systemctl restart dstack-vmm
```

> **Important:** VMM must be restarted after adding new images for them to appear in the management interface.

List all installed images:

```bash
ls -la /var/lib/dstack/images/
```

Or list them on the filesystem:

```bash
ls /var/lib/dstack/images/
```

When deploying applications, specify which image version to use in the docker-compose.yml.

## Troubleshooting

For detailed solutions, see the [dstack Installation Troubleshooting Guide](/tutorial/troubleshooting-dstack-installation#guest-image-setup-issues):

- [Images not appearing in VMM](/tutorial/troubleshooting-dstack-installation#images-not-appearing-in-vmm)
- [Image download fails](/tutorial/troubleshooting-dstack-installation#image-download-fails)
- [Image metadata missing](/tutorial/troubleshooting-dstack-installation#image-metadata-missing)
- [VMM service not running](/tutorial/troubleshooting-dstack-installation#vmm-service-not-running)

## Verification Checklist

Before proceeding, verify you have:

- [ ] Created image directory structure
- [ ] Downloaded guest OS image
- [ ] Extracted image components (OVMF.fd, bzImage, initramfs, rootfs)
- [ ] Verified metadata.json exists and is valid
- [ ] Confirmed VMM service is running
- [ ] Verified VMM web interface is accessible

### Quick verification script

```bash
echo "Image Directory: $([ -d /var/lib/dstack/images ] && echo 'exists' || echo 'missing')"
echo "Guest Images: $(ls -d /var/lib/dstack/images/dstack-* 2>/dev/null | wc -l) found"
echo "VMM Service: $(sudo systemctl is-active dstack-vmm)"
echo "VMM Web UI: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9080/ 2>/dev/null || echo 'unreachable')"
echo "Image files:"
ls /var/lib/dstack/images/dstack-*/metadata.json 2>/dev/null || echo "  No images found"
```

Image directory should exist with at least one guest image, VMM service should be active, and VMM web UI should return HTTP 200.

## Understanding the Boot Process

When a CVM starts, the following sequence occurs:

```
1. VMM launches QEMU with TDX enabled
           ↓
2. OVMF (Virtual Firmware) boots
   - Measures itself into MRTD
   - Initializes virtual hardware
           ↓
3. Linux Kernel loads
   - Measured into RTMR1
   - Kernel cmdline measured into RTMR2
           ↓
4. Initramfs runs
   - Measured into RTMR2
   - Mounts rootfs
           ↓
5. Tappd starts
   - Guest daemon for attestation
   - Provides /var/run/tappd.sock
           ↓
6. Docker containers start
   - Application workloads
   - Can request TDX quotes via tappd
```

Each step creates cryptographic measurements that can be verified through TDX attestation.

## Next Steps

With guest images configured and VMM able to access them, you're ready to deploy your first application. The next tutorial covers deploying a Hello World application to verify your setup works correctly.

## Additional Resources

- [meta-dstack Repository](https://github.com/Dstack-TEE/meta-dstack)
- [dstack GitHub Repository](https://github.com/Dstack-TEE/dstack)
- [Yocto Project](https://www.yoctoproject.org/)
- [TDX Guest Architecture](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
