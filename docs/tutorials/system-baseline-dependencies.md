---
title: "System Baseline & Dependencies"
description: "Update the host system and install required build dependencies for dstack"
section: "dstack Installation"
stepNumber: 1
totalSteps: 8
lastUpdated: 2025-12-07
prerequisites:
  - tdx-bios-configuration
tags:
  - host-setup
  - dependencies
  - build-tools
  - system-update
difficulty: beginner
estimatedTime: 10-15 minutes
---

# System Baseline & Dependencies

Before building dstack components, you need to prepare the host system with updated packages and required build dependencies.

## Prerequisites

Before starting, ensure you have:

- Completed [TDX BIOS Configuration](/tutorial/tdx-bios-configuration)
- SSH access to your TDX-enabled server
- Root or sudo privileges


## What Gets Installed

| Package | Purpose |
|---------|---------|
| `build-essential` | GCC compiler, make, and essential build tools |
| `chrpath` | Modify rpath in ELF binaries |
| `diffstat` | Produce histogram of diff output |
| `lz4` | Fast compression algorithm |
| `wireguard-tools` | WireGuard VPN utilities for secure networking |
| `xorriso` | ISO 9660 filesystem tool for guest images |
| `git` | Version control for cloning dstack repository |
| `curl` | HTTP client for downloading files |
| `pkg-config` | Helper tool for compiling applications |
| `libssl-dev` | SSL development libraries |


---

## Manual Installation

If you prefer to install dependencies manually, follow these steps.

### Step 1: Connect to Your Server

```bash
ssh ubuntu@YOUR_SERVER_IP
```

### Step 2: Update System Packages

```bash
sudo apt update && sudo apt upgrade -y
```

This may take a few minutes. If prompted about kernel updates or service restarts, accept the defaults.

### Step 3: Install Build Dependencies

```bash
sudo apt install -y \
  build-essential \
  chrpath \
  diffstat \
  lz4 \
  wireguard-tools \
  xorriso \
  git \
  curl \
  pkg-config \
  libssl-dev
```

### Step 4: Verify Installations

```bash
# Check compiler
gcc --version

# Check make
make --version

# Check git
git --version

# Check additional tools
wg --version
xorriso --version
lz4 --version
```

---

## Troubleshooting

For detailed solutions, see the [dstack Installation Troubleshooting Guide](/tutorial/troubleshooting-dstack-installation#system-baseline-dependencies-issues):

- [Package Installation Fails](/tutorial/troubleshooting-dstack-installation#package-installation-fails)
- [OpenMetal Grub Error](/tutorial/troubleshooting-dstack-installation#openmetal-grub-error)
- [Kernel Upgrade Prompts](/tutorial/troubleshooting-dstack-installation#kernel-upgrade-prompts)

---

## Next Steps

With system dependencies installed, proceed to:

- [Rust Toolchain Installation](/tutorial/rust-toolchain-installation) - Install Rust and Cargo for building dstack components
