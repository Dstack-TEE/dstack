---
title: "Clone & Build dstack-vmm"
description: "Clone the dstack repository and build the Virtual Machine Monitor (VMM) component"
section: "dstack Installation"
stepNumber: 3
totalSteps: 8
lastUpdated: 2025-12-07
prerequisites:
  - rust-toolchain-installation
tags:
  - dstack
  - vmm
  - cargo
  - build
  - compilation
difficulty: "intermediate"
estimatedTime: "20 minutes"
---

# Clone & Build dstack-vmm

This tutorial guides you through cloning the dstack repository and building the Virtual Machine Monitor (VMM) component. The VMM is the core component that manages TEE virtual machines on your host system.

## Prerequisites

Before starting, ensure you have:

- Completed [Rust Toolchain Installation](/tutorial/rust-toolchain-installation)
- SSH access to your TDX-enabled server
- At least 2GB free disk space


## What Gets Built

| Binary | Purpose |
|--------|---------|
| `dstack-vmm` | Virtual Machine Monitor - manages TDX-protected VMs |
| `dstack-supervisor` | Process supervisor - manages processes within VMs |

Both binaries are installed to `/usr/local/bin/` for system-wide access.

---

## Manual Build

If you prefer to build manually, follow these steps.

### Step 1: Connect to Your Server

```bash
ssh ubuntu@YOUR_SERVER_IP
```

All build commands should be run as the `ubuntu` user. Only the final installation step requires `sudo`.

### Step 2: Verify dstack Repository

The dstack repository should already be cloned and checked out at v0.5.7 from [Gramine Key Provider](/tutorial/gramine-key-provider):

```bash
cd ~/dstack
git describe --tags
# Should show v0.5.7
```

### Step 3: Build dstack-vmm

```bash
cd ~/dstack/vmm
cargo build --release
```

### Step 5: Build dstack-supervisor

```bash
cd ~/dstack
cargo build --release -p supervisor
```

### Step 6: Install Binaries

```bash
# Install VMM
sudo cp ~/dstack/target/release/dstack-vmm /usr/local/bin/dstack-vmm
sudo chmod 755 /usr/local/bin/dstack-vmm

# Install supervisor
sudo cp ~/dstack/target/release/supervisor /usr/local/bin/dstack-supervisor
sudo chmod 755 /usr/local/bin/dstack-supervisor
```

### Step 7: Verify Installation

```bash
which dstack-vmm
dstack-vmm --version

which dstack-supervisor
ls -la /usr/local/bin/dstack-supervisor
```

---

## Build Options

### Specify a Different Version

```bash
# Check out a specific version
git checkout v0.5.4

# Or use main branch for latest development
git checkout main
git pull
```

### Clean Build

To rebuild from scratch:

```bash
cargo clean
cargo build --release
```

### Debug Build

For development with better error messages:

```bash
cargo build
# Binary at ~/dstack/target/debug/dstack-vmm
```

---

## Troubleshooting

For detailed solutions, see the [dstack Installation Troubleshooting Guide](/tutorial/troubleshooting-dstack-installation#clone--build-dstack-vmm-issues):

- [Network timeout downloading crates](/tutorial/troubleshooting-dstack-installation#network-timeout-downloading-crates)
- [Linker errors](/tutorial/troubleshooting-dstack-installation#linker-errors)
- [Permission denied on install](/tutorial/troubleshooting-dstack-installation#permission-denied-on-install)
- [Build cache issues](/tutorial/troubleshooting-dstack-installation#build-cache-issues)

---

## Next Steps

With dstack-vmm built, proceed to:

- [VMM Configuration](/tutorial/vmm-configuration) - Configure the VMM for production

## Additional Resources

- [dstack GitHub Repository](https://github.com/Dstack-TEE/dstack)
- [Cargo Documentation](https://doc.rust-lang.org/cargo/)
