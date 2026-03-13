---
title: "Rust Toolchain Installation"
description: "Install and configure the Rust programming language toolchain for building dstack components"
section: "dstack Installation"
stepNumber: 2
totalSteps: 8
lastUpdated: 2025-12-07
prerequisites:
  - system-baseline-dependencies
tags:
  - rust
  - cargo
  - rustup
  - toolchain
difficulty: "beginner"
estimatedTime: "10 minutes"
---

# Rust Toolchain Installation

This tutorial guides you through installing the Rust programming language toolchain, which is required for building dstack components.

## Prerequisites

Before starting, ensure you have:

- Completed [System Baseline & Dependencies](/tutorial/system-baseline-dependencies)
- SSH access to your TDX-enabled server


## What Gets Installed

| Component | Purpose |
|-----------|---------|
| `rustup` | Rust toolchain installer and version manager |
| `rustc` | Rust compiler |
| `cargo` | Rust package manager and build tool |
| `clippy` | Rust linter for catching common mistakes |
| `rustfmt` | Rust code formatter |

---

## Manual Installation

If you prefer to install Rust manually, follow these steps.

### Step 1: Connect to Your Server

```bash
ssh ubuntu@YOUR_SERVER_IP
```

All commands should be run as the `ubuntu` user (not root). Rust will be installed in your home directory at `~/.cargo` and `~/.rustup`.

### Step 2: Install rustup

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

The `-y` flag accepts default options:
- Installs the stable toolchain
- Adds cargo to your PATH
- Sets up shell configuration

### Step 3: Load the Environment

```bash
source $HOME/.cargo/env
```

### Step 4: Install Additional Components

```bash
rustup component add clippy rustfmt
```

### Step 5: Verify Installation

```bash
rustc --version
cargo --version
rustup --version
```

Expected output (versions may vary):
```
rustc 1.82.0 (f6e511eec 2024-10-15)
cargo 1.82.0 (8f40fc59f 2024-08-21)
rustup 1.27.1 (54dd3d00f 2024-04-24)
```

### Step 6: Test Compilation

```bash
cargo new --bin rust-test && cd rust-test && cargo run && cd ~ && rm -rf rust-test
```

You should see "Hello, world!" printed.

---

## Troubleshooting

For detailed solutions, see the [dstack Installation Troubleshooting Guide](/tutorial/troubleshooting-dstack-installation#rust-toolchain-installation-issues):

- [rustup command not found](/tutorial/troubleshooting-dstack-installation#rustup-command-not-found)
- [Permission denied errors](/tutorial/troubleshooting-dstack-installation#permission-denied-errors)
- [Network timeout during installation](/tutorial/troubleshooting-dstack-installation#network-timeout-during-installation)
- [Updating Rust](/tutorial/troubleshooting-dstack-installation#updating-rust)

---

## Next Steps

With Rust installed, proceed to:

- [Clone & Build dstack-vmm](/tutorial/clone-build-dstack-vmm) - Build the dstack virtual machine manager

## Additional Resources

- [The Rust Programming Language Book](https://doc.rust-lang.org/book/)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- [rustup Documentation](https://rust-lang.github.io/rustup/)
