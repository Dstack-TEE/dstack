# Self-Host Tutorials

Step-by-step guides for deploying dstack on your own TDX hardware. These
tutorials walk through the entire process from bare-metal host setup to
running your first confidential application.

## Tutorial Order

### 1. Host Setup

| Step | Tutorial | File |
|------|----------|------|
| 1 | TDX Hardware Verification | [tdx-hardware-verification.md](tdx-hardware-verification.md) |
| 2 | TDX & SGX BIOS Configuration | [tdx-bios-configuration.md](tdx-bios-configuration.md) |
| 3 | TDX Software Installation | [tdx-software-installation.md](tdx-software-installation.md) |
| 4 | TDX & SGX Verification | [tdx-sgx-verification.md](tdx-sgx-verification.md) |

### 2. Prerequisites

| Step | Tutorial | File |
|------|----------|------|
| 1 | DNS Configuration | [dns-configuration.md](dns-configuration.md) |
| 2 | SSL Certificate Setup | [ssl-certificate-setup.md](ssl-certificate-setup.md) |
| 3 | Docker Setup | [docker-setup.md](docker-setup.md) |
| 3 | HAProxy Setup | [haproxy-setup.md](haproxy-setup.md) |
| 4 | Gramine Key Provider | [gramine-key-provider.md](gramine-key-provider.md) |
| 4 | Local Docker Registry | [local-docker-registry.md](local-docker-registry.md) |
| 5 | Blockchain Wallet Setup | [blockchain-setup.md](blockchain-setup.md) |

> Steps 3–4 contain parallel tracks. Docker Setup and HAProxy Setup are
> both step 3; Gramine Key Provider and Local Docker Registry are both
> step 4. Complete both within each step number.

### 3. dstack Installation

| Step | Tutorial | File |
|------|----------|------|
| 1 | System Baseline & Dependencies | [system-baseline-dependencies.md](system-baseline-dependencies.md) |
| 2 | Rust Toolchain Installation | [rust-toolchain-installation.md](rust-toolchain-installation.md) |
| 3 | Clone & Build dstack-vmm | [clone-build-dstack-vmm.md](clone-build-dstack-vmm.md) |
| 4 | VMM Configuration | [vmm-configuration.md](vmm-configuration.md) |
| 5 | VMM Service Setup | [vmm-service-setup.md](vmm-service-setup.md) |
| 6 | Management Interface Setup | [management-interface-setup.md](management-interface-setup.md) |
| 7 | Guest OS Image Setup | [guest-image-setup.md](guest-image-setup.md) |

### 4. KMS Deployment

| Step | Tutorial | File |
|------|----------|------|
| 1 | Contract Deployment | [contract-deployment.md](contract-deployment.md) |
| 2 | KMS Build & Configuration | [kms-build-configuration.md](kms-build-configuration.md) |
| 3 | KMS CVM Deployment | [kms-cvm-deployment.md](kms-cvm-deployment.md) |

### 5. Gateway Deployment

| Step | Tutorial | File |
|------|----------|------|
| 1 | Gateway CVM Preparation | [gateway-build-configuration.md](gateway-build-configuration.md) |
| 2 | Gateway CVM Deployment | [gateway-service-setup.md](gateway-service-setup.md) |

### 6. First Application

| Step | Tutorial | File |
|------|----------|------|
| 1 | Hello World Application | [hello-world-app.md](hello-world-app.md) |
| 2 | Attestation Verification | [attestation-verification.md](attestation-verification.md) |

### Troubleshooting

These guides are not part of the main flow. Refer to them as needed.

| Tutorial | File |
|----------|------|
| Troubleshooting: Prerequisites | [troubleshooting-prerequisites.md](troubleshooting-prerequisites.md) |
| Troubleshooting: Host Setup | [troubleshooting-host-setup.md](troubleshooting-host-setup.md) |
| Troubleshooting: dstack Installation | [troubleshooting-dstack-installation.md](troubleshooting-dstack-installation.md) |
| Troubleshooting: KMS Deployment | [troubleshooting-kms-deployment.md](troubleshooting-kms-deployment.md) |
| Troubleshooting: Gateway Deployment | [troubleshooting-gateway-deployment.md](troubleshooting-gateway-deployment.md) |
| Troubleshooting: First Application | [troubleshooting-first-application.md](troubleshooting-first-application.md) |
