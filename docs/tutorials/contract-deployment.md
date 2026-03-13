---
title: "Contract Deployment"
description: "Deploy dstack KMS smart contracts to Sepolia testnet from your local machine"
section: "KMS Deployment"
stepNumber: 1
totalSteps: 3
lastUpdated: 2026-01-09
prerequisites:
  - blockchain-setup
tags:
  - dstack
  - kms
  - ethereum
  - sepolia
  - hardhat
  - deployment
difficulty: "intermediate"
estimatedTime: "15 minutes"
---

# Contract Deployment

This tutorial deploys the dstack KMS smart contracts to the Sepolia testnet. Contracts are deployed from your **local machine** - your private key never leaves your computer.

## Prerequisites

Before starting, ensure you have:

- Completed [Blockchain Wallet Setup](/tutorial/blockchain-setup) with:
  - Wallet private key stored in `~/.dstack/secrets/sepolia-private-key`
  - Sepolia testnet ETH (~0.01 ETH recommended)
- dstack repository cloned locally at v0.5.7: `git clone -b v0.5.7 https://github.com/Dstack-TEE/dstack ~/dstack`
## What Gets Deployed

The deployment creates two smart contracts on Sepolia:

| Contract | Purpose |
|----------|---------|
| **DstackKms Proxy** | Main entry point - manages KMS settings and app authorization |
| **DstackApp Implementation** | Logic template for application contracts |

These contracts use the UUPS (Universal Upgradeable Proxy Standard) pattern for future upgrades.

---

## Deployment

> **Important: Run these steps on your LOCAL machine, not on the TDX server.** Contract deployment requires your Ethereum private key. By running locally, your private key never touches the server. You need a clone of the dstack repo on your local machine: `git clone -b v0.5.7 https://github.com/Dstack-TEE/dstack ~/dstack`

### Step 1: Clone Repository and Navigate to auth-eth

On your **local machine**, clone the dstack repository (if you haven't already) and check out v0.5.7:

```bash
git clone https://github.com/Dstack-TEE/dstack.git ~/dstack 2>/dev/null || true
cd ~/dstack
git checkout v0.5.7
cd kms/auth-eth
```

### Step 2: Install Node.js and Dependencies

Install nvm (Node Version Manager), then use it to install the correct Node.js version:

```bash
# Install nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash

# Load nvm into current shell
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# Install and use Node.js 18 (LTS)
nvm install 18
nvm use 18

# Verify versions
node --version   # Should show v18.x.x
npm --version    # Should show 9.x.x or 10.x.x
```

Then install the project dependencies:

```bash
npm install
```

### Step 3: Load Credentials

Load your wallet private key and set the RPC URL:

```bash
# Load wallet private key
export PRIVATE_KEY=$(cat ~/.dstack/secrets/sepolia-private-key)

# Set RPC URL for Sepolia testnet
export RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
```

Verify the private key loaded correctly:

```bash
echo "Private key loaded: ${PRIVATE_KEY:0:6}...${PRIVATE_KEY: -4}"
```

### Step 4: Check Wallet Balance

```bash
# Check balance using cast
cast balance "$(cat ~/.dstack/secrets/sepolia-address)" --rpc-url $RPC_URL
```

You need at least 0.01 ETH (shown in wei: `10000000000000000`). If insufficient, get free Sepolia ETH from:
- [PoW Faucet](https://sepolia-faucet.pk910.de/) (no requirements)
- [Faucet List](https://faucetlink.to/sepolia) (more options)

### Step 5: Compile Contracts

```bash
npx hardhat compile
```

Expected output (compiler version and file count may vary):

```
Downloading compiler 0.8.22
Generating typings for: 19 artifacts in dir: typechain-types for target: ethers-v6
Successfully generated 72 typings!
Compiled 19 Solidity files successfully (evm target: paris).
```

This generates the contract artifacts (ABI and bytecode) needed for deployment.

### Step 6: Deploy Contracts

```bash
npx hardhat kms:deploy --with-app-impl --network custom
```

Expected output:

```
Deploying with account: 0xYourAddress
Account balance: 0.123456789 ETH
Step 1: Deploying DstackApp implementation...
DstackApp implementation deployed to: 0x...
Step 2: Deploying DstackKms...
DstackKms Proxy deployed to: 0x...
Complete KMS setup deployed successfully!
```

### Step 7: Save Contract Addresses

Save the deployed addresses for use in later tutorials:

```bash
# Replace with your actual addresses from the output above
KMS_ADDRESS="0xYourKmsProxyAddress"
APP_ADDRESS="0xYourAppImplAddress"

# Save to secrets directory
echo "$KMS_ADDRESS" > ~/.dstack/secrets/kms-contract-address
echo "$APP_ADDRESS" > ~/.dstack/secrets/app-contract-address

echo "Addresses saved to ~/.dstack/secrets/"
```

### Step 8: Verify Deployment

Check the contract exists on-chain:

```bash
KMS_ADDRESS=$(cat ~/.dstack/secrets/kms-contract-address)
cast code "$KMS_ADDRESS" --rpc-url https://ethereum-sepolia-rpc.publicnode.com | head -c 20
```

If the contract is deployed, this returns bytecode (starting with `0x`). If it shows just `0x`, the contract was not found.

View on Etherscan:
```bash
echo "https://sepolia.etherscan.io/address/$KMS_ADDRESS"
```

---

## Understanding the Contracts

### UUPS Proxy Pattern

The contracts use UUPS (Universal Upgradeable Proxy Standard):

```
Client Request
     │
     ▼
┌─────────────┐
│ KMS Proxy   │ ← Stores state, immutable address
│ (0x...)     │
└─────┬───────┘
      │ delegatecall
      ▼
┌─────────────┐
│ KMS Logic   │ ← Contains code, can be upgraded
│ (impl)      │
└─────────────┘
```

This allows upgrading contract logic without changing addresses or losing state.

### Contract Functions

The DstackKms contract provides:

| Function | Purpose |
|----------|---------|
| `isAppAllowed(appId)` | Check if an app is authorized |
| `registerApp(appId)` | Register a new application |
| `gatewayAppId()` | Get the gateway app identifier |

---

## Troubleshooting

For detailed solutions, see the [KMS Deployment Troubleshooting Guide](/tutorial/troubleshooting-kms-deployment#contract-deployment-issues):

- [Artifact not found](/tutorial/troubleshooting-kms-deployment#artifact-not-found)
- [Insufficient funds](/tutorial/troubleshooting-kms-deployment#insufficient-funds)
- [Transaction underpriced](/tutorial/troubleshooting-kms-deployment#transaction-underpriced)
- [Nonce too low](/tutorial/troubleshooting-kms-deployment#nonce-too-low)
- [Connection failed](/tutorial/troubleshooting-kms-deployment#connection-failed)

---

## Cost Estimation

| Operation | Gas Used | Cost at 2 gwei |
|-----------|----------|----------------|
| DstackApp implementation | ~1,100,000 | ~0.0022 ETH |
| DstackKms proxy | ~210,000 | ~0.0004 ETH |
| **Total** | ~1,300,000 | ~0.0026 ETH |

Sepolia testnet ETH is free from faucets.

---

## Next Steps

With contracts deployed, you're ready to build and configure the KMS:

- [KMS Build & Configuration](/tutorial/kms-build-configuration) - Build and configure the dstack Key Management Service

## Additional Resources

- [Sepolia Etherscan](https://sepolia.etherscan.io/)
- [Hardhat Deployment Guide](https://hardhat.org/hardhat-runner/docs/guides/deploying)
- [dstack GitHub Repository](https://github.com/Dstack-TEE/dstack)
