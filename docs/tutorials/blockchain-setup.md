---
title: "Blockchain Wallet Setup"
description: "Set up an Ethereum wallet and fund it with testnet ETH for dstack deployment"
section: "Prerequisites"
stepNumber: 5
totalSteps: 7
lastUpdated: 2026-01-09
prerequisites: []
tags:
    - blockchain
    - ethereum
    - wallet
    - testnet
    - sepolia
difficulty: intermediate
estimatedTime: 15-20 minutes
---

# Blockchain Wallet Setup

dstack's Key Management Service (KMS) is deployed as a smart contract on the Ethereum blockchain. For tutorial purposes, we'll use the **Sepolia testnet**, which allows you to deploy and test without spending real ETH.

## What You'll Need

-   **Ethereum wallet** with a private key
-   **Testnet ETH** (~0.1 ETH minimum for deployment)

## Why Sepolia?

Sepolia is one of Ethereum's official testnets:

-   Free testnet ETH from faucets
-   Similar to mainnet but without real value
-   Perfect for development and testing
-   Widely supported by tools and services

---

## Option 1: Command-Line Wallet (Recommended)

If you have [Foundry](https://book.getfoundry.sh/getting-started/installation) installed, you can create a wallet using the `cast` command.

### Step 1.1: Check if Foundry is Installed

```bash
cast --version
```

If not installed, see: https://book.getfoundry.sh/getting-started/installation

### Step 1.2: Generate New Wallet

```bash
cast wallet new
```

**Example output:**

```
Successfully created new keypair.
Address:     0x91Ba69FCD13D2876FD06907a2880BDBC93C336aF
Private key: 0xd76e8d3059484d5d9167c4e10cfeea2a4efa655875112e693e18fb4ab890b98a
```

⚠️ **Save these immediately:**

-   **Address:** Your public wallet address (safe to share)
-   **Private Key:** SECRET - never share or commit to git

### Step 1.3: Store Wallet Credentials Securely

Create secure files to store your wallet address and private key:

```bash
# Create secure directory
mkdir -p ~/.dstack/secrets
chmod 700 ~/.dstack/secrets

# Store wallet address (replace with your address)
echo "0xYOUR_ADDRESS_HERE" > ~/.dstack/secrets/sepolia-address
chmod 600 ~/.dstack/secrets/sepolia-address

# Store private key (replace with your key)
echo "0xYOUR_PRIVATE_KEY_HERE" > ~/.dstack/secrets/sepolia-private-key
chmod 600 ~/.dstack/secrets/sepolia-private-key
```

⚠️ **IMPORTANT:** Add to `.gitignore` if working in a git repository:

```bash
echo "~/.dstack/secrets/" >> ~/.gitignore
```

### Step 1.4: Check Wallet Balance

```bash
# Quick check using public Sepolia RPC
cast balance "$(cat ~/.dstack/secrets/sepolia-address)" --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

Expected output for new wallet: `0` (zero)

---

## Option 2: MetaMask Wallet

If you prefer a browser-based wallet, MetaMask is the most popular choice.

### Step 2.1: Install MetaMask

1. Visit: https://metamask.io/
2. Install browser extension (Chrome, Firefox, Brave, Edge)
3. Create new wallet or import existing one
4. **Save your seed phrase securely** (12 or 24 words)

### Step 2.2: Add Sepolia Network

1. Open MetaMask
2. Click network dropdown (top center)
3. Click "Add Network" or "Add a network manually"
4. Enter Sepolia network details:

```
Network Name: Sepolia
RPC URL: https://ethereum-sepolia-rpc.publicnode.com
Chain ID: 11155111
Currency Symbol: ETH
Block Explorer: https://sepolia.etherscan.io
```

5. Click "Save"

### Step 2.3: Get Your Wallet Address

1. Open MetaMask
2. Click on account name (top center)
3. Address shown below name (starts with `0x...`)
4. Click to copy

### Step 2.4: Export Private Key (for dstack CLI)

⚠️ **Only do this if you need the private key for programmatic access**

1. Open MetaMask
2. Click three dots (top right) → Account Details
3. Click "Export Private Key"
4. Enter MetaMask password
5. Click to reveal and copy private key
6. Store securely as shown in Step 1.3

---

## Step 2: Get Testnet ETH

You need testnet ETH to deploy the KMS smart contract.

### PoW Faucet (Recommended)

**Best option for new wallets** - no requirements:

1. Visit: https://sepolia-faucet.pk910.de/
2. Enter your wallet address
3. Click "Start Mining"
4. Wait 10-30 minutes while mining runs in your browser
5. Claim your testnet ETH (typically 0.05-0.1 ETH per session)

✅ **Why this faucet?**

-   No mainnet ETH balance required
-   No account signup needed
-   No MetaMask required
-   Works for brand new wallets
-   Just needs patience for mining

### MetaMask Faucet

If you're using MetaMask:

-   URL: https://docs.metamask.io/developer-tools/faucet
-   ❌ **Requires:** MetaMask extension installed

### More Faucet Options

For a comprehensive list of Sepolia faucets with their specific requirements, see:
**https://faucetlink.to/sepolia**

This page lists all available faucets and their requirements (mainnet ETH balance, account signup, etc.)

### Verify You Received ETH

**Command Line:**

```bash
# Quick check using public Sepolia RPC
cast balance "$(cat ~/.dstack/secrets/sepolia-address)" --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

Expected: Non-zero value (e.g., `50000000000000000` = 0.05 ETH, `100000000000000000` = 0.1 ETH in wei)

**MetaMask:**

-   Switch to Sepolia network
-   Check balance shown in extension

**Block Explorer:**

```bash
# Open in browser
open "https://sepolia.etherscan.io/address/$(cat ~/.dstack/secrets/sepolia-address)"

# Or manually visit with your address
https://sepolia.etherscan.io/address/YOUR_ADDRESS
```

---

## Step 3: Verify Your Secrets

Check that all required secrets are stored:

```bash
# List your secrets
ls -la ~/.dstack/secrets/
```

You should have:
- `sepolia-address` - Your wallet address
- `sepolia-private-key` - Your wallet private key

**Test your configuration:**

```bash
echo "Wallet: $(cat ~/.dstack/secrets/sepolia-address)"
echo "Balance: $(cast balance "$(cat ~/.dstack/secrets/sepolia-address)" --rpc-url https://ethereum-sepolia-rpc.publicnode.com)"
```

---

## Verification Checklist

Before proceeding to KMS deployment, verify:

-   ✅ Wallet created and address saved to `~/.dstack/secrets/sepolia-address`
-   ✅ Private key stored securely in `~/.dstack/secrets/sepolia-private-key`
-   ✅ Wallet has ≥0.1 testnet ETH
-   ✅ Can query balance via cast

---

## Troubleshooting

For detailed solutions, see the [Prerequisites Troubleshooting Guide](/tutorial/troubleshooting-prerequisites#blockchain-wallet-setup-issues):

- [Faucet not sending ETH](/tutorial/troubleshooting-prerequisites#problem-faucet-not-sending-eth)
- [RPC endpoint timing out](/tutorial/troubleshooting-prerequisites#problem-rpc-endpoint-timing-out)
- ["Connection refused" error](/tutorial/troubleshooting-prerequisites#problem-connection-refused-error)
- [Can't see balance in cast](/tutorial/troubleshooting-prerequisites#problem-cant-see-balance-in-cast)

---

## Security Best Practices

### DO:

✅ **Follow these practices:**

-   Store private keys in encrypted files with restricted permissions (chmod 600)
-   Use environment variables for sensitive data
-   Keep separate wallets for testnet and mainnet
-   Back up your wallet securely (encrypted USB, password manager)
-   Use hardware wallet for mainnet production deployments

### DON'T:

❌ **Avoid these mistakes:**

-   Commit private keys to git repositories
-   Share private keys via email, chat, or screenshots
-   Use testnet wallet for mainnet (always use separate wallets)
-   Store private keys in plain text on cloud storage
-   Reuse private keys across projects

---

## Next Steps

Once your wallet is set up and funded, you can proceed to:

1. **Host Setup:** [TDX Hardware Verification](/tutorial/tdx-hardware-verification) - Begin configuring your TDX-capable server
2. **Skip Ahead:** If you already have a TDX-enabled server, you'll use this wallet in the KMS deployment phase

Your blockchain wallet is ready for dstack KMS deployment! 🎉
