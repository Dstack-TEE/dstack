# ZetaChain Integration with dstack

This directory contains examples demonstrating how to use dstack's Trusted Execution Environment (TEE) with ZetaChain.

## Overview

dstack provides hardware-based secure key management using Intel TDX technology. ZetaChain is an EVM-compatible blockchain focused on cross-chain interoperability. Together, they enable:

- **Secure Cross-Chain Applications**: Build omnichain apps with TEE security guarantees
- **Confidential Key Management**: Private keys never leave the TEE hardware
- **Verifiable Execution**: Cryptographic proof that code runs in genuine TEE
- **Deterministic Wallets**: Reproducible accounts across deployments

## Installation

### Basic Installation

```bash
# Install dstack SDK with ZetaChain support
pip install "dstack-sdk[zetachain]"
```

### Full Installation (All Blockchains)

```bash
# Install with support for Ethereum, Solana, and ZetaChain
pip install "dstack-sdk[all]"
```

### Development Installation

```bash
# Install from source
cd sdk/python
pip install -e ".[zetachain]"
```

## Quick Start

### Basic Account Creation

```python
from dstack_sdk import DstackClient
from dstack_sdk.zetachain import to_account_secure

# Initialize dstack client (connects to TEE)
client = DstackClient()

# Derive a deterministic key for ZetaChain
key = client.get_key('zetachain/mainnet', 'wallet')

# Convert to ZetaChain account
account = to_account_secure(key)

print(f"ZetaChain Address: {account.address}")
# Private key is secure in TEE and never exposed!
```

### Check Balance

```python
from web3 import Web3
from dstack_sdk import DstackClient
from dstack_sdk.zetachain import to_account_secure

# Create account
client = DstackClient()
key = client.get_key('zetachain/testnet', 'wallet')
account = to_account_secure(key)

# Connect to ZetaChain testnet
w3 = Web3(Web3.HTTPProvider('https://zetachain-athens-evm.blockpi.network/v1/rpc/public'))

# Check balance
balance = w3.eth.get_balance(account.address)
print(f"Balance: {w3.from_wei(balance, 'ether')} ZETA")
```

### Sign and Send Transaction

```python
from web3 import Web3
from dstack_sdk import DstackClient
from dstack_sdk.zetachain import to_account_secure

# Setup
client = DstackClient()
key = client.get_key('zetachain/testnet', 'wallet')
account = to_account_secure(key)
w3 = Web3(Web3.HTTPProvider('https://zetachain-athens-evm.blockpi.network/v1/rpc/public'))

# Prepare transaction
tx = {
    'from': account.address,
    'to': '0x...',
    'value': w3.to_wei(1, 'ether'),
    'gas': 21000,
    'gasPrice': w3.eth.gas_price,
    'nonce': w3.eth.get_transaction_count(account.address),
    'chainId': 7001,  # ZetaChain Athens Testnet
}

# Sign with TEE-protected key
signed_tx = w3.eth.account.sign_transaction(tx, account.key)

# Send transaction
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
print(f"Transaction: {tx_hash.hex()}")
```

## Running the Demo

The demo application showcases all features:

```bash
# Run the comprehensive demo
python examples/zetachain_demo.py
```

This demo includes:
1. Basic account creation with TEE security
2. Balance checking on ZetaChain network
3. Transaction signing with TEE-protected keys
4. Multiple deterministic accounts
5. Cross-chain account management
6. TEE attestation with ZetaChain
7. Async operations

## ZetaChain Networks

### Mainnet

```python
RPC_URL = "https://zetachain-evm.blockpi.network/v1/rpc/public"
CHAIN_ID = 7000
EXPLORER = "https://explorer.zetachain.com"
```

### Testnet (Athens)

```python
RPC_URL = "https://zetachain-athens-evm.blockpi.network/v1/rpc/public"
CHAIN_ID = 7001
EXPLORER = "https://athens.explorer.zetachain.com"
FAUCET = "https://labs.zetachain.com/get-zeta"
```

## Advanced Features

### Deterministic Key Derivation

```python
# Same path and subject always produce same account
client = DstackClient()

# Create two accounts for different purposes
trading_key = client.get_key('zetachain/mainnet', 'trading')
governance_key = client.get_key('zetachain/mainnet', 'governance')

trading_account = to_account_secure(trading_key)
governance_account = to_account_secure(governance_key)

# Accounts are different but deterministic
print(f"Trading: {trading_account.address}")
print(f"Governance: {governance_account.address}")
```

### Cross-Chain Key Management

```python
from dstack_sdk import DstackClient
from dstack_sdk.ethereum import to_account_secure as eth_to_account
from dstack_sdk.solana import to_keypair_secure
from dstack_sdk.zetachain import to_account_secure as zeta_to_account

client = DstackClient()

# Derive keys for different chains
eth_account = eth_to_account(client.get_key('ethereum/mainnet', 'wallet'))
sol_keypair = to_keypair_secure(client.get_key('solana/mainnet', 'wallet'))
zeta_account = zeta_to_account(client.get_key('zetachain/mainnet', 'wallet'))

print(f"Ethereum: {eth_account.address}")
print(f"Solana: {sol_keypair.pubkey()}")
print(f"ZetaChain: {zeta_account.address}")
```

### TEE Attestation

```python
from dstack_sdk import DstackClient
from dstack_sdk.zetachain import to_account_secure

client = DstackClient()

# Create account
key = client.get_key('zetachain/mainnet', 'wallet')
account = to_account_secure(key)

# Get TEE attestation quote
# This proves the account was created in genuine TEE hardware
report_data = account.address.encode()[:64]
quote = client.get_quote(report_data)

print(f"Quote size: {len(quote.quote)} bytes")
print(f"Event log entries: {len(quote.event_log)}")
# Quote can be verified to prove TEE execution
```

### Async Operations

```python
import asyncio
from dstack_sdk import AsyncDstackClient
from dstack_sdk.zetachain import to_account_secure

async def create_accounts():
    async with AsyncDstackClient() as client:
        # Derive multiple keys concurrently
        keys = await asyncio.gather(
            client.get_key('zetachain/mainnet', 'wallet-1'),
            client.get_key('zetachain/mainnet', 'wallet-2'),
            client.get_key('zetachain/testnet', 'wallet-1'),
        )

        # Convert to accounts
        accounts = [to_account_secure(key) for key in keys]
        for account in accounts:
            print(account.address)

asyncio.run(create_accounts())
```

## Security Best Practices

### ✅ DO

- **Use `to_account_secure`** instead of `to_account` (better security)
- **Keep path and subject names organized** for easy key management
- **Use different paths for different environments** (mainnet vs testnet)
- **Verify TEE quotes** when accepting keys from other parties
- **Use hardware attestation** for critical operations

### ❌ DON'T

- **Don't extract private keys** from the TEE if possible
- **Don't use `get_tls_key`** for blockchain accounts (it shows deprecation warning)
- **Don't reuse accounts** across different security contexts
- **Don't skip attestation verification** in production

## Troubleshooting

### Connection Issues

```python
# If you can't connect to dstack, check if TEE/simulator is running
from dstack_sdk import DstackClient

try:
    client = DstackClient()
    info = client.get_info()
    print(f"Connected! Version: {info}")
except Exception as e:
    print(f"Connection failed: {e}")
    print("Make sure dstack TEE or simulator is running")
```

### Using Simulator for Development

```bash
# Download dstack simulator
# macOS
curl -LO https://github.com/Dstack-TEE/dstack/releases/latest/download/dstack-sim-darwin-x86_64.tar.gz
tar xf dstack-sim-darwin-x86_64.tar.gz

# Linux
curl -LO https://github.com/Dstack-TEE/dstack/releases/latest/download/dstack-sim-linux-x86_64.tar.gz
tar xf dstack-sim-linux-x86_64.tar.gz

# Run simulator
./dstack-simulator

# In another terminal, run your code
python examples/zetachain_demo.py
```

## Resources

### dstack Resources

- **Documentation**: https://docs.phala.network/dstack
- **GitHub**: https://github.com/Dstack-TEE/dstack
- **PyPI**: https://pypi.org/project/dstack-sdk/

### ZetaChain Resources

- **Documentation**: https://docs.zetachain.com/
- **Explorer (Mainnet)**: https://explorer.zetachain.com/
- **Explorer (Testnet)**: https://athens.explorer.zetachain.com/
- **Testnet Faucet**: https://labs.zetachain.com/get-zeta
- **GitHub**: https://github.com/zeta-chain

### Related Projects

- **Phala Network**: https://phala.network/
- **Flashbots**: https://flashbots.net/
- **Web3.py**: https://web3py.readthedocs.io/

## Use Cases

### 1. Confidential Cross-Chain DEX

Build a decentralized exchange that:
- Stores trading strategies in TEE
- Executes cross-chain swaps via ZetaChain
- Provides cryptographic proof of fair execution

### 2. Secure Omnichain Wallet

Create a wallet that:
- Manages keys for multiple chains in single TEE
- Uses ZetaChain for cross-chain transfers
- Never exposes private keys to frontend

### 3. Cross-Chain DeFi Strategies

Implement strategies that:
- Monitor prices across multiple chains
- Execute arbitrage via ZetaChain connectors
- Keep strategy logic confidential in TEE

### 4. Verifiable Random Oracles

Build oracles that:
- Generate random numbers in TEE
- Provide attestation of randomness
- Bridge results to ZetaChain and connected chains

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

Apache-2.0 License - see LICENSE file for details.

## Support

- **Issues**: https://github.com/Dstack-TEE/dstack/issues
- **Discussions**: https://github.com/Dstack-TEE/dstack/discussions
- **Discord**: https://discord.gg/phala-network
