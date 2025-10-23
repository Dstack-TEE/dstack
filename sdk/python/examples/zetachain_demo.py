#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""ZetaChain + dstack Integration Demo

This example demonstrates how to use dstack's secure key derivation with ZetaChain.
It shows:
1. Connecting to dstack TEE environment
2. Deriving deterministic ZetaChain keys
3. Using Web3 to interact with ZetaChain networks
4. Cross-chain capabilities with confidential computing

Requirements:
    pip install "dstack-sdk[zetachain]"
"""

import asyncio
from web3 import Web3
from web3.middleware import geth_poa_middleware

from dstack_sdk import DstackClient
from dstack_sdk.zetachain import to_account_secure


# ZetaChain Network Configuration
ZETACHAIN_NETWORKS = {
    "mainnet": {
        "rpc": "https://zetachain-evm.blockpi.network/v1/rpc/public",
        "chain_id": 7000,
        "explorer": "https://explorer.zetachain.com",
    },
    "testnet": {
        "rpc": "https://zetachain-athens-evm.blockpi.network/v1/rpc/public",
        "chain_id": 7001,
        "explorer": "https://athens.explorer.zetachain.com",
    },
}


def get_web3_client(network="testnet"):
    """Create Web3 client for ZetaChain network."""
    w3 = Web3(Web3.HTTPProvider(ZETACHAIN_NETWORKS[network]["rpc"]))
    # Add PoA middleware if needed
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    return w3


def demo_basic_account_creation():
    """Demo: Create ZetaChain account from dstack TEE."""
    print("=" * 60)
    print("Demo 1: Basic ZetaChain Account Creation with TEE Security")
    print("=" * 60)

    # Initialize dstack client (connects to TEE)
    client = DstackClient()

    # Derive a deterministic key for ZetaChain mainnet
    # Keys are unique per path and subject, but deterministic
    print("\n📊 Deriving key from TEE...")
    key_response = client.get_key("zetachain/mainnet", "wallet-1")

    # Convert to ZetaChain account
    account = to_account_secure(key_response)

    print(f"\n✅ ZetaChain Account Created:")
    print(f"   Address: {account.address}")
    print(f"   🔐 Private key is secure in TEE, never exposed!")

    return account


def demo_check_balance(network="testnet"):
    """Demo: Check ZetaChain balance."""
    print("\n" + "=" * 60)
    print("Demo 2: Check Balance on ZetaChain Network")
    print("=" * 60)

    # Create account
    client = DstackClient()
    key_response = client.get_key(f"zetachain/{network}", "wallet-1")
    account = to_account_secure(key_response)

    # Connect to ZetaChain
    w3 = get_web3_client(network)

    print(f"\n🌐 Connected to ZetaChain {network.upper()}")
    print(f"   Chain ID: {w3.eth.chain_id}")
    print(f"   Block Number: {w3.eth.block_number}")

    # Check balance
    balance_wei = w3.eth.get_balance(account.address)
    balance_zeta = w3.from_wei(balance_wei, "ether")

    print(f"\n💰 Account Balance:")
    print(f"   Address: {account.address}")
    print(f"   Balance: {balance_zeta} ZETA")

    if balance_zeta == 0 and network == "testnet":
        print(
            f"\n💡 Get testnet ZETA from faucet: https://labs.zetachain.com/get-zeta"
        )

    return account, w3


def demo_sign_transaction(network="testnet"):
    """Demo: Sign transaction with TEE-protected key."""
    print("\n" + "=" * 60)
    print("Demo 3: Sign Transaction with TEE Security")
    print("=" * 60)

    # Create account
    client = DstackClient()
    key_response = client.get_key(f"zetachain/{network}", "wallet-1")
    account = to_account_secure(key_response)

    # Connect to ZetaChain
    w3 = get_web3_client(network)

    # Prepare transaction (example - not actually sent)
    tx = {
        "from": account.address,
        "to": "0x0000000000000000000000000000000000000000",  # Example address
        "value": w3.to_wei(0.01, "ether"),
        "gas": 21000,
        "gasPrice": w3.eth.gas_price,
        "nonce": w3.eth.get_transaction_count(account.address),
        "chainId": w3.eth.chain_id,
    }

    print(f"\n📝 Transaction Details:")
    print(f"   From: {tx['from']}")
    print(f"   To: {tx['to']}")
    print(f"   Value: {w3.from_wei(tx['value'], 'ether')} ZETA")
    print(f"   Gas: {tx['gas']}")

    # Sign transaction (key never leaves TEE!)
    print("\n🔐 Signing transaction in TEE...")
    signed_tx = w3.eth.account.sign_transaction(tx, account.key)

    print(f"✅ Transaction Signed!")
    print(f"   Hash: {signed_tx.hash.hex()}")
    print(f"   Signature: {signed_tx.signature.hex()[:64]}...")

    print("\n💡 Transaction is signed but not sent (demo only)")

    return signed_tx


def demo_multi_account():
    """Demo: Create multiple accounts for different purposes."""
    print("\n" + "=" * 60)
    print("Demo 4: Multiple Deterministic Accounts")
    print("=" * 60)

    client = DstackClient()

    # Different paths create different accounts
    accounts = {}
    purposes = ["wallet-1", "wallet-2", "trading", "governance"]

    print("\n📊 Creating multiple accounts from same TEE:")

    for purpose in purposes:
        key_response = client.get_key("zetachain/mainnet", purpose)
        account = to_account_secure(key_response)
        accounts[purpose] = account
        print(f"   {purpose:12} -> {account.address}")

    print(
        "\n✅ Each account is deterministic and can be recreated with same path/purpose"
    )

    return accounts


def demo_cross_chain_compatibility():
    """Demo: Same dstack client for multiple chains."""
    print("\n" + "=" * 60)
    print("Demo 5: Cross-Chain Account Management")
    print("=" * 60)

    client = DstackClient()

    print("\n🌐 Creating accounts across different chains:")

    # ZetaChain
    zeta_key = client.get_key("zetachain/mainnet", "wallet")
    zeta_account = to_account_secure(zeta_key)
    print(f"   ZetaChain:  {zeta_account.address}")

    # Can also create Ethereum accounts (if ethereum module available)
    try:
        from dstack_sdk.ethereum import to_account_secure as eth_to_account

        eth_key = client.get_key("ethereum/mainnet", "wallet")
        eth_account = eth_to_account(eth_key)
        print(f"   Ethereum:   {eth_account.address}")
    except ImportError:
        print("   Ethereum:   (install dstack-sdk[ethereum] to enable)")

    # And Solana (if solana module available)
    try:
        from dstack_sdk.solana import to_keypair_secure

        sol_key = client.get_key("solana/mainnet", "wallet")
        sol_keypair = to_keypair_secure(sol_key)
        print(f"   Solana:     {sol_keypair.pubkey()}")
    except ImportError:
        print("   Solana:     (install dstack-sdk[solana] to enable)")

    print(
        "\n✅ Single TEE environment manages keys for all chains securely!"
    )


def demo_get_quote():
    """Demo: Get TEE attestation quote."""
    print("\n" + "=" * 60)
    print("Demo 6: TEE Attestation with ZetaChain Account")
    print("=" * 60)

    client = DstackClient()

    # Create account
    key_response = client.get_key("zetachain/mainnet", "wallet")
    account = to_account_secure(key_response)

    # Get attestation quote (proves execution in TEE)
    print(f"\n🔐 Getting TEE attestation quote...")
    report_data = account.address.encode()[:64]  # Use address as report data
    quote_response = client.get_quote(report_data)

    print(f"✅ TEE Quote Generated:")
    print(f"   Quote size: {len(quote_response.quote)} bytes")
    print(f"   Event log entries: {len(quote_response.event_log)}")
    print(f"   Report data: {account.address}")

    print(
        "\n💡 This quote proves the account was created in genuine TEE hardware!"
    )

    return quote_response


async def demo_async_operations():
    """Demo: Async operations with dstack."""
    print("\n" + "=" * 60)
    print("Demo 7: Async Operations")
    print("=" * 60)

    from dstack_sdk import AsyncDstackClient

    # Create async client
    async with AsyncDstackClient() as client:
        print("\n📊 Running async key derivation...")

        # Derive multiple keys concurrently
        keys = await asyncio.gather(
            client.get_key("zetachain/mainnet", "wallet-1"),
            client.get_key("zetachain/mainnet", "wallet-2"),
            client.get_key("zetachain/testnet", "wallet-1"),
        )

        print(f"✅ Derived {len(keys)} keys concurrently!")

        # Convert to accounts
        accounts = [to_account_secure(key) for key in keys]
        for i, account in enumerate(accounts, 1):
            print(f"   Account {i}: {account.address}")


def main():
    """Run all demos."""
    print("\n" + "🚀 " * 20)
    print("ZetaChain + dstack TEE Integration Demo")
    print("🚀 " * 20)

    try:
        # Basic demos
        demo_basic_account_creation()
        demo_check_balance("testnet")
        demo_sign_transaction("testnet")
        demo_multi_account()
        demo_cross_chain_compatibility()
        demo_get_quote()

        # Async demo
        print("\n⏳ Running async demo...")
        asyncio.run(demo_async_operations())

        print("\n" + "=" * 60)
        print("✅ All demos completed successfully!")
        print("=" * 60)

        print("\n💡 Key Benefits:")
        print("   • Keys are secure in TEE hardware")
        print("   • Deterministic key derivation")
        print("   • Cryptographic proof of TEE execution")
        print("   • Cross-chain compatibility")
        print("   • No private key exposure")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        print(
            "\n💡 Make sure you have dstack TEE environment running or simulator available"
        )
        print("   See: https://docs.phala.network/dstack/getting-started")


if __name__ == "__main__":
    main()
