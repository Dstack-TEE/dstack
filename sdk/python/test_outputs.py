# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys

from dstack_sdk import DstackClient, AsyncDstackClient, TappdClient, AsyncTappdClient, get_compose_hash, verify_env_encrypt_public_key


async def main():
    print("=== Python SDK Output Test ===")
    
    try:
        # Test client get_key
        client = DstackClient()
        print("\n1. Testing DstackClient.get_key()")
        
        test_paths = [
            {"path": "test/wallet", "purpose": "ethereum"},
            {"path": "test/signing", "purpose": "solana"},
            {"path": "user/alice", "purpose": "mainnet"}
        ]
        
        for test_case in test_paths:
            path, purpose = test_case["path"], test_case["purpose"]
            key_result = client.get_key(path, purpose)
            print(f"get_key('{path}', '{purpose}'):")
            print(f"  key: {key_result.decode_key().hex()}")
            print(f"  signature_chain length: {len(key_result.signature_chain)}")
            print(f"  signature_chain[0]: {key_result.decode_signature_chain()[0].hex()}")

        # Test viem integration (if available)
        print("\n2. Testing Viem Integration")
        eth_key = client.get_key("eth/test", "wallet")
        
        print("\n2.1 to_account (legacy):")
        try:
            from dstack_sdk.ethereum import to_account
            account = to_account(eth_key)
            print(f"  address: {account.address}")
            print(f"  type: ethereum account")
        except ImportError:
            print("  error: Ethereum integration not available (install with pip install 'dstack-sdk[eth]')")
        except Exception as error:
            print(f"  error: {error}")
        
        print("\n2.2 to_account_secure:")
        try:
            from dstack_sdk.ethereum import to_account_secure
            account_secure = to_account_secure(eth_key)
            print(f"  address: {account_secure.address}")
            print(f"  type: ethereum account")
        except ImportError:
            print("  error: Ethereum integration not available (install with pip install 'dstack-sdk[eth]')")
        except Exception as error:
            print(f"  error: {error}")

        # Test solana integration (if available)
        print("\n3. Testing Solana Integration")
        sol_key = client.get_key("sol/test", "wallet")
        
        print("\n3.1 to_keypair (legacy):")
        try:
            from dstack_sdk.solana import to_keypair
            keypair = to_keypair(sol_key)
            print(f"  publicKey: {keypair.pubkey()}")
            print(f"  secretKey length: {len(bytes(keypair))}")
            print(f"  secretKey (first 32 bytes): {bytes(keypair)[:32].hex()}")
        except ImportError:
            print("  error: Solana integration not available (install with pip install 'dstack-sdk[sol]')")
        except Exception as error:
            print(f"  error: {error}")
        
        print("\n3.2 to_keypair_secure:")
        try:
            from dstack_sdk.solana import to_keypair_secure
            keypair_secure = to_keypair_secure(sol_key)
            print(f"  publicKey: {keypair_secure.pubkey()}")
            print(f"  secretKey length: {len(bytes(keypair_secure))}")
            print(f"  secretKey (first 32 bytes): {bytes(keypair_secure)[:32].hex()}")
        except ImportError:
            print("  error: Solana integration not available (install with pip install 'dstack-sdk[sol]')")
        except Exception as error:
            print(f"  error: {error}")

        # Test TappdClient (deprecated)
        print("\n4. Testing TappdClient (deprecated)")
        try:
            tappd_client = TappdClient()
            print("\n4.1 TappdClient.get_key():")
            tappd_key = tappd_client.get_key("test/wallet", "ethereum")
            print(f"  key: {tappd_key.decode_key().hex()}")
            print(f"  signature_chain length: {len(tappd_key.signature_chain)}")

            print("\n4.2 TappdClient.tdx_quote():")
            tappd_quote = tappd_client.tdx_quote("test-data", "raw")
            print(f"  quote length: {len(tappd_quote.quote)}")
            print(f"  event_log length: {len(tappd_quote.event_log)}")
            print(f"  rtmrs count: {len(tappd_quote.replay_rtmrs())}")
        except Exception as error:
            print(f"  error: {error}")

        # Test AsyncTappdClient (deprecated)
        print("\n4.3 Testing AsyncTappdClient (deprecated)")
        try:
            async_tappd_client = AsyncTappdClient()
            print("\n4.3.1 AsyncTappdClient.get_key():")
            async_tappd_key = await async_tappd_client.get_key("test/wallet", "ethereum")
            print(f"  key: {async_tappd_key.decode_key().hex()}")
            print(f"  signature_chain length: {len(async_tappd_key.signature_chain)}")

            print("\n4.3.2 AsyncTappdClient.tdx_quote():")
            async_tappd_quote = await async_tappd_client.tdx_quote("test-data", "raw")
            print(f"  quote length: {len(async_tappd_quote.quote)}")
            print(f"  event_log length: {len(async_tappd_quote.event_log)}")
            print(f"  rtmrs count: {len(async_tappd_quote.replay_rtmrs())}")
        except Exception as error:
            print(f"  error: {error}")

        # Test quotes
        print("\n5. Testing Quote Methods")
        print("\n5.1 DstackClient.get_quote():")
        dstack_quote = client.get_quote("test-data-for-quote")
        print(f"  quote length: {len(dstack_quote.quote)}")
        print(f"  event_log length: {len(dstack_quote.event_log)}")
        print(f"  rtmrs count: {len(dstack_quote.replay_rtmrs())}")

        print("\n5.2 AsyncDstackClient.get_quote():")
        async_client = AsyncDstackClient()
        async_dstack_quote = await async_client.get_quote("test-data-for-quote")
        print(f"  quote length: {len(async_dstack_quote.quote)}")
        print(f"  event_log length: {len(async_dstack_quote.event_log)}")
        print(f"  rtmrs count: {len(async_dstack_quote.replay_rtmrs())}")

        # Test get_compose_hash
        print("\n6. Testing get_compose_hash")
        test_composes = [
            {
                "manifest_version": 1,
                "name": "test-app",
                "runner": "docker-compose",
                "docker_compose_file": "services:\\n  app:\\n    image: test\\n    ports:\\n      - 8080:8080"
            },
            {
                "manifest_version": 1,
                "name": "another-app", 
                "runner": "docker-compose",
                "docker_compose_file": "services:\\n  web:\\n    build: .\\n    environment:\\n      - NODE_ENV=production"
            }
        ]
        
        for index, compose in enumerate(test_composes):
            hash_value = get_compose_hash(compose)
            print(f"compose {index + 1}: {hash_value}")
            print(f"  name: {compose['name']}")
            print(f"  runner: {compose['runner']}")

        # Test verify_env_encrypt_public_key
        print("\n7. Testing verify_env_encrypt_public_key")
        test_cases = [
            {
                "public_key": bytes.fromhex('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a'),
                "signature": bytes.fromhex('8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00'),
                "app_id": '0000000000000000000000000000000000000000'
            },
            {
                "public_key": bytes.fromhex('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'),
                "signature": bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
                "app_id": 'invalid-app-id'
            }
        ]

        for index, test_case in enumerate(test_cases):
            try:
                result = verify_env_encrypt_public_key(
                    test_case["public_key"],
                    test_case["signature"],
                    test_case["app_id"]
                )
                print(f"test case {index + 1}: {result.hex() if result else 'null'}")
            except Exception as error:
                print(f"test case {index + 1}: error - {error}")

    except Exception as error:
        print(f"Error: {error}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())