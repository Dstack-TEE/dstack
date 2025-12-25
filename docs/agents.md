# Secure Agents & RAG

Run AI agents with secure key management, protected API credentials, and verifiable execution.

## Why TEE for Agents?

Autonomous agents need:
- **Private keys** for blockchain transactions
- **API credentials** for external services (OpenAI, databases, etc.)
- **Sensitive data** in RAG pipelines

Running in a TEE ensures these secrets remain protected, and attestation proves the agent code hasn't been tampered with.

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    dstack CVM (TDX)                        │
│                                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Your Agent                        │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │   │
│  │  │ LangChain│  │  Claude  │  │ Custom Agent     │   │   │
│  │  │  Agent   │  │ Agent SDK│  │ Framework        │   │   │
│  │  └────┬─────┘  └────┬─────┘  └────────┬─────────┘   │   │
│  │       │             │                 │             │   │
│  │       └─────────────┴─────────────────┘             │   │
│  │                     │                               │   │
│  │              dstack SDK                             │   │
│  │       ┌─────────────┴─────────────┐                 │   │
│  │       │                           │                 │   │
│  │  get_key()              Encrypted Env Vars          │   │
│  │  (wallet keys)          (API_KEY, DB_URL)           │   │
│  └───────┴───────────────────────────┴─────────────────┘   │
│                          │                                  │
│               /var/run/dstack.sock                          │
└────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Docker Compose

```yaml
# docker-compose.yaml
services:
  agent:
    image: your-agent-image:latest
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    environment:
      - OPENAI_API_KEY        # Encrypted at deploy time
      - ANTHROPIC_API_KEY     # Encrypted at deploy time
      - DATABASE_URL          # Encrypted at deploy time
    ports:
      - "8080:8080"
```

### 2. Derive Wallet Keys

Your agent can derive deterministic keys for blockchain operations:

```python
from dstack_sdk import DstackClient
from dstack_sdk.ethereum import to_account

client = DstackClient()

# Derive Ethereum wallet - same path = same key every time
eth_key = client.get_key('agent/wallet', 'mainnet')
account = to_account(eth_key)

print(f"Agent wallet: {account.address}")

# Sign transactions securely
signed_tx = account.sign_transaction(tx_dict)
```

### 3. Access Protected Credentials

API keys are encrypted at deploy time and only decrypted inside the TEE:

```python
import os
from langchain.llms import OpenAI

# These were encrypted during deployment
# Only accessible inside this specific TEE
api_key = os.environ["OPENAI_API_KEY"]

llm = OpenAI(api_key=api_key)
```

## LangChain Agent Example

```python
from langchain.agents import initialize_agent, Tool
from langchain.llms import ChatOpenAI
from dstack_sdk import DstackClient
from dstack_sdk.ethereum import to_account
import os

client = DstackClient()

# Derive a wallet for the agent
wallet = to_account(client.get_key('agent/eth-wallet', 'mainnet'))

def check_balance(address: str) -> str:
    """Check ETH balance of an address."""
    # ... web3 code
    return f"Balance: {balance} ETH"

def send_eth(to_address: str, amount: str) -> str:
    """Send ETH from agent wallet."""
    # Agent's private key never leaves the TEE
    tx = wallet.sign_transaction({
        'to': to_address,
        'value': int(float(amount) * 1e18),
        # ...
    })
    return f"Sent {amount} ETH to {to_address}"

tools = [
    Tool(name="CheckBalance", func=check_balance, description="Check ETH balance"),
    Tool(name="SendETH", func=send_eth, description="Send ETH to address"),
]

# API key is encrypted, only accessible in TEE
llm = ChatOpenAI(api_key=os.environ["OPENAI_API_KEY"])

agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
agent.run("Send 0.1 ETH to 0x742d35Cc...")
```

## Claude Agent SDK Example

```python
from anthropic import Anthropic
from dstack_sdk import DstackClient
import os

client = DstackClient()
anthropic = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

# Agent with TEE-derived signing keys
signing_key = client.get_key('agent/signing', 'production')

def execute_with_proof(task: str):
    """Execute task and provide attestation proof."""

    # Run the agent
    response = anthropic.messages.create(
        model="claude-sonnet-4-20250514",
        messages=[{"role": "user", "content": task}]
    )

    result = response.content[0].text

    # Generate attestation proving execution
    quote = client.get_quote(result.encode()[:64])

    return {
        "result": result,
        "attestation": quote.quote,
        "signing_address": signing_key.decode_key().hex()[:40]
    }
```

## RAG with Protected Documents

```python
from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings
from dstack_sdk import DstackClient
import os

client = DstackClient()

# Embeddings use protected API key
embeddings = OpenAIEmbeddings(api_key=os.environ["OPENAI_API_KEY"])

# Documents stored in TEE-encrypted storage
vectorstore = Chroma(
    persist_directory="/data/vectors",
    embedding_function=embeddings
)

def rag_query(question: str) -> dict:
    """Query with attestation proof."""

    docs = vectorstore.similarity_search(question, k=3)
    answer = generate_answer(question, docs)

    # Prove the query was executed in TEE
    quote = client.get_quote(f"{question}:{answer}".encode()[:64])

    return {
        "answer": answer,
        "sources": [d.metadata for d in docs],
        "attestation": quote.quote
    }
```

## Deploying with Encrypted Secrets

When deploying, encrypt sensitive environment variables:

```python
from dstack_sdk import encrypt_env_vars, EnvVar
import requests

# Define secrets
env_vars = [
    EnvVar(key='OPENAI_API_KEY', value='sk-...'),
    EnvVar(key='ANTHROPIC_API_KEY', value='sk-ant-...'),
    EnvVar(key='DATABASE_URL', value='postgresql://...'),
    EnvVar(key='WALLET_MNEMONIC', value='abandon abandon...'),
]

# Get encryption key from dstack KMS
response = requests.post(
    'https://your-dstack/prpc/GetAppEnvEncryptPubKey?json',
    json={'app_id': 'your-app-id'}
)
public_key = response.json()['public_key']

# Encrypt - only the TEE can decrypt
encrypted = encrypt_env_vars(env_vars, public_key)

# Deploy with encrypted secrets
deploy_app(compose_file, encrypted_env=encrypted)
```

## Verify Agent Execution

Clients can verify the agent is running unmodified in a TEE:

```python
import requests

# Get attestation from agent
attestation = requests.get(
    "https://agent-endpoint/attestation",
    params={"nonce": "random-challenge"}
).json()

# Verify TDX quote via proof.t16z.com or programmatically
is_valid = verify_tdx_quote(attestation['quote'])

# Check agent code hash matches expected
assert attestation['compose_hash'] == EXPECTED_AGENT_HASH
```

## Security Guarantees

| Feature | Protection |
|---------|------------|
| API Keys | Encrypted at deploy, decrypted only in TEE |
| Wallet Keys | Derived deterministically, never leave TEE |
| Agent Code | Measured and attested via TDX |
| Data in Transit | TLS termination inside TEE |
| Execution Proof | TDX quotes for any operation |

## Production Considerations

1. **Key Rotation**: Use versioned paths (`agent/wallet/v2`) for key rotation
2. **Rate Limiting**: Implement rate limits on wallet operations
3. **Audit Logging**: Use `emit_event()` for security-critical actions
4. **Multi-Sig**: Derive multiple keys for threshold signatures

## Source

- [dstack Python SDK](../sdk/python/README.md)
- [Environment Encryption Guide](../sdk/python/README.md#environment-variables-encryption)
