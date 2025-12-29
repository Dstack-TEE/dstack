# Private Inference

Run LLM inference with hardware attestation and cryptographic proof of responses.

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────────────┐
│   Client    │     │                 dstack CVM                    │
│             │     │  ┌─────────────┐      ┌─────────────────┐    │
│  Request ───┼────►│  │ vllm-proxy  │──────│  vLLM Backend   │    │
│             │     │  │ (attestation│      │  (OpenAI API)   │    │
│  ◄──────────┼─────│  │  + signing) │◄─────│                 │    │
│  Response   │     │  └─────────────┘      └─────────────────┘    │
│  + Signature│     │         │                                    │
│  + TEE Quote│     │         └── /var/run/dstack.sock             │
└─────────────┘     └──────────────────────────────────────────────┘
```

**vllm-proxy** adds a security layer to vLLM:
- **Hardware attestation** — TEE quotes proving execution in secure hardware
- **Response signing** — Every response cryptographically signed (ECDSA + ED25519)
- **GPU attestation** — NVIDIA Confidential Computing verification (when available)

## Quick Start

```yaml
services:
  vllm-proxy:
    image: dstacktee/vllm-proxy:latest
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    environment:
      - MODEL_NAME=openai/gpt-oss-20b
    ports:
      - "8000:8000"

  vllm:
    image: vllm/vllm-openai:latest
    runtime: nvidia
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
    command: --model openai/gpt-oss-20b
```

Deploy to [Phala Cloud](https://cloud.phala.network) or any dstack instance.

## Usage

Standard OpenAI-compatible API:

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://your-endpoint:8000/v1",
    api_key="your-token"
)

response = client.chat.completions.create(
    model="openai/gpt-oss-20b",
    messages=[{"role": "user", "content": "Hello!"}]
)

print(response.choices[0].message.content)
```

## Verify

Every response can be verified. Retrieve the signature and attestation:

```python
import requests

# Get signature for a chat completion
chat_id = response.id
sig = requests.get(f"https://your-endpoint:8000/v1/signature/{chat_id}").json()

print(f"Request hash: {sig['request_hash']}")
print(f"Response hash: {sig['response_hash']}")
print(f"ECDSA signature: {sig['ecdsa_signature']}")
print(f"Signing address: {sig['signing_address']}")

# Get attestation report
attestation = requests.get(
    f"https://your-endpoint:8000/v1/attestation",
    params={"nonce": "your-random-nonce"}
).json()

print(f"TEE quote: {attestation['quote'][:100]}...")
print(f"GPU evidence: {attestation.get('gpu_evidence', 'N/A')}")
```

Or paste the attestation into [proof.t16z.com](https://proof.t16z.com) for visual verification.

The attestation binds the signing key to the TEE hardware. Verify:
1. TEE quote is valid (via [proof.t16z.com](https://proof.t16z.com) or dstack verifier)
2. Signing address in quote matches the one that signed responses
3. Response hash matches your received content

## Live Demo

Try it: [dstack-demo.phala.com](https://dstack-demo.phala.com)

## Production Users

- **redpill.ai** — Verifiable AI inference platform
- **NEAR AI** — Decentralized AI services

## Source

[github.com/Dstack-TEE/vllm-proxy](https://github.com/Dstack-TEE/vllm-proxy)
