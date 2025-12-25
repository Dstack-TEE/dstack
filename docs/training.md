# Confidential Training

Fine-tune LLMs on sensitive data with hardware-enforced privacy.

## Why TEE for Training?

Training data is often the most sensitive asset:
- **Medical records** for healthcare AI
- **Financial data** for fraud detection
- **Proprietary documents** for enterprise RAG
- **User conversations** for personalization

Running training in a TEE ensures:
- Data is encrypted in memory
- Model weights stay protected
- Training code is attested and verifiable

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      dstack CVM (TDX)                        │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                    Training Pipeline                   │  │
│  │                                                        │  │
│  │  ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │  │
│  │  │ Encrypted│    │ Unsloth  │    │   Fine-tuned     │  │  │
│  │  │ Dataset  │───►│  / LoRA  │───►│   Model          │  │  │
│  │  │          │    │ Training │    │   (encrypted)    │  │  │
│  │  └──────────┘    └──────────┘    └──────────────────┘  │  │
│  │       ▲                                    │           │  │
│  │       │                                    ▼           │  │
│  │  Decrypted                         Model export        │  │
│  │  only in TEE                       with attestation    │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  GPU: NVIDIA H100 (Confidential Computing)                   │
└──────────────────────────────────────────────────────────────┘
```

## Quick Start

### Docker Compose

```yaml
# docker-compose.yaml
services:
  trainer:
    image: unsloth/unsloth:latest
    runtime: nvidia
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
      - HF_TOKEN              # Encrypted at deploy time
      - WANDB_API_KEY         # Encrypted at deploy time
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - /mnt/data:/data       # Encrypted dataset
      - /mnt/models:/models   # Model output
    command: python train.py
```

### Training Script

```python
# train.py
from unsloth import FastLanguageModel
from dstack_sdk import DstackClient
import os

client = DstackClient()

# Verify we're running in TEE
info = client.info()
print(f"Training in TEE: {info.app_id}")
print(f"TCB Info: {info.tcb_info}")

# Load base model
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/Llama-3.2-3B-Instruct",
    max_seq_length=2048,
    load_in_4bit=True,
)

# Add LoRA adapters
model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    lora_alpha=16,
    lora_dropout=0,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
)

# Load sensitive training data (decrypted only in TEE)
from datasets import load_dataset
dataset = load_dataset("json", data_files="/data/training.json")

# Train
from trl import SFTTrainer
from transformers import TrainingArguments

trainer = SFTTrainer(
    model=model,
    train_dataset=dataset["train"],
    args=TrainingArguments(
        output_dir="/models/output",
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        num_train_epochs=3,
        learning_rate=2e-4,
        fp16=True,
        logging_steps=10,
        save_strategy="epoch",
    ),
    tokenizer=tokenizer,
)

trainer.train()

# Save with attestation proof
model.save_pretrained("/models/finetuned")

# Generate attestation for the training run
quote = client.get_quote(b"training-complete")
with open("/models/finetuned/attestation.txt", "w") as f:
    f.write(quote.quote)

print("Training complete with attestation proof")
```

## Encrypted Dataset Upload

Encrypt datasets before uploading:

```python
from dstack_sdk import encrypt_env_vars, EnvVar
import requests
import json

# Encrypt the dataset content
dataset = json.dumps([
    {"instruction": "...", "response": "..."},
    # ... sensitive training examples
])

env_vars = [EnvVar(key='TRAINING_DATA', value=dataset)]

# Get encryption key from KMS
response = requests.post(
    'https://your-dstack/prpc/GetAppEnvEncryptPubKey?json',
    json={'app_id': 'training-app-id'}
)
public_key = response.json()['public_key']

encrypted = encrypt_env_vars(env_vars, public_key)
# Deploy with encrypted dataset
```

For large datasets, use encrypted volumes or secure data transfer protocols.

## Verify Training Provenance

After training, verify the model was trained in a TEE:

```python
import requests

# Get training attestation
with open("model/attestation.txt") as f:
    quote = f.read()

# Verify the quote
# Option 1: Paste into proof.t16z.com for visual verification
# Option 2: Programmatic verification
verification = verify_tdx_quote(quote)

print(f"Valid TEE: {verification['valid']}")
print(f"App hash: {verification['compose_hash']}")
```

## Multi-GPU Training

For distributed training across multiple GPUs:

```yaml
# docker-compose.yaml
services:
  trainer:
    image: unsloth/unsloth:latest
    runtime: nvidia
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
      - NCCL_DEBUG=INFO
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - /mnt/data:/data
      - /mnt/models:/models
    command: >
      torchrun --nproc_per_node=4 train.py
      --model unsloth/Llama-3.2-8B-Instruct
      --data /data/training.json
```

## Continuous Training Pipeline

```python
from dstack_sdk import DstackClient
import schedule
import time

client = DstackClient()

def training_job():
    """Run scheduled training with attestation."""

    # Log training start
    client.emit_event("training", json.dumps({
        "status": "started",
        "timestamp": time.time()
    }))

    try:
        # Run training
        run_training()

        # Generate success attestation
        quote = client.get_quote(b"training-success")
        upload_model_with_attestation(quote.quote)

        client.emit_event("training", json.dumps({
            "status": "completed",
            "timestamp": time.time()
        }))

    except Exception as e:
        client.emit_event("training", json.dumps({
            "status": "failed",
            "error": str(e),
            "timestamp": time.time()
        }))
        raise

# Schedule daily training
schedule.every().day.at("02:00").do(training_job)

while True:
    schedule.run_pending()
    time.sleep(60)
```

## NVIDIA Confidential Computing

For full GPU memory encryption, use NVIDIA H100 with Confidential Computing:

```yaml
# docker-compose.yaml with CC-enabled GPU
services:
  trainer:
    image: unsloth/unsloth:latest
    runtime: nvidia
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
      - NVIDIA_CC_ACCEPT_EULA=accept  # Enable Confidential Computing
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
```

With CC-enabled GPUs:
- GPU memory is encrypted
- Model weights protected during training
- Gradient data stays confidential

## Security Guarantees

| Stage | Protection |
|-------|------------|
| Dataset at rest | Encrypted storage |
| Dataset in memory | TDX memory encryption |
| Model weights | TDX + GPU CC memory encryption |
| Gradients | Never leave TEE |
| Output model | Attestation-signed |

## Frameworks Tested

| Framework | Status | Notes |
|-----------|--------|-------|
| Unsloth | ✅ Production | Fast LoRA fine-tuning |
| Hugging Face TRL | ✅ Production | Full RLHF support |
| PyTorch | ✅ Production | Native training |
| DeepSpeed | ✅ Tested | Distributed training |
| Axolotl | ✅ Tested | Config-driven training |

## Production Considerations

1. **Checkpointing**: Save checkpoints to encrypted storage
2. **Logging**: Use `emit_event()` for audit trails
3. **Data Validation**: Verify dataset integrity before training
4. **Model Export**: Sign models with TEE-derived keys

## Source

- [Unsloth](https://github.com/unslothai/unsloth) - Fast LLM fine-tuning
- [dstack Python SDK](../sdk/python/README.md)
