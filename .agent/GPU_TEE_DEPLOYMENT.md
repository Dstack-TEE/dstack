# GPU TEE Deployment Guide

Learnings from deploying GPU workloads to Phala Cloud TEE infrastructure.

## Instance Types

Query available instance types:
```bash
curl -s "https://cloud-api.phala.network/api/v1/instance-types" | jq
```

### CPU-only (Intel TDX)
- `tdx.small` through `tdx.8xlarge`

### GPU (H200 + TDX)
- `h200.small` — Single H200 GPU, suitable for inference
- `h200.16xlarge` — Multi-GPU for larger workloads
- `h200.8x.large` — High-memory configuration

## Deployment Commands

### GPU Deployment
```bash
phala deploy -n my-app -c docker-compose.yaml \
  --instance-type h200.small \
  --region US-EAST-1 \
  --image dstack-nvidia-dev-0.5.4.1
```

Key flags:
- `--instance-type h200.small` — Required for GPU access
- `--image dstack-nvidia-dev-0.5.4.1` — NVIDIA development image with GPU drivers
- `--region US-EAST-1` — Region with GPU nodes (gpu-use2)

### Debugging
```bash
# Check CVM status
phala cvms list

# View serial logs (boot + container output)
phala cvms serial-logs <app_id> --tail 100

# Delete CVM
phala cvms delete <name-or-id> --force
```

## Docker Compose GPU Configuration

GPU devices must be explicitly reserved in docker-compose.yaml:

```yaml
services:
  my-gpu-app:
    image: my-image
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

Without the `deploy.resources.reservations.devices` section, the container will fail with:
```
libcuda.so.1: cannot open shared object file: No such file or directory
```

## vLLM Example

Working docker-compose.yaml for vLLM inference:

```yaml
services:
  vllm:
    image: vllm/vllm-openai:latest
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
      - HF_TOKEN=${HF_TOKEN:-}
    ports:
      - "8000:8000"
    command: >
      --model Qwen/Qwen2.5-1.5B-Instruct
      --host 0.0.0.0
      --port 8000
      --max-model-len 4096
      --gpu-memory-utilization 0.8
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

## Endpoint URLs

After deployment, the app is accessible at:
```
https://<app_id>-<port>.dstack-pha-<region>.phala.network
```

Example for vLLM on port 8000:
```bash
# List models
curl https://<app_id>-8000.dstack-pha-use2.phala.network/v1/models

# Chat completion
curl -X POST https://<app_id>-8000.dstack-pha-use2.phala.network/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "Qwen/Qwen2.5-1.5B-Instruct", "messages": [{"role": "user", "content": "Hello"}]}'
```

## vllm-proxy (Response Signing)

vllm-proxy provides response signing and attestation for vLLM inference. It sits between clients and vLLM, signing responses with TEE-derived keys.

### Configuration

**IMPORTANT**: The authentication environment variable is `TOKEN`, not `AUTH_TOKEN`.

```yaml
services:
  vllm:
    image: vllm/vllm-openai:latest
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
    command: >
      --model Qwen/Qwen2.5-1.5B-Instruct
      --host 0.0.0.0
      --port 8000
      --max-model-len 4096
      --gpu-memory-utilization 0.8
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]

  proxy:
    image: phalanetwork/vllm-proxy:v0.2.18
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock  # Required for TEE key derivation
    environment:
      - VLLM_BASE_URL=http://vllm:8000
      - MODEL_NAME=Qwen/Qwen2.5-1.5B-Instruct
      - TOKEN=your-secret-token    # NOT AUTH_TOKEN
    ports:
      - "8000:8000"
    depends_on:
      - vllm
```

### API Endpoints

```bash
# List models (no auth required)
curl https://<endpoint>/v1/models

# Chat completion (requires auth)
curl -X POST https://<endpoint>/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret-token" \
  -d '{"model": "Qwen/Qwen2.5-1.5B-Instruct", "messages": [{"role": "user", "content": "Hello"}]}'

# Get response signature
curl https://<endpoint>/v1/signature/<chat_id> \
  -H "Authorization: Bearer your-secret-token"

# Attestation report
curl https://<endpoint>/v1/attestation/report \
  -H "Authorization: Bearer your-secret-token"
```

### Tested Configuration

- Image: `phalanetwork/vllm-proxy:v0.2.18`
- Instance: `h200.small`
- Region: `US-EAST-1`
- Model: `Qwen/Qwen2.5-1.5B-Instruct`

### vllm-proxy Issues

**"Invalid token" error**:
- Check that you're using `TOKEN` environment variable, not `AUTH_TOKEN`
- Verify the token value matches your request header

**"All connection attempts failed" from proxy**:
- vLLM is still loading the model (takes 1-2 minutes after container starts)
- Wait for vLLM to show "Uvicorn running on" in serial logs

**NVML error on attestation**:
- GPU confidential computing attestation may not be fully available
- This doesn't affect inference or response signing

## Common Issues

### "No available resources match your requirements"
- GPU nodes are limited. Wait for other CVMs to finish or try a different region.
- Ensure you're using the correct instance type (`h200.small`).

### Container crashes with GPU errors
- Add `deploy.resources.reservations.devices` section to docker-compose.yaml.
- Verify using NVIDIA development image (`dstack-nvidia-dev-*`).

### Image pull takes too long
- Large images (5GB+ for vLLM) take 3-5 minutes to download and extract.
- Check serial logs for progress.

## Testing Workflow

1. Deploy: `phala deploy -n test -c docker-compose.yaml --instance-type h200.small --region US-EAST-1 --image dstack-nvidia-dev-0.5.4.1`
2. Wait for status: `phala cvms list` (wait for "running")
3. Check logs: `phala cvms serial-logs <app_id> --tail 100`
4. Test API: `curl https://<app_id>-<port>.dstack-pha-use2.phala.network/...`
5. Cleanup: `phala cvms delete <name> --force`

## GPU Wrapper Script

For repeated GPU deployments, use a wrapper script:

```bash
#!/bin/bash
# phala-gpu.sh
source "$(dirname "$0")/.env"
export PHALA_CLOUD_API_KEY=$PHALA_CLOUD_API_GPU
phala "$@"
```

This allows maintaining separate API keys for CPU and GPU workspaces.
