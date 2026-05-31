# Quickstart

Deploy your first confidential workload on GCP in under 10 minutes.

> **Interested in AWS Nitro Enclaves?** We support AWS Nitro attestation verification and are expanding deployment tooling. [Book a call](https://calendly.com/aspect-ux/30min) to learn more about AWS deployment options.

## Prerequisites

- GCP account with Confidential VM quota (Intel TDX)
- `gcloud` CLI installed and authenticated

## Install the CLI

Download the `dstack-cloud` CLI:

```bash
# Clone the repository (temporary until packaged release)
git clone https://github.com/Phala-Network/meta-dstack-cloud.git
export PATH="$PATH:$(pwd)/meta-dstack-cloud/scripts/bin"
```

Verify the installation:

```bash
dstack-cloud --help
```

## Configure

Set up your cloud credentials:

```bash
dstack-cloud config-edit
```

This opens an editor with the global configuration file. For GCP, configure:

```toml
[gcp]
project = "your-gcp-project-id"
zone = "us-central1-a"
machine_type = "n2d-standard-4"
```

## Create a Project

Create a new dstack-cloud project:

```bash
dstack-cloud new my-app
cd my-app
```

This creates a project directory with:

```
my-app/
├── app.json           # Application configuration
├── docker-compose.yaml # Your container definition
├── .env               # Environment variables
└── prelaunch.sh       # Pre-launch script (optional)
```

## Define Your Workload

Edit `docker-compose.yaml` with your application:

```yaml
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
```

For AI workloads with GPU:

```yaml
services:
  vllm:
    image: vllm/vllm-openai:latest
    runtime: nvidia
    command: --model Qwen/Qwen2.5-7B-Instruct
    ports:
      - "8000:8000"
```

## Add Secrets (Optional)

Add sensitive environment variables to `.env`:

```bash
API_KEY=your-secret-key
DATABASE_URL=postgres://...
```

These are encrypted before leaving your machine and only decrypted inside the TEE.

## Deploy

Deploy to your cloud provider:

```bash
dstack-cloud deploy
```

The CLI will:
1. Build and push your container configuration
2. Create a Confidential VM
3. Boot the dstack guest OS
4. Start your containers

## Check Status

Monitor your deployment:

```bash
# Check deployment status
dstack-cloud status

# View console logs
dstack-cloud logs

# Follow logs in real-time
dstack-cloud logs --follow
```

## Configure Firewall

Allow traffic to your application:

```bash
# Allow HTTPS traffic
dstack-cloud fw allow 443

# Allow your app port
dstack-cloud fw allow 8080

# List firewall rules
dstack-cloud fw list
```

## Access Your App

Once deployed, access your application via the assigned endpoint. The `dstack-cloud status` command shows the public URL.

For apps with TLS:
```
https://<app-id>.<gateway-domain>
```

For specific ports:
```
https://<app-id>-8080.<gateway-domain>
```

## Verify Attestation

Users can verify your deployment is running in a genuine TEE:

```bash
# Get attestation quote from your app
curl https://<your-app>/attestation

# Verify with dstack-verifier
dstack-verifier verify <quote>
```

See the [Verification Guide](./verification.md) for details.

## Manage Deployments

```bash
# List all deployments
dstack-cloud list

# Stop a deployment
dstack-cloud stop

# Start a stopped deployment
dstack-cloud start

# Remove a deployment completely
dstack-cloud remove
```

## Next Steps

- [Usage Guide](./usage.md) - Detailed deployment and management
- [Confidential AI](./confidential-ai.md) - Run AI workloads with hardware privacy
- [GCP Attestation](./attestation-gcp.md) - How TDX + TPM attestation works
- [AWS Nitro Attestation](./attestation-nitro-enclave.md) - How NSM attestation works
- [Security Model](./security/security-model.md) - Understand the trust boundaries

## Troubleshooting

**Deployment stuck at "Creating VM":**
- Check your cloud quota for Confidential VMs
- Verify your credentials with `gcloud auth list`

**Container not starting:**
- Check logs with `dstack-cloud logs`
- Verify your docker-compose.yaml syntax
- Ensure images are accessible from the cloud region

**Cannot access application:**
- Check firewall rules with `dstack-cloud fw list`
- Verify the port mapping in docker-compose.yaml
- Check if the container is healthy in the logs
