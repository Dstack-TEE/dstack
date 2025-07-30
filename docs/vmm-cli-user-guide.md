# VMM CLI User Guide

Welcome to the **VMM CLI**! This tool helps you manage CVMs in the dstack platform.

## Table of Contents

- [Getting Started](#getting-started)
- [Basic Commands](#basic-commands)
- [VM Management](#vm-management)
- [Application Deployment](#application-deployment)
- [Security Features](#security-features)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

## Getting Started

### Prerequisites

Before using the VMM CLI, ensure you have:
- Python 3.6 or higher installed
- Access to a dstack-vmm server
- Required Python packages (cryptography, eth_keys, eth_utils)

### Installation

The VMM CLI is a single Python script (`vmm-cli.py`) that you can run directly:

```bash
./vmm-cli.py --help
```

### Basic Configuration

By default, the CLI connects to `http://localhost:8080`. You can configure the server URL in several ways:

### Server URL Configuration

#### Environment Variable (Recommended)

Set the `DSTACK_VMM_URL` environment variable:

```bash
# Set for current shell session
export DSTACK_VMM_URL=http://your-server:8080
./vmm-cli.py lsvm
```

#### Command Line Argument

Override the environment variable or default with `--url`:

```bash
./vmm-cli.py --url http://your-server:8080 <command>
```

#### Unix Domain Sockets

For local Unix socket connections:
```bash
# Via environment variable
export DSTACK_VMM_URL=unix:/path/to/socket

# Via command line
./vmm-cli.py --url unix:/path/to/socket <command>
```

**Priority Order:** Command line `--url` > `DSTACK_VMM_URL` environment variable > default `http://localhost:8080`

### Authentication

If your dstack-vmm server requires authentication, you can provide credentials using:

#### Environment Variables (Recommended)

```bash
# Set authentication credentials
export DSTACK_VMM_AUTH_USER=your-username
export DSTACK_VMM_AUTH_PASSWORD=your-password

# Then use CLI normally
./vmm-cli.py lsvm
```

#### Command Line Arguments

```bash
./vmm-cli.py --auth-user your-username --auth-password your-password lsvm
```

**Note:** Environment variables take precedence over command line arguments for authentication.


## Basic Commands

### List Virtual Machines

View all your VMs and their current status:

```bash
# Basic list
./vmm-cli.py lsvm

# Detailed view with configuration info
./vmm-cli.py lsvm -v
```

This shows VM ID, App ID, Name, Status, and Uptime. The verbose mode adds vCPU, Memory, Disk, Image, and GPU assignment information.

### List Available Images

See what VM images you can deploy:

```bash
./vmm-cli.py lsimage
```

### List Available GPUs

Check what GPU resources are available:

```bash
./vmm-cli.py lsgpu
```

This command shows available GPU slots, their descriptions, and availability status. GPU information is also displayed in the GPUs column when using `./vmm-cli.py lsvm -v`.

#### GPU Display in VM Listings

When using the verbose list command (`lsvm -v`), the GPUs column will show:
- **"All GPUs"** - when the VM is configured with `--ppcie` mode (all available GPUs)
- **"0a:00.0, 1a:00.0"** - specific GPU slot assignments when using `--gpu` flags
- **"-"** - when no GPUs are assigned to the VM

Example output:
```
┌──────────────────────┬─────────┬──────────┬─────────┬─────────┬──────┬─────────┬───────┬─────────────┬────────────────────┐
│ VM ID                │ App ID  │ Name     │ Status  │ Uptime  │ vCPU │ Memory  │ Disk  │ Image       │ GPUs               │
├──────────────────────┼─────────┼──────────┼─────────┼─────────┼──────┼─────────┼───────┼─────────────┼────────────────────┤
│ abc123...            │ xyz789  │ ml-model │ running │ 2h 30m  │ 8    │ 32GB    │ 500GB │ dstack-0.5.3│ 18:00.0, 9a:00.0  │
│ def456...            │ uvw012  │ web-app  │ running │ 1h 15m  │ 2    │ 4GB     │ 50GB  │ dstack-0.5.3│ -                  │
│ ghi789...            │ rst345  │ ai-train │ running │ 45m     │ 16   │ 64GB    │ 1TB   │ dstack-0.5.3│ All GPUs           │
└──────────────────────┴─────────┴──────────┴─────────┴─────────┴──────┴─────────┴───────┴─────────────┴────────────────────┘
```

## VM Management

### Starting and Stopping VMs

```bash
# Start a VM
./vmm-cli.py start <vm-id>

# Gracefully stop a VM
./vmm-cli.py stop <vm-id>

# Force stop a VM
./vmm-cli.py stop -f <vm-id>
```

### Viewing VM Logs

Monitor your VM's output:

```bash
# Show last 20 lines of logs
./vmm-cli.py logs <vm-id>

# Show last 50 lines
./vmm-cli.py logs <vm-id> -n 50

# Follow logs in real-time (like tail -f)
./vmm-cli.py logs <vm-id> -f
```

Press `Ctrl+C` to stop following logs.

### Removing VMs

When you're done with a VM:

```bash
./vmm-cli.py remove <vm-id>
```

**⚠️ Warning:** This permanently deletes the VM and all its data!

## Application Deployment

Deploying applications involves two main steps: creating an app compose file and deploying the VM.

### Step 1: Create App Compose File

First, create an application composition file that describes your application:

```bash
./vmm-cli.py compose \
  --name "my-web-app" \
  --docker-compose ./docker-compose.yml \
  --output ./app-compose.json
```

#### App Compose Options

- `--name`: Friendly name for your application
- `--docker-compose`: Path to your Docker Compose file
- `--prelaunch-script`: Optional script to run before starting containers
- `--kms`: Enable Key Management Service for secrets
- `--gateway`: Enable dstack-gateway for external access
- `--local-key-provider`: Use local key provider
- `--public-logs`: Make logs publicly accessible
- `--public-sysinfo`: Make system info publicly accessible
- `--env-file`: File with environment variables to encrypt
- `--no-instance-id`: Disable unique instance identification

#### Example with Security Features

```bash
./vmm-cli.py compose \
  --name "secure-app" \
  --docker-compose ./docker-compose.yml \
  --kms \
  --gateway \
  --env-file ./secrets.env \
  --output ./app-compose.json
```

### Step 2: Deploy the VM

Deploy your application with the compose file:

```bash
./vmm-cli.py deploy \
  --name "my-app-vm" \
  --image "dstack-0.5.3" \
  --compose ./app-compose.json \
  --vcpu 2 \
  --memory 2G \
  --disk 50G
```

#### Deployment Options

- `--name`: VM instance name
- `--image`: Base VM image to use
- `--compose`: Path to your app-compose.json file
- `--vcpu`: Number of virtual CPUs (default: 1)
- `--memory`: Memory size (e.g., 1G, 512M, 2048M)
- `--disk`: Disk size (e.g., 20G, 100G)
- `--port`: Port mappings (see Port Mapping section)
- `--gpu`: GPU assignments
- `--ppcie`: Enable PPCIE mode (attach ALL available GPUs and NVSwitches)
- `--env-file`: Environment variables file
- `--user-config`: Path to user config file (will be placed at `/dstack/.user-config` in the CVM)
- `--kms-url`: KMS server URL
- `--gateway-url`: Gateway server URL
- `--stopped`: Create VM in stopped state (requires dstack-vmm >= 0.5.4)

#### Port Mapping

Expose services running in your VM:

```bash
# Format: protocol:host_port:vm_port
--port tcp:8080:80

# Format: protocol:host_address:host_port:vm_port
--port tcp:127.0.0.1:8080:80

# Multiple ports
--port tcp:8080:80 --port tcp:8443:443
```

#### GPU Assignment

The VMM CLI supports two GPU attachment modes:

##### Specific GPU Assignment

Assign individual GPUs by their slot identifiers:

```bash
# Single GPU
--gpu "0a:00.0"

# Multiple specific GPUs
--gpu "0a:00.0" --gpu "1a:00.0" --gpu "2a:00.0"
```

You can find the slot identifiers by running `./vmm-cli.py lsgpu`.

##### PPCIE (Protected PCIe) Mode

To run the CVM in PPCIE mode, use the `--ppcie` flag. This will attach ALL available GPUs and NVSwitches to the CVM.

```bash
# Enable PPCIE (Protected PCIe) mode - attach ALL available GPUs and NVSwitches
--ppcie
```

**Important Notes:**
- `--ppcie` takes precedence over individual `--gpu` specifications
- Use `./vmm-cli.py lsgpu` to see available GPU slots before assignment
- PPCIE mode (`--ppcie`) provides the best performance for GPU-intensive workloads in a CVM

#### Testing Your Deployment

After successful deployment, verify your VM is running correctly:

```bash
# Check if your VM appears in the list
./vmm-cli.py lsvm -v

# Monitor the startup process
./vmm-cli.py logs <vm-id> -f
```

#### Complete Deployment Examples

##### Simple Web Application (Local Development)

```bash
# Connect to local VMM instance
export DSTACK_VMM_URL=http://127.0.0.1:12000

# If authentication is required
export DSTACK_VMM_AUTH_USER=your-username
export DSTACK_VMM_AUTH_PASSWORD=your-password

# Create a basic docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
EOF

# Create app compose file
./vmm-cli.py compose \
  --name "test-webapp" \
  --docker-compose ./docker-compose.yml \
  --output ./app-compose.json

# Deploy the VM
./vmm-cli.py deploy \
  --name "test-vm" \
  --image "dstack-dev-0.5.3" \
  --compose ./app-compose.json \
  --vcpu 2 \
  --memory 4G \
  --disk 30G

# Verify deployment
./vmm-cli.py lsvm -v
```

##### Web Server with Specific GPUs

```bash
./vmm-cli.py deploy \
  --name "web-server" \
  --image "dstack-0.5.3" \
  --compose ./app-compose.json \
  --vcpu 4 \
  --memory 4G \
  --disk 100G \
  --port tcp:8080:80 \
  --port tcp:8443:443 \
  --gpu "0" --gpu "1" \
  --env-file ./production.env \
  --kms-url http://kms-server:9000
```

##### High-Performance ML Workload with All GPUs

```bash
# Set VMM URL via environment
export DSTACK_VMM_URL=http://ml-cluster:8080

# Deploy with all GPUs in PPCIE mode
./vmm-cli.py deploy \
  --name "ml-training" \
  --image "pytorch:latest" \
  --compose ./ml-app-compose.json \
  --vcpu 16 \
  --memory 32G \
  --disk 500G \
  --ppcie \
  --hugepages \
  --pin-numa \
  --env-file ./ml-secrets.env
```

##### VM with User Configuration and Stopped State

```bash
# Create a user configuration file
cat > user-config.json << EOF
{
  "timezone": "UTC",
  "locale": "en_US.UTF-8",
  "custom_settings": {
    "debug_mode": false,
    "log_level": "INFO"
  }
}
EOF

# Deploy VM in stopped state with user config
./vmm-cli.py deploy \
  --name "configured-vm" \
  --image "dstack-0.5.4" \
  --compose ./app-compose.json \
  --vcpu 4 \
  --memory 8G \
  --disk 100G \
  --user-config ./user-config.json \
  --stopped

# The VM is created but not started - start it manually when ready
./vmm-cli.py start configured-vm
```

**Note:** The `--stopped` flag is useful for:
- Pre-staging VMs for later use
- Preparing VMs with specific configurations before startup

### Environment Variable Encryption

The VMM CLI automatically encrypts sensitive environment variables before sending them to the server.

#### Creating Environment Files

Create a `secrets.env` file with your variables:

```bash
# secrets.env
DATABASE_URL=postgresql://user:pass@db:5432/myapp
API_KEY=secret-api-key-12345
JWT_SECRET=your-jwt-secret-here
```

Lines starting with `#` are ignored as comments.

#### Using Encrypted Variables

```bash
# During compose creation
./vmm-cli.py compose \
  --name "my-app" \
  --docker-compose ./docker-compose.yml \
  --env-file ./secrets.env \
  --kms \
  --output ./app-compose.json

# During deployment
./vmm-cli.py deploy \
  --name "my-app-vm" \
  --image "dstack-0.5.3" \
  --compose ./app-compose.json \
  --env-file ./secrets.env
```

### KMS (Key Management Service)

KMS provides secure key management and CVM execution verification.

#### Trusted KMS Public Key Whitelist

Manage trusted KMS public keys for enhanced security:

```bash
# List current trusted KMS public keys
./vmm-cli.py kms list

# Add a trusted KMS public key
./vmm-cli.py kms add 0x1234567890abcdef...

# Remove a trusted KMS public key
./vmm-cli.py kms remove 0x1234567890abcdef...
```

The whitelist is stored in `~/.dstack-vmm/kms-whitelist.json`.

### Updating Running VMs

#### Update Environment Variables

```bash
./vmm-cli.py update-env <vm-id> --env-file ./new-secrets.env
```

#### Update Application Compose

```bash
./vmm-cli.py update-app-compose <vm-id> ./new-app-compose.json
```

#### Update User Configuration

```bash
./vmm-cli.py update-user-config <vm-id> ./new-config.json
```

### Performance Optimization

#### NUMA Pinning

For better performance on multi-socket systems:

```bash
./vmm-cli.py deploy \
  --name "high-perf-vm" \
  --image "dstack-0.5.3" \
  --compose ./app-compose.json \
  --pin-numa
```

#### Huge Pages

Enable huge pages for memory-intensive applications:

```bash
./vmm-cli.py deploy \
  --name "memory-intensive-vm" \
  --image "dstack-0.5.3" \
  --compose ./app-compose.json \
  --hugepages
```

### Size Specifications

The CLI accepts human-readable size formats:

#### Memory Sizes
- `1G` or `1GB` = 1024 MB
- `512M` or `512MB` = 512 MB
- `2T` or `2TB` = 2,097,152 MB

#### Disk Sizes
- `50G` or `50GB` = 50 GB
- `1T` or `1TB` = 1024 GB

## Troubleshooting
#### VM Won't Start

1. Check VM logs: `./vmm-cli.py logs <vm-id>`
2. Verify image exists: `./vmm-cli.py lsimage`
3. Check resource availability: `./vmm-cli.py lsgpu`

#### Port Mapping Problems

Ensure ports are not already in use:
```bash
# Check if port is available
netstat -tuln | grep :8080
```

### Getting Help

- Use `--help` with any command for detailed options
- Check the server logs for additional error information
- Verify your Docker Compose file is valid before creating the app compose
- Use `./vmm-cli.py lsgpu` to see available GPU slots and their status
- Set `DSTACK_VMM_URL` environment variable to avoid typing `--url` repeatedly

### Error Messages

#### "API call failed"
- Check server URL and connectivity
- Verify server is running and accessible

#### "Invalid signature"
- Add the signer to your trusted whitelist
- Or confirm to proceed with untrusted signer

#### "VM not found"
- Use `./vmm-cli.py lsvm` to verify VM ID
- Check if VM was removed
