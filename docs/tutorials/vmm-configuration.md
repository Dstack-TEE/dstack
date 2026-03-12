---
title: "VMM Configuration"
description: "Configure the dstack Virtual Machine Monitor for your environment"
section: "dstack Installation"
stepNumber: 4
totalSteps: 8
lastUpdated: 2025-12-07
prerequisites:
  - clone-build-dstack-vmm
  - dns-configuration
tags:
  - dstack
  - vmm
  - configuration
  - toml
difficulty: "intermediate"
estimatedTime: "15 minutes"
---

# VMM Configuration

This tutorial guides you through configuring the dstack Virtual Machine Monitor (VMM) for **production use**. The VMM uses a TOML configuration file to define server settings, VM resource limits, networking, authentication, and service endpoints.

## Prerequisites

Before starting, ensure you have:

- Completed [Clone & Build dstack-vmm](/tutorial/clone-build-dstack-vmm)
- SSH access to your TDX-enabled server
- Root or sudo privileges
- Your gateway domain configured (e.g., `dstack.yourdomain.com`)


## Configuration

### Step 1: Connect to Your Server

```bash
ssh ubuntu@YOUR_SERVER_IP
```

### Step 2: Check Server Resources

```bash
# Check CPU cores
nproc

# Check total memory in MB
free -m | awk '/^Mem:/{print $2}'
```

Calculate your resource limits:
- **Max vCPUs**: Total cores - 4 (reserve for host)
- **Max Memory**: Total MB - 16384 (reserve 16GB for host)
- **Workers**: Total cores / 8 (minimum 4, maximum 32)

For example, on a 128-core, 1TB RAM server:
- Max vCPUs: 128 - 4 = **124**
- Max Memory: 1,007,000 - 16,384 = **990,616 MB**
- Workers: 128 / 8 = **16**

### Step 3: Generate an Auth Token

```bash
# Generate a secure random token and save it
AUTH_TOKEN=$(openssl rand -hex 32)
mkdir -p ~/.dstack/secrets
echo -n "$AUTH_TOKEN" > ~/.dstack/secrets/vmm-auth-token
chmod 600 ~/.dstack/secrets/vmm-auth-token
echo "Auth token saved to ~/.dstack/secrets/vmm-auth-token"
```

### Step 4: Create Configuration Directory

```bash
sudo mkdir -p /etc/dstack
```

### Step 5: Create VMM Configuration File

Replace the placeholder values with your actual settings:

```bash
AUTH_TOKEN=$(cat ~/.dstack/secrets/vmm-auth-token)
sudo tee /etc/dstack/vmm.toml > /dev/null <<EOF
# dstack VMM Configuration - Production
# See: https://dstack.info/tutorial/vmm-configuration

# Server settings
workers = 16                                    # Adjust based on your CPU count
max_blocking = 64
ident = "dstack VMM"
temp_dir = "/tmp"
keep_alive = 10
log_level = "info"
address = "127.0.0.1:9080"
reuse = true
kms_url = "http://127.0.0.1:8081"
event_buffer_size = 20
node_name = ""
image_path = "/var/lib/dstack/images"

[cvm]
qemu_path = ""
kms_urls = ["http://127.0.0.1:8081"]
gateway_urls = ["http://127.0.0.1:8082"]
pccs_url = "https://pccs.phala.network/sgx/certification/v4"
docker_registry = ""
cid_start = 1000
cid_pool_size = 1000
max_allocable_vcpu = 124                        # Adjust: total cores - 4
max_allocable_memory_in_mb = 990616             # Adjust: total MB - 16384
qmp_socket = false
user = ""
use_mrconfigid = true
qemu_pci_hole64_size = 0
qemu_hotplug_off = false

[cvm.networking]
mode = "user"
net = "10.0.2.0/24"
dhcp_start = "10.0.2.10"
restrict = false

[cvm.port_mapping]
enabled = true
address = "127.0.0.1"
range = [
    { protocol = "tcp", from = 1, to = 20000 },
]

[cvm.auto_restart]
enabled = true
interval = 20

[cvm.gpu]
enabled = false
listing = []
exclude = []
include = []
allow_attach_all = false

[gateway]
base_domain = "dstack.yourdomain.com"              # Your gateway domain
port = 8082
agent_port = 8090

[auth]
enabled = true                                  # Production: enable auth
tokens = ["$AUTH_TOKEN"]

[supervisor]
exe = "/usr/local/bin/dstack-supervisor"
sock = "/var/run/dstack/supervisor.sock"
pid_file = "/var/run/dstack/supervisor.pid"
log_file = "/var/log/dstack/supervisor.log"
detached = false
auto_start = true

[host_api]
ident = "dstack VMM"
address = "vsock:2"
port = 10000

[key_provider]
enabled = true
address = "127.0.0.1"
port = 3443
EOF
```

The `$AUTH_TOKEN` variable is automatically substituted from `~/.dstack/secrets/vmm-auth-token`.

### Step 6: Configure Host QCNL for Quote Generation

The host's Quote Generation Service (QGS) needs to reach a PCCS to fetch PCK certificates for TDX quote generation. This is **separate** from the CVM's `pccs_url` setting in vmm.toml — both must point to a working PCCS.

> **Important:** There are two independent PCCS configurations:
>
> | Config | File | Used By | Purpose |
> |--------|------|---------|---------|
> | Host QCNL | `/etc/sgx_default_qcnl.conf` | QGS | PCK certs for quote **generation** |
> | CVM pccs_url | `/etc/dstack/vmm.toml` | dstack-util inside CVM | Collateral for quote **verification** |
>
> Both must point to a working PCCS. If the host QCNL is misconfigured, CVMs will fail during boot with `QGS error code: 0x12001`.

Update the host QCNL to use Phala Network's public PCCS:

```bash
sudo tee /etc/sgx_default_qcnl.conf > /dev/null << 'EOF'
{
  "pccs_url": "https://pccs.phala.network/sgx/certification/v4/",
  "use_secure_cert": false,
  "retry_times": 6,
  "retry_delay": 10,
  "pck_cache_expire_hours": 168,
  "verify_collateral_cache_expire_hours": 168,
  "local_cache_only": false
}
EOF
```

Restart QGS to pick up the new configuration:

```bash
sudo systemctl restart qgsd
```

Verify QGS is running:

```bash
systemctl status qgsd
```

### Step 7: Create Runtime Directories

```bash
sudo mkdir -p /var/run/dstack
sudo mkdir -p /var/log/dstack
sudo mkdir -p /var/lib/dstack
sudo chmod 755 /var/run/dstack /var/log/dstack /var/lib/dstack
```

### Step 8: Verify Configuration

```bash
# Check config file exists
cat /etc/dstack/vmm.toml

# Verify TOML syntax (no output = valid, error message = invalid)
python3 -c "import tomllib; tomllib.load(open('/etc/dstack/vmm.toml', 'rb')); print('TOML syntax OK')"
```

---

## Configuration Reference

### Networking Modes

| Mode | Performance | Isolation | Setup | Recommended For |
|------|-------------|-----------|-------|-----------------|
| `user` | Good | Good | None | **Recommended** — reliable internet access from CVM boot |

| `host` | Best | None | None | Special cases only |

**User Mode (Recommended):**

QEMU user-mode networking creates a virtual NAT network inside the QEMU process. Internet connectivity is available **immediately** when the CVM boots — before external network routes are established. This is critical because the CVM's `dstack-prepare` service needs to reach the public PCCS (`pccs.phala.network`) during early boot to fetch SGX quote collateral for sealing key verification.

```toml
[cvm.networking]
mode = "user"
net = "10.0.2.0/24"
dhcp_start = "10.0.2.10"
restrict = false
```

With user-mode networking, CVMs have internet access through QEMU's built-in NAT. The PCCS at `https://pccs.phala.network` is reachable immediately, and host services are accessible at `10.0.2.2`.

### Authentication

For production, always enable authentication:

```toml
[auth]
enabled = true
tokens = ["your-secure-token-here"]
```

You can specify multiple tokens for different clients:

```toml
[auth]
enabled = true
tokens = [
    "token-for-admin",
    "token-for-ci-cd",
    "token-for-monitoring"
]
```

### GPU Passthrough

To enable GPU passthrough for AI/ML workloads:

```toml
[cvm.gpu]
enabled = true
listing = ["10de:2335"]          # NVIDIA GPU product IDs
allow_attach_all = true
```

**Requirements:**
- IOMMU enabled in BIOS
- VFIO driver configured
- GPU not in use by host

---

## Troubleshooting

For detailed solutions, see the [dstack Installation Troubleshooting Guide](/tutorial/troubleshooting-dstack-installation#vmm-configuration-issues):

- [Configuration file not found](/tutorial/troubleshooting-dstack-installation#configuration-file-not-found)
- [TOML syntax errors](/tutorial/troubleshooting-dstack-installation#toml-syntax-errors)
- [Permission denied on socket](/tutorial/troubleshooting-dstack-installation#permission-denied-on-socket)
- [Resource limit errors](/tutorial/troubleshooting-dstack-installation#resource-limit-errors)

---

## Next Steps

With VMM configured, proceed to set up the systemd service:

- [VMM Service Setup](/tutorial/vmm-service-setup) - Create and start the VMM service

## Additional Resources

- [dstack GitHub Repository](https://github.com/Dstack-TEE/dstack)
- [TOML Specification](https://toml.io/en/)
