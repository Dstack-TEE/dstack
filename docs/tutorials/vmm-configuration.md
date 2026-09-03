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
# Optional. See "NVIDIA GPU attestation cache" below.
# nvidia_attestation_proxy_url = "http://10.0.2.2:8090"
docker_registry = ""
cid_start = 1000
cid_pool_size = 1000
max_allocable_vcpu = 124                        # Adjust: total cores - 4
max_allocable_memory_in_mb = 990616             # Adjust: total MB - 16384
qmp_socket = false
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

[cvm.gpu.nvswitch]
managed = false

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

### Optional: NVIDIA GPU attestation cache

GPU images perform local NVIDIA attestation before app keys are provisioned.
Without a cache this contacts NVIDIA's OCSP and RIM services during every cold
boot. A fleet can run the persistent
[`dstack-nvidia-attest-proxy`](../../dstack/nvidia-attest-proxy/README.md) and pass its
URL to guests through sys-config:

```toml
[cvm]
nvidia_attestation_proxy_url = "http://10.0.2.2:8090"
```

The example address is the host as seen from QEMU user-mode networking. The
proxy must be reachable during `dstack-prepare`. It stores only NVIDIA-signed
collateral and never becomes a signing trust anchor. OCSP entries are not
served after their signed validity window.

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
# Example: narrow this list to what the host actually holds if you want discovery to reject anything else.
listing = ["10de:2335", "10de:3182"]   # H200 SXM, B300 SXM6
allow_attach_all = true
```

A card whose product ID is not in `listing` is never offered for passthrough,
so the shipped default names every Hopper and Blackwell SKU dstack runs on —
see `[cvm.gpu]` in `dstack/vmm/vmm.toml` for the annotated list. NVSwitches are
not listed: the `all` attach mode finds GPUs and switches by PCI class instead.

**Requirements:**
- IOMMU enabled in BIOS
- VFIO driver configured
- GPU not in use by host

### NVSwitch Partitions

On an HGX/DGX host, the NVIDIA fabric manager can only activate NVLink
partitions that already exist in its partition definition file, and it reads
that file once, at startup. Its built-in table hard-codes a fixed set of GPU
groupings, so handing an arbitrary subset of the free GPUs to a new CVM is not
expressible. Let dstack-vmm own the file instead:

```toml
[cvm.gpu.nvswitch]
managed = true
partition_file = "/usr/share/nvidia/nvswitch/customPartition.json"
apply_command = ["/usr/local/bin/dstack-apply-fabric-partitions"]
apply_timeout_ms = 60000

[cvm.gpu.nvswitch.module_ids]
"0000:1b:00.0" = 1
"0000:43:00.0" = 2
# ... one entry per attachable GPU
```

Every VM start then rewrites the file with one partition per GPU-attached VM
that is running or starting. A VM keeps the partition id it was assigned on its
first start, so a rewrite never redefines the partition a running VM sits on,
and the file is rewritten — and `apply_command` run — only when the partitions
actually changed.

`module_ids` maps each attachable GPU's PCI address to its fabric module id,
which `nvidia-smi -q` reports as `Module ID` on the host.

#### The apply command

`apply_command` owns the whole way from a rewritten file to a partition the
guest can use, **activation included**. When it exits 0, dstack-vmm attaches the
GPUs and boots the VM; it has no way to check whether the partition is really
live, so an incomplete command fails silently at the point where the guest finds
no NVLink.

The command gets two variables:

| Variable | Meaning |
| --- | --- |
| `DSTACK_NVSWITCH_PARTITION_FILE` | Path of the file just written. |
| `DSTACK_NVSWITCH_ACTIVE_PARTITION_IDS` | The ids that must be live when the command returns, and the only ones that may be. |

The second is a goal, not a report. The table only ever holds VMs that are
running or starting, so its ids are exactly the ids that belong active — the
command's job is to converge the fabric to that set:

```sh
#!/bin/sh
set -e
systemctl restart nvidia-fabricmanager   # reload the table; does not activate
for id in $DSTACK_NVSWITCH_ACTIVE_PARTITION_IDS; do
    fmpm -a "$id"
done
```

Restarting the fabric manager on its own only makes it re-read the file. It
leaves every partition *defined but inactive*, which is why there is no default
`apply_command`: a host that sets `managed = true` has to state how its table
becomes effective, and dstack-vmm refuses to start otherwise.

**Requirements:**
- `SHARED_PARTITION_DEFINITION_FILE` in `fabricmanager.cfg` points at
  `partition_file`
- The NVSwitches stay on the host — a VM that also passes NVSwitch bridges
  through is rejected while this is managed
- dstack-vmm may write `partition_file` and run `apply_command`

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
