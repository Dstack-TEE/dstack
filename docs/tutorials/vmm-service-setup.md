---
title: "VMM Service Setup"
description: "Configure dstack VMM to run as a systemd service with automatic startup"
section: "dstack Installation"
stepNumber: 5
totalSteps: 8
lastUpdated: 2025-12-07
prerequisites:
  - vmm-configuration
tags:
  - dstack
  - vmm
  - systemd
  - service
difficulty: "intermediate"
estimatedTime: "10 minutes"
---

# VMM Service Setup

This tutorial guides you through setting up the dstack Virtual Machine Monitor (VMM) as a systemd service. Running VMM as a service ensures it starts automatically on boot and restarts if it crashes.

## Prerequisites

Before starting, ensure you have:

- Completed [VMM Configuration](/tutorial/vmm-configuration)
- SSH access to your TDX-enabled server
- Root or sudo privileges


## Service Management Commands

| Command | Description |
|---------|-------------|
| `sudo systemctl start dstack-vmm` | Start the service |
| `sudo systemctl stop dstack-vmm` | Stop the service |
| `sudo systemctl restart dstack-vmm` | Restart the service |
| `sudo systemctl status dstack-vmm` | Check service status |
| `sudo systemctl enable dstack-vmm` | Enable start on boot |
| `sudo systemctl disable dstack-vmm` | Disable start on boot |

### View Logs

| Command | Description |
|---------|-------------|
| `journalctl -u dstack-vmm` | View all logs |
| `journalctl -u dstack-vmm -n 100` | View last 100 lines |
| `journalctl -u dstack-vmm -f` | Follow logs in real-time |
| `journalctl -u dstack-vmm --since "1 hour ago"` | Logs from last hour |
| `journalctl -u dstack-vmm -p err` | Show only errors |

---

## Manual Setup

If you prefer to set up the service manually, follow these steps.

### Step 1: Create the Systemd Service File

```bash
sudo tee /etc/systemd/system/dstack-vmm.service > /dev/null <<'EOF'
[Unit]
Description=dstack Virtual Machine Monitor
Documentation=https://dstack.org
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/dstack-vmm --config /etc/dstack/vmm.toml serve
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Resource limits for handling many concurrent VMs
LimitNOFILE=65536
LimitNPROC=4096

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
RuntimeDirectory=dstack
ReadWritePaths=/var/run/dstack /var/log/dstack /var/lib/dstack /tmp

[Install]
WantedBy=multi-user.target
EOF
```

### Step 2: Reload Systemd and Enable Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable dstack-vmm
```

### Step 3: Start the Service

```bash
sudo systemctl start dstack-vmm
```

### Step 4: Verify Service Status

```bash
sudo systemctl status dstack-vmm
```

Expected output:
```
● dstack-vmm.service - dstack Virtual Machine Monitor
     Loaded: loaded (/etc/systemd/system/dstack-vmm.service; enabled)
     Active: active (running) since ...
```

### Step 5: Verify VMM is Working

Check that the HTTP API is responding:

```bash
curl -s http://127.0.0.1:9080/ | head -5
```

Check that the supervisor socket exists:

```bash
ls -la /var/run/dstack/supervisor.sock
```

---

## Service Configuration

### Service File Explained

| Setting | Description |
|---------|-------------|
| `Type=simple` | Service runs as a foreground process |
| `User=root` | VMM requires root for VM management |
| `Restart=always` | Automatically restart on failure |
| `RestartSec=5` | Wait 5 seconds before restarting |
| `LimitNOFILE=65536` | Max open file descriptors (for many concurrent VMs) |
| `LimitNPROC=4096` | Max processes/threads |
| `ProtectSystem=strict` | Read-only access to system directories |
| `RuntimeDirectory=dstack` | Creates `/run/dstack` automatically on each boot |
| `ReadWritePaths` | Directories VMM can write to |

### Environment Variables

To enable debug logging:

```bash
sudo tee /etc/systemd/system/dstack-vmm.service.d/environment.conf > /dev/null <<'EOF'
[Service]
Environment="RUST_LOG=debug"
Environment="RUST_BACKTRACE=1"
EOF
sudo systemctl daemon-reload
sudo systemctl restart dstack-vmm
```

---

## Troubleshooting

For detailed solutions, see the [dstack Installation Troubleshooting Guide](/tutorial/troubleshooting-dstack-installation#vmm-service-setup-issues):

- [Service fails to start](/tutorial/troubleshooting-dstack-installation#service-fails-to-start)
- [Service keeps restarting](/tutorial/troubleshooting-dstack-installation#service-keeps-restarting)
- [HTTP API not responding](/tutorial/troubleshooting-dstack-installation#http-api-not-responding)
- [Supervisor socket not created](/tutorial/troubleshooting-dstack-installation#supervisor-socket-not-created)
- [Permission denied errors](/tutorial/troubleshooting-dstack-installation#permission-denied-errors)

---

## Next Steps

With VMM running as a service, proceed to deploy the Key Management Service:

- [Contract Deployment](/tutorial/contract-deployment) - Deploy KMS contracts to Sepolia

## Additional Resources

- [systemd Documentation](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [journalctl Manual](https://www.freedesktop.org/software/systemd/man/journalctl.html)
- [dstack GitHub Repository](https://github.com/Dstack-TEE/dstack)
