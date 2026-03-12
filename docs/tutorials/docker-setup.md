---
title: "Docker Setup"
description: "Install Docker Engine for dstack services"
section: "Prerequisites"
stepNumber: 3
totalSteps: 7
lastUpdated: 2026-01-09
prerequisites:
  - ssl-certificate-setup
tags:
  - docker
  - containers
  - prerequisites
difficulty: beginner
estimatedTime: "10 minutes"
---

# Docker Setup

This tutorial guides you through installing Docker Engine on your TDX server. Docker is required for the Gramine Key Provider and Local Docker Registry.

## What You'll Install

| Component | Purpose |
|-----------|---------|
| **docker-ce** | Docker Engine (Community Edition) |
| **docker-ce-cli** | Docker command-line interface |
| **containerd.io** | Container runtime |
| **docker-buildx-plugin** | Extended build capabilities |
| **docker-compose-plugin** | Multi-container orchestration |

## Prerequisites

Before starting, ensure you have:

- Completed [SSL Certificate Setup](/tutorial/ssl-certificate-setup)
- SSH access to your TDX server
- sudo privileges


## Manual Installation

### Step 1: Check if Docker is Already Installed

```bash
docker --version
```

If Docker is already installed, you can skip to [Verification](#verification).

### Step 2: Install Prerequisites

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
```

### Step 3: Add Docker GPG Key

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo tee /etc/apt/keyrings/docker.asc > /dev/null
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

### Step 4: Add Docker Repository

```bash
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

### Step 5: Install Docker Packages

```bash
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Step 6: Start Docker Service

```bash
sudo systemctl start docker
sudo systemctl enable docker
```

### Step 7: Add User to Docker Group

This allows running Docker commands without sudo:

```bash
sudo usermod -aG docker $USER
```

**Important:** Log out and back in for the group membership to take effect, or run:

```bash
newgrp docker
```

---

## Verification

### Check Docker is Running

```bash
docker info
```

You should see detailed information about the Docker installation.

### Check Docker Version

```bash
docker --version
```

Expected output:
```
Docker version 27.x.x, build xxxxxxx
```

### Test Docker

```bash
docker run hello-world
```

This downloads and runs a test image. You should see:
```
Hello from Docker!
This message shows that your installation appears to be working correctly.
```

---

## Troubleshooting

For detailed solutions, see the [Prerequisites Troubleshooting Guide](/tutorial/troubleshooting-prerequisites#docker-setup-issues):

- [Permission Denied](/tutorial/troubleshooting-prerequisites#permission-denied)
- [Docker Service Not Starting](/tutorial/troubleshooting-prerequisites#docker-service-not-starting)
- [Repository Not Found](/tutorial/troubleshooting-prerequisites#repository-not-found)

---

## Next Steps

With Docker installed, proceed to:

- [Gramine Key Provider](/tutorial/gramine-key-provider) - Deploy SGX-based key provider

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Engine Installation](https://docs.docker.com/engine/install/ubuntu/)
