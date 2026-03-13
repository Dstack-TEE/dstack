---
title: "Troubleshooting: dstack Installation"
description: "Solutions for common issues during system dependencies, Rust toolchain, VMM build, configuration, service, management interface, and guest image setup"
section: "Troubleshooting"
stepNumber: null
totalSteps: null
isAppendix: true
tags:
  - troubleshooting
  - dstack
  - vmm
  - rust
  - installation
difficulty: intermediate
estimatedTime: "reference"
lastUpdated: 2026-03-06
---

# Troubleshooting: dstack Installation

This appendix consolidates troubleshooting content from the dstack Installation tutorials. For inline notes and warnings, see the individual tutorials.

---

## System Baseline Dependencies Issues

### Package Installation Fails

```bash
# Fix broken packages
sudo apt --fix-broken install

# Clear apt cache and retry
sudo apt clean
sudo apt update
sudo apt install -y build-essential
```

### OpenMetal Grub Error

On OpenMetal servers, you may see this error during package installation:

```
grub-install: error: diskfilter writes are not supported.
```

**This error does not affect dstack installation** - your packages are still installed correctly. To prevent this from blocking future apt operations:

```bash
sudo apt-mark hold grub-pc grub-efi-amd64-signed
```

### Kernel Upgrade Prompts

If prompted about kernel upgrades during `apt upgrade`:
1. Select "Keep the local version currently installed" if unsure
2. A reboot may be required after kernel updates

```bash
# Check if reboot is required
cat /var/run/reboot-required 2>/dev/null || echo "No reboot required"
```

---

## Rust Toolchain Installation Issues

### rustup command not found

If `rustup` is not found after installation:

```bash
# Manually add to PATH
export PATH="$HOME/.cargo/bin:$PATH"

# Add to shell profile permanently
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Permission denied errors

```bash
# Ensure cargo directory is owned by your user
sudo chown -R $USER:$USER ~/.cargo ~/.rustup
```

### Network timeout during installation

```bash
# Increase timeout and retry
export CARGO_HTTP_TIMEOUT=300
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Updating Rust

To update to the latest stable version:

```bash
rustup update stable
```

---

## Clone & Build dstack-vmm Issues

### Network timeout downloading crates

```bash
export CARGO_HTTP_TIMEOUT=300
cargo build --release
```

### Linker errors

Ensure build dependencies are installed:

```bash
sudo apt install -y build-essential pkg-config libssl-dev
```

### Permission denied on install

```bash
# Ensure you're using sudo
sudo cp ~/dstack/target/release/dstack-vmm /usr/local/bin/

# Or install to user directory
mkdir -p ~/.local/bin
cp ~/dstack/target/release/dstack-vmm ~/.local/bin/
```

### Build cache issues

```bash
cargo clean
cargo update
cargo build --release
```

---

## VMM Configuration Issues

### Configuration file not found

```bash
ls -la /etc/dstack/vmm.toml
```

### TOML syntax errors

```bash
python3 -c "import tomllib; tomllib.load(open('/etc/dstack/vmm.toml', 'rb')); print('TOML syntax OK')"
```

If valid, prints "TOML syntax OK". If invalid, shows the error location.

### Permission denied on socket

```bash
sudo ls -la /var/run/dstack/
sudo chmod 755 /var/run/dstack
```

### Resource limit errors

Check current usage and adjust limits:

```bash
ps aux --sort=-%mem | head
# Then reduce max_allocable_vcpu or max_allocable_memory_in_mb
```

---

## VMM Service Setup Issues

### Service fails to start

```bash
# Check logs for error details
sudo journalctl -u dstack-vmm -n 100 --no-pager

# Check binary exists
which dstack-vmm
ls -la /usr/local/bin/dstack-vmm

# Check config exists
ls -la /etc/dstack/vmm.toml
```

### Service keeps restarting

```bash
# Check for crash loops
sudo journalctl -u dstack-vmm --since "10 minutes ago" | grep -i error

# Check memory
free -h
```

### HTTP API not responding

```bash
# Check VMM is listening on port 9080
sudo ss -tlnp | grep 9080

# Check logs for binding errors
sudo journalctl -u dstack-vmm -n 50 | grep -i "endpoint\|bind\|error"

# Restart service
sudo systemctl restart dstack-vmm
```

### Supervisor socket not created

```bash
# Check directory exists
ls -la /var/run/dstack/

# Create if missing and restart
sudo mkdir -p /var/run/dstack
sudo chmod 755 /var/run/dstack
sudo systemctl restart dstack-vmm
```

### Permission denied errors

```bash
# Ensure directories are writable
sudo chmod 755 /var/run/dstack /var/log/dstack /var/lib/dstack
```

---

## Management Interface Setup Issues

### 502 Bad Gateway

**Symptom:** HAProxy returns 502 error

**Solution:**
```bash
# Check VMM is running
sudo systemctl status dstack-vmm

# Check VMM is listening on 9080
sudo ss -tlnp | grep 9080

# Start VMM if needed
sudo systemctl start dstack-vmm
```

### Connection Refused

**Symptom:** Cannot connect to https://vmm.dstack.yourdomain.com

**Solution:**
```bash
# Check HAProxy is running
sudo systemctl status haproxy

# Check HAProxy is listening on 443
sudo ss -tlnp | grep 443

# Check firewall allows 443
sudo ufw status
```

### DNS Not Resolving

**Symptom:** Browser shows DNS error

**Solution:**
```bash
# Verify DNS resolves (wildcard should cover vmm.dstack.*)
dig +short vmm.dstack.yourdomain.com

# Should return your server IP
# If not, check your wildcard DNS record in Cloudflare
```

### Authentication Failed

**Symptom:** API returns 401 Unauthorized

**Solution:**
1. Verify saved token matches vmm.toml: `cat ~/.dstack/secrets/vmm-auth-token` vs `sudo grep tokens /etc/dstack/vmm.toml`
2. Check `Authorization: Bearer TOKEN` header format
3. Re-save if needed: `sudo python3 -c "import tomllib; c=tomllib.load(open('/etc/dstack/vmm.toml','rb')); print(c['auth']['tokens'][0], end='')" > ~/.dstack/secrets/vmm-auth-token`

### Backend Marked as DOWN

**Symptom:** HAProxy stats show vmm_backend as DOWN

**Solution:**
```bash
# Check HAProxy stats
curl -s http://127.0.0.1:8404/stats | grep vmm

# Verify VMM responds to health check
curl -s http://127.0.0.1:9080/

# Check HAProxy logs
sudo journalctl -u haproxy --no-pager -n 20
```

---

## Guest Image Setup Issues

### Images not appearing in VMM

Check the VMM logs for image loading errors:

```bash
sudo journalctl -u dstack-vmm -n 100 --no-pager | grep -i image
```

Common issues:

**Image directory not found:**
```bash
# Verify image directory exists and has correct permissions
ls -la /var/lib/dstack/images/
```

**Metadata.json missing or invalid:**
```bash
# Check if metadata exists
cat /var/lib/dstack/images/dstack-*/metadata.json
```

**VMM not configured for correct path:**
```bash
# Check VMM configuration
grep image_path /etc/dstack/vmm.toml
```

### Image download fails

Try alternative download methods:

```bash
# Using curl instead of wget
curl -L -o dstack-${DSTACK_VERSION}.tar.gz \
  https://github.com/Dstack-TEE/meta-dstack/releases/download/v${DSTACK_VERSION}/dstack-${DSTACK_VERSION}.tar.gz
```

### Image metadata missing

If metadata.json is missing, the image may be corrupted:

```bash
# Re-download and extract
rm -rf /var/lib/dstack/images/dstack-${DSTACK_VERSION}
# Then repeat Steps 2-3
```

### VMM service not running

```bash
# Check service status
sudo systemctl status dstack-vmm

# View recent logs
sudo journalctl -u dstack-vmm -n 50

# Restart if needed
sudo systemctl restart dstack-vmm
```
