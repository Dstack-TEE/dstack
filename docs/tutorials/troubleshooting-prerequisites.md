---
title: "Troubleshooting: Prerequisites"
description: "Solutions for common issues during DNS, SSL, Docker, HAProxy, key provider, blockchain, and registry setup"
section: "Troubleshooting"
stepNumber: null
totalSteps: null
isAppendix: true
tags:
  - troubleshooting
  - dns
  - ssl
  - docker
  - haproxy
  - registry
  - blockchain
  - prerequisites
difficulty: intermediate
estimatedTime: "reference"
lastUpdated: 2026-03-06
---

# Troubleshooting: Prerequisites

This appendix consolidates troubleshooting content from the Prerequisites tutorials. For inline notes and warnings, see the individual tutorials.

---

## DNS Configuration Issues

### DNS Not Resolving

**Issue:** `dig` returns `NXDOMAIN` or no answer.

**Solutions:**
1. Wait for DNS propagation (can take up to 48 hours)
2. Check nameservers are set correctly at registrar
3. Verify Cloudflare shows domain as "Active"
4. Ensure DNS records saved correctly in Cloudflare dashboard

### Wildcard Not Working

**Issue:** Base domain resolves, but `*.dstack.yourdomain.com` doesn't.

**Solutions:**
1. Verify wildcard record uses `*.dstack` not `*`
2. Check wildcard record has same IP as base record
3. Confirm proxy status is "DNS only" (gray cloud)
4. Wait for DNS cache to expire (TTL)

### API Token Permission Denied

**Issue:** `curl` test returns `"success": false` or permission errors.

**Solutions:**
1. Verify token has "Zone → DNS → Edit" permission
2. Ensure token is scoped to correct zone (your domain)
3. Check token hasn't expired (if TTL was set)
4. Regenerate token if compromised

### Propagation Taking Too Long

**Issue:** DNS changes not visible after several hours.

**Solutions:**
1. Check nameservers at registrar match Cloudflare's
2. Use `dig @1.1.1.1` to query Cloudflare DNS directly (bypasses local cache)
3. Clear local DNS cache: `sudo systemd-resolve --flush-caches` (Linux) or `sudo dscacheutil -flushcache` (macOS)
4. Test from external DNS checker: https://www.whatsmydns.net/

---

## SSL Certificate Setup Issues

### Challenge Failed: Could not connect

**Symptom:** Certbot fails with connection error

**Solution:**
1. Verify port 80 is open: `sudo ss -tlnp | grep :80`
2. Stop any services using port 80
3. Check firewall allows port 80: `sudo ufw status`
4. Verify DNS resolves to your server: `dig +short registry.yourdomain.com`

### Rate Limit Exceeded

**Symptom:** Let's Encrypt returns rate limit error

**Solution:**
1. Wait 1 hour and retry
2. Check https://letsencrypt.org/docs/rate-limits/

### DNS Resolution Failed

**Symptom:** Certbot can't verify domain ownership

**Solution:**
1. Check DNS record exists: `dig +short registry.yourdomain.com`
2. Wait for DNS propagation (up to 48 hours for new records)
3. Verify record points to correct IP

### HAProxy Can't Read Certificates

**Symptom:** HAProxy fails to start with certificate permission error

**Solution:**
```bash
# Check certificate permissions
sudo ls -la /etc/letsencrypt/live/registry.yourdomain.com/

# Certificates are symlinks - check actual files
sudo ls -la /etc/letsencrypt/archive/registry.yourdomain.com/

# Check HAProxy combined PEM files
sudo ls -la /etc/haproxy/certs/

# Regenerate combined PEM if needed
sudo cat /etc/letsencrypt/live/registry.yourdomain.com/fullchain.pem \
         /etc/letsencrypt/live/registry.yourdomain.com/privkey.pem \
         | sudo tee /etc/haproxy/certs/registry.pem > /dev/null
sudo chmod 600 /etc/haproxy/certs/registry.pem

# If issues persist, check HAProxy logs
sudo journalctl -u haproxy --no-pager -n 20
```

---

## Docker Setup Issues

### Permission Denied

**Symptom:** `Got permission denied while trying to connect to the Docker daemon socket`

**Solution:**
1. Ensure user is in docker group: `groups`
2. If not listed, add user: `sudo usermod -aG docker $USER`
3. Log out and back in, or run: `newgrp docker`

### Docker Service Not Starting

**Symptom:** `systemctl status docker` shows failed

**Solution:**
```bash
# Check logs
sudo journalctl -u docker -n 50

# Common fix: restart containerd first
sudo systemctl restart containerd
sudo systemctl restart docker
```

### Repository Not Found

**Symptom:** `apt update` fails with Docker repository error

**Solution:**
```bash
# Verify the repository file
cat /etc/apt/sources.list.d/docker.list

# Should contain a valid URL for your Ubuntu version
# If incorrect, recreate with Step 4 above
```

---

## HAProxy Setup Issues

### Port 443 Already in Use

**Symptom:** HAProxy fails to start with "Address already in use"

**Solution:**
```bash
# Find what's using port 443
sudo ss -tlnp | grep :443

# Common culprits: nginx, apache, docker
sudo systemctl stop nginx 2>/dev/null
sudo systemctl stop apache2 2>/dev/null

# Check for Docker containers on 443
docker ps --format '{{.Names}} {{.Ports}}' | grep 443
```

### Configuration Test Fails

**Symptom:** `haproxy -c` shows errors

**Solution:**
```bash
# Check the specific error message
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Common issues:
# - Certificate file not found: check /etc/haproxy/certs/
# - Invalid ACL syntax: check domain patterns
# - Backend server unreachable: check service is running
```

### Certificate Errors

**Symptom:** TLS handshake failures

**Solution:**
```bash
# Check certificate files exist
ls -la /etc/haproxy/certs/

# Verify certificate format (should have both cert and key)
openssl x509 -in /etc/haproxy/certs/registry.pem -noout -subject
openssl rsa -in /etc/haproxy/certs/registry.pem -check -noout

# Regenerate combined PEM if needed
sudo cat /etc/letsencrypt/live/registry.yourdomain.com/fullchain.pem \
         /etc/letsencrypt/live/registry.yourdomain.com/privkey.pem \
         | sudo tee /etc/haproxy/certs/registry.pem > /dev/null
```

### Backend Health Check Failing

**Symptom:** Backend marked as DOWN in stats

**Solution:**
```bash
# Check if backend service is running
sudo ss -tlnp | grep 5000  # Registry
sudo ss -tlnp | grep 9080  # VMM
sudo ss -tlnp | grep 9204  # Gateway proxy
sudo ss -tlnp | grep 9202  # Gateway RPC

# Test backend directly
curl -s http://127.0.0.1:5000/v2/  # Registry
curl -s http://127.0.0.1:9080/     # VMM
```

### Gateway Not Receiving Traffic

**Symptom:** Requests to *.dstack.* domains fail

**Solution:**
```bash
# Check gateway proxy is listening on 9204
sudo ss -tlnp | grep 9204

# Check gateway RPC is listening on 9202
sudo ss -tlnp | grep 9202

# Check HAProxy routing (enable debug)
sudo haproxy -d -f /etc/haproxy/haproxy.cfg

# Verify SNI pattern in config matches your domain
grep "dstack" /etc/haproxy/haproxy.cfg
```

---

## Gramine Key Provider Issues

### Container fails to start: SGX devices not found

**Symptom:** Container exits immediately with device error

**Solution:**
1. Verify SGX devices exist: `ls -la /dev/sgx*`
2. If missing, check BIOS SGX settings
3. Ensure SGX kernel module is loaded: `lsmod | grep sgx`

### Error: AESM service not ready

**Symptom:** Key provider fails with AESM connection error

**Solution:**
```bash
# Restart aesmd first
docker restart aesmd
sleep 5
docker restart gramine-sealing-key-provider

# Check aesmd logs
docker logs aesmd 2>&1 | tail -30
```

### Quote verification failures

**Symptom:** Logs show "quote verification failed"

**Solution:**
1. Verify QCNL configuration points to `https://pccs.phala.network/sgx/certification/v4/`
2. Check network connectivity: `curl -sk https://pccs.phala.network/sgx/certification/v4/rootcacrl`
3. Verify the QCNL config file exists at `~/dstack/key-provider-build/sgx_default_qcnl.conf`

### Empty response from curl test

**Symptom:** `curl -sk https://127.0.0.1:3443/` returns nothing

**Explanation:** This is normal. The key provider doesn't serve a root endpoint - it only responds to specific API calls from CVMs. An empty response means the TLS handshake succeeded, confirming the service is running.

If you get `curl: (7) Failed to connect`, the service is not running - check container logs with `docker logs gramine-sealing-key-provider`.

### Port 3443 already in use

**Symptom:** Container fails to bind to port

**Solution:**
```bash
# Find what's using the port
sudo ss -tlnp | grep 3443

# Kill the process or change port in docker-compose.yml
```

### SGX enclave initialization timeout

**Symptom:** Container starts but enclave never initializes

**Solution:**
1. Check SGX is enabled in BIOS
2. Verify SGX Auto MP Registration is enabled
3. Check PCCS is reachable: `curl -sk https://pccs.phala.network/sgx/certification/v4/rootcacrl`

---

## Blockchain Wallet Setup Issues

### Problem: Faucet not sending ETH

**Solutions:**

-   Try different faucet from the list above
-   Check wallet address is correct
-   Wait 5-10 minutes (sometimes delayed)
-   Check block explorer:
    ```bash
    open "https://sepolia.etherscan.io/address/$(cat ~/.dstack/secrets/sepolia-address)"
    ```

### Problem: RPC endpoint timing out

**Solutions:**

-   Check internet connection
-   Verify RPC URL is correct (should be `https://ethereum-sepolia-rpc.publicnode.com`)
-   Try a different public RPC endpoint from [chainlist.org](https://chainlist.org/chain/11155111)

### Problem: "Connection refused" error

**Solutions:**

-   Ensure using `https://` not `http://`
-   Try alternative RPC endpoint
-   Check firewall not blocking outbound connections

### Problem: Can't see balance in cast

**Solutions:**

-   Wait for testnet ETH to arrive (check block explorer)
-   Verify RPC URL is correct
-   Try different RPC endpoint
-   Ensure wallet address is correct

---

## Local Docker Registry Issues

### Certificate Verification Failed

**Symptom:** `curl` returns SSL certificate error

**Solution:**
```bash
# Check certificate dates
openssl x509 -in /etc/letsencrypt/live/registry.yourdomain.com/fullchain.pem -dates -noout

# If expired, renew
sudo certbot renew --force-renewal

# Reload HAProxy to pick up new certs
sudo systemctl reload haproxy
```

### 503 Service Unavailable from HAProxy

**Symptom:** `curl https://registry.yourdomain.com/v2/` returns `503 Service Unavailable`, but `curl http://127.0.0.1:5000/v2/` works fine locally.

**Root Cause:** HAProxy's health check has marked the registry backend as DOWN. This typically happens when HAProxy started before the registry container was running.

**Solution:**
```bash
# Check backend health status in HAProxy stats
curl -s http://127.0.0.1:8404/stats | grep registry

# Or check via the stats page (via SSH tunnel)
ssh -L 8404:127.0.0.1:8404 user@your-server
# Then open http://localhost:8404/stats in browser
```

The fix is simply to reload HAProxy so it re-checks the backend:

```bash
sudo systemctl reload haproxy
```

After reloading, HAProxy will re-run its health check (`GET /v2/`), see the registry is healthy, and start routing traffic again. Verify:

```bash
curl -s https://registry.yourdomain.com/v2/
```

> **Tip:** If you start services in the order: HAProxy first, then registry, HAProxy will mark the registry backend as DOWN until the next health check interval. Reloading HAProxy forces an immediate re-check.

### 502 Bad Gateway from HAProxy

**Symptom:** External requests return 502 error

**Solution:**
```bash
# Check registry container is running
docker ps | grep registry

# Check registry is listening on localhost:5000
curl -s http://127.0.0.1:5000/v2/

# If not running, start it
docker start registry

# Check container logs for errors
docker logs registry
```

### DNS Not Resolving (Docker Registry)

**Symptom:** `curl` to registry fails with "Could not resolve host"

**Solution:**
1. Verify DNS record exists: `dig +short registry.yourdomain.com`
2. Wait for DNS propagation (up to 48 hours for new records)
3. Check Cloudflare/DNS provider dashboard

### Registry Container Not Starting

**Symptom:** Container won't start or immediately exits

**Solution:**
```bash
# Check container logs
docker logs registry

# Remove and recreate if needed
docker rm -f registry
docker run -d \
  --name registry \
  --restart always \
  -p 127.0.0.1:5000:5000 \
  -v /var/lib/registry:/var/lib/registry \
  registry:2
```

### HAProxy Configuration Error

**Symptom:** HAProxy won't start or reload

**Solution:**
```bash
# Test configuration
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Check HAProxy logs
sudo journalctl -u haproxy --no-pager -n 20

# Verify certificates exist
ls -la /etc/haproxy/certs/
```
