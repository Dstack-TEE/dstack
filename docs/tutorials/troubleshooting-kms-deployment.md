---
title: "Troubleshooting: KMS Deployment"
description: "Solutions for common issues during contract deployment, KMS build, and KMS CVM deployment"
section: "Troubleshooting"
stepNumber: null
totalSteps: null
isAppendix: true
tags:
  - troubleshooting
  - kms
  - contracts
  - deployment
  - cvm
difficulty: intermediate
estimatedTime: "reference"
lastUpdated: 2026-03-06
---

# Troubleshooting: KMS Deployment

This appendix consolidates troubleshooting content from the KMS Deployment tutorials. For inline notes and warnings, see the individual tutorials.

---

## Contract Deployment Issues

### Artifact not found

```
Error HH700: Artifact for contract "DstackApp" not found.
```

Contracts must be compiled before deployment. Run:

```bash
npx hardhat compile
```

### Insufficient funds

```
Error: insufficient funds for gas
```

Get Sepolia ETH from faucets listed above.

### Transaction underpriced

```
Error: replacement transaction underpriced
```

Wait for pending transactions to complete, then retry.

### Nonce too low

```
Error: nonce too low
```

A transaction with this nonce already exists. Wait for confirmation.

### Connection failed

```
Error: could not detect network
```

Check your RPC endpoint is reachable:

```bash
curl -s -X POST "https://ethereum-sepolia-rpc.publicnode.com" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

Should return a block number, not an error.

---

## KMS Build & Configuration Issues

### Build fails with missing dependencies

```
Error: linker `cc` not found
```

Install build dependencies:

```bash
sudo apt install -y build-essential pkg-config libssl-dev
```

### Configuration file not found

```
Error: Could not find configuration file
```

Verify the file exists and has correct permissions:

```bash
ls -la /etc/kms/kms.toml
```

### Auth-eth npm install fails

```
Error: EACCES permission denied
```

Fix npm permissions:

```bash
mkdir -p ~/.npm-global
npm config set prefix '~/.npm-global'
export PATH=~/.npm-global/bin:$PATH
npm install
```

### Invalid TOML syntax

```
Error: invalid TOML
```

Validate your configuration:

```bash
cat /etc/kms/kms.toml | python3 -c "import sys, tomllib; tomllib.load(sys.stdin.buffer)"
```

### RPC connection failed

```
Error: could not connect to RPC
```

Check network connectivity:

```bash
curl -s -X POST "https://ethereum-sepolia-rpc.publicnode.com" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### Contract address not set

```
Error: KMS_CONTRACT_ADDR not set
```

Ensure you've completed [Contract Deployment](/tutorial/contract-deployment) and the contract address is saved:

```bash
cat ~/.dstack/secrets/kms-contract-address
```

---

## KMS CVM Deployment Issues

### CVM fails to start

```
Error: Failed to create CVM
```

Check VMM status and logs:

```bash
systemctl status dstack-vmm
journalctl -u dstack-vmm -n 50
```

Ensure VMM has TDX enabled and sufficient resources.

### CVM Exits Immediately or Reboots in a Loop

**Symptom:** The CVM shows status `exited` after only 15-20 seconds, or keeps restarting if `auto_restart` is enabled.

**Root Cause:** The `dstack-prepare` service fails to fetch SGX quote collateral from PCCS during early boot, which prevents sealing key generation. The service has `FailureAction=reboot`, so it reboots the CVM on failure.

Check the CVM logs (replace `VM_ID` with actual ID from `lsvm`):

```bash
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=false&ansi=false&lines=500" | grep -A3 "Failed to get sealing key"
```

If you see `Failed to get sealing key` → `Failed to get quote collateral` → `Network is unreachable` or `Connection refused`, the CVM cannot reach PCCS.

**Solution:** Verify these settings:

1. **VMM networking mode must be `user`** — see [VMM Configuration: Networking Modes](/tutorial/vmm-configuration#networking-modes) for why
2. **`pccs_url` must be set** in `/etc/dstack/vmm.toml`:
   ```toml
   pccs_url = "https://pccs.phala.network/sgx/certification/v4"
   ```
3. **The CVM must have internet access** to reach `pccs.phala.network` — user-mode networking provides this automatically.

After fixing, restart VMM (`sudo systemctl restart dstack-vmm`) and redeploy.

### Bootstrap hangs

```
Waiting for bootstrap to complete...
```

Check if guest-agent is running inside the CVM. Use the VMM web console to view the instance details, or check the logs (replace `VM_ID` with actual ID from `lsvm`):

```bash
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=false&ansi=false&lines=100"
```

The `/var/run/dstack.sock` socket must exist inside the CVM for TDX quote generation.

### Port 9100 not accessible

```
Connection refused
```

Check CVM network configuration:

```bash
# Verify port mapping in docker-compose.yml
cat ~/kms-deployment/docker-compose.yml | grep ports -A2

# Check CVM status via vmm-cli.py
cd ~/dstack/vmm
export DSTACK_VMM_AUTH_PASSWORD=$(cat ~/.dstack/secrets/vmm-auth-token)
./src/vmm-cli.py --url http://127.0.0.1:9080 lsvm
```

### TDX quote not generated

```
"quote": null
```

This indicates guest-agent issues, simulator misconfiguration, or **SGX not properly configured**:

```bash
# Check CVM logs for TDX-related errors (replace VM_ID with actual ID from lsvm)
curl -s -H "Authorization: Bearer $(cat ~/.dstack/secrets/vmm-auth-token)" \
  "http://127.0.0.1:9080/logs?id=VM_ID&follow=false&ansi=false&lines=100" | grep -i "quote\|tdx\|sgx"
```

**Common causes:**

1. **SGX not enabled in BIOS** - Verify SGX devices exist on host:
   ```bash
   ls -la /dev/sgx*
   ```
   If missing, configure SGX in BIOS. See [TDX & SGX BIOS Configuration](/tutorial/tdx-bios-configuration).

2. **SGX Auto MP Registration not enabled** - Without this BIOS setting, your platform isn't registered with Intel's PCS, and attestation quotes cannot be verified. Re-enter BIOS and enable "SGX Auto MP Registration".

3. **Guest-agent / simulator not running** - The KMS must be able to reach a working dstack guest agent endpoint. In a real CVM, `/var/run/dstack.sock` must exist. For local development, start `sdk/simulator` first.

### CVM Fails with "QGS error code: 0x12001"

**Symptom:** CVM exits after ~13 seconds with:
```
Error: Failed to request app keys
  0: Failed to get sealing key
  1: Failed to get quote
  2: quote failure: QGS error code: 0x12001
```

**Root Cause:** The host's Quote Generation Service (QGS) cannot fetch PCK certificates from PCCS. This is a **host-side** issue, not a CVM issue. Check QGS logs:

```bash
sudo journalctl -u qgsd -n 20
```

If you see `[QPL] No certificate data for this platform` or `Intel PCS server returns error(401)`, the host QCNL is misconfigured.

**Solution:** Update `/etc/sgx_default_qcnl.conf` to use a working PCCS:

```bash
# Check current config
grep pccs_url /etc/sgx_default_qcnl.conf

# Update to Phala's public PCCS
sudo tee /etc/sgx_default_qcnl.conf > /dev/null << 'EOF'
{
  "pccs_url": "https://pccs.phala.network/sgx/certification/v4/",
  "use_secure_cert": false,
  "retry_times": 6,
  "retry_delay": 10
}
EOF

sudo systemctl restart qgsd
```

> **Note:** The host QCNL controls TDX quote **generation**. The CVM's `pccs_url` in vmm.toml controls quote **verification**. Both must point to a working PCCS. See [VMM Configuration: Configure Host QCNL](/tutorial/vmm-configuration#step-6-configure-host-qcnl-for-quote-generation).

### GetMeta Returns "Connection refused" on Port 9200

**Symptom:** KMS responds to `GetTempCaCert` but GetMeta returns:
```json
{"error": "error sending request for url (http://127.0.0.1:9200/): ...Connection refused (os error 111)"}
```

**Root Cause:** auth-eth defaults to port 8000, but kms.toml expects the webhook at port 9200.

**Solution:** Ensure your docker-compose.yaml includes `PORT=9200` in the environment section:

```yaml
environment:
  - PORT=9200    # Must match kms.toml webhook URL port
```

Then regenerate the app-compose.json and redeploy:

```bash
./src/vmm-cli.py --url http://127.0.0.1:9080 compose \
  --name kms \
  --docker-compose ~/kms-deploy/docker-compose.yaml \
  --local-key-provider \
  --output ~/kms-deploy/app-compose.json
```

### GetMeta Returns "missing field `status`"

**Symptom:** KMS responds but GetMeta returns:
```json
{"error": "error decoding response body: missing field `status` at line 1 column ..."}
```

**Root Cause:** auth-eth is running and reachable (port 9200 is correct), but it cannot connect to Ethereum RPC. Without `ETH_RPC_URL` and `KMS_CONTRACT_ADDR`, auth-eth defaults to `http://localhost:8545` (nothing there) and returns a Fastify error instead of the expected `{status: 'ok', ...}` response.

**Solution:** Ensure your docker-compose.yaml includes both Ethereum configuration variables:

```yaml
environment:
  - ETH_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
  - KMS_CONTRACT_ADDR=YOUR_CONTRACT_ADDRESS
```

Get your contract address from `~/.dstack/secrets/kms-contract-address`. See Step 3 for the complete docker-compose.yaml template.

### GetMeta Hangs or Times Out

**Symptom:** `curl` to GetMeta hangs indefinitely or times out after 30+ seconds

**Root Cause:** The auth-eth service is using an unreachable or rate-limited Ethereum RPC endpoint.

**Solution:** Verify your `ETH_RPC_URL` environment variable points to a working Sepolia RPC:

```bash
# Check what ETH_RPC_URL is set in your deployment
grep ETH_RPC_URL ~/kms-deploy/docker-compose.yaml

# Test the endpoint directly
curl -s -X POST YOUR_ETH_RPC_URL \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
```

Verify the URL matches `https://ethereum-sepolia-rpc.publicnode.com` (or your preferred Sepolia RPC provider).

### CVM Hangs at "Waiting for time to be synchronized"

**Symptom:** CVM boot log shows "Waiting for the system time to be synchronized" and never proceeds

**Root Cause:** The `--secure-time` flag was used during deployment

**Solution:** Redeploy without the `--secure-time` flag:

```bash
./src/vmm-cli.py --url http://127.0.0.1:9080 deploy \
  --name kms \
  --image dstack-0.5.7 \
  --compose ~/kms-deploy/app-compose.json \
  --vcpu 2 \
  --memory 4096 \
  --disk 20 \
  --port tcp:127.0.0.1:9100:9100
  # Note: NO --secure-time flag
```
