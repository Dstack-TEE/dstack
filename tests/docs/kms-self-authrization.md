# KMS Self-Authorization Manual Integration Test Guide

This document describes a manual, AI-executable integration test flow for KMS self-authorization and quote-required KMS behavior.

The goal is to validate the following behaviors without depending on `kms/e2e/` from PR #538:

1. **Bootstrap self-check**: a KMS must call the auth API and verify that **itself** is allowed before bootstrap succeeds.
2. **Onboard receiver-side source check**: a new KMS must reject onboarding if the **source KMS** is not allowed by the receiver's auth policy.
3. **Trusted RPC self-check**: trusted KMS RPCs such as `GetTempCaCert`, `GetKmsKey`, `GetAppKey`, and `SignCert` must fail when the running KMS is no longer allowed by its auth policy.
4. **Attestation requirement**: KMS always requires attestation; for local development without TDX hardware, use `sdk/simulator`.

This guide is written as a deployment-and-test runbook so an AI agent can follow it end-to-end.

> **Execution notes from a real run on teepod2 (2026-03-19):**
>
> 1. Do **not** assume a host-local `auth-simple` instance is reachable from a CVM. In practice, the auth API must be:
>    - publicly reachable by the CVM, or
>    - deployed as a sidecar/internal service inside the same test environment.
> 2. For PR validation, prefer a **prebuilt KMS test image**. The run documented here used `cr.kvin.wang/dstack-kms:kms-auth-checks-157ad4ba`.
> 3. `Boot Progress: done` only means the VM guest boot finished. It does **not** guarantee the KMS onboard endpoint is already ready.
> 4. If you inject helper scripts through `docker-compose.yaml`, prefer inline `configs.content` over `configs.file` unless you have confirmed the extra files are copied into the deployment bundle.
> 5. The onboard completion endpoint is **GET `/finish`**, not POST.
> 6. Do **not** reuse a previously captured `mr_aggregated` across redeploys. Auth policies must be generated from the attestation of the **current** VM under test.
> 7. KMS now always requires quote/attestation. For local development without TDX hardware, use `sdk/simulator` instead of trying to run a no-attestation KMS flow.
> 8. For `auth-simple`, `kms.mrAggregated = []` is a deny-all policy for KMS. Use that as the baseline deny configuration, then add the measured KMS MR values for allow cases.

---

## Table of Contents

1. [Why this document exists](#1-why-this-document-exists)
2. [Test strategy](#2-test-strategy)
3. [Topology](#3-topology)
4. [Prerequisites](#4-prerequisites)
5. [Shared setup](#5-shared-setup)
6. [Test case 1: bootstrap is denied when self is not allowed](#6-test-case-1-bootstrap-is-denied-when-self-is-not-allowed)
7. [Test case 2: bootstrap succeeds after self is whitelisted](#7-test-case-2-bootstrap-succeeds-after-self-is-whitelisted)
8. [Test case 3: receiver rejects onboarding from a denied source KMS](#8-test-case-3-receiver-rejects-onboarding-from-a-denied-source-kms)
9. [Test case 4: trusted RPCs fail when the running KMS is no longer allowed](#9-test-case-4-trusted-rpcs-fail-when-the-running-kms-is-no-longer-allowed)
10. [Test case 5: local development should use the simulator](#10-test-case-5-local-development-should-use-the-simulator)
11. [Evidence to capture](#11-evidence-to-capture)
12. [Cleanup](#12-cleanup)

---

## 1. Why this document exists

PR #538 already proposes a richer `kms/e2e/` framework, but as of **2026-03-19** it is still open/draft and touches overlapping KMS files. To avoid waiting for that PR, this guide uses:

- existing KMS deploy flows
- `auth-simple` as a controllable auth API
- manual RPC calls via `curl`

This keeps the test independent from PR #538 while still exercising real deployment paths.

---

## 2. Test strategy

Use **real KMS CVMs** with a hot-reloadable `auth-simple` policy.

Why `auth-simple`:

- it implements the same `/bootAuth/kms` webhook contract used by KMS
- its config is re-read on every request
- allow/deny behavior can be changed without restarting the service

The test intentionally focuses on **authorization decisions**, not on a new Rust test harness.

---

## 3. Topology

Use the following layout:

```text
Host / operator machine
├── auth-simple-src  (source KMS auth policy)
├── auth-simple-dst  (target KMS auth policy)
├── kms-src          (bootstrapped, later used as source KMS)
├── kms-dst          (fresh KMS used for onboard tests)
```

Policy responsibilities:

- `auth-simple-src` must authorize:
  - `kms-src` itself, for bootstrap and trusted RPC self-checks
  - `kms-dst`, when `kms-dst` calls `GetKmsKey` during onboarding
- `auth-simple-dst` decides whether `kms-dst` accepts `kms-src` as an allowed source KMS

---

## 4. Prerequisites

Before starting, make sure the following are available:

1. A branch or image containing the PR #573 KMS changes
2. A working `dstack-vmm` or teepod deployment target
3. Two routable KMS onboard URLs
4. `bun` installed on the host, because `kms/auth-simple` runs on Bun
5. `jq`, `curl`, and Python 3 on the host

Recommended references:

- KMS deployment tutorial: `docs/tutorials/kms-cvm-deployment.md`
- KMS troubleshooting: `docs/tutorials/troubleshooting-kms-deployment.md`
- `auth-simple` usage: `kms/auth-simple/README.md`

If deploying on teepod/dstack-vmm, the easiest pattern is:

- deploy KMS in onboard mode
- expose the onboard page through gateway
- call `/prpc/Onboard.*?json` via HTTPS

Strong recommendation for this manual test:

- **publish a test KMS image first**, then deploy that image
- avoid `build:` in `docker-compose.yaml` unless you have already confirmed image builds work correctly in your VMM environment

Using a prebuilt image significantly reduces ambiguity when a failure happens: you can focus on KMS authorization logic rather than image build or registry behavior.

Teepod/gateway URL convention observed during a real run:

- **onboard mode:** use the `-8000` style URL
- **runtime TLS KMS RPC after bootstrap/onboard:** use the `-8000s` style URL

Do not assume the same external URL works before and after onboarding is finished.

---

## 5. Shared setup

### 5.1 Create a working directory

```bash
export REPO_ROOT="$(git rev-parse --show-toplevel)"
mkdir -p /tmp/kms-self-auth
cd /tmp/kms-self-auth
```

### 5.2 Make the auth API reachable from the test KMS instances

The original plan was to run two host-local `auth-simple` processes. In practice, this only works if the CVMs can reach that host directly.

Choose one of these options:

1. **Preferred:** deploy the auth API as a separate public service or CVM
2. **Also fine:** run the auth API as a sidecar in the same KMS test deployment
3. **Only if reachable:** run `auth-simple` on the operator host and point KMS at that reachable host/IP

If you use the sidecar/public-service pattern, keep the same logical split:

- source-side auth policy
- destination-side auth policy

and make sure you still have a way to update allow/deny policy during the test.

### 5.3 If using host-local `auth-simple`, install and start two instances

```bash
cd "$REPO_ROOT/kms/auth-simple"
bun install
```

Create placeholder configs:

```bash
cat > /tmp/kms-self-auth/auth-src.json <<'EOF'
{
  "osImages": [],
  "gatewayAppId": "any",
  "kms": {
    "mrAggregated": [],
    "devices": [],
    "allowAnyDevice": true
  },
  "apps": {}
}
EOF

cat > /tmp/kms-self-auth/auth-dst.json <<'EOF'
{
  "osImages": [],
  "gatewayAppId": "any",
  "kms": {
    "mrAggregated": [],
    "devices": [],
    "allowAnyDevice": true
  },
  "apps": {}
}
EOF
```

These placeholder configs intentionally deny all KMS boots until you populate `kms.mrAggregated` with the measured source or destination KMS values for the current run.

Start the services:

```bash
cd "$REPO_ROOT/kms/auth-simple"
AUTH_CONFIG_PATH=/tmp/kms-self-auth/auth-src.json PORT=3101 bun run start \
  >/tmp/kms-self-auth/auth-src.log 2>&1 &
echo $! >/tmp/kms-self-auth/auth-src.pid

AUTH_CONFIG_PATH=/tmp/kms-self-auth/auth-dst.json PORT=3102 bun run start \
  >/tmp/kms-self-auth/auth-dst.log 2>&1 &
echo $! >/tmp/kms-self-auth/auth-dst.pid
```

Health check:

```bash
curl -sf http://127.0.0.1:3101/ | jq .
curl -sf http://127.0.0.1:3102/ | jq .
```

### 5.4 Deploy `kms-src` and `kms-dst`

Deploy two KMS CVMs using the existing KMS deployment workflow.

Requirements for **both** VMs:

- `core.onboard.enabled = true`
- `core.onboard.auto_bootstrap_domain = ""`
- `core.auth_api.type = "webhook"`

Point them at different auth services or sidecars:

- `kms-src` → `http://<host-reachable-ip>:3101`
- `kms-dst` → `http://<host-reachable-ip>:3102`

If you use sidecars instead of host-local auth servers, replace those URLs with the sidecar/internal service addresses.

If you need an example deployment template, adapt the flow in:

- `docs/tutorials/kms-cvm-deployment.md`

Record these values:

```bash
export KMS_SRC_ONBOARD='https://<kms-src-onboard-host>/'
export KMS_DST_ONBOARD='https://<kms-dst-onboard-host>/'
```

Notes:

- The onboard endpoint is plain onboarding mode, so use `Onboard.*`
- The runtime KMS endpoint is available only after bootstrap/onboard and `/finish`

Wait until the onboard endpoint is actually ready before continuing. A simple probe loop is recommended:

```bash
until curl -sk -X POST "${KMS_SRC_ONBOARD%/}/prpc/Onboard.GetAttestationInfo?json" \
  -H 'Content-Type: application/json' -d '{}' >/dev/null 2>&1; do
  echo "waiting for kms-src onboard endpoint..."
  sleep 10
done

until curl -sk -X POST "${KMS_DST_ONBOARD%/}/prpc/Onboard.GetAttestationInfo?json" \
  -H 'Content-Type: application/json' -d '{}' >/dev/null 2>&1; do
  echo "waiting for kms-dst onboard endpoint..."
  sleep 10
done
```

### 5.5 Read attestation info for both KMS instances

```bash
curl -sf -X POST "${KMS_SRC_ONBOARD%/}/prpc/Onboard.GetAttestationInfo?json" \
  -H 'Content-Type: application/json' \
  -d '{}' | tee /tmp/kms-self-auth/kms-src-attestation.json | jq .

curl -sf -X POST "${KMS_DST_ONBOARD%/}/prpc/Onboard.GetAttestationInfo?json" \
  -H 'Content-Type: application/json' \
  -d '{}' | tee /tmp/kms-self-auth/kms-dst-attestation.json | jq .
```

Expected fields:

- `device_id`
- `mr_aggregated`
- `os_image_hash`
- `attestation_mode`

Extract values:

```bash
SRC_OS=$(jq -r '.os_image_hash' /tmp/kms-self-auth/kms-src-attestation.json)
SRC_MR=$(jq -r '.mr_aggregated' /tmp/kms-self-auth/kms-src-attestation.json)
SRC_DEV=$(jq -r '.device_id' /tmp/kms-self-auth/kms-src-attestation.json)

DST_OS=$(jq -r '.os_image_hash' /tmp/kms-self-auth/kms-dst-attestation.json)
DST_MR=$(jq -r '.mr_aggregated' /tmp/kms-self-auth/kms-dst-attestation.json)
DST_DEV=$(jq -r '.device_id' /tmp/kms-self-auth/kms-dst-attestation.json)
```

All three values above are expected to be hex strings **without** the `0x` prefix. When writing `auth-simple` config, prepend `0x`.

### 5.6 Helper configs

#### Deny-by-MR config

Use a wrong `mrAggregated` value while allowing the observed OS image:

```bash
cat > /tmp/kms-self-auth/deny-by-mr.json <<'EOF'
{
  "osImages": ["0xREPLACE_OS"],
  "gatewayAppId": "any",
  "kms": {
    "mrAggregated": ["0x0000000000000000000000000000000000000000000000000000000000000000"],
    "devices": [],
    "allowAnyDevice": true
  },
  "apps": {}
}
EOF
```

#### Allow-single-KMS config

```bash
cat > /tmp/kms-self-auth/allow-single.json <<'EOF'
{
  "osImages": ["0xREPLACE_OS"],
  "gatewayAppId": "any",
  "kms": {
    "mrAggregated": ["0xREPLACE_MR"],
    "devices": [],
    "allowAnyDevice": true
  },
  "apps": {}
}
EOF
```

#### Allow-source-and-target config

```bash
cat > /tmp/kms-self-auth/allow-src-and-dst.json <<'EOF'
{
  "osImages": ["0xREPLACE_SRC_OS", "0xREPLACE_DST_OS"],
  "gatewayAppId": "any",
  "kms": {
    "mrAggregated": ["0xREPLACE_SRC_MR", "0xREPLACE_DST_MR"],
    "devices": [],
    "allowAnyDevice": true
  },
  "apps": {}
}
EOF
```

Create concrete variants:

```bash
sed "s/REPLACE_OS/$SRC_OS/g; s/REPLACE_MR/$SRC_MR/g" \
  /tmp/kms-self-auth/allow-single.json \
  >/tmp/kms-self-auth/auth-src-allow-self.json

sed "s/REPLACE_OS/$SRC_OS/g" \
  /tmp/kms-self-auth/deny-by-mr.json \
  >/tmp/kms-self-auth/auth-src-deny-self.json

sed "s/REPLACE_SRC_OS/$SRC_OS/g; s/REPLACE_DST_OS/$DST_OS/g; s/REPLACE_SRC_MR/$SRC_MR/g; s/REPLACE_DST_MR/$DST_MR/g" \
  /tmp/kms-self-auth/allow-src-and-dst.json \
  >/tmp/kms-self-auth/auth-src-allow-both.json

sed "s/REPLACE_OS/$SRC_OS/g; s/REPLACE_MR/$SRC_MR/g" \
  /tmp/kms-self-auth/allow-single.json \
  >/tmp/kms-self-auth/auth-dst-allow-src.json

sed "s/REPLACE_OS/$SRC_OS/g" \
  /tmp/kms-self-auth/deny-by-mr.json \
  >/tmp/kms-self-auth/auth-dst-deny-src.json
```

Because `auth-simple` hot reloads its config on every request, switching policy is just a file copy:

```bash
cp /tmp/kms-self-auth/auth-src-deny-self.json /tmp/kms-self-auth/auth-src.json
cp /tmp/kms-self-auth/auth-src-allow-self.json /tmp/kms-self-auth/auth-src.json
cp /tmp/kms-self-auth/auth-src-allow-both.json /tmp/kms-self-auth/auth-src.json
cp /tmp/kms-self-auth/auth-dst-deny-src.json /tmp/kms-self-auth/auth-dst.json
cp /tmp/kms-self-auth/auth-dst-allow-src.json /tmp/kms-self-auth/auth-dst.json
```

---

## 6. Test case 1: bootstrap is denied when self is not allowed

### Purpose

Verify that a KMS refuses bootstrap if the auth API denies **its own** measurements.

### Steps

1. Make sure `kms-src` is still fresh and not bootstrapped yet.
2. Apply the deny-self policy to `auth-simple-src`:

```bash
cp /tmp/kms-self-auth/auth-src-deny-self.json /tmp/kms-self-auth/auth-src.json
```

3. Call bootstrap:

```bash
curl -sf -X POST "${KMS_SRC_ONBOARD%/}/prpc/Onboard.Bootstrap?json" \
  -H 'Content-Type: application/json' \
  -d '{"domain":"kms-src.example.test"}' \
  | tee /tmp/kms-self-auth/bootstrap-src-denied.json | jq .
```

### Expected result

- the response contains `.error`
- the error should indicate bootstrap was denied because the KMS is not allowed

Acceptable examples:

- `KMS is not allowed to bootstrap`
- `Boot denied: ...`

### Failure interpretation

If bootstrap succeeds under the deny policy, the self-check is not working.

---

## 7. Test case 2: bootstrap succeeds after self is whitelisted

### Purpose

Verify that bootstrap succeeds once the same KMS is explicitly allowed.

### Steps

1. Switch `auth-simple-src` to allow `kms-src`:

```bash
cp /tmp/kms-self-auth/auth-src-allow-self.json /tmp/kms-self-auth/auth-src.json
```

2. Retry bootstrap:

```bash
curl -sf -X POST "${KMS_SRC_ONBOARD%/}/prpc/Onboard.Bootstrap?json" \
  -H 'Content-Type: application/json' \
  -d '{"domain":"kms-src.example.test"}' \
  | tee /tmp/kms-self-auth/bootstrap-src-allowed.json | jq .
```

3. Finish onboarding mode so the process can restart into normal TLS KMS mode:

```bash
curl -sf "${KMS_SRC_ONBOARD%/}/finish"
```

4. Wait for the runtime KMS endpoint to become available and record it as:

```bash
export KMS_SRC_RUNTIME='https://<kms-src-runtime-host>'
```

On teepod-style deployments, this is often the `-8000s` URL rather than the original onboard `-8000` URL.

5. Probe runtime metadata:

```bash
curl -sk "${KMS_SRC_RUNTIME%/}/prpc/KMS.GetMeta?json" \
  | tee /tmp/kms-self-auth/kms-src-meta.json | jq .
```

### Expected result

- bootstrap returns `ca_pubkey`, `k256_pubkey`, and `attestation`
- `/finish` returns `OK`
- `KMS.GetMeta` succeeds after restart

---

## 8. Test case 3: receiver rejects onboarding from a denied source KMS

### Purpose

Verify that the onboarding receiver rejects a source KMS whose attestation is denied by the receiver's auth API.

### Important setup note

For this scenario to reach the receiver-side check:

- `auth-simple-src` must allow **both** `kms-src` and `kms-dst`
  - `kms-src` must allow itself, because trusted RPC self-checks run on the source
  - `kms-src` must also allow `kms-dst`, because `GetKmsKey` verifies the caller KMS
- `auth-simple-dst` must initially **deny** `kms-src`

### Steps

1. Apply source policy that allows both KMS instances:

```bash
cp /tmp/kms-self-auth/auth-src-allow-both.json /tmp/kms-self-auth/auth-src.json
```

2. Apply receiver policy that denies `kms-src`:

```bash
cp /tmp/kms-self-auth/auth-dst-deny-src.json /tmp/kms-self-auth/auth-dst.json
```

3. Attempt onboarding from `kms-dst`:

```bash
curl -sf -X POST "${KMS_DST_ONBOARD%/}/prpc/Onboard.Onboard?json" \
  -H 'Content-Type: application/json' \
  -d "{\"source_url\":\"${KMS_SRC_RUNTIME%/}/prpc\",\"domain\":\"kms-dst.example.test\"}" \
  | tee /tmp/kms-self-auth/onboard-dst-denied.json | jq .
```

### Expected result

- the response contains `.error`
- the error should indicate the source KMS is not allowed, or onboarding failed because source authorization was denied

### Then verify the positive path

4. Switch receiver policy to allow `kms-src`:

```bash
cp /tmp/kms-self-auth/auth-dst-allow-src.json /tmp/kms-self-auth/auth-dst.json
```

5. Retry onboarding:

```bash
curl -sf -X POST "${KMS_DST_ONBOARD%/}/prpc/Onboard.Onboard?json" \
  -H 'Content-Type: application/json' \
  -d "{\"source_url\":\"${KMS_SRC_RUNTIME%/}/prpc\",\"domain\":\"kms-dst.example.test\"}" \
  | tee /tmp/kms-self-auth/onboard-dst-allowed.json | jq .
```

6. Finish onboarding mode on `kms-dst`:

```bash
curl -sf "${KMS_DST_ONBOARD%/}/finish"
```

7. Wait for the runtime endpoint and record:

```bash
export KMS_DST_RUNTIME='https://<kms-dst-runtime-host>'
```

Again, when TLS passthrough is used, prefer the `-8000s` URL for runtime KMS RPCs.

8. Probe runtime metadata:

```bash
curl -sk "${KMS_DST_RUNTIME%/}/prpc/KMS.GetMeta?json" \
  | tee /tmp/kms-self-auth/kms-dst-meta.json | jq .
```

### Expected result

- first onboard attempt is rejected
- second onboard attempt succeeds
- `kms-dst` starts normally after `/finish`

---

## 9. Test case 4: trusted RPCs fail when the running KMS is no longer allowed

### Purpose

Verify that a running KMS re-checks its own authorization on trusted RPCs.

### Recommended canary RPC

Use `GetTempCaCert` first. It is simpler than `GetAppKey` because it does not require preparing an attested app client, but it still exercises the new runtime self-check.

### Steps

1. While `kms-src` is healthy, confirm the canary RPC works:

```bash
curl -sk "${KMS_SRC_RUNTIME%/}/prpc/KMS.GetTempCaCert?json" \
  | tee /tmp/kms-self-auth/get-temp-ca-allowed.json | jq .
```

2. Flip `auth-simple-src` to deny `kms-src` itself:

```bash
cp /tmp/kms-self-auth/auth-src-deny-self.json /tmp/kms-self-auth/auth-src.json
```

3. Retry the same RPC:

```bash
curl -sk "${KMS_SRC_RUNTIME%/}/prpc/KMS.GetTempCaCert?json" \
  | tee /tmp/kms-self-auth/get-temp-ca-denied.json | jq .
```

### Expected result

- before the policy flip: `GetTempCaCert` succeeds
- after the policy flip: the response contains `.error`
- the error should indicate KMS self-authorization failed, or that the KMS is not allowed

### Optional deeper checks

If you already have tooling for attested app/KMS clients, also verify:

- `GetKmsKey` fails when source KMS denies itself
- `GetAppKey` fails when KMS denies itself
- `SignCert` fails when KMS denies itself

The important part is that the running KMS must not rely only on bootstrap-time authorization.

---

## 10. Test case 5: local development should use the simulator

### Purpose

KMS now always requires attestation. For local development without TDX hardware, use `sdk/simulator` so bootstrap, onboard, and trusted RPC flows still exercise the quoted path.

### Suggested minimal coverage

1. Start the simulator:

```bash
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
```

2. Point the guest agent client at the simulator endpoint as documented in the SDK README.
3. Run KMS locally against the simulator-backed guest agent.
4. Verify bootstrap and trusted RPCs still produce attestation-backed behavior.

### Expected result

- local development still uses the same quote-required logic
- there is no separate no-quote KMS mode to validate anymore
- simulator-backed development should be treated as the replacement for the old noquote/dev workflow

---

## 11. Evidence to capture

For each run, save:

1. `Onboard.GetAttestationInfo` output for every KMS
2. auth config snapshots used for each step
3. bootstrap/onboard RPC responses
4. `KMS.GetMeta` output after successful boot
5. `GetTempCaCert` allow/deny responses
6. relevant CVM logs if a step fails unexpectedly

Recommended archive:

```bash
tar czf /tmp/kms-self-auth-results.tar.gz /tmp/kms-self-auth
```

---

## 12. Cleanup

Stop local auth services:

```bash
kill "$(cat /tmp/kms-self-auth/auth-src.pid)" || true
kill "$(cat /tmp/kms-self-auth/auth-dst.pid)" || true
```

Then remove test CVMs using your normal `vmm-cli.py remove` or teepod cleanup flow.

---

## Success criteria summary

The change is considered validated if all of the following are true:

1. bootstrap fails under deny policy
2. bootstrap succeeds after self allowlisting
3. onboarding rejects a denied source KMS on the receiver side
4. runtime trusted RPCs stop working after the source KMS is removed from the allowlist
5. local development without TDX hardware is expected to use `sdk/simulator` rather than a no-quote KMS mode
