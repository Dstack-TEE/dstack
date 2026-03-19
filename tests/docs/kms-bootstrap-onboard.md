# KMS Bootstrap / Onboard / Trusted RPC Manual Test Guide

This document describes a manual, AI-executable integration flow for validating:

1. KMS bootstrap
2. KMS onboard from an existing KMS
3. post-onboard trusted runtime RPCs

It is intentionally written as a deployment runbook so an AI agent can execute it step by step on teepod / dstack-vmm without depending on `kms/e2e/`.

---

## 1. Scope

This guide covers the normal happy-path flow:

1. deploy `kms-src`
2. bootstrap `kms-src`
3. finish `kms-src`
4. deploy `kms-dst`
5. onboard `kms-dst` from `kms-src`
6. finish `kms-dst`
7. probe trusted runtime RPCs on the running KMS

It also includes a compact deny-case matrix for common service-rejection paths so a deployment run can validate both success and failure behavior in one pass.

For a deeper authorization-focused runbook, also see:

- `tests/docs/kms-self-authrization.md`

---

## 2. Topology

```text
Host / operator machine
├── auth-simple-src  (policy for source KMS)
├── auth-simple-dst  (policy for destination KMS)
├── kms-src          (bootstrapped first)
└── kms-dst          (onboarded from kms-src)
```

Both KMS instances are expected to run with attestation enabled. For local development without TDX hardware, use `sdk/simulator`.

Policy reminder:

- source-side auth must allow:
  - `kms-src` itself
  - `kms-dst` when it calls `GetKmsKey` during onboarding
- destination-side auth must allow:
  - `kms-src` during onboarding
  - `kms-dst` itself before you probe trusted runtime RPCs on `kms-dst`

---

## 3. Prerequisites

Before starting, make sure the following are available:

1. a KMS image or branch containing the code under test
2. a working teepod / dstack-vmm target
3. routable HTTPS entrypoints for onboard and runtime RPC
4. `curl`, `jq`, Python 3, and `bun`
5. an auth service such as `kms/auth-simple`, or an equivalent webhook

Recommended references:

- `docs/tutorials/kms-cvm-deployment.md`
- `docs/tutorials/troubleshooting-kms-deployment.md`
- `kms/auth-simple/README.md`
- `tests/docs/kms-self-authrization.md`

Operational notes:

1. Prefer a **prebuilt KMS image**.
2. `Boot Progress: done` does **not** guarantee the onboard endpoint is ready.
3. The onboarding completion endpoint is **GET `/finish`**.
4. On teepod, onboard mode usually uses the `-8000` URL, while runtime TLS KMS RPC usually uses the `-8000s` URL.
5. If you use a very small custom webhook instead of the real auth service, `KMS.GetMeta` may fail because `auth_api.get_info()` expects extra chain / contract metadata fields. In that case, use `GetTempCaCert` as the runtime readiness probe.

---

## 4. Shared setup

### 4.1 Create a workspace

```bash
export REPO_ROOT="$(git rev-parse --show-toplevel)"
mkdir -p /tmp/kms-bootstrap-onboard
cd /tmp/kms-bootstrap-onboard
```

### 4.2 Prepare auth services

Use two independently controllable auth services:

- one for `kms-src`
- one for `kms-dst`

They can be:

1. host-local if reachable by CVMs
2. public services
3. sidecars inside each KMS deployment

At minimum, both policies must allow the KMS instance they serve. During onboard, source-side policy must also allow the destination KMS caller.

For `auth-simple`, `kms.mrAggregated = []` is a deny-all policy for KMS. Add the current KMS MR values explicitly when switching a test from deny to allow.

### 4.3 Deploy `kms-src` and `kms-dst`

Deploy both KMS instances in onboard mode with:

- `core.onboard.enabled = true`
- `core.onboard.auto_bootstrap_domain = ""`
- `core.auth_api.type = "webhook"`

Record:

```bash
export KMS_SRC_ONBOARD='https://<kms-src-onboard-host>/'
export KMS_DST_ONBOARD='https://<kms-dst-onboard-host>/'
```

Wait until the onboard endpoints actually respond:

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

Capture initial attestation info:

```bash
curl -sk -X POST "${KMS_SRC_ONBOARD%/}/prpc/Onboard.GetAttestationInfo?json" \
  -H 'Content-Type: application/json' -d '{}' \
  | tee /tmp/kms-bootstrap-onboard/kms-src-att.json | jq .

curl -sk -X POST "${KMS_DST_ONBOARD%/}/prpc/Onboard.GetAttestationInfo?json" \
  -H 'Content-Type: application/json' -d '{}' \
  | tee /tmp/kms-bootstrap-onboard/kms-dst-att.json | jq .
```

---

## 5. Bootstrap `kms-src`

### 5.1 Call bootstrap

```bash
curl -sk -X POST "${KMS_SRC_ONBOARD%/}/prpc/Onboard.Bootstrap?json" \
  -H 'Content-Type: application/json' \
  -d '{"domain":"kms-src.example.test"}' \
  | tee /tmp/kms-bootstrap-onboard/kms-src-bootstrap.json | jq .
```

### Expected result

- response contains:
  - `ca_pubkey`
  - `k256_pubkey`
  - `attestation`
- no `.error`

### 5.2 Finish onboard mode

```bash
curl -sk "${KMS_SRC_ONBOARD%/}/finish" \
  | tee /tmp/kms-bootstrap-onboard/kms-src-finish.txt
```

### 5.3 Record runtime endpoint

```bash
export KMS_SRC_RUNTIME='https://<kms-src-runtime-host>'
```

On teepod, this is typically the `-8000s` style URL.

### 5.4 Probe runtime metadata

```bash
curl -sk "${KMS_SRC_RUNTIME%/}/prpc/KMS.GetMeta?json" \
  | tee /tmp/kms-bootstrap-onboard/kms-src-meta.json | jq .
```

### Expected result

- `KMS.GetMeta` succeeds when the configured auth service implements `auth_api.get_info()`-compatible fields
- returned metadata includes:
  - `ca_cert`
  - `k256_pubkey`
  - `bootstrap_info`

If `KMS.GetMeta` fails because your minimal webhook does not return chain / contract info, use `GetTempCaCert` below as the runtime readiness probe instead.

---

## 6. Onboard `kms-dst` from `kms-src`

Before this step:

- destination-side auth must allow `kms-src`
- source-side auth must allow `kms-dst` to call `GetKmsKey`
- if you plan to probe trusted runtime RPCs on `kms-dst` immediately after onboard, destination-side auth must also allow `kms-dst` itself

### 6.1 Call onboard

```bash
curl -sk -X POST "${KMS_DST_ONBOARD%/}/prpc/Onboard.Onboard?json" \
  -H 'Content-Type: application/json' \
  -d "{\"source_url\":\"${KMS_SRC_RUNTIME%/}/prpc\",\"domain\":\"kms-dst.example.test\"}" \
  | tee /tmp/kms-bootstrap-onboard/kms-dst-onboard.json | jq .
```

### Expected result

- response is `{}` or otherwise empty success
- no `.error`

### 6.2 Finish onboard mode

```bash
curl -sk "${KMS_DST_ONBOARD%/}/finish" \
  | tee /tmp/kms-bootstrap-onboard/kms-dst-finish.txt
```

### 6.3 Record runtime endpoint

```bash
export KMS_DST_RUNTIME='https://<kms-dst-runtime-host>'
```

Again, on teepod this is usually the `-8000s` style URL.

### 6.4 Probe runtime metadata

```bash
curl -sk "${KMS_DST_RUNTIME%/}/prpc/KMS.GetMeta?json" \
  | tee /tmp/kms-bootstrap-onboard/kms-dst-meta.json | jq .
```

### Expected result

- `KMS.GetMeta` succeeds when the configured auth service implements `auth_api.get_info()`-compatible fields
- `kms-dst` now serves as a normal runtime KMS

If `KMS.GetMeta` fails because your minimal webhook does not return chain / contract info, continue with the trusted RPC probes below. Those are the better canary for this manual flow.

---

## 7. Trusted runtime RPC checks

This section folds the runtime trusted-RPC verification into the same flow.

### Deny-case matrix

| Case | Policy change | Expected failure point | Typical error shape |
| --- | --- | --- | --- |
| bootstrap deny | source-side auth leaves `kms.mrAggregated` empty or omits the current `kms-src` MR | `Onboard.Bootstrap` on `kms-src` | `KMS is not allowed to bootstrap`, `MR aggregated not allowed` |
| onboard deny (receiver-side) | destination-side auth leaves `kms.mrAggregated` empty or omits the current `kms-src` MR | `Onboard.Onboard` on `kms-dst` | source KMS not allowed / onboarding failed |
| onboard deny (source-side) | source-side auth leaves `kms.mrAggregated` empty or omits the current `kms-dst` MR | `Onboard.Onboard` on `kms-dst` | source rejected destination caller / `GetKmsKey` authorization failed |
| runtime deny | auth removes the running KMS from `kms.mrAggregated` | `GetTempCaCert` or another trusted RPC | `KMS self authorization failed`, `KMS is not allowed` |

Use the happy-path steps below first, then flip policies one by one and rerun the indicated probe.

### 7.1 Minimum canary: `GetTempCaCert`

```bash
curl -sk "${KMS_SRC_RUNTIME%/}/prpc/KMS.GetTempCaCert?json" \
  | tee /tmp/kms-bootstrap-onboard/kms-src-get-temp-ca.json | jq .
```

Expected result:

- success
- response contains:
  - `temp_ca_cert`
  - `temp_ca_key`
  - `ca_cert`

### 7.2 `GetKmsKey`

This RPC is normally exercised by onboard itself, but you can also treat a successful onboard as proof that:

- source KMS accepted the destination KMS as an attested caller
- source KMS returned its shared keys

If you want a standalone explicit probe, use an attested KMS client path and call:

```text
KMS.GetKmsKey
```

Expected result:

- succeeds only for an attested / authorized KMS caller

### 7.3 `GetAppKey`

This requires an attested app caller plus valid `vm_config`.

Expected result:

- success for an attested and authorized app caller
- returned fields should include app key material and `gateway_app_id`

### 7.4 `SignCert`

This requires a valid CSR plus verified attestation.

Expected result:

- success for a valid attested app CSR
- returned `certificate_chain` is non-empty

### 7.5 Optional regression check

After a normal happy-path run, flip source-side auth policy to deny `kms-src` itself and retry:

```bash
curl -sk "${KMS_SRC_RUNTIME%/}/prpc/KMS.GetTempCaCert?json" \
  | tee /tmp/kms-bootstrap-onboard/kms-src-get-temp-ca-after-deny.json | jq .
```

Expected result:

- trusted runtime RPCs fail after the KMS is no longer authorized

This overlaps with `kms-self-authrization.md`, but is useful as a quick post-deploy sanity check.

### 7.6 Recommended deny-case checks

To make this flow more robust, add these negative checks to the same run and save each failure response as evidence.

#### A. Bootstrap deny

Before the successful bootstrap run, configure source-side auth so that `kms-src` is not allowlisted by MR (for example, leave `kms.mrAggregated` empty), then call:

```bash
curl -sk -X POST "${KMS_SRC_ONBOARD%/}/prpc/Onboard.Bootstrap?json" \
  -H 'Content-Type: application/json' \
  -d '{"domain":"kms-src.example.test"}' \
  | tee /tmp/kms-bootstrap-onboard/kms-src-bootstrap-denied.json | jq .
```

Expected result:

- response contains `.error`
- error indicates the KMS itself is not allowed to bootstrap

Then allowlist `kms-src` and rerun the normal bootstrap flow.

#### B1. Onboard deny at the receiver side

Before the successful onboard run, make destination-side policy leave `kms-src` out of `kms.mrAggregated` (for example, keep it empty), then call:

```bash
curl -sk -X POST "${KMS_DST_ONBOARD%/}/prpc/Onboard.Onboard?json" \
  -H 'Content-Type: application/json' \
  -d "{\"source_url\":\"${KMS_SRC_RUNTIME%/}/prpc\",\"domain\":\"kms-dst.example.test\"}" \
  | tee /tmp/kms-bootstrap-onboard/kms-dst-onboard-denied.json | jq .
```

Expected result:

- response contains `.error`
- the error indicates the receiver refused the source KMS, source authorization failed, or onboarding failed before keys were accepted

Then restore destination-side allowlists.

#### B2. Onboard deny at the source side

Make source-side policy leave `kms-dst` out of `kms.mrAggregated`, then call the same onboard request again:

```bash
curl -sk -X POST "${KMS_DST_ONBOARD%/}/prpc/Onboard.Onboard?json" \
  -H 'Content-Type: application/json' \
  -d "{\"source_url\":\"${KMS_SRC_RUNTIME%/}/prpc\",\"domain\":\"kms-dst.example.test\"}" \
  | tee /tmp/kms-bootstrap-onboard/kms-dst-onboard-denied-by-src.json | jq .
```

Expected result:

- response contains `.error`
- the error indicates the source KMS rejected the destination KMS caller, or `GetKmsKey` authorization failed

Then restore both source-side and destination-side allowlists and rerun the normal onboard flow.

#### C. Trusted RPC deny

After a successful bootstrap or onboard, remove the running KMS's own MR from `kms.mrAggregated` and retry:

```bash
curl -sk "${KMS_SRC_RUNTIME%/}/prpc/KMS.GetTempCaCert?json" \
  | tee /tmp/kms-bootstrap-onboard/kms-src-get-temp-ca-denied.json | jq .
```

Expected result:

- response contains `.error`
- error indicates KMS self authorization failed or the KMS is not allowed

You can repeat the same check on `kms-dst` after onboard by removing `kms-dst` from destination-side policy and retrying `KMS.GetTempCaCert`.

---

## 8. Evidence to capture

For each run, save:

1. `Onboard.GetAttestationInfo` output for both KMS instances
2. bootstrap response
3. onboard response
4. `/finish` responses
5. runtime `KMS.GetMeta` responses
6. trusted RPC responses such as `GetTempCaCert`
7. deny-case responses such as `kms-src-bootstrap-denied.json`, `kms-dst-onboard-denied.json`, `kms-dst-onboard-denied-by-src.json`, and `kms-src-get-temp-ca-denied.json`
8. auth policy snapshots used during the run

Recommended archive:

```bash
tar czf /tmp/kms-bootstrap-onboard-results.tar.gz /tmp/kms-bootstrap-onboard
```

---

## 9. Success criteria summary

The flow is considered validated if all of the following are true:

1. `kms-src` bootstrap succeeds
2. `kms-src` transitions to runtime mode successfully
3. `kms-dst` onboard succeeds against `kms-src`
4. `kms-dst` transitions to runtime mode successfully
5. runtime metadata probes succeed on both KMS instances, or `GetTempCaCert` succeeds when `GetMeta` is unavailable with a minimal webhook
6. at least one trusted runtime RPC such as `GetTempCaCert` succeeds
7. the selected deny cases fail at the expected RPC with an authorization error

---

## 10. Cleanup

Remove the test CVMs using your normal teepod / `vmm-cli.py remove` flow.

If you ran host-local auth services, stop them as well.
