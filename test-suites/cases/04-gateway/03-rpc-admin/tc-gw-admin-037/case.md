<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-admin-037"></a>
# TC-GW-ADMIN-037: Admin.ImportCert

## Metadata

- Priority: P1
- Type: Functional, API, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-admin-037](../../../../catalog/feature-audit.md#req-gw-admin-037)
- Risks: [risk-gw-admin-037](../../../../catalog/feature-audit.md#risk-gw-admin-037)
- Source: `dstack/gateway/rpc/proto/gateway_rpc.proto:557`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Prepared RPC contract: `Admin.ImportCert` takes `ImportCertRequest` (`domain: string`, `cert_pem: string`, `key_pem: string`) and returns `google.protobuf.Empty` (no fields). The certificate is served for `*.<domain>`, replicated to every node through WaveKV, and never renewed by the gateway. The authoritative field matrix is the matching entry in [`api-inventory.json`](../../../../catalog/api-inventory.json); do not reconstruct it from implementation source.
- PR #1239 introduced this method and removed the file-configured proxy certificate (`[core.proxy] base_domain`, `cert_chain`, `cert_key`). The `gateway-cluster` fixture now imports its own `*.localhost` certificate through this method; this case uses a separate run-scoped domain.
- A handshake with SNI `gateway.<domain>` is answered by the node itself, so it observes the served certificate without a registered app.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify the request, authorization, normalization, replication, refusal and isolation contract of `Admin.ImportCert`.

## Preconditions

1. A case-owned three-node `gateway-cluster` fixture with WaveKV sync enabled and the admin listener on every node.
2. The fixture's `*.localhost` certificate is served on every node, and no certificate exists for the run-scoped domain `import-<lease>.localhost`.

## Test Data

Case-generated self-signed P-256 wildcard certificates for `*.import-<lease>.localhost`: two valid certificates with distinct keys, one certificate whose validity ended a day ago, and a third key that matches neither certificate. Invalid domains: the empty string and `bad..import-<lease>.localhost`. No certificate, key, token or domain is retained in evidence.

## Steps

<a id="tc-gw-admin-037-step-01"></a>
### Step 1: Inspect the effective prerequisite

Handshake with every node's proxy listener for `gateway.localhost` and for `gateway.import-<lease>.localhost`.

**Expected results:**

- Every node presents the fixture certificate for `gateway.localhost`, and no node completes a handshake for the run-scoped domain.

<a id="tc-gw-admin-037-step-02"></a>
### Step 2: Exercise the behavior

Call `Admin.ImportCert` on node 1 without a credential. Then import the first certificate on node 1 as JSON, spelling the domain `*.IMPORT-<lease>.LOCALHOST.`, and the second certificate on node 2 as protobuf.

**Expected results:**

- The call without a credential returns HTTP 401 and changes nothing.
- The JSON call returns HTTP 200 with an empty body; the wildcard prefix, case and trailing dot are normalized, and within 15 seconds every node presents the first certificate for the run-scoped domain.
- The protobuf call returns HTTP 200 and every node then presents the second certificate, replacing the first.
- Every node still presents the unchanged fixture certificate for `gateway.localhost`.

<a id="tc-gw-admin-037-step-03"></a>
### Step 3: Verify refusals, state and availability

Import, on node 1, an empty domain, a malformed domain, an unparsable certificate, the expired certificate, and the first certificate with the unrelated key; then re-import the second certificate.

**Expected results:**

- Every invalid import returns an HTTP 4xx structured error.
- Every node keeps presenting the second certificate after the refusals.
- The final valid import returns HTTP 200.

## Postconditions

The imported certificates remain in the lease-owned cluster store, which is discarded with the lease; Admin has no delete for an imported certificate. Evidence retains HTTP statuses, counts and booleans only.
