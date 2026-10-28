<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-gateway-001"></a>
# TC-GW-GATEWAY-001: Gateway.RegisterCvm

## Metadata

- Priority: P0
- Type: Functional, API, Security, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gw-gateway-001](../../../../catalog/feature-audit.md#req-gw-gateway-001)
- Risks: [risk-gw-gateway-001](../../../../catalog/feature-audit.md#risk-gw-gateway-001)
- Source: `dstack/gateway/rpc/proto/gateway_rpc.proto:209`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Prepared RPC contract: `Gateway.RegisterCvm` takes `RegisterCvmRequest` (`client_public_key: string`, `port_policy: PortPolicy`) and returns `RegisterCvmResponse` (`wg: WireGuardConfig`, `agent: GuestAgentConfig`, `gateways: GatewayNodeInfo`). The authoritative field matrix is the matching entry in [`api-inventory.json`](../../../../catalog/api-inventory.json); do not reconstruct it from implementation source.
- For the candidate guest-agent target, use `shared/automation/start-simulator.sh` and the recorded service socket/route, then `shared/automation/stop-simulator.sh`. Do not compile or design another simulator launcher.
- Exercise the case-prescribed absent/default/valid/boundary-invalid/unknown-field and JSON/protobuf representations with a checked-in helper when available. Keep secret response material in memory and record only structural checks, public material, and hashes.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The `gateway-cluster` fixture starts three case-owned candidate Gateway nodes. Use
  `values.gateway_cluster.nodes` for the node inventory and
  `values.gateway.registration_client.{cert,key}` as the client-authenticated
  app-info identity for the positive registration row. Do not print either file.
- The main JSON pRPC route is `POST /prpc/RegisterCvm`. A `404` response at `/`
  and a `401` response from an unauthenticated admin request prove that those
  listeners are alive; this fixture does not declare a separate metrics listener.
- Generate a syntactically valid WireGuard public key with `wg genkey | wg pubkey`.
  The positive row must use the prepared client certificate and key with TLS
  verification disabled only for the case-owned simulator CA.

## Objective

Verify the complete request, response, authorization, state transition, and error contract of `Gateway.RegisterCvm`.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

The `Gateway.RegisterCvm` entry in [`api-inventory.json`](../../../../catalog/api-inventory.json) is mandatory test data. Exercise every request field and every recursively referenced message field as absent/default, valid, boundary-invalid and combined with an unknown field; validate every response field, nested message field, and presence bit.

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-gw-gateway-001-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for gateway.registercvm.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-gw-gateway-001-step-02"></a>
### Step 2: Exercise the behavior

Invoke `Gateway.RegisterCvm` with a valid `RegisterCvmRequest` request using valid service-specific authentication and attestation context; capture the binary and JSON pRPC representations. Then send a schema-invalid request and, where protected, omit the credential.

**Expected results:**

- The valid call returns `RegisterCvmResponse` with every documented field and exhibits the documented `RegisterCvm` state and side effects; invalid framing or fields return a structured error, and protected calls reject missing credentials.

<a id="tc-gw-gateway-001-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
