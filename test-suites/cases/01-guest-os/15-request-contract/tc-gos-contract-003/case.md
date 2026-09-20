<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-contract-003"></a>
# TC-GOS-CONTRACT-003: Worker request-contract matrix

## Metadata

- Priority: P0
- Type: Functional, API, Security, Robustness, Regression
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gos-contract-003](../../../../catalog/feature-audit.md#req-gos-contract-003)
- Risks: [risk-gos-contract-003](../../../../catalog/feature-audit.md#risk-gos-contract-003)
- Source: [`catalog/api-inventory.json`](../../../../catalog/api-inventory.json), [`shared/automation/api-contract-matrix-policy.json`](../../../../shared/automation/api-contract-matrix-policy.json)

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- The method list, the request field list and every field's declared type come
  from [`api-inventory.json`](../../../../catalog/api-inventory.json). Do not reconstruct
  them from implementation source: the point of this case is that the indexed
  contract and the running service agree.
- [`api-contract-matrix-policy.json`](../../../../shared/automation/api-contract-matrix-policy.json)
  says how far each method may be driven. `full` runs every vector, and is only
  used for a method whose effect is confined to the lease. `rejection-only`
  runs the vectors a service must refuse before it dispatches, so nothing can
  mutate. `skip` is for a method whose valid invocation ends the process or
  consumes an external resource, and the policy file records why for each one.
- Every method the inventory declares for this service must carry a policy. A
  method added to the inventory without one fails this case rather than being
  silently skipped.

## Objective

Verify that every method `Worker` declares answers absent, default, valid,
boundary-invalid, wrong-typed, unknown-field and malformed-framing input, in
both the JSON and the protobuf representation, without violating the
invariants that hold for every method whatever it means.

The per-method cases in this suite each send one valid request and one
wrong-typed value for the first request field. That leaves the input classes
where a service actually breaks — an out-of-range integer, an oversized
string, a wrong protobuf wire type, a truncated body — untested for every
method. This case closes that gap once, for the whole service, and is driven
by the same inventory the per-method cases cite as mandatory test data.

## Preconditions

1. The shared plan prerequisites are healthy and the guest agent's external listener, which is reachable from outside the CVM is reachable.
2. The fixture is lease-owned. The matrix drives mutating methods with
   run-scoped identifiers, so it must never be pointed at a shared or
   production deployment.

## Test Data

The `guest-os` entries in [`api-inventory.json`](../../../../catalog/api-inventory.json)
whose `service` is `Worker`, and the vector set in
[`api_contract_matrix.py`](../../../../shared/automation/api_contract_matrix.py):

- per field type — empty, wrong type, null, a NUL byte, a newline, a path
  traversal, an absolute path, control characters, 64 KiB, 1 MiB, odd-length
  hex, non-hex, 31/63/64/65-byte lengths, zero, negative, `u32::MAX`,
  `u64::MAX`, past `u64::MAX`, and a 4096-element repeated field;
- per representation — an empty body, a non-object, a scalar, `null`, a
  truncated object, trailing garbage, 2000-deep nesting, duplicate keys, a
  4 MiB body, a truncated varint, a runaway varint, a length that overflows,
  a length past the end of the body, an unknown wire type, a group wire type,
  field number zero, a field number past the declared range, 8 KiB of random
  bytes, a JSON body sent as protobuf, a protobuf body sent as JSON, an
  absent content type, and an unrecognised content type;
- per method — the declared request encoded with an unknown field appended,
  and a declared field number sent with the wrong wire type.

## Steps

<a id="tc-gos-contract-003-step-01"></a>
### Step 1: Resolve the listener and the indexed contract

Resolve the guest agent's external listener, which is reachable from outside the CVM from the lease-owned fixture, load the inventory
entries for `Worker`, and confirm every one of them carries a policy.

**Expected results:**

- The listener is reachable, every declared method has a policy, and no method
  in the policy table is absent from the inventory.

<a id="tc-gos-contract-003-step-02"></a>
### Step 2: Drive the matrix

Send every vector the policy allows for every method, recording the status,
the response content type, the body size and the elapsed time of each call.

**Expected results:**

- **L1** No request produces a 5xx, a dropped connection, or a transport-level
  failure. A malformed request is a client error, not a server error, and
  never a crash: the workspace builds release binaries with `panic = "abort"`,
  so a reachable panic is a process abort rather than a failed request.
- **L2** A rejected JSON request carries a structured JSON body with an
  `error` string; a rejected protobuf request carries a decodable `ProtoError`.
- **L4** No rejection echoes an unbounded amount of the caller's input, and no
  response contains the unknown-field marker the request carried.
- **L5** No request exceeds the per-call deadline.
- **L6** A rejection's `Content-Type` matches the representation the request
  arrived in, so a client that sent JSON can parse the error it gets back.

<a id="tc-gos-contract-003-step-03"></a>
### Step 3: Verify the listener survived

Send one valid request after the whole matrix.

**Expected results:**

- **L3** The listener answers it. A service that stopped answering has either
  aborted or wedged on one of the preceding vectors.

## Postconditions

Remove run-scoped objects the `full` policy created and restore changed
configuration. Preserve the per-call observation table in the result
artifacts: it is the evidence that each vector was actually sent, and its
status histogram is what a reviewer compares across runs.
