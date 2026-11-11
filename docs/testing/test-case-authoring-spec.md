<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="dstack-test-case-authoring-spec"></a>
# dstack Test-Case Authoring Specification

This document defines the normative layout and content of a dstack test plan and its `case.md` files. See the [test methodology](dstack-test-methodology.md#dstack-test-methodology) and [report output specification](test-report-output-spec.md#dstack-test-report-output-spec).

<a id="case-plan-layout"></a>
## 1. Plan layout

```text
<plan>/
├── index.json
├── README.md
├── results/<run-id>/
└── <chapter>/
    ├── README.md                 # optional
    └── <section>/
        ├── README.md             # optional
        └── <case-id>/
            ├── case.md
            ├── fixtures/         # optional
            ├── scripts/          # optional
            └── results/<run-id>/
```

Only chapter, section, and case are semantic organization levels. Each case has its own directory and a specification named `case.md`.

<a id="case-identifiers"></a>
## 2. IDs and anchors

All referenceable objects use explicit, stable, globally unique ASCII IDs. Use lowercase letters, digits, and hyphens. IDs must not change when titles change. Place `<a id="..."></a>` before each referenceable heading and use relative paths with fragments for cross-file links.

Recommended forms:

```text
chapter-gateway
section-gateway-proxy-protocol
tc-gw-pp-001
tc-gw-pp-001-step-01
req-gw-pp-001
risk-gw-spoofing-001
```

<a id="case-plan-guide"></a>
## 3. Top-level guide

The top-level `README.md` is the first document an executor reads. It must state:

1. objectives and scope;
2. system topology and system under test;
3. hardware, software, account, and external-service requirements;
4. reproducible common setup commands;
5. shared preconditions and health checks;
6. status rules and release acceptance criteria;
7. evidence, redaction, and attachment rules;
8. order, concurrency, and stop conditions;
9. cleanup and recovery; and
10. validation, packaging, and rendering commands.

Avoid non-reproducible instructions such as “configure a working KMS.”

<a id="case-index"></a>
## 4. `index.json`

The index is authoritative for discovery and order. A minimal example is:

```json
{
  "schema_version": "1.0",
  "id": "dstack-v0-6-0-release",
  "title": "dstack v0.6.0 Release Test Plan",
  "guide": {"path": "README.md", "anchor": "release-test-guide"},
  "chapters": [
    {
      "id": "chapter-gateway",
      "title": "Gateway",
      "order": 1,
      "path": "01-gateway",
      "sections": [
        {
          "id": "section-gateway-proxy-protocol",
          "title": "Proxy Protocol",
          "order": 1,
          "path": "01-gateway/01-proxy-protocol",
          "cases": [
            {
              "id": "tc-gw-pp-001",
              "title": "Forward a Proxy v1 client address over TLS termination",
              "order": 1,
              "priority": "P0",
              "path": "01-gateway/01-proxy-protocol/tc-gw-pp-001",
              "spec": {
                "path": "01-gateway/01-proxy-protocol/tc-gw-pp-001/case.md",
                "anchor": "tc-gw-pp-001"
              },
              "requirements": ["req-gw-pp-001"],
              "risks": ["risk-gw-spoofing-001"],
              "tags": ["gateway", "proxy-protocol"]
            }
          ]
        }
      ]
    }
  ]
}
```

Array order must agree with `order`. Paths must remain below the plan root and must not contain absolute paths or `..` traversal.

### Fixture and executor declarations

Cases may declare an isolated fixture contract and the product actions that
fixture setup must not perform:

```json
{
  "fixture": {
    "profile": "vmm-empty-control-plane",
    "capabilities": ["create_vm", "remove_vm"]
  },
  "actions_under_test": ["Vmm.CreateVm"]
}
```

The fixture supplies substrate, dependencies, resource capacity, and a verified
initial state. The case performs the declared product action through the real
product interface. Mutable release tests must not reuse a long-lived shared
guest or control-plane instance.

Execution defaults to the configured Agent. A deterministic case can instead
declare an executable entrypoint:

```json
{
  "execution": {
    "entrypoint": "01-gateway/01-proxy-protocol/tc-gw-pp-001/automation/run-test.py",
    "args": [],
    "timeout_seconds": 600
  }
}
```

The path is relative to the plan root, must remain inside that root, must be a
regular executable file, and must contain a shebang. Arguments are passed as an
argv array without a shell. The script writes the same `result.json`, evidence,
and attachments as an Agent case. Its exit code describes executor health; the
validated `result.json` describes the product result.

<a id="case-required-structure"></a>
## 5. Required `case.md` structure

Use this order:

```markdown
<a id="tc-example-001"></a>
# TC-EXAMPLE-001: Title

## Metadata

## Objective

## Preconditions

## Test Data

## Steps

<a id="tc-example-001-step-01"></a>
### Step 1: Step title

Action instructions.

**Expected results:**

- First observable result.
- Second observable result.

## Postconditions
```

<a id="case-metadata"></a>
## 6. Metadata

At minimum include case ID, priority (`P0`, `P1`, or `P2`), type (for example Functional, Security, Compatibility, Regression, or Performance), minimum environment level, automation suitability, and requirement/risk references.

Do not repeat common versions in every case. When a case requires an old or special component version, add a **Special Version Requirements** field and record the actual value as a result-level version override.

<a id="case-objective"></a>
## 7. Objective

Define one independently decidable behavior: the relevant configuration or state, the action, and the essential externally observable result. Split a case when its title contains multiple independent “and” clauses. An implementation function name or a script's zero exit status is not a product objective.

<a id="case-preconditions"></a>
## 8. Preconditions

Preconditions must be verifiable and distinct from the tested action. Put shared environment conditions in the plan guide and only case-specific conditions in the case. If a prerequisite fails before the tested behavior starts, preserve evidence and report `BLOCKED`; do not report a product `FAIL` for setup failure.

<a id="case-test-data"></a>
## 9. Test data

Prefer JSON blocks for protocol fields, boundary values, and expected values. Document how random values are generated and preserve the actual values in results. Use RFC documentation address ranges for security-test addresses. Never put reusable credentials, tokens, private keys, or production secrets in plan files.

<a id="case-steps"></a>
## 10. Steps and expected results

Prefer three to eight logical steps. One logical step may invoke several mechanical commands, but it validates one phase. Every step must have:

1. an explicit unique anchor;
2. a reproducible action;
3. precise, observable, comparable expected results; and
4. at least one item of command evidence in the native session.

Do not write a separate failure criterion. If the actual result does not fully satisfy the expected result, the step and case are `FAIL`. Replace vague words such as “normal,” “correct,” or “without errors” with exact states, fields, addresses, digests, counts, or response codes.

<a id="case-postconditions"></a>
## 11. Postconditions

State which data is removed, which services are stopped or retained, how modified policy/configuration is restored, which state is intentionally retained for later cases, and how cleanup failures are recorded. Cleanup failure does not erase the original test result but must be reported.

<a id="case-proxy-example"></a>
## 12. Proxy Protocol example

````markdown
<a id="tc-gw-pp-001"></a>
# TC-GW-PP-001: A PP-enabled application port receives the client address

## Metadata

- Priority: P0
- Type: Functional, Regression, Security
- Environment: INTEGRATION
- Requirements: req-gw-pp-001
- Risks: risk-gw-spoofing-001

## Objective

Verify that, when inbound Proxy Protocol is enabled and application port 8443 declares `pp=true`, gateway forwards the Proxy v1 client address to the application and completes the following HTTP request.

## Preconditions

1. Gateway has `inbound_pp_enabled=true`.
2. The guest is registered and port 8443 has `pp=true`.
3. The capture backend is ready and gateway has loaded the instance port policy.

## Test Data

```json
{
  "source": "198.51.100.27:45678",
  "destination": "203.0.113.10:8443",
  "request_id": "tc-gw-pp-001"
}
```

<a id="tc-gw-pp-001-step-01"></a>
### Step 1: Check effective policy

Query the guest and gateway port policy.

**Expected results:** The instance ID matches; port 8443 exists and has `pp=true`.

<a id="tc-gw-pp-001-step-02"></a>
### Step 2: Reset capture state

Clear earlier capture records.

**Expected results:** The backend is ready and contains zero records.

<a id="tc-gw-pp-001-step-03"></a>
### Step 3: Send the request

Send a Proxy v1 header, then complete TLS and HTTP on the same connection.

**Expected results:** TLS succeeds, HTTP returns 200, and the request ID matches.

<a id="tc-gw-pp-001-step-04"></a>
### Step 4: Inspect the capture

Query the backend capture records.

**Expected results:** Exactly one new record exists; source and destination match the test data and the HTTP request is complete.
````

<a id="case-review-checklist"></a>
## 13. Review checklist

Before submission, confirm that:

- directory, case ID, and index entry agree;
- explicit anchors are present and unique;
- each case references a requirement or risk;
- the objective has one core behavior;
- preconditions are verifiable;
- every step has precise expected results and raw evidence;
- step count is reasonable;
- simulation and physical-hardware requirements are explicit;
- postconditions restore the environment; and
- no secret or environment-private value is present.
