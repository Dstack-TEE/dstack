<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="dstack-test-methodology"></a>
# dstack Test Methodology

This document defines the common process for dstack release testing, from change analysis and risk assessment through execution, evidence collection, and release decisions. See the [test-case authoring specification](test-case-authoring-spec.md#dstack-test-case-authoring-spec) and [report output specification](test-report-output-spec.md#dstack-test-report-output-spec) for normative formats.

<a id="method-objectives"></a>
## 1. Objectives

Testing must produce reproducible, auditable, and traceable release evidence—not merely show that a script once exited successfully. A conclusion must be traceable from a requirement or risk to a case, step, original command evidence, observation, and attachment.

Testing is complete only when:

1. every relevant change, requirement, and material risk has explicit coverage;
2. an executor unfamiliar with the implementation can reproduce each case;
3. the native AI session preserves executed commands and their raw output;
4. simulated and physical-hardware results are reported separately;
5. tools can recompute aggregate status from atomic case results; and
6. references, attachment digests, and statistics are machine-verifiable.

<a id="method-artifacts"></a>
## 2. Artifact layers

Do not mix these four layers:

| Layer | Purpose | Immutable after execution starts |
|---|---|---:|
| Change audit | Establishes changed behavior, dependencies, and risks | Yes |
| Test plan | Defines scope, topology, cases, and execution order | Yes |
| Case specification | Defines preconditions, actions, and expected results | Yes |
| `results/<run-id>/` | Records versions, native sessions, observations, and attachments | No, while running |

A plan uses exactly three semantic levels: chapter, section, and case. Its machine-readable execution order is defined by `index.json`; its top-level `README.md` is the executor's environment guide.

<a id="method-workflow"></a>
## 3. Workflow

### 3.1 Audit the release delta

Compare the previous released tag with the candidate commit. Inspect commits, pull requests, schemas, RPCs, command-line interfaces, configuration defaults, systemd units, image recipes, deployment manifests, migrations, and dependency changes. For every change record:

- the user-visible or operational behavior;
- affected components and interfaces;
- compatibility direction and version combinations;
- failure modes and security impact;
- the requirement and risk IDs used by test cases; and
- whether physical TEE hardware is required.

Generated changelogs alone are insufficient. Follow data and control flow across component boundaries.

### 3.2 Build a risk-based coverage matrix

Classify coverage as:

- **new or changed functionality**: full positive, boundary, and relevant negative coverage;
- **regression**: behavior likely to be affected by shared code, configuration, images, protocols, or lifecycle changes;
- **compatibility**: supported mixed-version combinations and upgrade order;
- **security**: trust boundaries, identity, attestation, key handling, authorization, and secret disclosure;
- **operations**: install, upgrade, restart, recovery, logging, and diagnostics.

Prioritize by impact, likelihood, detectability, and breadth. `P0` covers release-blocking trust, data-loss, availability, or primary-path risks; `P1` covers important supported behavior; `P2` covers lower-risk variants.

### 3.3 Define environments

The plan guide must describe topology, component endpoints, credentials, test data, health checks, concurrency constraints, cleanup, and prohibited operations. Record common software versions once in run-level context. A case records a version override only when it deliberately uses a different component version.

Environment levels are:

- **UNIT**: isolated code-level validation;
- **SIMULATOR**: no-TEE or mock-attestation execution;
- **INTEGRATION**: deployed multi-component system;
- **HARDWARE**: physical supported TEE hardware.

Simulation may follow `docs/development-without-tee.md`; a no-TEE development guest may independently use `key_provider=tpm` when the SGX local key provider is unavailable. This does not run local-key-provider in a TPM mode or cover its SGX behavior. Simulation never proves hardware-specific boot, measurement, attestation, sealing, or device behavior. Such unconfirmed items must be called out separately in the report.

### 3.4 Author and review cases

Each case validates one independently decidable behavior and references at least one requirement or risk. Prefer three to eight logical steps. Every step defines an action and exact observable expected results. Do not write a separate failure criterion: any result that does not fully match the expected result is `FAIL`.

Review the plan for change coverage, regression breadth, compatibility matrices, security boundaries, operational recovery, test-data isolation, and cleanup before execution.

### 3.5 Execute

The `run-plan` orchestration agent must first read the guide, index, and every
case specification. It processes cases in index order, starts an independent
case-agent session for each runnable case, and reads the completed result before
deciding about later cases. It may mark a later case `SKIPPED` without launching
it only when a recorded earlier non-PASS result demonstrably makes the later
case's prerequisite false or its result meaningless. Similarity, expected cost,
or a mere possibility of failure is not sufficient. Independent cases continue.

Each case executor must:

1. read the plan `README.md` and `index.json`;
2. execute cases in index order unless the guide explicitly permits parallelism;
3. start a fresh Codex or Claude session for each case;
4. execute real commands rather than infer outcomes;
5. preserve the native JSONL session as step evidence;
6. write only a shallow atomic `result.json`; and
7. continue to later independent cases after a case-level failure.

The executor name and model are recorded by the runner. Secrets must never be emitted into sessions or artifacts.

<a id="method-status"></a>
## 4. Status model

Case and step status is one of:

- `PASS`: every expected result was fully observed;
- `FAIL`: at least one expected result was not fully observed;
- `BLOCKED`: an external prerequisite prevented the tested behavior from starting;
- `NOT_RUN`: execution was not attempted;
- `SKIPPED`: omission was explicitly authorized and explained.

`PARTIAL` is forbidden. A completed run may contain any terminal case status. A run is `INCOMPLETE` only when required case result artifacts are missing.

Product failure and test-infrastructure failure must be distinguished. A healthy system returning the wrong response is `FAIL`; an unavailable required laboratory host before the tested action begins is `BLOCKED`.

<a id="method-evidence"></a>
## 5. Evidence and traceability

Every logical step must be supported by observed commands and raw output in the native session. Screenshots or other files are attachments, not replacements for command evidence where machine-readable evidence is available. Preserve timestamps, exit codes, stdout, stderr, and tool errors as supplied by the agent CLI.

Use explicit HTML anchors for all chapters, sections, cases, and steps. Do not rely on renderer-specific heading slugs. `index.json` is the authority for ordering and paths; IDs remain stable after publication.

<a id="method-compatibility"></a>
## 6. Compatibility testing

Derive version combinations from supported deployment behavior rather than testing arbitrary permutations. For a rolling upgrade, cover at least:

- latest control-plane services with both previous and latest guest images;
- persisted state created by the previous release and consumed by the candidate;
- protocol/schema defaults when one side omits newly introduced fields;
- upgrade order, restart behavior, and rollback where supported; and
- explicit rejection of unsupported combinations with actionable diagnostics.

For dstack v0.6.0, the expected online topology includes latest VMM, KMS, and gateway components while instances may use a mixture of old and new images.

<a id="method-release-decision"></a>
## 7. Release decision

The final report must provide coverage by requirement and risk, status counts, unresolved failures, blocked or skipped cases, simulation-only results, unconfirmed hardware items, and material deviations from the plan. Release acceptance criteria belong in the plan guide and must state which statuses or open risks block release.

Before publishing, run `dstack-test validate`, render the self-contained HTML report, and package the selected run. The package is an immutable review artifact and must not include secrets or results from unrelated run IDs.
