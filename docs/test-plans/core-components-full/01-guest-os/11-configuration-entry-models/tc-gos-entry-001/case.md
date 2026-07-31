<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-entry-001"></a>
# TC-GOS-ENTRY-001: Guest-agent configuration precedence and compose deserialization

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: SIMULATOR
- Automation: Yes
- Requirements: [req-gos-entry-001](../../../feature-audit.md#req-gos-entry-001)
- Risks: [risk-gos-entry-001](../../../feature-audit.md#risk-gos-entry-001)
- Source: `dstack/guest-agent/src/config.rs`

## Prepared execution knowledge

- Read and obey [`automation/execution-guide.md`](../../../automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The guest-agent loader merges embedded defaults, discovered config files,
  and the explicit `--config` leaf file. It does not register an environment
  provider, so candidate environment variables must not override these values.
  Record this as the source-defined precedence rather than expecting an
  undocumented environment override.
- A quoting, parsing, missing-tool, or evidence-projection error in the test
  command is not a product failure. Retry it with a bounded compatible command
  and grade the behavior only from the corrected observation.
- The fixture must provide `values.config_entry_peer` for the adjacent
  identity check. Use its separate lease-owned VM/SSH identity for Step 4; do
  not mark the product blocked merely because a single-guest fixture was used.

## Objective

Verify guest-agent embedded-default/explicit-leaf precedence and compose-file deserialization exactly match the source-defined pure-loader behavior.

## Preconditions

1. Use an isolated deployment with the relevant effective configuration and a clean run-scoped baseline.
2. Enable redacted process, file, RPC, and lifecycle evidence collection.

## Test Data

The `guest-agent` portion of [`configuration-inventory.json`](../../../configuration-inventory.json) is mandatory test data. Exercise every listed field at its implicit default, an explicit valid value, boundary-invalid values, an unknown sibling field, and after restart.

Include embedded defaults, an explicit TOML leaf, valid minimal compose, absent optional fields, an unknown optional field, a missing compose file, malformed JSON, and missing required compose fields.

## Steps

<a id="tc-gos-entry-001-step-01"></a>
### Step 1: Record effective inputs and baseline

Resolve the candidate source, locked dependency graph, shared Cargo target, embedded defaults, and case-owned temporary inputs.

**Expected results:**

- The loader and compose types are the candidate implementation and every mutable input is temporary and process-local.

<a id="tc-gos-entry-001-step-02"></a>
### Step 2: Exercise behavior and boundaries

Load embedded defaults plus an explicit leaf file and exercise valid compose raw-byte preservation, unknown optional fields, absent optional values, a missing file, malformed JSON, and missing required fields.

**Expected results:**

- Explicit leaf values override embedded defaults, valid compose bytes are preserved losslessly, optional defaults remain stable, and invalid required data fails before AppState or listeners are constructed.

<a id="tc-gos-entry-001-step-03"></a>
### Step 3: Inject failure and concurrency

Repeat the stateless loader matrix in fresh temporary directories and run the underlying load-config precedence suite.

**Expected results:**

- Results are deterministic without shared mutable state; failures identify read versus parse phase and a subsequent valid extraction succeeds.

<a id="tc-gos-entry-001-step-04"></a>
### Step 4: Verify restart, isolation, and redaction

Verify temporary directories are independently scoped, no listener or service was started, and bounded evidence contains no compose payload or credential.

**Expected results:**

- No runtime identity can be mutated by this pure loader; all temporary inputs are removed and evidence retains only named test outcomes and output hashes.

## Postconditions

Remove temporary loader inputs and retain only bounded test names, counts, and output hashes.
