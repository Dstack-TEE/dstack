<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-serial-006"></a>
# TC-VMM-SERIAL-006: Serial log separator rotation history and follow continuity

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-serial-006](../../../feature-audit.md#req-vmm-serial-006)
- Risks: [risk-vmm-serial-006](../../../feature-audit.md#risk-vmm-serial-006)
- Source: `dstack/vmm/src/app.rs`

## Objective

Verify serial log separator rotation history and follow continuity using the complete source-defined decision matrix and independently observable output.

## Preconditions

1. Record candidate and pinned historical image/compose/config versions plus baseline identity, measurements, processes, files and public status.
2. Use isolated run-scoped inputs and retain native redacted output.

## Test Data

Build a table with one row for every condition named in Step 1, including each condition alone and security-relevant conflicting combinations.

## Steps

<a id="tc-vmm-serial-006-step-01"></a>
### Step 1: Execute the full decision matrix

Boot/reboot/crash until serial history exceeds configured maximum; read current/history/tail/follow during rotation, partial lines, ANSI/binary bytes and concurrent readers.

**Expected results:**

- Each boot separator occurs once, rotation bounds storage without corrupting current log, history ordering is preserved, follow has no gap/duplication and reader input cannot alter paths/files.

<a id="tc-vmm-serial-006-step-02"></a>
### Step 2: Verify the selected state end to end

Compare parser/validation output, persisted manifest/config, generated measurement inputs, launch arguments, guest-visible state and public status for every accepted row.

**Expected results:**

- Every representation agrees with the selected row, no rejected value is partially persisted or launched, and unrelated inputs do not change measured identity.

<a id="tc-vmm-serial-006-step-03"></a>
### Step 3: Verify failure recovery and version compatibility

Restart after accepted/rejected rows, replay applicable v0.5.4/v0.5.8/v0.5.11 inputs, and retry after correcting one invalid field.

**Expected results:**

- Supported historical defaults remain stable, unsupported combinations fail before secret/device consumption, restart reconstructs the same decision and corrected retry succeeds without stale state.

## Postconditions

Remove run-scoped VMs/files/devices and verify baseline restoration.
