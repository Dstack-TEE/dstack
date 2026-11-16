<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-serial-006"></a>
# TC-VMM-SERIAL-006: CVM log rotation retention and follow continuity

## Metadata

- Priority: P0
- Type: Functional, Security, Regression, Compatibility
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-vmm-serial-006](../../../../catalog/feature-audit.md#req-vmm-serial-006)
- Risks: [risk-vmm-serial-006](../../../../catalog/feature-audit.md#risk-vmm-serial-006)
- Source: `dstack/vmm/src/logrotate.rs`, `dstack/vmm/src/app.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.
- The fixture rewrites `cvm.log.max_bytes` to a small case-owned limit. `cvm.log` is a TOML sub-table, so the fixture rewrites that value in place; appending to the `[cvm]` scalar block would swallow every `[cvm]` key that follows it.
- Create and register one VM with `values.vmm.test_input.create_stopped_helper_argv`, then use the public StartVm/StopVm operations repeatedly to produce real boots. Do not synthesize or overwrite log files as behavior evidence.
- Use the candidate log route `/logs?id=<vm-id>&ch=<serial|stdout|stderr>&lines=<n>&follow=<bool>&ansi=<bool>` and the exact `values.vmm.json_prpc_routes.ReloadVms` JSON endpoint. `vmm-cli.py` has no `reload` subcommand. Bound every follow reader and correlate its output with the real log files under the registered VM work directory.

## Objective

Verify that the logs a CVM writes into its work directory stay bounded within a boot, that rotation preserves the writer's open file descriptor, and that a follower crosses a rotation without gap or duplication.

## Preconditions

1. Record candidate and pinned historical image/compose/config versions plus baseline identity, measurements, processes, files and public status.
2. Use isolated run-scoped inputs and retain native redacted output.

## Test Data

Build a table with one row for every condition named in Step 1, including each condition alone and security-relevant conflicting combinations.

Rotation is bounded by `cvm.log.max_bytes` and retains `cvm.log.max_backups` segments as `<log>.1` … `<log>.N`, discarding the oldest. It applies to `serial.log`, `stdout.log` and `stderr.log`. A VM start is itself a rotation trigger, so the previous boot survives as `<log>.1` and boot boundaries land on segment boundaries.

Two properties are load-bearing and must be observed rather than assumed:

- The live file keeps its inode across a rotation. QEMU and the supervisor hold it open for the life of the VM, so a rename would leave them appending into an unlinked inode and every later line would vanish without an error.
- The live file is emptied rather than compacted to a retained buffer. A follower must therefore resume cleanly at offset zero instead of replaying retained content.

Synthetic ANSI, non-UTF-8, and partial-line inputs are confined to the candidate rotation unit matrix; rotation evidence must come from real case-owned QEMU boots.

## Steps

<a id="tc-vmm-serial-006-step-01"></a>
### Step 1: Execute the full decision matrix

Run the candidate rotation unit matrix, then boot and reboot until a live log exceeds the configured maximum. Read the live file, its segments, tail and follow output during rotation, with partial lines, ANSI/binary bytes and concurrent readers.

**Expected results:**

- Every live log is bounded by `max_bytes`, segments shift with the oldest discarded, the live file keeps its inode, and no segment is spent on an empty log.
- A follower crosses a rotation with no gap and no duplicated line.
- Reader input cannot alter paths or files.

<a id="tc-vmm-serial-006-step-02"></a>
### Step 2: Verify the selected state end to end

Compare parser/validation output, persisted manifest/config, generated measurement inputs, launch arguments, guest-visible state and public status for every accepted row.

**Expected results:**

- Every representation agrees with the selected row, no rejected value is partially persisted or launched, and unrelated inputs do not change measured identity.
- The serial chardev is launched with `logappend=on`, which is what makes truncating the log in place safe: without it QEMU keeps writing at its stale offset and the file springs back over the cap.

<a id="tc-vmm-serial-006-step-03"></a>
### Step 3: Verify failure recovery and version compatibility

Restart after accepted/rejected rows, replay applicable v0.5.4/v0.5.8/v0.5.11 inputs, and retry after correcting one invalid field.

**Expected results:**

- Supported historical defaults remain stable, unsupported combinations fail before secret/device consumption, restart reconstructs the same decision and corrected retry succeeds without stale state.
- A VM inherited across a VMM restart is not rotated on the serial channel until its next boot. Its QEMU was launched by the previous binary and holds the log without `O_APPEND`, so truncating it would leave the file as large as it was and every later check would rotate again. `stdout.log` and `stderr.log` are written by the supervisor, always opened in append mode, and stay eligible across the restart.

## Postconditions

Remove run-scoped VMs/files/devices and verify baseline restoration.
