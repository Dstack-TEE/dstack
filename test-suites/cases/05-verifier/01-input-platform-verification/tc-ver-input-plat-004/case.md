<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-input-plat-004"></a>
# TC-INT-INPUT-PLAT-004: TDX-lite measurement verification

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-ver-input-plat-004](../../../../catalog/feature-audit.md#req-ver-input-plat-004)
- Risks: [risk-ver-input-plat-004](../../../../catalog/feature-audit.md#risk-ver-input-plat-004)
- Source: `dstack/verifier/src/verification.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify tdx-lite measurement verification across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-ver-input-plat-004-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for tdx-lite measurement verification.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-ver-input-plat-004-step-02"></a>
### Step 2: Exercise the behavior

Verify fixture/hardware with correct and altered MRTD/RTMR/config/image plus unsupported requirements.

**Expected results:**

- Lite measurements bind image/config as defined; unsupported full-TDX claims fail rather than being assumed.

<a id="tc-ver-input-plat-004-step-03"></a>
### Step 3: Replay quotes from the measurement document and reject forged documents

Decode `vm_config.tdx_measurement` of the committed legacy `tdx-lite-getquote.json` capture and of the two setup-header-normalized captures (one image on QEMU 8.2.2 and 10.2.1). Independently replay RTMR1 from the document kernel Authenticode digest and RTMR2 from the document command line plus ` initrd=initrd` and the initrd digest, and compare them with the registers in each quote. Then rewrite the legacy document and rebuild `sha256sum.txt` and `os_image_hash` so the image identity stays self-consistent, and verify each variant through the one-shot verifier: unchanged re-encoding, command line with ` forged=1`, command line already carrying ` initrd=initrd`, command line of exactly 2048 and 2049 bytes, command line without `dstack.rootfs_hash`, `version = 3`, the version-3 `cmdline_sha384` digest field, and a declared `kernel_header_normalized = true`.

**Expected results:**

- Every document is version 4 and carries the bare `cmdline` string; `sha256(checksum_file) == os_image_hash` and the `measurement.tdx.cbor` line matches the document.
- For all three captures the replayed RTMR1 and RTMR2 equal the quoted registers; the bare command line without the suffix does not reproduce RTMR2.
- The legacy document omits `kernel_header_normalized`; both normalized captures declare it, share one `os_image_hash`, and have identical quoted RTMR1 and RTMR2 while MRTD and RTMR0 differ between QEMU 8.2.2 and 10.2.1.
- The unchanged re-encoding verifies with a byte-identical result.
- The forged and suffixed documents fail with `quote_verified = true`, `os_image_hash_verified = false`, and `RTMR2 mismatch: expected=<independently replayed value>`; the forged row reports `actual=<quoted RTMR2>`; the 2048-byte row also fails on RTMR2 rather than the length bound.
- The 2049-byte row fails naming `2049 bytes` and `COMMAND_LINE_SIZE`, the row without `dstack.rootfs_hash` fails naming `dstack.rootfs_hash`, version 3 fails with `unsupported version 3`, and the digest-field row fails naming the missing `cmdline`; none of these four reaches an RTMR comparison.
- Declaring `kernel_header_normalized` at 2 GiB keeps the verdict valid but the reported `app_info.os_image_hash` equals the rebuilt identity and differs from the original.

<a id="tc-ver-input-plat-004-step-04"></a>
### Step 4: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression coverage (PRs #1189, #1199, and #1207)

- #1189: an image whose OVMF normalizes the Linux setup header declares `kernel_header_normalized`, and its RTMR1 is the plain Authenticode replay of the shipped kernel on every QEMU version. Step 2 verifies both committed normalized captures offline with `os_image_hash_verified` and `acpi_tables_verified`; Step 3 proves from the quotes that RTMR1/RTMR2 do not depend on the host QEMU, and that the pre-normalization capture keeps verifying.
- #1199: measurement document version 4 carries the image command line instead of its digest; the verifier appends ` initrd=initrd` exactly once, enforces `dstack.rootfs_hash` and the 2048-byte `COMMAND_LINE_SIZE` bound, rejects version 3, and catches a self-consistent forged command line through RTMR2 (Step 3).
- #1207: Step 2 verifies the same-boot v1 `Attest` (MessagePack V1) and v0 `Attest` (legacy SCALE) captures and requires byte-identical verification results.
- The verifier's no-download memory gate for pre-normalization documents (`memory_size` must be 2 GiB or at least 2816 MiB) is not observable with the committed 2 GiB captures, because the declared-shape ACPI digest check rejects a changed memory size first. Exercising it needs a hardware capture of a pre-normalization image at another memory size.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
