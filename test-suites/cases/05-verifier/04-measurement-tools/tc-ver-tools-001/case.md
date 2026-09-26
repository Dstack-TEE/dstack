<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-ver-tools-001"></a>
# TC-VER-TOOLS-001: dstack-mr supported platform CLI matrix

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-ver-tools-001](../../../../catalog/feature-audit.md#req-ver-tools-001)
- Risks: [risk-ver-tools-001](../../../../catalog/feature-audit.md#risk-ver-tools-001)
- Source: `dstack/dstack-mr/cli`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify dstack-mr supported platform cli matrix with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The prepared `dstack-mr` candidate binary and manifest-declared extracted full-TDX image are available.
2. The case uses a run-scoped shared matrix cache keyed by run ID and candidate commit; the first of these two cases executes the matrix under a file lock and the second reuses the exact result.
3. Every artifact mutation occurs in a reflink/copy of the prepared image. This case consumes an image and does not test mkosi or Yocto construction.

## Test Data

Use the prepared 0.5.4.1 image, QEMU 8.x/9.x/10.x rows, every CLI configuration field, isolated artifact copies, malformed/missing inputs, and output hashes rather than raw boot artifacts.

## Steps

<a id="tc-ver-tools-001-step-01"></a>
### Step 1: Establish the baseline

Validate the prepared CLI hash, removed legacy version flag rejection, image manifest identity, and empty case workspace.

**Expected results:**

- The candidate CLI accepts the historical image version, emits four 48-byte measurements, and starts without case-owned output or mutation state.

<a id="tc-ver-tools-001-step-02"></a>
### Step 2: Exercise supported and boundary paths

Run measurement CLI for every supported platform/image/config combination and the explicitly unsupported swtpm=true input.

**Expected results:**

- Supported outputs are deterministic and labeled by platform; swtpm=true fails immediately with an actionable unsupported message and no guessed measurement.

<a id="tc-ver-tools-001-step-03"></a>
### Step 3: Exercise failure and recovery

Run supported hugepage/NUMA plus ignored legacy version metadata plus unsupported old-QEMU, swtpm, malformed-metadata, and missing-artifact rows; then repeat the valid baseline.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-ver-tools-001-step-04"></a>
### Step 4: Verify isolation and persistence

Repeat measurement from an adjacent isolated image copy and compare it byte-for-byte with the baseline; verify the CLI leaves no persistent runtime state.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

## Post-baseline regression coverage (PRs #1189 and #1199)

- `metadata.json` field `kernel_header_normalized` is the image's declaration of which kernel bytes RTMR1 covers; absent means the canonical boot-loader layout that dstack's OVMF writes. The shared matrix measures the historical image with and without the declaration and a normalized copy across QEMU 8.2.2/9.2.1/10.2.1 and 1-8 GiB (see TC-VER-TOOLS-002).
- `dstack-mr tdx-measurement-cbor` is deterministic and emits measurement document version 4 whose `image.cmdline` is the bare metadata cmdline, with `kernel_header_normalized` omitted for the historical image and `true` for the zeroed-header copy; the document kernel digest and cmdline replay to the CLI RTMR1 and RTMR2, the firmware (`tdvf`) material is unchanged by the header form, and a cmdline without `dstack.rootfs_hash` is rejected by name.
- Native vectors `image_info_tests::metadata_declares_whether_the_kernel_header_is_normalized`, `tdx_measurement_cbor_tests::the_kernel_header_flag_round_trips`, `tdx_measurement_cbor_tests::a_pre_normalization_document_does_not_drift`, `tdx_measurement_cbor_tests::unknown_versions_are_rejected`, and `tdx_measurement_cbor_tests::an_oversized_command_line_is_rejected_by_name` in `dstack-types` pass by exact name.

## Post-baseline regression coverage (PRs #1275, #1367, and #1387)

- `dstack-mr diagnose` (#1367) rebuilds the machine from a VmConfig the way the verifier does. For `{cpu_count: 2, memory_size: 2 GiB, qemu_version: "9.2.1", num_nics: 3, num_verity_volumes: 2}` with `--image-dir` it reports exactly the four registers `measure --num-nics 3 --num-verity-volumes 2` reports, which differ from the baseline in RTMR0; the same VmConfig with `swtpm: true` is rejected with `swtpm measurement is not supported`.
- GPU passthrough (#1387): the GPU/NVSwitch topology is rejected with `set hotplug_off for GPU passthrough` under `--hotplug-off false`, and measured under `--hotplug-off true`, and with it changes exactly RTMR0.
- Measurement documents (#1275): native vectors `cbor_canonicalization_tests::cbor_decoders_reject_trailing_bytes`, `cbor_canonicalization_tests::the_aws_measurement_document_names_and_checks_its_version`, and `mr_config::tests::a_document_without_a_version_is_not_a_v3_document` in `dstack-types` pass by exact name.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
