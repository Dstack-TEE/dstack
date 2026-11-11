<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-compute-ne-007"></a>
# TC-VMM-COMPUTE-NE-007: QEMU command and platform matrix

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-vmm-compute-ne-007](../../../../catalog/feature-audit.md#req-vmm-compute-ne-007)
- Risks: [risk-vmm-compute-ne-007](../../../../catalog/feature-audit.md#risk-vmm-compute-ne-007)
- Source: `dstack/vmm/src/app/qemu.rs`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify qemu command and platform matrix across success, boundary, failure, security, and recovery conditions.

## Preconditions

1. The shared plan prerequisites are healthy and the target listener is reachable.
2. Commands use isolated test data and preserve native request and response output.

## Test Data

Use a unique run-scoped identifier and non-production credentials.

## Steps

<a id="tc-vmm-compute-ne-007-step-01"></a>
### Step 1: Inspect the effective prerequisite

Query the relevant health, configuration, and baseline state for qemu command and platform matrix.

**Expected results:**

- The target component is healthy, the intended listener and policy are effective, and the baseline contains no run-scoped test object.

<a id="tc-vmm-compute-ne-007-step-02"></a>
### Step 2: Exercise the behavior

Generate launches for TDX full/lite, SNP, GCP TDX, Nitro TPM, no-TEE, swtpm, GPU, and networking combinations.

**Expected results:**

- Machine type, firmware, devices, confidential-guest objects, shares, and vm_config measurements agree for every supported matrix row.

<a id="tc-vmm-compute-ne-007-step-03"></a>
### Step 3: Verify state, isolation, and diagnostics

Re-query the public status/state interfaces, inspect component and peer logs, and repeat the request with one invalid or unauthorized input appropriate to this interface.

**Expected results:**

- Repeated observations match the method’s documented persistence, determinism, and idempotency semantics and remain scoped to the caller or run-scoped object; invalid or unauthorized input is rejected without secret disclosure, partial mutation, or loss of service availability.

## Post-baseline regression matrix

Generate ACPI for every supported QEMU profile and version clamp, compare seeded randomized tables against the reference implementation, cover AMD PCI-hole and high-memory relocation, and require deterministic DSDT/SRAT/MCFG output for identical VM shape.

## Post-baseline regression coverage (PR #1204, PR #1145, PR #1214, PR #1065)

- PR #1204: the QEMU version declared in `vm_config` is resolved at every VM start. Without `qemu_version` it is read from the binary at `qemu_path` (so a package upgrade between starts is reflected), a wrapper banner on stdout or stderr does not hide the version line, an explicit `qemu_version` wins over the binary, and a binary whose version cannot be read fails the start with an error that names `qemu_version` instead of booting with an undeclared version.
- PR #1145 and PR #1214: every bridge NIC uses the netd-built TAP as `-netdev tap,...,ifname=<tap>,script=no,downscript=no` (no `qemu-bridge-helper`), vhost-net is `on`/`off` per the resolved setting, multiqueue bridge and macvtap NICs derive `queues=` and MSI-X vectors from vCPU count capped at 16, macvtap takes one inherited descriptor per queue, user mode keeps its netdev and a single queue whatever vhost says, custom netdevs are passed through unmodified, and a node that never enabled vhost keeps the pre-change device shape.
- PR #1065: GPU sanitization issues a VFIO PCI hot reset instead of writing Bridge Control through sysfs. The unit rows prove slot normalization, dedicated-upstream-bridge detection, refusal when the bridge is shared with another device, and skipping when passthrough or sanitization is disabled. Two mandatory CPU-only CLI rows run `dstack-vmm sanitize-gpu` with no slot (usage error) and with a PCI slot absent from the host (`failed to resolve PCI device`), and require a non-zero exit before any hot reset is issued. A real hot reset of an attached GPU requires GPU hardware and stays in the hardware-gated `tc-vmm-compute-ne-004`.

## Post-baseline regression coverage (PR #1364, PR #1346, PR #1286, PR #1351, PR #1230)

Each row passes only when every named `dstack-vmm` unit test reports `ok`.

- `resource-bounds` (PR #1364): `round_up` saturates instead of wrapping, and a deployment with zero memory is refused. The zero vCPU/memory/disk refusals over pRPC are in `tc-vmm-vmm-001`.
- `listed-gpu-policy` (PR #1346): a listed slot that `ListGpus` does not offer, including one carrying QEMU option separators (`0000:0f:00.0,romfile=...`), is refused before it reaches `-device vfio-pci`. The fixture node has GPU passthrough disabled, so the pRPC path stops at `GPU is not enabled`; the offered-device check on a GPU host belongs to `tc-vmm-compute-ne-004`.
- `update-validation` (PR #1286, PR #1351): a mapping the VM already holds stays accepted after the node disables or narrows port mapping, a new one is refused, and a rejected update leaves the stored compose file untouched. The pRPC rows are in `tc-vmm-compute-ne-002`.
- `disk-preallocation` (PR #1230): `off` builds the pre-change `qemu-img create` arguments; `metadata`/`falloc`/`full` add `preallocation=` and, on a backing file, `extended_l2=on`; a `falloc` disk on a backing file reserves its size (skipped by the test itself where `qemu-img` is absent); a leftover `hda.img.partial` is never booted; the node default applies when the request is unset or empty; and `falloc`/`full` are refused while the compose file lets the guest discard. The pRPC rows are in `tc-vmm-vmm-001` and `tc-vmm-vm-lifecyc-003`.

## Postconditions

Remove run-scoped objects and restore changed configuration. Preserve logs and responses in the result artifacts.
