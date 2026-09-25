<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-platform-005"></a>
# TC-GOS-PLATFORM-005: Guest kernel and userspace hardening

## Metadata

- Priority: P0
- Type: Functional, Security, Regression
- Minimum environment: HARDWARE
- Automation: Yes
- Requirements: [req-gos-platform-005](../../../../catalog/feature-audit.md#req-gos-platform-005)
- Risks: [risk-gos-platform-005](../../../../catalog/feature-audit.md#risk-gos-platform-005)
- Source: `os/common/rootfs/sysctl.d/99-dstack.conf`, `os/image/kernel-cmdline.sh`,
  `os/mkosi/components/kernel/kernel.config`, `os/mkosi/versions.env`,
  `os/common/nvidia/nvidia-module-options`,
  `os/common/nvidia/nvidia-module-options.service`,
  `os/common/nvidia/nvidia-blacklist.conf`, `os/common/rootfs/tdx-guest-tune.sh`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its prepared binaries, shared Cargo target, fixture paths, commit, and toolchain as authoritative. Do not rediscover them from processes, old sessions, or broad source searches.
- Runtime state and evidence remain case-scoped even though immutable build outputs are shared.
- Use the case metadata, inventories, and prepared manifest as the complete initial execution specification. Source inspection before the first tested operation is allowed only for a specific unresolved ambiguity.
- Do not run a clean build unless this case explicitly tests build, packaging, features, or reproducibility. Otherwise reuse the shared target and prepared binaries.
- If a mismatch occurs, write the provisional result first. Perform narrow source-level root-cause analysis only when failure investigation is enabled.

## Objective

Verify guest kernel and userspace hardening with explicit success, boundary, failure, restart, and isolation observations.

## Preconditions

1. The target runs in an isolated environment with effective configuration and synchronized evidence capture.
2. Baseline service, file, process, device, listener, and secret-redaction state has been recorded.

## Test Data

Use run-scoped identities and sentinel secrets that can be detected by hash without being retained in evidence.

## Steps

<a id="tc-gos-platform-005-step-01"></a>
### Step 1: Establish the baseline

Query the effective configuration, service dependencies, listener/device state, and persisted files involved in this behavior.

**Expected results:**

- Required dependencies are healthy, ownership and permissions match policy, and no run-scoped object or sentinel is present before the action.

<a id="tc-gos-platform-005-step-02"></a>
### Step 2: Exercise supported and boundary paths

Audit kernel config, sysctl, mounts, capabilities, device nodes, SSH/accounts, network discovery, and writable executable paths.

**Expected results:**

- The image exposes only required devices/services, applies hardening settings, has no default credential, and application containers cannot modify measured/privileged host state.

<a id="tc-gos-platform-005-step-03"></a>
### Step 3: Exercise failure and recovery

Inject one invalid input and one dependency interruption appropriate to the behavior, restore the dependency, and repeat the valid operation.

**Expected results:**

- Failure is bounded, fails closed, produces actionable redacted diagnostics, leaves no partial trusted state, and the repeated valid operation succeeds exactly once after recovery.

<a id="tc-gos-platform-005-step-04"></a>
### Step 4: Verify isolation and persistence

Restart the affected service or VM when permitted, re-query state, and check adjacent app/instance/node identities.

**Expected results:**

- Documented state persists, transient state disappears, adjacent identities are unchanged, and no private key, credential, or plaintext sentinel appears in APIs, metrics, dashboards, journals, or artifacts.

<a id="tc-gos-platform-005-step-05"></a>
### Step 5: Audit the booted kernel and shipped GPU userspace

On the primary guest, read `/proc/cmdline` and `/proc/config.gz`; read
`NVIDIA_VERSION` from the candidate `os/mkosi/versions.env` and compare it with
`modinfo -F version nvidia` and the versioned directories under
`/usr/lib/firmware/nvidia`; list `ldconfig -p`; run `ldd` on
`/usr/bin/nvattest`, `/usr/bin/nvidia-smi`, and `/usr/bin/nvidia-container-cli`;
read the TDX scaling switches under `/sys/module/kernel/parameters`, the
`cpuidle_haltpoll` module state, `modprobe --showconfig`, the `nvidia-module-options.service` state,
`nvidia-gpu-detect count-gpus` and `nvidia-gpu-detect nvswitch`, and
`/run/modprobe.d/nvidia-dstack.conf`; and test the rootfs paths listed below.
The assertions are static image content and hold on a guest without a GPU.

**Expected results:**

- `/proc/cmdline` contains `pci=noearly` and does not contain `pci=nommconf`.
- `CONFIG_NET_SCH_HTB=y`, `CONFIG_NET_SCH_INGRESS=y`, `CONFIG_NET_CLS_U32=y`,
  `CONFIG_NET_ACT_POLICE=y`, `CONFIG_CHECKPOINT_RESTORE=y`, `CONFIG_MACVLAN=y`,
  `CONFIG_NETFILTER_XT_MATCH_COMMENT=m`, and `CONFIG_SWIOTLB_DYNAMIC=y`; and
  `CONFIG_TIGON3`, `CONFIG_E1000`, `CONFIG_E1000E`, `CONFIG_R8169`,
  `CONFIG_PCCARD`, `CONFIG_AGP`, `CONFIG_PROVIDE_OHCI1394_DMA_INIT`,
  `CONFIG_EARLY_PRINTK_DBGP`, and `CONFIG_NETCONSOLE` are unset.
- The NVIDIA module version equals the candidate pin, and the pin is the only
  versioned firmware directory.
- The linker cache lists `libnvidia-ml.so.1`, `libnvidia-container.so.1`, and
  `libnvidia-container-go.so.1`; `ldd` reports no `not found` library.
- The modprobe configuration blacklists `nvidia` and `nvidia_drm`;
  `nvidia-module-options.service` is `active`, `success`, and `enabled`; the
  generated file records `gpus=<count> nvswitch=<yes|no>` for the live topology
  and contains exactly the `RmEnableProtectedPcie=0x1` option when an NVSwitch is
  present, exactly `NVreg_NvLinkDisable=1` for one GPU, and no `options` line
  otherwise.
- `/sys/module/kernel/parameters/tdx_wake_q_batch` is `Y`,
  `/sys/module/kernel/parameters/tdx_pv_single_ipi` exists (its value also
  depends on the host advertising PV IPIs), `cpuidle_haltpoll` is not loaded,
  and `modinfo` resolves it as a module.
- `/etc/modules-load.d/nvidia.conf` and `/usr/lib/dstack/kernel-devel` are
  absent, and `/usr/lib/dstack/tdx-guest-tune.sh` is executable.
- Every `*.preset` file under `/usr/lib/systemd/system-preset` and
  `/etc/systemd/system-preset` has `dstack` in its name, and
  `systemd-networkd-wait-online.service` is `enabled`.
- `/usr/lib/tmpfiles.d/dstack-image.conf` is absent, `dstack-firstboot.service`
  is `not-found`, `/var/mail/.dstack-keep` and
  `/var/lib/tpm2-tss/system/keystore/.dstack-keep` are absent,
  `/var/lib/tpm2-tss/system/keystore` has mode `755`, and `/tapp` links to
  `dstack`.

## Post-baseline regression coverage (PR #1156, #1157, #1160, #1173, #1177, #1181, #1182, #1191, #1192, #1220, #1226)

- PR #1156 removes `pci=nommconf` from the measured command line; Step 5 checks
  the command line the guest actually booted with.
- PR #1160, #1182, and #1192 change the guest kernel configuration; Step 5 reads
  the running kernel's configuration. TC-GOS-BUILD-001 audits the full
  fragment and `lxc-checkconfig` gate against the published `bzImage`.
- PR #1157 moves NVIDIA module options from a static line to
  `nvidia-module-options.service` and blacklists udev autoload; PR #1177 pins
  driver 595.91.07; PR #1173 ships `libxmlsec1-openssl` for `nvattest`; PR #1181
  ships `libnvidia-container-go.so.1`; PR #1191 refreshes the linker cache after
  staging. Step 5 checks these on a GPU-less guest. GPU-positive loading is
  covered by TC-GOS-PLATFORM-009 and is hardware-gated.
- PR #1220 adds the TDX wake-queue batching and PV single-IPI switches, builds
  halt polling as an opt-in module, and installs
  `/usr/lib/dstack/tdx-guest-tune.sh`; PR #1226 moves the kernel build tree out
  of the measured rootfs.

## Post-baseline regression coverage (PRs #1321 and #1331)

- PR #1321 deletes every non-dstack preset file at image build time, so a
  distribution preset such as Debian's `90-systemd.preset` cannot shadow the
  terminal `disable *` in `99-dstack-default.preset`, and enables
  `systemd-networkd-wait-online.service`, the unit behind the
  `network-online.target` that `dstack-prepare` waits on.
- PR #1331 applies `rootfs.tmpfiles` once in `mkosi.finalize` instead of
  shipping it in `tmpfiles.d`, where it re-ran against the read-only root on
  every boot, and drops the `dstack-firstboot.service` and `.dstack-keep`
  placeholders. Step 5 checks the booted result.

## Post-baseline regression matrix

For both Yocto and mkosi images, assert the effective SELinux kernel gates plus nftables bridge/CHECKSUM capabilities and shipped modules. Start an Incus-compatible bridge workload, verify rule programming and xtables-lock handling, and fail closed by dropping the WireGuard configuration when rules cannot be applied.

## Postconditions

Remove run-scoped state, undo fault injection, and verify services and devices returned to their recorded baseline.
