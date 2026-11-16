# Core component retest watchlist

This document records review corrections and conditions that must be checked during the next core-component retest. It is a watchlist, not a replacement for the case specifications or result evidence.

## Simulator changes requiring focused retest

### PR #844: FUSE shared-library SONAME compatibility

PR #844 must remain limited to the Nitro NSM CUSE loader.

Retest requirements:

- Verify startup when only `libfuse3.so.4` is installed.
- Verify the compatibility fallback when only `libfuse3.so.3` is installed.
- Verify startup fails with a clear dynamic-library error when neither SONAME is available.
- Confirm the PR does not change TDX configfs handling, mount behavior, Cargo dependencies, or TPM device creation.
- Record the library selected at runtime and the resulting `/dev/nsm` readiness evidence.

### PR #976: TDX configfs without a kernel TSM provider

PR #976 owns the TDX configfs fallback that was removed from #844.

Retest requirements:

- Run in a development guest where configfs is mounted but no kernel TSM provider has registered `/sys/kernel/config/tsm`.
- Confirm creation of `/sys/kernel/config/tsm/report` initially fails with `EPERM` or `EACCES` and triggers the intended tmpfs shadow path.
- Verify the simulator exposes the expected TSM report ABI at the standard path after fallback.
- Verify errors other than `EPERM` or `EACCES` remain fatal.
- Verify a custom simulator mountpoint does not trigger the configfs shadow.
- Check that shadowing `/sys/kernel/config` does not unexpectedly break another configfs consumer in the development guest.
- Confirm mount cleanup and repeated-start behavior; no stale tmpfs/FUSE mount may survive the case lease.
- Confirm `tdx.rs` contains no raw `unsafe` mount or UID/GID operation.

### Rejected PR #845: TPM device-node race tolerance

PR #845 was rejected and must not be included in a candidate build. The original strict behavior on `master` is intentional.

Required invariants:

- The selected simulator platform determines which device ABI is created.
- `dstack-gcp-tdx` creates the GCP vTPM path.
- `dstack-aws-nitro-tpm` creates the Nitro TPM path.
- Non-TPM simulator modes do not create a TPM device.
- A pre-existing `/dev/tpm0` or `/dev/tpmrm0` causes startup to fail.
- Failure of the selected mode's `mknod` operation, including `EEXIST`, remains fatal.
- The simulator must not adopt an existing node based only on path existence.
- Do not add or expect a `create_tpm_device_node` configuration field.

## Cases to rerun

| Case | Focus | Required observations |
|---|---|---|
| `TC-GOS-SETUP-015` | TPM command proxy and lifecycle | Platform-selected creation, strict conflict failure, PCR/quote/random operations, dependency failure, restart, and exact device/process cleanup |
| `TC-GOS-SETUP-017` | Five-platform simulator lifecycle | Correct platform-to-device mapping, GCP and Nitro device ABI readiness, failure isolation, repeated start, and cleanup |
| `TC-GOS-SETUP-022` | vTPM CLI integration | `/dev/tpm0` and `/dev/tpmrm0` usability, quote verification, fault recovery, restart behavior, and cleanup |
| `TC-GOS-SETUP-016` | Nitro NSM request ABI | `.so.4` and `.so.3` CUSE loader coverage, NSM ioctl behavior, malformed requests, and `/dev/nsm` cleanup |
| TDX simulator row in `TC-GOS-SETUP-017` | TSM filesystem fallback | No-provider configfs failure, tmpfs fallback, report generation, repeated start, and mount cleanup |

## Environment controls

- Use the candidate mkosi development image; do not test Yocto or mkosi build correctness as part of these cases.
- Capture the effective `TeeVariant`, simulator configuration, kernel modules, configfs mounts, and device nodes before startup.
- Record whether udev/devtmpfs is running, but do not treat it as authority to change simulator device ownership.
- Remove `/dev/tpm0`, `/dev/tpmrm0`, `/dev/nsm`, simulator FUSE mounts, tmpfs shadows, swtpm processes, and `tpm_vtpm_proxy` state during case cleanup.
- Before each TPM row, prove that no physical or stale TPM node is present.
- Do not suppress a node-creation conflict to make a lifecycle case pass; record the failure and investigate ownership/configuration instead.

## Evidence to retain

For every affected case, retain:

- candidate commit and PR head;
- effective simulator platform and redacted configuration;
- relevant `/sys/class/tpm*` and `/sys/kernel/config/tsm` state;
- device major/minor values and file types;
- mount table entries before, during, and after execution;
- simulator exit status and bounded logs;
- explicit cleanup evidence;
- PASS/FAIL/BLOCKED classification with a one-sentence reason.

## Completion gate

The retest is not complete until all affected cases have fresh candidate evidence and no result relies on the rejected #845 tolerance behavior. Hardware-only limitations remain BLOCKED only when the case genuinely requires unavailable hardware; simulator setup, fixture, script, documentation, or product failures are not environmental blockers.
