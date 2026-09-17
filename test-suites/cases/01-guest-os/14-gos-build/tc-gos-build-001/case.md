<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gos-build-001"></a>
# TC-GOS-BUILD-001: Guest image builder provenance

## Metadata

- Priority: P0
- Type: Functional, Regression, Supply Chain
- Minimum environment: INTEGRATION
- Automation: Yes
- Requirements: [req-gos-build-001](../../../../catalog/feature-audit.md#req-gos-build-001)
- Risks: [risk-gos-build-001](../../../../catalog/feature-audit.md#risk-gos-build-001)
- Source: `os/image/assemble.sh`, `os/mkosi/tests/check-output.sh`,
  `os/image/kernel-cmdline.sh`, `os/mkosi/components/kernel/kernel.config`,
  `os/mkosi/parity.json`, `os/common/scripts/check-kernel-config.sh`,
  `os/common/scripts/check-lxc-kernel-config.sh`,
  `os/spec/artifact-manifest.schema.json`

## Objective

Verify that an assembled candidate guest image records the selected builder,
that the mkosi output contract rejects metadata that does not identify mkosi,
and that the published artifact carries the kernel configuration and command
line its candidate build definition declares.

## Preconditions

1. Provide a protected candidate image store through the `image-assembly` fixture.
2. Record the expected builder in `DSTACK_TEST_GUEST_IMAGE_BUILDER`.

## Test Data

```json
{
  "required_kernel_config": {
    "CONFIG_NET_SCHED": "y", "CONFIG_NET_CLS_ACT": "y",
    "CONFIG_NET_SCH_HTB": "y", "CONFIG_NET_SCH_INGRESS": "y",
    "CONFIG_NET_CLS_U32": "y", "CONFIG_NET_ACT_POLICE": "y",
    "CONFIG_CHECKPOINT_RESTORE": "y", "CONFIG_MACVLAN": "y",
    "CONFIG_NETFILTER_XT_MATCH_COMMENT": "m",
    "CONFIG_SWIOTLB_DYNAMIC": "y",
    "CONFIG_CPU_IDLE_GOV_HALTPOLL": "y", "CONFIG_HALTPOLL_CPUIDLE": "m",
    "CONFIG_IKCONFIG": "y"
  },
  "disabled_kernel_config": [
    "CONFIG_TIGON3", "CONFIG_E100", "CONFIG_E1000", "CONFIG_E1000E",
    "CONFIG_SKY2", "CONFIG_FORCEDETH", "CONFIG_8139TOO", "CONFIG_R8169",
    "CONFIG_NET_TULIP", "CONFIG_PCCARD", "CONFIG_AGP",
    "CONFIG_MACINTOSH_DRIVERS", "CONFIG_NVRAM",
    "CONFIG_PROVIDE_OHCI1394_DMA_INIT", "CONFIG_EARLY_PRINTK_DBGP",
    "CONFIG_NETCONSOLE"
  ],
  "cmdline_required": ["pci=noearly"],
  "cmdline_forbidden": ["pci=nommconf"]
}
```

<a id="tc-gos-build-001-step-01"></a>
### Step 1: Validate the assembly and output-check scripts

Run bounded shell syntax validation on the candidate assembly script and mkosi
output checker.

**Expected results:** Both candidate scripts parse successfully.

<a id="tc-gos-build-001-step-02"></a>
### Step 2: Inspect candidate artifact provenance

Read the fixture-selected candidate image's `metadata.json` and compare its
`builder` field with the expected image builder.

**Expected results:** `builder` is present, non-empty, and equals the selected
backend; a legacy-only `backend` field is not accepted as provenance.

<a id="tc-gos-build-001-step-03"></a>
### Step 3: Verify the mkosi contract

Confirm the candidate mkosi output checker requires `builder` and compares it
with `mkosi` before accepting an artifact.

**Expected results:** The checked-in contract cannot accept output metadata that
omits or misidentifies the builder.

<a id="tc-gos-build-001-step-04"></a>
### Step 4: Audit the configuration embedded in the shipped kernel

Extract the `IKCONFIG` block from the image's `bzImage` (decompress the boot
payload, then the `IKCFG_ST`..`IKCFG_ED` gzip stream). Run the candidate
`os/common/scripts/check-kernel-config.sh` with
`os/mkosi/components/kernel/kernel.config` and
`os/common/scripts/check-lxc-kernel-config.sh` against it, apply every
`required_kernel_config` entry of `os/mkosi/parity.json` with the semantics of
`check-parity.py`, and compare the explicit regression pins listed below.

**Expected results:** A configuration is extracted; both candidate checkers exit
0; every parity entry is present; each pinned option has exactly the listed
value; and every listed unreachable driver is unset or absent.

<a id="tc-gos-build-001-step-05"></a>
### Step 5: Verify the recorded command line and measured bundle boundary

Recompute the command line with the candidate `dstack_kernel_cmdline` from the
`dstack.rootfs_hash` and `dstack.rootfs_size` recorded in `metadata.json`. List
the image directory and `sha256sum.txt`, and read the `artifacts.kernel_devel`
definition from the candidate artifact-manifest schema.

**Expected results:** `metadata.json.cmdline` equals the recomputed value byte
for byte, contains `pci=noearly`, and does not contain `pci=nommconf`; no
`kernel-devel` file is in the image directory or `sha256sum.txt`; the schema
does not require `kernel_devel` and accepts exactly a relative artifact path or
`null` for it.

## Post-baseline regression coverage (PR #1156, #1160, #1182, #1192, #1220, #1226)

- PR #1156: the measured command line re-enables MMCONFIG (`pci=nommconf`
  removed, `pci=noearly` kept) so GPU drivers can read PCIe extended config
  space. Step 5 checks the recorded command line against the candidate
  definition.
- PR #1160: bare-metal NIC, bus, and early-debug drivers unreachable in a CVM
  are disabled. Step 4 checks the shipped kernel, not only the fragment.
- PR #1182: `lxc-checkconfig` now gates the build, and the fragments add the
  traffic-control, checkpoint/restore, MACVLAN, and xt `comment` options Incus
  needs. Step 4 reruns both gates against the shipped kernel.
- PR #1192: `CONFIG_SWIOTLB_DYNAMIC=y` lets the bounce buffer grow at runtime.
- PR #1220: guest halt polling is built as a module so it can be toggled at
  runtime.
- PR #1226: the kernel build tree is published as an optional
  `kernel_devel` artifact outside `sha256sum.txt` and `os_image_hash`. A
  cached hardware-run build does not archive it, so this case checks the
  measured-bundle boundary and the schema; the archive content itself is not
  produced by `prepare-hardware-run.sh`.

## Postconditions

Release the fixture without modifying the protected image store. Retain only
the builder name, candidate revision, boolean checks, and hashes.
