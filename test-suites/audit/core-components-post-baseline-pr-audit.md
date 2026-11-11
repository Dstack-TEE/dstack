<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Core component post-baseline pull request audit

PR #841 was last fully exercised against `next` at `cb961ad7877b0f2f60abfba73fdcd6dbc11b5c39` with candidate head `c7364e9e84410097ff6fa0952750af697938df0c`. This audit covers first-parent merges through `89fe3184ba46143324e27acf94b762db4e393e6c`.

| PR | Change area | Acceptance coverage after audit |
| --- | --- | --- |
| #837 | Libvirt-filtered VMM networking | `tc-vmm-compute-ne-001`, `tc-vmm-compute-ne-007` |
| #1023 | Pre-launch ordering documentation | Documentation-only; no executable behavior added |
| #1025, #1026 | Branch/CI/repository rename | Repository workflow validation; no runtime case added |
| #1027 | Atomic Gateway refresh failover | `tc-gos-observabil-003`, `tc-gos-setup-009` |
| #1038 | TDX V2 event preimage integrity | `tc-gos-setup-018`, `tc-ver-input-plat-003` |
| #1040 | dstackup CID-window allocation | `tc-vmm-internal-002` |
| #1039 | Simulator vTPM device/state race | `tc-gos-setup-013`, `tc-gos-setup-015` |
| #1034 | Auth-mock dependency update | Existing KMS authorization and build gates |
| #1030 | Named MessagePack encoding | `tc-gos-attestatio-002`, `tc-int-mixed-007` |
| #1036 | Gateway sync authentication and bounds | `tc-gw-cluster-ad-002` |
| #1037 | Gateway Prometheus metrics | `tc-gw-cluster-ad-004`, `tc-gos-observabil-001` |
| #1043 | Guest SELinux parity | `tc-gos-platform-005` |
| #1042 | Guest nftables/netfilter parity | `tc-gos-platform-005`, `tc-gos-observabil-003` |
| #1035 | Gateway KV validation and recovery | `tc-gw-kv-009`, `tc-gw-cluster-ad-001` |
| #1044 | Administrative CVM removal | New `tc-gw-admin-034` |
| #1046 | Rejected-record and node recovery APIs | New `tc-gw-admin-035`, `tc-gw-admin-036` |
| #1048 | GPU secondary-bus-reset sanitization | `tc-vmm-compute-ne-004` |
| #1050, #1052, #1053 | Rust QEMU ACPI generation and profiles | `tc-vmm-compute-ne-007`, `tc-ver-image-meas-003` |
| #1051 | Lite-TDX ACPI verification | `tc-ver-image-meas-003`, `tc-ver-input-plat-003` |
| #1057 | Auth-mock lockfile synchronization | Dependency lock only; KMS authorization and build gates apply |
| #1056 | Lite-TDX ACPI digest generation | `tc-gos-setup-018`, `tc-ver-image-meas-003`, `tc-ver-input-plat-003` |
| #1059 | s2n-quic dependency update | Dependency-only; Gateway build, RPC, proxy, and cluster gates apply |
| #1054 | Streaming `dstack-util` encrypt/decrypt | New `tc-gos-setup-025` |
| #1064 | Explicit netd bridge preparation RPC | `tc-vmm-compute-ne-001`, `tc-vmm-compute-ne-009` |
| #1060 | Multiple Gateway clusters | `tc-gos-setup-009` and multi-cluster Gateway integration cases |
| #1067 | Materialized WaveKV proxy winner | `tc-gw-kv-009`, `tc-gw-cluster-ad-001` |
| #1031 | WaveKV v2 delta-state synchronization | `tc-gw-admin-010`, `tc-gw-cluster-ad-001`, `tc-gw-cluster-ad-002`, `tc-gw-kv-009` |
| #1061 | Netd-managed macvtap networking | `tc-vmm-compute-ne-009` |
| #1068 | Restricted deployment network overrides | `tc-vmm-compute-ne-009` |
| #1069 | Secure netd socket activation | `tc-vmm-compute-ne-009` |
| #1070 | KMS RPC endpoint normalization | Corrected `tc-gos-setup-006` |
| #1071 | SEV-SNP simulator ABI semantics | `tc-gos-setup-014` |
| #1072 | Stable Certbot certificate ordering | Extended `tc-gw-certbot-005` |
| #1073 | Guest image builder provenance | New `tc-gos-build-001` |
| #1074 | Source-local component tests and fixtures | Existing component cases consume the tests and prepared fixture binary; no new runtime behavior |

The three new Gateway Admin methods were absent from the previous API inventory and were the only newly merged public RPC surface without a dedicated case. This branch adds their complete API inventory, case specifications, deterministic authenticated smoke coverage, and recovery matrices. Existing cases are tightened below for the non-RPC regression surfaces.

The audit also refreshes deterministic harness expectations invalidated by the
merged source changes: the renamed TDX simulator atomicity test, the renamed
lite-TDX verifier test, the expanded verifier and RA-TLS unit-test totals, and
the QEMU 10 RTMR0 delta and supported hugepage/NUMA row introduced by the new
ACPI generator.
