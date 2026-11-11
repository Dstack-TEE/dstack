<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# PR 841 next-rebase test audit (2026-09-17)

PR 841 was rebased from `afbafb90aa` onto `next` at `e2cf39ae01`. The 82 first-parent changes in that range were reviewed by merged-PR boundary and mapped to acceptance regressions. Documentation-only, CI-only, release-bump and dependency-bump changes (#1135, #1142, #1143, #1150, #1153, #1168, #1169, #1172, #1195–#1197, #1201, #1202, #1206, #1210, #1212, #1216, #1222–#1224, and the 0.6.0-rc2 bump and revert) remain covered by existing build and lint gates.

## Harnesses repaired by product changes

- #1148 removed `insecure_skip_attestation`: the isolated-component Gateway fixture, `tc-gw-internal-001`, and `tc-gos-setup-009` no longer write or read the key, and `Gateway.GetPeers` is now called with the fixture client certificate.
- #1161 changed the default VMM GPU listing layout (`tc-vmm-configurat-001`), #1200 renamed the TDX auto-variant unit test (`tc-vmm-tdxvariant-005`), and #1214/#1217 made bridge networking depend on `dstack-vmm netd` (`tc-vmm-compute-ne-001`).
- The guest-agent GPU telemetry series added `gpu_info` to the dashboard model, which broke the `tc-gos-entry-003` model program.

## Focused regression boundaries

- Certbot and Gateway certificates: #1132 (DNS-PERSIST-01 records, challenge selection and validation), #1136 (per-name stale TXT cleanup), #1137 (SAN reissue), #1138 (shared ACME lock), #1147 (app-id client certificates for sync), and #1198 (signal handling during startup) in `tc-gw-certbot-001`, `tc-gw-certbot-006`, `tc-gw-certificat-001`, `tc-gw-certificat-004`, and `tc-gw-cluster-ad-002`.
- Build images: #1190 OCI metadata and #1211 apt error mode in `tc-kms-build-001`.
- VMM: #1145 vhost and multiqueue validation, #1161 GPU listing, #1163 size units, #1179 CLI discovery, #1193 status filter, #1204 per-start QEMU version detection, #1213 port-mapping NIC pins, #1214/#1217 netd lifecycle, #1065 GPU reset, and the `ProxiedGuestApi.GpuInfo` proxy in `tc-vmm-vmm-001`, `tc-vmm-vmm-015`, `tc-vmm-configurat-001`, `tc-vmm-compute-ne-001`, `tc-vmm-compute-ne-002`, `tc-vmm-compute-ne-007`, `tc-vmm-ui-observa-001`, `tc-vmm-ui-observa-005`, and `tc-vmm-manifest-001`. The source installer fix #1162 is covered by the new `tc-vmm-install-007`.
- Guest agent: `GuestApi.GpuInfo` (new `tc-gos-guestapi-006`), the `dstack-util gpu-info` collector (new `tc-gos-setup-026`), dashboard and metrics rendering (`tc-gos-entry-003`, `tc-gos-observabil-001`), #1175 data-disk discard (`tc-gos-setup-007`, `tc-gos-setup-008`), and #1207 MessagePack v1 attestations (`tc-gos-dstackguest-001`, `tc-gos-dstackguest-004`).
- Measurement and verifier: #1189 kernel setup-header normalization and #1199 command-line suffix composition in the dstack-mr matrix (`tc-ver-tools-001`, `tc-ver-tools-002`) and verifier input cases (`tc-ver-input-plat-004`, `tc-ver-cli-cert-o-006`, `tc-ver-strategy-006`); #1207 verifier equivalence in `tc-ver-tools-003` and `tc-ver-cli-cert-o-002`.
- Guest image: #1156, #1160, #1182, #1192, and #1220 kernel command line and configuration in `tc-gos-build-001` and `tc-gos-platform-005`; #1158 vendor drop-in locations in `tc-gos-platform-006`; #1157, #1173, #1177, #1181, and #1191 NVIDIA userspace, module options, and linker cache in `tc-gos-platform-005`; #1226 kernel-devel artifact boundaries in `tc-gos-build-001`. GPU-positive behavior for #1157 and #1194 is hardware-gated in `tc-gos-platform-009`; Yocto-only #1166, #1215, and #1225 are recorded against the Yocto cases, which are blocked without Yocto images.

## Catalog maintenance

- `api-inventory.json` was regenerated from the protobuf sources while preserving hand-written field constraints. It adds `GuestApi.GpuInfo` and `ProxiedGuestApi.GpuInfo`, and refreshes changed request, response, and schema fields for the VMM, Gateway, and guest services.
- `configuration-inventory.json` drops `core.debug.insecure_skip_attestation` and adds `cvm.max_net_queues` and `cvm.networking.vhost`.
- `source-inventory.json` and `source-coverage-map.json` add the new product files, follow renamed NVIDIA and test-fixture paths, and remove deleted files.
- Pre-existing gaps not introduced in this range: `DstackGuest.EmitEvent`, `Admin.RotateAcmeCredentials`, `Admin.GetTombstoneGcConfig`, `Admin.SetTombstoneGcConfig`, and `Admin.SetInstanceReady` still have no RPC inventory row.

## Product findings

- `dstack/scripts/install.sh` assigns its temporary checkout inside a command-substitution subshell, so the exit trap never removes it. `tc-vmm-install-007` records the leak without failing until the script is fixed.
