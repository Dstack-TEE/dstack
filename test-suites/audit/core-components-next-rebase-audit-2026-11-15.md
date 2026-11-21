<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# PR 841 next-rebase test audit (2026-11-15)

PR 841 was rebased from `9b87d9f9a6` onto `next` at `aa8805a917` (#1587). The merged PRs in that range were reviewed by merged-PR boundary and mapped to acceptance regressions. #1570 (version bump), #1573 (CI release assets), #1576 (dstack-auth documentation) and #1578 (hono lock bump, run by the auth backend suites) need no case change; #1533 was already in the suite through the #1534 rebase.

## Harnesses repaired by product changes

- #1585 and #1587 moved the KMS and gateway listener settings under `[listeners.*]` and refuse the old locations at startup. The isolated-component KMS and gateway configs, the mkosi KMS fixture, the candidate KMS of the upgrade matrix (released KMS images keep the old sections), `tc-gos-setup-009`, `tc-gw-internal-001` and `tc-gw-internal-002` render or read the new sections. The gateway fixture inserts `app_address_dns_servers` under the `[core.proxy]` header, which a comment in the new `gateway.toml` also names (`tc-gw-proxy-prot-005`).
- #1582 moved the PROXY header reader and its tests into `rocket-proxy-listener` (`tc-gw-proxy-prot-001`), and #1555 moved the TDX lite ACPI tests into `dstack-mr` (`tc-ver-image-meas-003`).
- #1577: a KMS on a webhook auth API pins the onboarding source to the `rootCaPubkey` its auth API reports. The upgrade-policy webhook serves the source's root CA and root epoch for the target's context (`tc-kms-upgrade-008`).
- #1533: a KMS refuses to onboard from a source whose certificate does not carry its OS image hash, which KMS 0.5.8 and older do not. `tc-kms-upgrade-003` now expects that refusal, `tc-kms-upgrade-001` bridges 0.5.4 through 0.5.7 and 0.5.11, `tc-kms-upgrade-005` expects only the 0.5.11 source to succeed, and the old clusters of `tc-kms-upgrade-006`, `-008` to `-012`, `tc-int-compatibil-003` and `tc-int-mixed-002`/`-004` start from 0.5.11. A 0.6.4 guest needs a 0.6.4 KMS, so phases served only by 0.5.11 nodes run 0.5.8 guests (`tc-kms-upgrade-009`, `-010`), `tc-int-compatibil-002` onboards a candidate KMS for its candidate guest, and the matrix encrypts a candidate guest's env with a candidate KMS. The 0.5.11 source caches the target image it verified, so `tc-kms-upgrade-008` checks a retry without the target archive instead of a refusal.
- The physical guest's host share carries `.sealed-env`, since the provider pins the KMS signer (`tc-gos-boot-and-i-003`), and `tc-gos-setup-024` runs `get-keys` with the event log the guest's TEE simulator publishes.

Cases that had not run since changes before this range were repaired too:

- `f697616cfd` made the guest refuse a KMS whose RPC certificate carries no verified attestation; the candidate row of `tc-gos-platform-010` gets its keys from a candidate KMS the case runs in a TDX CVM, and the case keeps the whole VMM info output.
- #1484 reports a request the verifier cannot process as HTTP 500 (`tc-ver-image-meas-002`, `tc-ver-tools-004`).
- The contract matrix expects a 401 for an unknown method only on the scope-gated Worker listener, not on the gateway admin listener (`tc-gw-contract-003`).
- `tc-gos-entry-004` builds its consumer crates against the workspace lockfile; `tc-kms-rotation-014` builds into case-owned Foundry directories instead of cleaning the shared package under parallel cases.

## Focused regression boundaries

- KMS and gateway listeners: #1580 public read-only listener, #1582 PROXY protocol, #1583 KMS audit lines, #1585 KMS `[listeners.*]` (new `tc-kms-kms-007`); #1587 gateway `[listeners.*]`, #1588 admin audit lines, #1589 access lines (new `tc-gw-internal-009`).
- #1577 launch tickets and root CA pinning, #1555 `dstack-mr` lite check and `dstack-verifier-wasm`, #1526 SEV-SNP key provider, and the refusal of old listener settings: product tests in the new `tc-int-forward-017`. Launch-ticket deployment on TDX hardware and SEV-SNP sealing on AMD hardware are not covered.
- #1566 guest hardening (`systemd.gpt_auto=0`, `systemd.import_credentials=no`, no `DMI_SYSFS`, `FW_CFG_SYSFS`, `PSTORE`): `tc-gos-build-001`.
- #1567 TEE platform allowlists and #1577 `Manage.s.sol`: `tc-kms-rotation-014` adds `LegacyAppCompat.t.sol` and `ManageScript.t.sol`. #1568 and #1569 are covered by the contract suites it already ran.

## Product fixes found while validating

- #1590: a simulated TDX guest got the vm_config of a no-TEE guest, so its simulator reported placeholder measurements and the KMS refused its key request (`tc-gos-setup-009`, `tc-gos-attestatio-003`, `tc-gos-boot-and-i-003`, `tc-gos-boot-and-i-004`).
- #1565: `dstack-util get-keys` verified the KMS against the production collateral only (`tc-gos-setup-024`).

## Catalog maintenance

- `api-inventory.json` was regenerated from the protobuf sources while preserving case mappings and hand-written field constraints. It adds the KMS `ReadOnly` service (`tc-kms-kms-007`), the `launch_ticket` fields and the request and response fields added since the last refresh. Methods no case covers yet (`DstackGuest.EmitEvent`, `Vmm.GetSealedEnvPubKey`, `HostApi.UpdateSealedEnv`, `KMS.GetSealedEnvPubKey`, `Onboard.GetSetupStatus`, Gateway `Admin.RotateAcmeCredentials`, `Admin.GetTombstoneGcConfig`, `Admin.SetTombstoneGcConfig` and `Admin.SetInstanceReady`) predate this range and are left out.
- `configuration-inventory.json` moves the KMS and gateway listener keys to `listeners.*` and `insecure_localhost_backend` to `core.proxy`.
- `source-inventory.json` and `source-coverage-map.json` add the new product files: `rocket-proxy-listener`, `load_config/src/listeners.rs`, the KMS `readonly_service.rs`, the gateway `access_log.rs`, `dstack-verifier-wasm`, `TeeVariantPolicy.sol`, the SEV-SNP sealing and setup sources, and the issuer pinning test.

## tdxlab validation

Run `pr841-validate-1115-full-5c5a85f86` on the tdxlab TDX host, 4 workers, with this branch plus #1565 and #1590: 370 PASS, 7 BLOCKED (an NVIDIA confidential-computing GPU is not available), 1 FAIL and 1 ERROR. `tc-int-failure-se-001` (observer listener timeout) and `tc-gos-observabil-002` (host API port taken between reservation and bind) passed rerun alone. `tc-kms-kms-007`, `tc-gw-internal-009` and `tc-int-forward-017` were promoted from that run.
