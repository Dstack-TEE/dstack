<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="core-feature-audit"></a>
# Core Component Feature and Risk Audit

This audit is derived from the repository source inventory and is the traceability authority for the full test plan. Each requirement and risk maps to exactly one indexed case.

<a id="audit-chapter-guest-os"></a>
## Guest OS

<a id="audit-section-guest-os-rpc-tappd"></a>
### Tappd RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-tappd-001"></a><a id="risk-gos-tappd-001"></a>| `req-gos-tappd-001` | `risk-gos-tappd-001` | [tc-gos-tappd-001](01-guest-os/01-rpc-tappd/tc-gos-tappd-001/case.md#tc-gos-tappd-001) — Tappd.DeriveKey | P1 |
<a id="req-gos-tappd-002"></a><a id="risk-gos-tappd-002"></a>| `req-gos-tappd-002` | `risk-gos-tappd-002` | [tc-gos-tappd-002](01-guest-os/01-rpc-tappd/tc-gos-tappd-002/case.md#tc-gos-tappd-002) — Tappd.DeriveK256Key | P1 |
<a id="req-gos-tappd-003"></a><a id="risk-gos-tappd-003"></a>| `req-gos-tappd-003` | `risk-gos-tappd-003` | [tc-gos-tappd-003](01-guest-os/01-rpc-tappd/tc-gos-tappd-003/case.md#tc-gos-tappd-003) — Tappd.TdxQuote | P1 |
<a id="req-gos-tappd-004"></a><a id="risk-gos-tappd-004"></a>| `req-gos-tappd-004` | `risk-gos-tappd-004` | [tc-gos-tappd-004](01-guest-os/01-rpc-tappd/tc-gos-tappd-004/case.md#tc-gos-tappd-004) — Tappd.RawQuote | P1 |
<a id="req-gos-tappd-005"></a><a id="risk-gos-tappd-005"></a>| `req-gos-tappd-005` | `risk-gos-tappd-005` | [tc-gos-tappd-005](01-guest-os/01-rpc-tappd/tc-gos-tappd-005/case.md#tc-gos-tappd-005) — Tappd.Info | P1 |
<a id="req-gos-tappd-006"></a><a id="risk-gos-tappd-006"></a>| `req-gos-tappd-006` | `risk-gos-tappd-006` | [tc-gos-tappd-006](01-guest-os/01-rpc-tappd/tc-gos-tappd-006/case.md#tc-gos-tappd-006) — Tappd.Version | P1 |

<a id="audit-section-guest-os-rpc-dstackguest"></a>
### DstackGuest RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-dstackguest-001"></a><a id="risk-gos-dstackguest-001"></a>| `req-gos-dstackguest-001` | `risk-gos-dstackguest-001` | [tc-gos-dstackguest-001](01-guest-os/02-rpc-dstackguest/tc-gos-dstackguest-001/case.md#tc-gos-dstackguest-001) — DstackGuest.GetTlsKey | P1 |
<a id="req-gos-dstackguest-002"></a><a id="risk-gos-dstackguest-002"></a>| `req-gos-dstackguest-002` | `risk-gos-dstackguest-002` | [tc-gos-dstackguest-002](01-guest-os/02-rpc-dstackguest/tc-gos-dstackguest-002/case.md#tc-gos-dstackguest-002) — DstackGuest.GetKey | P1 |
<a id="req-gos-dstackguest-003"></a><a id="risk-gos-dstackguest-003"></a>| `req-gos-dstackguest-003` | `risk-gos-dstackguest-003` | [tc-gos-dstackguest-003](01-guest-os/02-rpc-dstackguest/tc-gos-dstackguest-003/case.md#tc-gos-dstackguest-003) — DstackGuest.GetQuote | P0 |
<a id="req-gos-dstackguest-004"></a><a id="risk-gos-dstackguest-004"></a>| `req-gos-dstackguest-004` | `risk-gos-dstackguest-004` | [tc-gos-dstackguest-004](01-guest-os/02-rpc-dstackguest/tc-gos-dstackguest-004/case.md#tc-gos-dstackguest-004) — DstackGuest.Attest | P0 |
<a id="req-gos-dstackguest-005"></a><a id="risk-gos-dstackguest-005"></a>| `req-gos-dstackguest-005` | `risk-gos-dstackguest-005` | [tc-gos-dstackguest-005](01-guest-os/02-rpc-dstackguest/tc-gos-dstackguest-005/case.md#tc-gos-dstackguest-005) — DstackGuest.Info | P1 |
<a id="req-gos-dstackguest-006"></a><a id="risk-gos-dstackguest-006"></a>| `req-gos-dstackguest-006` | `risk-gos-dstackguest-006` | [tc-gos-dstackguest-006](01-guest-os/02-rpc-dstackguest/tc-gos-dstackguest-006/case.md#tc-gos-dstackguest-006) — DstackGuest.GpuInfo | P1 |
<a id="req-gos-dstackguest-007"></a><a id="risk-gos-dstackguest-007"></a>| `req-gos-dstackguest-007` | `risk-gos-dstackguest-007` | [tc-gos-dstackguest-007](01-guest-os/02-rpc-dstackguest/tc-gos-dstackguest-007/case.md#tc-gos-dstackguest-007) — DstackGuest.Sign | P1 |
<a id="req-gos-dstackguest-008"></a><a id="risk-gos-dstackguest-008"></a>| `req-gos-dstackguest-008` | `risk-gos-dstackguest-008` | [tc-gos-dstackguest-008](01-guest-os/02-rpc-dstackguest/tc-gos-dstackguest-008/case.md#tc-gos-dstackguest-008) — DstackGuest.Verify | P1 |
<a id="req-gos-dstackguest-009"></a><a id="risk-gos-dstackguest-009"></a>| `req-gos-dstackguest-009` | `risk-gos-dstackguest-009` | [tc-gos-dstackguest-009](01-guest-os/02-rpc-dstackguest/tc-gos-dstackguest-009/case.md#tc-gos-dstackguest-009) — DstackGuest.Version | P1 |

<a id="audit-section-guest-os-rpc-worker"></a>
### Worker RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-worker-001"></a><a id="risk-gos-worker-001"></a>| `req-gos-worker-001` | `risk-gos-worker-001` | [tc-gos-worker-001](01-guest-os/03-rpc-worker/tc-gos-worker-001/case.md#tc-gos-worker-001) — Worker.Info | P1 |
<a id="req-gos-worker-002"></a><a id="risk-gos-worker-002"></a>| `req-gos-worker-002` | `risk-gos-worker-002` | [tc-gos-worker-002](01-guest-os/03-rpc-worker/tc-gos-worker-002/case.md#tc-gos-worker-002) — Worker.Version | P1 |
<a id="req-gos-worker-003"></a><a id="risk-gos-worker-003"></a>| `req-gos-worker-003` | `risk-gos-worker-003` | [tc-gos-worker-003](01-guest-os/03-rpc-worker/tc-gos-worker-003/case.md#tc-gos-worker-003) — Worker.GetAttestationForAppKey | P1 |

<a id="audit-section-guest-os-rpc-guestapi"></a>
### GuestApi RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-guestapi-001"></a><a id="risk-gos-guestapi-001"></a>| `req-gos-guestapi-001` | `risk-gos-guestapi-001` | [tc-gos-guestapi-001](01-guest-os/04-rpc-guestapi/tc-gos-guestapi-001/case.md#tc-gos-guestapi-001) — GuestApi.Info | P1 |
<a id="req-gos-guestapi-002"></a><a id="risk-gos-guestapi-002"></a>| `req-gos-guestapi-002` | `risk-gos-guestapi-002` | [tc-gos-guestapi-002](01-guest-os/04-rpc-guestapi/tc-gos-guestapi-002/case.md#tc-gos-guestapi-002) — GuestApi.SysInfo | P1 |
<a id="req-gos-guestapi-003"></a><a id="risk-gos-guestapi-003"></a>| `req-gos-guestapi-003` | `risk-gos-guestapi-003` | [tc-gos-guestapi-003](01-guest-os/04-rpc-guestapi/tc-gos-guestapi-003/case.md#tc-gos-guestapi-003) — GuestApi.NetworkInfo | P1 |
<a id="req-gos-guestapi-004"></a><a id="risk-gos-guestapi-004"></a>| `req-gos-guestapi-004` | `risk-gos-guestapi-004` | [tc-gos-guestapi-004](01-guest-os/04-rpc-guestapi/tc-gos-guestapi-004/case.md#tc-gos-guestapi-004) — GuestApi.ListContainers | P1 |
<a id="req-gos-guestapi-005"></a><a id="risk-gos-guestapi-005"></a>| `req-gos-guestapi-005` | `risk-gos-guestapi-005` | [tc-gos-guestapi-005](01-guest-os/04-rpc-guestapi/tc-gos-guestapi-005/case.md#tc-gos-guestapi-005) — GuestApi.Shutdown | P1 |

<a id="audit-section-guest-os-rpc-proxiedguestapi"></a>
### ProxiedGuestApi RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-proxiedguestapi-001"></a><a id="risk-gos-proxiedguestapi-001"></a>| `req-gos-proxiedguestapi-001` | `risk-gos-proxiedguestapi-001` | [tc-gos-proxiedguestapi-001](01-guest-os/05-rpc-proxiedguestapi/tc-gos-proxiedguestapi-001/case.md#tc-gos-proxiedguestapi-001) — ProxiedGuestApi.Info | P1 |
<a id="req-gos-proxiedguestapi-002"></a><a id="risk-gos-proxiedguestapi-002"></a>| `req-gos-proxiedguestapi-002` | `risk-gos-proxiedguestapi-002` | [tc-gos-proxiedguestapi-002](01-guest-os/05-rpc-proxiedguestapi/tc-gos-proxiedguestapi-002/case.md#tc-gos-proxiedguestapi-002) — ProxiedGuestApi.SysInfo | P1 |
<a id="req-gos-proxiedguestapi-003"></a><a id="risk-gos-proxiedguestapi-003"></a>| `req-gos-proxiedguestapi-003` | `risk-gos-proxiedguestapi-003` | [tc-gos-proxiedguestapi-003](01-guest-os/05-rpc-proxiedguestapi/tc-gos-proxiedguestapi-003/case.md#tc-gos-proxiedguestapi-003) — ProxiedGuestApi.NetworkInfo | P1 |
<a id="req-gos-proxiedguestapi-004"></a><a id="risk-gos-proxiedguestapi-004"></a>| `req-gos-proxiedguestapi-004` | `risk-gos-proxiedguestapi-004` | [tc-gos-proxiedguestapi-004](01-guest-os/05-rpc-proxiedguestapi/tc-gos-proxiedguestapi-004/case.md#tc-gos-proxiedguestapi-004) — ProxiedGuestApi.ListContainers | P1 |
<a id="req-gos-proxiedguestapi-005"></a><a id="risk-gos-proxiedguestapi-005"></a>| `req-gos-proxiedguestapi-005` | `risk-gos-proxiedguestapi-005` | [tc-gos-proxiedguestapi-005](01-guest-os/05-rpc-proxiedguestapi/tc-gos-proxiedguestapi-005/case.md#tc-gos-proxiedguestapi-005) — ProxiedGuestApi.Shutdown | P1 |

<a id="audit-section-guest-os-boot-and-identity"></a>
### Boot And Identity

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-boot-and-i-001"></a><a id="risk-gos-boot-and-i-001"></a>| `req-gos-boot-and-i-001` | `risk-gos-boot-and-i-001` | [tc-gos-boot-and-i-001](01-guest-os/06-boot-and-identity/tc-gos-boot-and-i-001/case.md#tc-gos-boot-and-i-001) — Measured boot and prepare ordering | P0 |
<a id="req-gos-boot-and-i-002"></a><a id="risk-gos-boot-and-i-002"></a>| `req-gos-boot-and-i-002` | `risk-gos-boot-and-i-002` | [tc-gos-boot-and-i-002](01-guest-os/06-boot-and-identity/tc-gos-boot-and-i-002/case.md#tc-gos-boot-and-i-002) — No-TEE simulator early host share | P1 |
<a id="req-gos-boot-and-i-003"></a><a id="risk-gos-boot-and-i-003"></a>| `req-gos-boot-and-i-003` | `risk-gos-boot-and-i-003` | [tc-gos-boot-and-i-003](01-guest-os/06-boot-and-identity/tc-gos-boot-and-i-003/case.md#tc-gos-boot-and-i-003) — System and user configuration materialization | P1 |
<a id="req-gos-boot-and-i-004"></a><a id="risk-gos-boot-and-i-004"></a>| `req-gos-boot-and-i-004` | `risk-gos-boot-and-i-004` | [tc-gos-boot-and-i-004](01-guest-os/06-boot-and-identity/tc-gos-boot-and-i-004/case.md#tc-gos-boot-and-i-004) — Stable app, instance, device, and compose identity | P0 |
<a id="req-gos-boot-and-i-005"></a><a id="risk-gos-boot-and-i-005"></a>| `req-gos-boot-and-i-005` | `risk-gos-boot-and-i-005` | [tc-gos-boot-and-i-005](01-guest-os/06-boot-and-identity/tc-gos-boot-and-i-005/case.md#tc-gos-boot-and-i-005) — Host notification boot and shutdown events | P1 |

<a id="audit-section-guest-os-storage-and-containers"></a>
### Storage And Containers

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-storage-an-001"></a><a id="risk-gos-storage-an-001"></a>| `req-gos-storage-an-001` | `risk-gos-storage-an-001` | [tc-gos-storage-an-001](01-guest-os/07-storage-and-containers/tc-gos-storage-an-001/case.md#tc-gos-storage-an-001) — Encrypted root/data volume provisioning | P0 |
<a id="req-gos-storage-an-002"></a><a id="risk-gos-storage-an-002"></a>| `req-gos-storage-an-002` | `risk-gos-storage-an-002` | [tc-gos-storage-an-002](01-guest-os/07-storage-and-containers/tc-gos-storage-an-002/case.md#tc-gos-storage-an-002) — Ephemeral Docker storage lifecycle | P1 |
<a id="req-gos-storage-an-003"></a><a id="risk-gos-storage-an-003"></a>| `req-gos-storage-an-003` | `risk-gos-storage-an-003` | [tc-gos-storage-an-003](01-guest-os/07-storage-and-containers/tc-gos-storage-an-003/case.md#tc-gos-storage-an-003) — Compose validation and startup | P1 |
<a id="req-gos-storage-an-004"></a><a id="risk-gos-storage-an-004"></a>| `req-gos-storage-an-004` | `risk-gos-storage-an-004` | [tc-gos-storage-an-004](01-guest-os/07-storage-and-containers/tc-gos-storage-an-004/case.md#tc-gos-storage-an-004) — Supervisor lifecycle and restart policy | P1 |
<a id="req-gos-storage-an-005"></a><a id="risk-gos-storage-an-005"></a>| `req-gos-storage-an-005` | `risk-gos-storage-an-005` | [tc-gos-storage-an-005](01-guest-os/07-storage-and-containers/tc-gos-storage-an-005/case.md#tc-gos-storage-an-005) — Volume encryption and persistence semantics | P0 |
<a id="req-gos-compose-006"></a><a id="risk-gos-compose-006"></a>| `req-gos-compose-006` | `risk-gos-compose-006` | [tc-gos-compose-006](01-guest-os/07-storage-and-containers/tc-gos-compose-006/case.md#tc-gos-compose-006) — App manifest version feature and launch-requirement policy | P0 |

<a id="audit-section-guest-os-attestation-and-crypto"></a>
### Attestation And Crypto

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-attestatio-001"></a><a id="risk-gos-attestatio-001"></a>| `req-gos-attestatio-001` | `risk-gos-attestatio-001` | [tc-gos-attestatio-001](01-guest-os/08-attestation-and-crypto/tc-gos-attestatio-001/case.md#tc-gos-attestatio-001) — Quote report-data binding and hash algorithms | P0 |
<a id="req-gos-attestatio-002"></a><a id="risk-gos-attestatio-002"></a>| `req-gos-attestatio-002` | `risk-gos-attestatio-002` | [tc-gos-attestatio-002](01-guest-os/08-attestation-and-crypto/tc-gos-attestatio-002/case.md#tc-gos-attestatio-002) — Cross-platform versioned attestation | P0 |
<a id="req-gos-attestatio-003"></a><a id="risk-gos-attestatio-003"></a>| `req-gos-attestatio-003` | `risk-gos-attestatio-003` | [tc-gos-attestatio-003](01-guest-os/08-attestation-and-crypto/tc-gos-attestatio-003/case.md#tc-gos-attestatio-003) — Deterministic key derivation and purpose separation | P1 |
<a id="req-gos-attestatio-004"></a><a id="risk-gos-attestatio-004"></a>| `req-gos-attestatio-004` | `risk-gos-attestatio-004` | [tc-gos-attestatio-004](01-guest-os/08-attestation-and-crypto/tc-gos-attestatio-004/case.md#tc-gos-attestatio-004) — TLS key and certificate usage extensions | P0 |
<a id="req-gos-attestatio-005"></a><a id="risk-gos-attestatio-005"></a>| `req-gos-attestatio-005` | `risk-gos-attestatio-005` | [tc-gos-attestatio-005](01-guest-os/08-attestation-and-crypto/tc-gos-attestatio-005/case.md#tc-gos-attestatio-005) — Signing verification and negative inputs | P1 |
<a id="req-gos-attestatio-006"></a><a id="risk-gos-attestatio-006"></a>| `req-gos-attestatio-006` | `risk-gos-attestatio-006` | [tc-gos-attestatio-006](01-guest-os/08-attestation-and-crypto/tc-gos-attestatio-006/case.md#tc-gos-attestatio-006) — GPU boot attestation exposure | P0 |
<a id="req-gos-gpupolicy-007"></a><a id="risk-gos-gpupolicy-007"></a>| `req-gos-gpupolicy-007` | `risk-gos-gpupolicy-007` | [tc-gos-gpupolicy-007](01-guest-os/08-attestation-and-crypto/tc-gos-gpupolicy-007/case.md#tc-gos-gpupolicy-007) — GPU attestation proxy nonce claim and Rego policy enforcement | P0 |

<a id="audit-section-guest-os-observability-and-network"></a>
### Observability And Network

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-observabil-001"></a><a id="risk-gos-observabil-001"></a>| `req-gos-observabil-001` | `risk-gos-observabil-001` | [tc-gos-observabil-001](01-guest-os/09-observability-and-network/tc-gos-observabil-001/case.md#tc-gos-observabil-001) — Dashboard metrics and container log filtering | P1 |
<a id="req-gos-observabil-002"></a><a id="risk-gos-observabil-002"></a>| `req-gos-observabil-002` | `risk-gos-observabil-002` | [tc-gos-observabil-002](01-guest-os/09-observability-and-network/tc-gos-observabil-002/case.md#tc-gos-observabil-002) — Socket activation and listener isolation | P1 |
<a id="req-gos-observabil-003"></a><a id="risk-gos-observabil-003"></a>| `req-gos-observabil-003` | `risk-gos-observabil-003` | [tc-gos-observabil-003](01-guest-os/09-observability-and-network/tc-gos-observabil-003/case.md#tc-gos-observabil-003) — WireGuard configuration and checker recovery | P1 |
<a id="req-gos-observabil-004"></a><a id="risk-gos-observabil-004"></a>| `req-gos-observabil-004` | `risk-gos-observabil-004` | [tc-gos-observabil-004](01-guest-os/09-observability-and-network/tc-gos-observabil-004/case.md#tc-gos-observabil-004) — System network and resource telemetry | P1 |
<a id="req-gos-observabil-005"></a><a id="risk-gos-observabil-005"></a>| `req-gos-observabil-005` | `risk-gos-observabil-005` | [tc-gos-observabil-005](01-guest-os/09-observability-and-network/tc-gos-observabil-005/case.md#tc-gos-observabil-005) — Guest-agent watchdog recovery | P1 |

<a id="audit-section-guest-os-platform-services"></a>
### Platform Services and Image Integrity

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-platform-001"></a><a id="risk-gos-platform-001"></a>| `req-gos-platform-001` | `risk-gos-platform-001` | [tc-gos-platform-001](01-guest-os/10-platform-services/tc-gos-platform-001/case.md#tc-gos-platform-001) — Local key provider PCCS selection and collateral lifecycle | P0 |
<a id="req-gos-platform-002"></a><a id="risk-gos-platform-002"></a>| `req-gos-platform-002` | `risk-gos-platform-002` | [tc-gos-platform-002](01-guest-os/10-platform-services/tc-gos-platform-002/case.md#tc-gos-platform-002) — Local key provider sealing and identity isolation | P0 |
<a id="req-gos-platform-003"></a><a id="risk-gos-platform-003"></a>| `req-gos-platform-003` | `risk-gos-platform-003` | [tc-gos-platform-003](01-guest-os/10-platform-services/tc-gos-platform-003/case.md#tc-gos-platform-003) — Host-shared mount and unmount command | P1 |
<a id="req-gos-platform-005"></a><a id="risk-gos-platform-005"></a>| `req-gos-platform-005` | `risk-gos-platform-005` | [tc-gos-platform-005](01-guest-os/10-platform-services/tc-gos-platform-005/case.md#tc-gos-platform-005) — Guest kernel and userspace hardening | P0 |
<a id="req-gos-platform-006"></a><a id="risk-gos-platform-006"></a>| `req-gos-platform-006` | `risk-gos-platform-006` | [tc-gos-platform-006](01-guest-os/10-platform-services/tc-gos-platform-006/case.md#tc-gos-platform-006) — Systemd dependency and failure-action graph | P0 |
<a id="req-gos-platform-007"></a><a id="risk-gos-platform-007"></a>| `req-gos-platform-007` | `risk-gos-platform-007` | [tc-gos-platform-007](01-guest-os/10-platform-services/tc-gos-platform-007/case.md#tc-gos-platform-007) — Journal persistence rotation and redaction | P1 |
<a id="req-gos-platform-008"></a><a id="risk-gos-platform-008"></a>| `req-gos-platform-008` | `risk-gos-platform-008` | [tc-gos-platform-008](01-guest-os/10-platform-services/tc-gos-platform-008/case.md#tc-gos-platform-008) — Docker daemon and container privilege boundary | P0 |
<a id="req-gos-platform-009"></a><a id="risk-gos-platform-009"></a>| `req-gos-platform-009` | `risk-gos-platform-009` | [tc-gos-platform-009](01-guest-os/10-platform-services/tc-gos-platform-009/case.md#tc-gos-platform-009) — NVIDIA device initialization and attestation failure | P0 |
<a id="req-gos-platform-010"></a><a id="risk-gos-platform-010"></a>| `req-gos-platform-010` | `risk-gos-platform-010` | [tc-gos-platform-010](01-guest-os/10-platform-services/tc-gos-platform-010/case.md#tc-gos-platform-010) — Guest configuration backward and forward compatibility | P0 |

<a id="audit-section-guest-os-configuration-entry-models"></a>
### Configuration, Entry Points, and Presentation Models

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-entry-001"></a><a id="risk-gos-entry-001"></a>| `req-gos-entry-001` | `risk-gos-entry-001` | [tc-gos-entry-001](01-guest-os/11-configuration-entry-models/tc-gos-entry-001/case.md#tc-gos-entry-001) — Guest-agent configuration precedence and compose deserialization | P0 |
<a id="req-gos-entry-002"></a><a id="risk-gos-entry-002"></a>| `req-gos-entry-002` | `risk-gos-entry-002` | [tc-gos-entry-002](01-guest-os/11-configuration-entry-models/tc-gos-entry-002/case.md#tc-gos-entry-002) — Guest-agent startup modes and partial listener failure | P0 |
<a id="req-gos-entry-003"></a><a id="risk-gos-entry-003"></a>| `req-gos-entry-003` | `risk-gos-entry-003` | [tc-gos-entry-003](01-guest-os/11-configuration-entry-models/tc-gos-entry-003/case.md#tc-gos-entry-003) — Dashboard and metrics model escaping and units | P1 |
<a id="req-gos-entry-004"></a><a id="risk-gos-entry-004"></a>| `req-gos-entry-004` | `risk-gos-entry-004` | [tc-gos-entry-004](01-guest-os/11-configuration-entry-models/tc-gos-entry-004/case.md#tc-gos-entry-004) — Guest-agent library initialization reuse | P1 |

<a id="audit-section-guest-os-setup-utilities-simulator"></a>
### System Setup Utilities and TEE Simulator

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-setup-001"></a><a id="risk-gos-setup-001"></a>| `req-gos-setup-001` | `risk-gos-setup-001` | [tc-gos-setup-001](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-001/case.md#tc-gos-setup-001) — Environment JSON allowlist parsing | P0 |
<a id="req-gos-setup-002"></a><a id="risk-gos-setup-002"></a>| `req-gos-setup-002` | `risk-gos-setup-002` | [tc-gos-setup-002](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-002/case.md#tc-gos-setup-002) — Encrypted environment ECDH decryption | P0 |
<a id="req-gos-setup-003"></a><a id="risk-gos-setup-003"></a>| `req-gos-setup-003` | `risk-gos-setup-003` | [tc-gos-setup-003](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-003/case.md#tc-gos-setup-003) — Compose inspection and orphan removal | P1 |
<a id="req-gos-setup-004"></a><a id="risk-gos-setup-004"></a>| `req-gos-setup-004` | `risk-gos-setup-004` | [tc-gos-setup-004](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-004/case.md#tc-gos-setup-004) — Staged system setup idempotence and config identity | P0 |
<a id="req-gos-setup-005"></a><a id="risk-gos-setup-005"></a>| `req-gos-setup-005` | `risk-gos-setup-005` | [tc-gos-setup-005](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-005/case.md#tc-gos-setup-005) — MR config ID verification before provisioning | P0 |
<a id="req-gos-setup-006"></a><a id="risk-gos-setup-006"></a>| `req-gos-setup-006` | `risk-gos-setup-006` | [tc-gos-setup-006](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-006/case.md#tc-gos-setup-006) — KMS URL selection failover and local-provider orthogonality | P0 |
<a id="req-gos-setup-007"></a><a id="risk-gos-setup-007"></a>| `req-gos-setup-007` | `risk-gos-setup-007` | [tc-gos-setup-007](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-007/case.md#tc-gos-setup-007) — Data disk encryption filesystem repair and mount | P0 |
<a id="req-gos-setup-008"></a><a id="risk-gos-setup-008"></a>| `req-gos-setup-008` | `risk-gos-setup-008` | [tc-gos-setup-008](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-008/case.md#tc-gos-setup-008) — Swap file and ZFS zvol setup | P1 |
<a id="req-gos-setup-009"></a><a id="risk-gos-setup-009"></a>| `req-gos-setup-009` | `risk-gos-setup-009` | [tc-gos-setup-009](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-009/case.md#tc-gos-setup-009) — Gateway registration refresh and key-store persistence | P0 |
<a id="req-gos-setup-010"></a><a id="risk-gos-setup-010"></a>| `req-gos-setup-010` | `risk-gos-setup-010` | [tc-gos-setup-010](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-010/case.md#tc-gos-setup-010) — Host API notify and sealing-key client | P0 |
<a id="req-gos-setup-011"></a><a id="risk-gos-setup-011"></a>| `req-gos-setup-011` | `risk-gos-setup-011` | [tc-gos-setup-011](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-011/case.md#tc-gos-setup-011) — GPU measurement in system setup | P0 |
<a id="req-gos-setup-012"></a><a id="risk-gos-setup-012"></a>| `req-gos-setup-012` | `risk-gos-setup-012` | [tc-gos-setup-012](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-012/case.md#tc-gos-setup-012) — Supervisor client full API lifecycle | P1 |
<a id="req-gos-setup-013"></a><a id="risk-gos-setup-013"></a>| `req-gos-setup-013` | `risk-gos-setup-013` | [tc-gos-setup-013](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-013/case.md#tc-gos-setup-013) — TDX simulator device ABI | P0 |
<a id="req-gos-setup-014"></a><a id="risk-gos-setup-014"></a>| `req-gos-setup-014` | `risk-gos-setup-014` | [tc-gos-setup-014](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-014/case.md#tc-gos-setup-014) — SEV-SNP simulator device ABI | P0 |
<a id="req-gos-setup-015"></a><a id="risk-gos-setup-015"></a>| `req-gos-setup-015` | `risk-gos-setup-015` | [tc-gos-setup-015](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-015/case.md#tc-gos-setup-015) — TPM simulator command proxy and lifecycle | P0 |
<a id="req-gos-setup-016"></a><a id="risk-gos-setup-016"></a>| `req-gos-setup-016` | `risk-gos-setup-016` | [tc-gos-setup-016](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-016/case.md#tc-gos-setup-016) — Nitro NSM simulator request ABI | P0 |
<a id="req-gos-setup-017"></a><a id="risk-gos-setup-017"></a>| `req-gos-setup-017` | `risk-gos-setup-017` | [tc-gos-setup-017](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-017/case.md#tc-gos-setup-017) — Simulator platform selection config and mount safety | P0 |
<a id="req-gos-setup-018"></a><a id="risk-gos-setup-018"></a>| `req-gos-setup-018` | `risk-gos-setup-018` | [tc-gos-setup-018](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-018/case.md#tc-gos-setup-018) — TDX event-log extend show and replay CLI | P0 |
<a id="req-gos-setup-019"></a><a id="risk-gos-setup-019"></a>| `req-gos-setup-019` | `risk-gos-setup-019` | [tc-gos-setup-019](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-019/case.md#tc-gos-setup-019) — Quote and quote-report CLI bindings | P0 |
<a id="req-gos-setup-020"></a><a id="risk-gos-setup-020"></a>| `req-gos-setup-020` | `risk-gos-setup-020` | [tc-gos-setup-020](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-020/case.md#tc-gos-setup-020) — RA CA and app key generation CLI | P0 |
<a id="req-gos-setup-021"></a><a id="risk-gos-setup-021"></a>| `req-gos-setup-021` | `risk-gos-setup-021` | [tc-gos-setup-021](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-021/case.md#tc-gos-setup-021) — Random and hexadecimal utility CLI | P0 |
<a id="req-gos-setup-022"></a><a id="risk-gos-setup-022"></a>| `req-gos-setup-022` | `risk-gos-setup-022` | [tc-gos-setup-022](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-022/case.md#tc-gos-setup-022) — vTPM attest quote and verify CLI suite | P0 |
<a id="req-gos-setup-023"></a><a id="risk-gos-setup-023"></a>| `req-gos-setup-023` | `risk-gos-setup-023` | [tc-gos-setup-023](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-023/case.md#tc-gos-setup-023) — Versioned attestation create inspect JSON and strip CLI | P0 |
<a id="req-gos-setup-024"></a><a id="risk-gos-setup-024"></a>| `req-gos-setup-024` | `risk-gos-setup-024` | [tc-gos-setup-024](01-guest-os/12-setup-utilities-simulator/tc-gos-setup-024/case.md#tc-gos-setup-024) — KMS GetKeys CLI transport and output safety | P0 |

<a id="audit-section-guest-os-yocto-runtime-hardening"></a>
### Yocto Image, Runtime, and Hardening

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gos-yocto-002"></a><a id="risk-gos-yocto-002"></a>| `req-gos-yocto-002` | `risk-gos-yocto-002` | [tc-gos-yocto-002](01-guest-os/13-yocto-runtime-hardening/tc-gos-yocto-002/case.md#tc-gos-yocto-002) — OpenSSH account and password-auth hardening | P0 |
<a id="req-gos-yocto-003"></a><a id="risk-gos-yocto-003"></a>| `req-gos-yocto-003` | `risk-gos-yocto-003` | [tc-gos-yocto-003](01-guest-os/13-yocto-runtime-hardening/tc-gos-yocto-003/case.md#tc-gos-yocto-003) — Chrony synchronization and clock recovery | P0 |
<a id="req-gos-yocto-004"></a><a id="risk-gos-yocto-004"></a>| `req-gos-yocto-004` | `risk-gos-yocto-004` | [tc-gos-yocto-004](01-guest-os/13-yocto-runtime-hardening/tc-gos-yocto-004/case.md#tc-gos-yocto-004) — Containerd stargz snapshotter integrity and fallback | P0 |
<a id="req-gos-yocto-005"></a><a id="risk-gos-yocto-005"></a>| `req-gos-yocto-005` | `risk-gos-yocto-005` | [tc-gos-yocto-005](01-guest-os/13-yocto-runtime-hardening/tc-gos-yocto-005/case.md#tc-gos-yocto-005) — Sysbox runtime services and nested-container boundary | P0 |
<a id="req-gos-yocto-006"></a><a id="risk-gos-yocto-006"></a>| `req-gos-yocto-006` | `risk-gos-yocto-006` | [tc-gos-yocto-006](01-guest-os/13-yocto-runtime-hardening/tc-gos-yocto-006/case.md#tc-gos-yocto-006) — Docker daemon CPU/GPU configuration variants | P0 |

<a id="audit-section-gos-build"></a>
### Guest OS Build and Existing Regression Suite

| Requirement | Risk | Case | Priority |
|---|---|---|---|

<a id="audit-chapter-vmm"></a>
## VMM

<a id="audit-section-vmm-rpc-vmm"></a>
### Vmm RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-vmm-vmm-001"></a><a id="risk-vmm-vmm-001"></a>| `req-vmm-vmm-001` | `risk-vmm-vmm-001` | [tc-vmm-vmm-001](02-vmm/01-rpc-vmm/tc-vmm-vmm-001/case.md#tc-vmm-vmm-001) — Vmm.CreateVm | P0 |
<a id="req-vmm-vmm-002"></a><a id="risk-vmm-vmm-002"></a>| `req-vmm-vmm-002` | `risk-vmm-vmm-002` | [tc-vmm-vmm-002](02-vmm/01-rpc-vmm/tc-vmm-vmm-002/case.md#tc-vmm-vmm-002) — Vmm.StartVm | P1 |
<a id="req-vmm-vmm-003"></a><a id="risk-vmm-vmm-003"></a>| `req-vmm-vmm-003` | `risk-vmm-vmm-003` | [tc-vmm-vmm-003](02-vmm/01-rpc-vmm/tc-vmm-vmm-003/case.md#tc-vmm-vmm-003) — Vmm.StopVm | P1 |
<a id="req-vmm-vmm-004"></a><a id="risk-vmm-vmm-004"></a>| `req-vmm-vmm-004` | `risk-vmm-vmm-004` | [tc-vmm-vmm-004](02-vmm/01-rpc-vmm/tc-vmm-vmm-004/case.md#tc-vmm-vmm-004) — Vmm.RemoveVm | P1 |
<a id="req-vmm-vmm-005"></a><a id="risk-vmm-vmm-005"></a>| `req-vmm-vmm-005` | `risk-vmm-vmm-005` | [tc-vmm-vmm-005](02-vmm/01-rpc-vmm/tc-vmm-vmm-005/case.md#tc-vmm-vmm-005) — Vmm.UpgradeApp | P1 |
<a id="req-vmm-vmm-006"></a><a id="risk-vmm-vmm-006"></a>| `req-vmm-vmm-006` | `risk-vmm-vmm-006` | [tc-vmm-vmm-006](02-vmm/01-rpc-vmm/tc-vmm-vmm-006/case.md#tc-vmm-vmm-006) — Vmm.UpdateVm | P1 |
<a id="req-vmm-vmm-007"></a><a id="risk-vmm-vmm-007"></a>| `req-vmm-vmm-007` | `risk-vmm-vmm-007` | [tc-vmm-vmm-007](02-vmm/01-rpc-vmm/tc-vmm-vmm-007/case.md#tc-vmm-vmm-007) — Vmm.ShutdownVm | P1 |
<a id="req-vmm-vmm-008"></a><a id="risk-vmm-vmm-008"></a>| `req-vmm-vmm-008` | `risk-vmm-vmm-008` | [tc-vmm-vmm-008](02-vmm/01-rpc-vmm/tc-vmm-vmm-008/case.md#tc-vmm-vmm-008) — Vmm.ResizeVm | P1 |
<a id="req-vmm-vmm-009"></a><a id="risk-vmm-vmm-009"></a>| `req-vmm-vmm-009` | `risk-vmm-vmm-009` | [tc-vmm-vmm-009](02-vmm/01-rpc-vmm/tc-vmm-vmm-009/case.md#tc-vmm-vmm-009) — Vmm.GetComposeHash | P1 |
<a id="req-vmm-vmm-010"></a><a id="risk-vmm-vmm-010"></a>| `req-vmm-vmm-010` | `risk-vmm-vmm-010` | [tc-vmm-vmm-010](02-vmm/01-rpc-vmm/tc-vmm-vmm-010/case.md#tc-vmm-vmm-010) — Vmm.Status | P1 |
<a id="req-vmm-vmm-011"></a><a id="risk-vmm-vmm-011"></a>| `req-vmm-vmm-011` | `risk-vmm-vmm-011` | [tc-vmm-vmm-011](02-vmm/01-rpc-vmm/tc-vmm-vmm-011/case.md#tc-vmm-vmm-011) — Vmm.ListImages | P1 |
<a id="req-vmm-vmm-012"></a><a id="risk-vmm-vmm-012"></a>| `req-vmm-vmm-012` | `risk-vmm-vmm-012` | [tc-vmm-vmm-012](02-vmm/01-rpc-vmm/tc-vmm-vmm-012/case.md#tc-vmm-vmm-012) — Vmm.GetAppEnvEncryptPubKey | P1 |
<a id="req-vmm-vmm-013"></a><a id="risk-vmm-vmm-013"></a>| `req-vmm-vmm-013` | `risk-vmm-vmm-013` | [tc-vmm-vmm-013](02-vmm/01-rpc-vmm/tc-vmm-vmm-013/case.md#tc-vmm-vmm-013) — Vmm.GetInfo | P1 |
<a id="req-vmm-vmm-014"></a><a id="risk-vmm-vmm-014"></a>| `req-vmm-vmm-014` | `risk-vmm-vmm-014` | [tc-vmm-vmm-014](02-vmm/01-rpc-vmm/tc-vmm-vmm-014/case.md#tc-vmm-vmm-014) — Vmm.Version | P1 |
<a id="req-vmm-vmm-015"></a><a id="risk-vmm-vmm-015"></a>| `req-vmm-vmm-015` | `risk-vmm-vmm-015` | [tc-vmm-vmm-015](02-vmm/01-rpc-vmm/tc-vmm-vmm-015/case.md#tc-vmm-vmm-015) — Vmm.GetMeta | P1 |
<a id="req-vmm-vmm-016"></a><a id="risk-vmm-vmm-016"></a>| `req-vmm-vmm-016` | `risk-vmm-vmm-016` | [tc-vmm-vmm-016](02-vmm/01-rpc-vmm/tc-vmm-vmm-016/case.md#tc-vmm-vmm-016) — Vmm.ListGpus | P1 |
<a id="req-vmm-vmm-017"></a><a id="risk-vmm-vmm-017"></a>| `req-vmm-vmm-017` | `risk-vmm-vmm-017` | [tc-vmm-vmm-017](02-vmm/01-rpc-vmm/tc-vmm-vmm-017/case.md#tc-vmm-vmm-017) — Vmm.ReloadVms | P1 |
<a id="req-vmm-vmm-018"></a><a id="risk-vmm-vmm-018"></a>| `req-vmm-vmm-018` | `risk-vmm-vmm-018` | [tc-vmm-vmm-018](02-vmm/01-rpc-vmm/tc-vmm-vmm-018/case.md#tc-vmm-vmm-018) — Vmm.SvList | P1 |
<a id="req-vmm-vmm-019"></a><a id="risk-vmm-vmm-019"></a>| `req-vmm-vmm-019` | `risk-vmm-vmm-019` | [tc-vmm-vmm-019](02-vmm/01-rpc-vmm/tc-vmm-vmm-019/case.md#tc-vmm-vmm-019) — Vmm.SvStop | P1 |
<a id="req-vmm-vmm-020"></a><a id="risk-vmm-vmm-020"></a>| `req-vmm-vmm-020` | `risk-vmm-vmm-020` | [tc-vmm-vmm-020](02-vmm/01-rpc-vmm/tc-vmm-vmm-020/case.md#tc-vmm-vmm-020) — Vmm.SvRemove | P1 |
<a id="req-vmm-vmm-021"></a><a id="risk-vmm-vmm-021"></a>| `req-vmm-vmm-021` | `risk-vmm-vmm-021` | [tc-vmm-vmm-021](02-vmm/01-rpc-vmm/tc-vmm-vmm-021/case.md#tc-vmm-vmm-021) — Vmm.ListRegistryImages | P1 |
<a id="req-vmm-vmm-022"></a><a id="risk-vmm-vmm-022"></a>| `req-vmm-vmm-022` | `risk-vmm-vmm-022` | [tc-vmm-vmm-022](02-vmm/01-rpc-vmm/tc-vmm-vmm-022/case.md#tc-vmm-vmm-022) — Vmm.PullRegistryImage | P1 |
<a id="req-vmm-vmm-023"></a><a id="risk-vmm-vmm-023"></a>| `req-vmm-vmm-023` | `risk-vmm-vmm-023` | [tc-vmm-vmm-023](02-vmm/01-rpc-vmm/tc-vmm-vmm-023/case.md#tc-vmm-vmm-023) — Vmm.DeleteImage | P1 |

<a id="audit-section-vmm-rpc-hostapi"></a>
### HostApi RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-vmm-hostapi-001"></a><a id="risk-vmm-hostapi-001"></a>| `req-vmm-hostapi-001` | `risk-vmm-hostapi-001` | [tc-vmm-hostapi-001](02-vmm/02-rpc-hostapi/tc-vmm-hostapi-001/case.md#tc-vmm-hostapi-001) — HostApi.Info | P1 |
<a id="req-vmm-hostapi-002"></a><a id="risk-vmm-hostapi-002"></a>| `req-vmm-hostapi-002` | `risk-vmm-hostapi-002` | [tc-vmm-hostapi-002](02-vmm/02-rpc-hostapi/tc-vmm-hostapi-002/case.md#tc-vmm-hostapi-002) — HostApi.Notify | P1 |
<a id="req-vmm-hostapi-003"></a><a id="risk-vmm-hostapi-003"></a>| `req-vmm-hostapi-003` | `risk-vmm-hostapi-003` | [tc-vmm-hostapi-003](02-vmm/02-rpc-hostapi/tc-vmm-hostapi-003/case.md#tc-vmm-hostapi-003) — HostApi.GetSealingKey | P1 |

<a id="audit-section-vmm-configuration-and-security"></a>
### Configuration And Security

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-vmm-configurat-001"></a><a id="risk-vmm-configurat-001"></a>| `req-vmm-configurat-001` | `risk-vmm-configurat-001` | [tc-vmm-configurat-001](02-vmm/03-configuration-and-security/tc-vmm-configurat-001/case.md#tc-vmm-configurat-001) — Configuration defaults and validation | P1 |
<a id="req-vmm-configurat-002"></a><a id="risk-vmm-configurat-002"></a>| `req-vmm-configurat-002` | `risk-vmm-configurat-002` | [tc-vmm-configurat-002](02-vmm/03-configuration-and-security/tc-vmm-configurat-002/case.md#tc-vmm-configurat-002) — External API authentication and listener separation | P1 |
<a id="req-vmm-configurat-003"></a><a id="risk-vmm-configurat-003"></a>| `req-vmm-configurat-003` | `risk-vmm-configurat-003` | [tc-vmm-configurat-003](02-vmm/03-configuration-and-security/tc-vmm-configurat-003/case.md#tc-vmm-configurat-003) — Per-instance simulated TEE selection | P1 |
<a id="req-vmm-configurat-004"></a><a id="risk-vmm-configurat-004"></a>| `req-vmm-configurat-004` | `risk-vmm-configurat-004` | [tc-vmm-configurat-004](02-vmm/03-configuration-and-security/tc-vmm-configurat-004/case.md#tc-vmm-configurat-004) — TPM attachment decision materialization | P1 |
<a id="req-vmm-tdxvariant-005"></a><a id="risk-vmm-tdxvariant-005"></a>| `req-vmm-tdxvariant-005` | `risk-vmm-tdxvariant-005` | [tc-vmm-tdxvariant-005](02-vmm/03-configuration-and-security/tc-vmm-tdxvariant-005/case.md#tc-vmm-tdxvariant-005) — TDX legacy lite and auto variant resolution matrix | P0 |

<a id="audit-section-vmm-vm-lifecycle"></a>
### Vm Lifecycle

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-vmm-vm-lifecyc-001"></a><a id="risk-vmm-vm-lifecyc-001"></a>| `req-vmm-vm-lifecyc-001` | `risk-vmm-vm-lifecyc-001` | [tc-vmm-vm-lifecyc-001](02-vmm/04-vm-lifecycle/tc-vmm-vm-lifecyc-001/case.md#tc-vmm-vm-lifecyc-001) — Create/start/stop/remove idempotency | P1 |
<a id="req-vmm-vm-lifecyc-002"></a><a id="risk-vmm-vm-lifecyc-002"></a>| `req-vmm-vm-lifecyc-002` | `risk-vmm-vm-lifecyc-002` | [tc-vmm-vm-lifecyc-002](02-vmm/04-vm-lifecycle/tc-vmm-vm-lifecyc-002/case.md#tc-vmm-vm-lifecyc-002) — Graceful shutdown versus forced stop | P1 |
<a id="req-vmm-vm-lifecyc-003"></a><a id="risk-vmm-vm-lifecyc-003"></a>| `req-vmm-vm-lifecyc-003` | `risk-vmm-vm-lifecyc-003` | [tc-vmm-vm-lifecyc-003](02-vmm/04-vm-lifecycle/tc-vmm-vm-lifecyc-003/case.md#tc-vmm-vm-lifecyc-003) — Update and upgrade identity semantics | P1 |
<a id="req-vmm-vm-lifecyc-004"></a><a id="risk-vmm-vm-lifecyc-004"></a>| `req-vmm-vm-lifecyc-004` | `risk-vmm-vm-lifecyc-004` | [tc-vmm-vm-lifecyc-004](02-vmm/04-vm-lifecycle/tc-vmm-vm-lifecyc-004/case.md#tc-vmm-vm-lifecyc-004) — Resize CPU memory and disk | P1 |
<a id="req-vmm-vm-lifecyc-005"></a><a id="risk-vmm-vm-lifecyc-005"></a>| `req-vmm-vm-lifecyc-005` | `risk-vmm-vm-lifecyc-005` | [tc-vmm-vm-lifecyc-005](02-vmm/04-vm-lifecycle/tc-vmm-vm-lifecyc-005/case.md#tc-vmm-vm-lifecyc-005) — Reload and crash recovery | P1 |
<a id="req-vmm-vm-lifecyc-006"></a><a id="risk-vmm-vm-lifecyc-006"></a>| `req-vmm-vm-lifecyc-006` | `risk-vmm-vm-lifecyc-006` | [tc-vmm-vm-lifecyc-006](02-vmm/04-vm-lifecycle/tc-vmm-vm-lifecyc-006/case.md#tc-vmm-vm-lifecyc-006) — Auto-restart policy and backoff | P1 |

<a id="audit-section-vmm-compute-network-image"></a>
### Compute Network Image

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-vmm-compute-ne-001"></a><a id="risk-vmm-compute-ne-001"></a>| `req-vmm-compute-ne-001` | `risk-vmm-compute-ne-001` | [tc-vmm-compute-ne-001](02-vmm/05-compute-network-image/tc-vmm-compute-ne-001/case.md#tc-vmm-compute-ne-001) — User bridge and custom networking | P1 |
<a id="req-vmm-compute-ne-002"></a><a id="risk-vmm-compute-ne-002"></a>| `req-vmm-compute-ne-002` | `risk-vmm-compute-ne-002` | [tc-vmm-compute-ne-002](02-vmm/05-compute-network-image/tc-vmm-compute-ne-002/case.md#tc-vmm-compute-ne-002) — Port mapping protocols and conflicts | P1 |
<a id="req-vmm-compute-ne-003"></a><a id="risk-vmm-compute-ne-003"></a>| `req-vmm-compute-ne-003` | `risk-vmm-compute-ne-003` | [tc-vmm-compute-ne-003](02-vmm/05-compute-network-image/tc-vmm-compute-ne-003/case.md#tc-vmm-compute-ne-003) — NUMA pinning hugepages and resource isolation | P0 |
<a id="req-vmm-compute-ne-004"></a><a id="risk-vmm-compute-ne-004"></a>| `req-vmm-compute-ne-004` | `risk-vmm-compute-ne-004` | [tc-vmm-compute-ne-004](02-vmm/05-compute-network-image/tc-vmm-compute-ne-004/case.md#tc-vmm-compute-ne-004) — GPU discovery attach modes and ownership | P0 |
<a id="req-vmm-compute-ne-005"></a><a id="risk-vmm-compute-ne-005"></a>| `req-vmm-compute-ne-005` | `risk-vmm-compute-ne-005` | [tc-vmm-compute-ne-005](02-vmm/05-compute-network-image/tc-vmm-compute-ne-005/case.md#tc-vmm-compute-ne-005) — Local image discovery metadata and deletion | P1 |
<a id="req-vmm-compute-ne-006"></a><a id="risk-vmm-compute-ne-006"></a>| `req-vmm-compute-ne-006` | `risk-vmm-compute-ne-006` | [tc-vmm-compute-ne-006](02-vmm/05-compute-network-image/tc-vmm-compute-ne-006/case.md#tc-vmm-compute-ne-006) — Registry authentication pull and extraction | P1 |
<a id="req-vmm-compute-ne-007"></a><a id="risk-vmm-compute-ne-007"></a>| `req-vmm-compute-ne-007` | `risk-vmm-compute-ne-007` | [tc-vmm-compute-ne-007](02-vmm/05-compute-network-image/tc-vmm-compute-ne-007/case.md#tc-vmm-compute-ne-007) — QEMU command and platform matrix | P0 |
<a id="req-vmm-volume-008"></a><a id="risk-vmm-volume-008"></a>| `req-vmm-volume-008` | `risk-vmm-volume-008` | [tc-vmm-volume-008](02-vmm/05-compute-network-image/tc-vmm-volume-008/case.md#tc-vmm-volume-008) — Measured verity volume extraction resolution and path safety | P0 |

<a id="audit-section-vmm-ui-observability-host"></a>
### Ui Observability Host

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-vmm-ui-observa-001"></a><a id="risk-vmm-ui-observa-001"></a>| `req-vmm-ui-observa-001` | `risk-vmm-ui-observa-001` | [tc-vmm-ui-observa-001](02-vmm/06-ui-observability-host/tc-vmm-ui-observa-001/case.md#tc-vmm-ui-observa-001) — Status filtering pagination and event history | P1 |
<a id="req-vmm-ui-observa-002"></a><a id="risk-vmm-ui-observa-002"></a>| `req-vmm-ui-observa-002` | `risk-vmm-ui-observa-002` | [tc-vmm-ui-observa-002](02-vmm/06-ui-observability-host/tc-vmm-ui-observa-002/case.md#tc-vmm-ui-observa-002) — Console log channels follow and ANSI handling | P1 |
<a id="req-vmm-ui-observa-003"></a><a id="risk-vmm-ui-observa-003"></a>| `req-vmm-ui-observa-003` | `risk-vmm-ui-observa-003` | [tc-vmm-ui-observa-003](02-vmm/06-ui-observability-host/tc-vmm-ui-observa-003/case.md#tc-vmm-ui-observa-003) — Host sealing-key provider integration | P0 |
<a id="req-vmm-ui-observa-004"></a><a id="risk-vmm-ui-observa-004"></a>| `req-vmm-ui-observa-004` | `risk-vmm-ui-observa-004` | [tc-vmm-ui-observa-004](02-vmm/06-ui-observability-host/tc-vmm-ui-observa-004/case.md#tc-vmm-ui-observa-004) — Supervisor passthrough operations | P1 |
<a id="req-vmm-ui-observa-005"></a><a id="risk-vmm-ui-observa-005"></a>| `req-vmm-ui-observa-005` | `risk-vmm-ui-observa-005` | [tc-vmm-ui-observa-005](02-vmm/06-ui-observability-host/tc-vmm-ui-observa-005/case.md#tc-vmm-ui-observa-005) — Web UI deployment workflows | P1 |
<a id="req-vmm-serial-006"></a><a id="risk-vmm-serial-006"></a>| `req-vmm-serial-006` | `risk-vmm-serial-006` | [tc-vmm-serial-006](02-vmm/06-ui-observability-host/tc-vmm-serial-006/case.md#tc-vmm-serial-006) — Serial log separator rotation history and follow continuity | P0 |

<a id="audit-section-vmm-guest-proxy-and-manifest"></a>
### Guest Proxy and Manifest Fidelity

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-vmm-manifest-001"></a><a id="risk-vmm-manifest-001"></a>| `req-vmm-manifest-001` | `risk-vmm-manifest-001` | [tc-vmm-manifest-001](02-vmm/07-guest-proxy-and-manifest/tc-vmm-manifest-001/case.md#tc-vmm-manifest-001) — Proxied GuestApi transport and VM targeting | P0 |
<a id="req-vmm-manifest-002"></a><a id="risk-vmm-manifest-002"></a>| `req-vmm-manifest-002` | `risk-vmm-manifest-002` | [tc-vmm-manifest-002](02-vmm/07-guest-proxy-and-manifest/tc-vmm-manifest-002/case.md#tc-vmm-manifest-002) — Manifest persistence and QEMU/vm_config agreement | P0 |

<a id="audit-section-vmm-internal-state-and-launch"></a>
### Internal State, Measurement, and Launch Helpers

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-vmm-internal-001"></a><a id="risk-vmm-internal-001"></a>| `req-vmm-internal-001` | `risk-vmm-internal-001` | [tc-vmm-internal-001](02-vmm/08-internal-state-and-launch/tc-vmm-internal-001/case.md#tc-vmm-internal-001) — Host-share disk creation and content bounds | P0 |
<a id="req-vmm-internal-002"></a><a id="risk-vmm-internal-002"></a>| `req-vmm-internal-002` | `risk-vmm-internal-002` | [tc-vmm-internal-002](02-vmm/08-internal-state-and-launch/tc-vmm-internal-002/case.md#tc-vmm-internal-002) — Numeric ID pool allocation reuse and exhaustion | P1 |
<a id="req-vmm-internal-003"></a><a id="risk-vmm-internal-003"></a>| `req-vmm-internal-003` | `risk-vmm-internal-003` | [tc-vmm-internal-003](02-vmm/08-internal-state-and-launch/tc-vmm-internal-003/case.md#tc-vmm-internal-003) — Image metadata parsing and firmware selection | P0 |
<a id="req-vmm-internal-004"></a><a id="risk-vmm-internal-004"></a>| `req-vmm-internal-004` | `risk-vmm-internal-004` | [tc-vmm-internal-004](02-vmm/08-internal-state-and-launch/tc-vmm-internal-004/case.md#tc-vmm-internal-004) — MR config and SNP host-data construction | P0 |
<a id="req-vmm-internal-005"></a><a id="risk-vmm-internal-005"></a>| `req-vmm-internal-005` | `risk-vmm-internal-005` | [tc-vmm-internal-005](02-vmm/08-internal-state-and-launch/tc-vmm-internal-005/case.md#tc-vmm-internal-005) — VM status protobuf projection and URL construction | P1 |
<a id="req-vmm-internal-006"></a><a id="risk-vmm-internal-006"></a>| `req-vmm-internal-006` | `risk-vmm-internal-006` | [tc-vmm-internal-006](02-vmm/08-internal-state-and-launch/tc-vmm-internal-006/case.md#tc-vmm-internal-006) — One-shot VM execution and cleanup | P1 |
<a id="req-vmm-internal-007"></a><a id="risk-vmm-internal-007"></a>| `req-vmm-internal-007` | `risk-vmm-internal-007` | [tc-vmm-internal-007](02-vmm/08-internal-state-and-launch/tc-vmm-internal-007/case.md#tc-vmm-internal-007) — Generated OpenAPI contract fidelity | P1 |
<a id="req-vmm-internal-008"></a><a id="risk-vmm-internal-008"></a>| `req-vmm-internal-008` | `risk-vmm-internal-008` | [tc-vmm-internal-008](02-vmm/08-internal-state-and-launch/tc-vmm-internal-008/case.md#tc-vmm-internal-008) — Launcher QEMU and swtpm coupled lifecycle | P0 |

<a id="audit-chapter-kms"></a>
## KMS

<a id="audit-section-kms-rpc-kms"></a>
### KMS RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-kms-001"></a><a id="risk-kms-kms-001"></a>| `req-kms-kms-001` | `risk-kms-kms-001` | [tc-kms-kms-001](03-kms/01-rpc-kms/tc-kms-kms-001/case.md#tc-kms-kms-001) — KMS.GetAppKey | P0 |
<a id="req-kms-kms-002"></a><a id="risk-kms-kms-002"></a>| `req-kms-kms-002` | `risk-kms-kms-002` | [tc-kms-kms-002](03-kms/01-rpc-kms/tc-kms-kms-002/case.md#tc-kms-kms-002) — KMS.GetKmsKey | P0 |
<a id="req-kms-kms-003"></a><a id="risk-kms-kms-003"></a>| `req-kms-kms-003` | `risk-kms-kms-003` | [tc-kms-kms-003](03-kms/01-rpc-kms/tc-kms-kms-003/case.md#tc-kms-kms-003) — KMS.GetAppEnvEncryptPubKey | P1 |
<a id="req-kms-kms-004"></a><a id="risk-kms-kms-004"></a>| `req-kms-kms-004` | `risk-kms-kms-004` | [tc-kms-kms-004](03-kms/01-rpc-kms/tc-kms-kms-004/case.md#tc-kms-kms-004) — KMS.GetMeta | P1 |
<a id="req-kms-kms-005"></a><a id="risk-kms-kms-005"></a>| `req-kms-kms-005` | `risk-kms-kms-005` | [tc-kms-kms-005](03-kms/01-rpc-kms/tc-kms-kms-005/case.md#tc-kms-kms-005) — KMS.GetTempCaCert | P1 |
<a id="req-kms-kms-006"></a><a id="risk-kms-kms-006"></a>| `req-kms-kms-006` | `risk-kms-kms-006` | [tc-kms-kms-006](03-kms/01-rpc-kms/tc-kms-kms-006/case.md#tc-kms-kms-006) — KMS.SignCert | P0 |

<a id="audit-section-kms-rpc-admin"></a>
### Admin RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-admin-001"></a><a id="risk-kms-admin-001"></a>| `req-kms-admin-001` | `risk-kms-admin-001` | [tc-kms-admin-001](03-kms/02-rpc-admin/tc-kms-admin-001/case.md#tc-kms-admin-001) — Admin.ClearImageCache | P1 |

<a id="audit-section-kms-rpc-onboard"></a>
### Onboard RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-onboard-001"></a><a id="risk-kms-onboard-001"></a>| `req-kms-onboard-001` | `risk-kms-onboard-001` | [tc-kms-onboard-001](03-kms/03-rpc-onboard/tc-kms-onboard-001/case.md#tc-kms-onboard-001) — Onboard.Bootstrap | P1 |
<a id="req-kms-onboard-002"></a><a id="risk-kms-onboard-002"></a>| `req-kms-onboard-002` | `risk-kms-onboard-002` | [tc-kms-onboard-002](03-kms/03-rpc-onboard/tc-kms-onboard-002/case.md#tc-kms-onboard-002) — Onboard.Onboard | P1 |
<a id="req-kms-onboard-003"></a><a id="risk-kms-onboard-003"></a>| `req-kms-onboard-003` | `risk-kms-onboard-003` | [tc-kms-onboard-003](03-kms/03-rpc-onboard/tc-kms-onboard-003/case.md#tc-kms-onboard-003) — Onboard.GetAttestationInfo | P1 |
<a id="req-kms-onboard-004"></a><a id="risk-kms-onboard-004"></a>| `req-kms-onboard-004` | `risk-kms-onboard-004` | [tc-kms-onboard-004](03-kms/03-rpc-onboard/tc-kms-onboard-004/case.md#tc-kms-onboard-004) — Onboard.Finish | P1 |

<a id="audit-section-kms-bootstrap-onboard"></a>
### Bootstrap Onboard

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-bootstrap--001"></a><a id="risk-kms-bootstrap--001"></a>| `req-kms-bootstrap--001` | `risk-kms-bootstrap--001` | [tc-kms-bootstrap--001](03-kms/04-bootstrap-onboard/tc-kms-bootstrap--001/case.md#tc-kms-bootstrap--001) — Fresh bootstrap key hierarchy | P0 |
<a id="req-kms-bootstrap--002"></a><a id="risk-kms-bootstrap--002"></a>| `req-kms-bootstrap--002` | `risk-kms-bootstrap--002` | [tc-kms-bootstrap--002](03-kms/04-bootstrap-onboard/tc-kms-bootstrap--002/case.md#tc-kms-bootstrap--002) — Onboard from existing KMS | P0 |
<a id="req-kms-bootstrap--003"></a><a id="risk-kms-bootstrap--003"></a>| `req-kms-bootstrap--003` | `risk-kms-bootstrap--003` | [tc-kms-bootstrap--003](03-kms/04-bootstrap-onboard/tc-kms-bootstrap--003/case.md#tc-kms-bootstrap--003) — Finish onboarding and listener transition | P0 |
<a id="req-kms-bootstrap--004"></a><a id="risk-kms-bootstrap--004"></a>| `req-kms-bootstrap--004` | `risk-kms-bootstrap--004` | [tc-kms-bootstrap--004](03-kms/04-bootstrap-onboard/tc-kms-bootstrap--004/case.md#tc-kms-bootstrap--004) — On-chain attestation information | P0 |

<a id="audit-section-kms-attestation-authorization"></a>
### Attestation Authorization

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-attestatio-001"></a><a id="risk-kms-attestatio-001"></a>| `req-kms-attestatio-001` | `risk-kms-attestatio-001` | [tc-kms-attestatio-001](03-kms/05-attestation-authorization/tc-kms-attestatio-001/case.md#tc-kms-attestatio-001) — TDX full and lite app authorization | P0 |
<a id="req-kms-attestatio-002"></a><a id="risk-kms-attestatio-002"></a>| `req-kms-attestatio-002` | `risk-kms-attestatio-002` | [tc-kms-attestatio-002](03-kms/05-attestation-authorization/tc-kms-attestatio-002/case.md#tc-kms-attestatio-002) — SEV-SNP app authorization | P0 |
<a id="req-kms-attestatio-003"></a><a id="risk-kms-attestatio-003"></a>| `req-kms-attestatio-003` | `risk-kms-attestatio-003` | [tc-kms-attestatio-003](03-kms/05-attestation-authorization/tc-kms-attestatio-003/case.md#tc-kms-attestatio-003) — GCP TDX and Nitro TPM authorization | P0 |
<a id="req-kms-attestatio-004"></a><a id="risk-kms-attestatio-004"></a>| `req-kms-attestatio-004` | `risk-kms-attestatio-004` | [tc-kms-attestatio-004](03-kms/05-attestation-authorization/tc-kms-attestatio-004/case.md#tc-kms-attestatio-004) — Upgrade authority and allow_any_upgrade | P0 |
<a id="req-kms-attestatio-005"></a><a id="risk-kms-attestatio-005"></a>| `req-kms-attestatio-005` | `risk-kms-attestatio-005` | [tc-kms-attestatio-005](03-kms/05-attestation-authorization/tc-kms-attestatio-005/case.md#tc-kms-attestatio-005) — Authorization backend matrix | P1 |
<a id="req-kms-platform-006"></a><a id="risk-kms-platform-006"></a>| `req-kms-platform-006` | `risk-kms-platform-006` | [tc-kms-platform-006](03-kms/05-attestation-authorization/tc-kms-platform-006/case.md#tc-kms-platform-006) — Nitro Enclave app and KMS authorization | P0 |

<a id="audit-section-kms-keys-certs-operations"></a>
### Keys Certs Operations

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-keys-certs-001"></a><a id="risk-kms-keys-certs-001"></a>| `req-kms-keys-certs-001` | `risk-kms-keys-certs-001` | [tc-kms-keys-certs-001](03-kms/06-keys-certs-operations/tc-kms-keys-certs-001/case.md#tc-kms-keys-certs-001) — Per-app key hierarchy isolation | P0 |
<a id="req-kms-keys-certs-002"></a><a id="risk-kms-keys-certs-002"></a>| `req-kms-keys-certs-002` | `risk-kms-keys-certs-002` | [tc-kms-keys-certs-002](03-kms/06-keys-certs-operations/tc-kms-keys-certs-002/case.md#tc-kms-keys-certs-002) — Environment public-key freshness signatures | P1 |
<a id="req-kms-keys-certs-003"></a><a id="risk-kms-keys-certs-003"></a>| `req-kms-keys-certs-003` | `risk-kms-keys-certs-003` | [tc-kms-keys-certs-003](03-kms/06-keys-certs-operations/tc-kms-keys-certs-003/case.md#tc-kms-keys-certs-003) — KMS key handover and rotation chain | P0 |
<a id="req-kms-keys-certs-004"></a><a id="risk-kms-keys-certs-004"></a>| `req-kms-keys-certs-004` | `risk-kms-keys-certs-004` | [tc-kms-keys-certs-004](03-kms/06-keys-certs-operations/tc-kms-keys-certs-004/case.md#tc-kms-keys-certs-004) — Certificate signing CSR and app binding | P0 |
<a id="req-kms-keys-certs-005"></a><a id="risk-kms-keys-certs-005"></a>| `req-kms-keys-certs-005` | `risk-kms-keys-certs-005` | [tc-kms-keys-certs-005](03-kms/06-keys-certs-operations/tc-kms-keys-certs-005/case.md#tc-kms-keys-certs-005) — CA persistence and near-expiry renewal | P0 |
<a id="req-kms-keys-certs-006"></a><a id="risk-kms-keys-certs-006"></a>| `req-kms-keys-certs-006` | `risk-kms-keys-certs-006` | [tc-kms-keys-certs-006](03-kms/06-keys-certs-operations/tc-kms-keys-certs-006/case.md#tc-kms-keys-certs-006) — Image measurement cache clear and refill | P1 |
<a id="req-kms-keys-certs-007"></a><a id="risk-kms-keys-certs-007"></a>| `req-kms-keys-certs-007` | `risk-kms-keys-certs-007` | [tc-kms-keys-certs-007](03-kms/06-keys-certs-operations/tc-kms-keys-certs-007/case.md#tc-kms-keys-certs-007) — Admin authentication transports | P1 |
<a id="req-kms-keys-certs-008"></a><a id="risk-kms-keys-certs-008"></a>| `req-kms-keys-certs-008` | `risk-kms-keys-certs-008` | [tc-kms-keys-certs-008](03-kms/06-keys-certs-operations/tc-kms-keys-certs-008/case.md#tc-kms-keys-certs-008) — Metrics metadata and failure diagnostics | P1 |
<a id="req-kms-keys-certs-009"></a><a id="risk-kms-keys-certs-009"></a>| `req-kms-keys-certs-009` | `risk-kms-keys-certs-009` | [tc-kms-keys-certs-009](03-kms/06-keys-certs-operations/tc-kms-keys-certs-009/case.md#tc-kms-keys-certs-009) — Crash consistency and backup recovery | P0 |
<a id="req-kms-release-010"></a><a id="risk-kms-release-010"></a>| `req-kms-release-010` | `risk-kms-release-010` | [tc-kms-release-010](03-kms/06-keys-certs-operations/tc-kms-release-010/case.md#tc-kms-release-010) — Platform-specific key-release feature gates | P0 |
<a id="req-kms-apiver-011"></a><a id="risk-kms-apiver-011"></a>| `req-kms-apiver-011` | `risk-kms-apiver-011` | [tc-kms-apiver-011](03-kms/06-keys-certs-operations/tc-kms-apiver-011/case.md#tc-kms-apiver-011) — GetAppKey and SignCert API-version compatibility | P0 |

<a id="audit-section-kms-authorization-implementations"></a>
### Authorization Implementations and Contract

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-auth-001"></a><a id="risk-kms-auth-001"></a>| `req-kms-auth-001` | `risk-kms-auth-001` | [tc-kms-auth-001](03-kms/07-authorization-implementations/tc-kms-auth-001/case.md#tc-kms-auth-001) — Simple authorization configuration rules | P0 |
<a id="req-kms-auth-002"></a><a id="risk-kms-auth-002"></a>| `req-kms-auth-002` | `risk-kms-auth-002` | [tc-kms-auth-002](03-kms/07-authorization-implementations/tc-kms-auth-002/case.md#tc-kms-auth-002) — Mock authorization safety boundary | P0 |
<a id="req-kms-auth-003"></a><a id="risk-kms-auth-003"></a>| `req-kms-auth-003` | `risk-kms-auth-003` | [tc-kms-auth-003](03-kms/07-authorization-implementations/tc-kms-auth-003/case.md#tc-kms-auth-003) — Ethereum authorization freshness and domain binding | P0 |
<a id="req-kms-auth-004"></a><a id="risk-kms-auth-004"></a>| `req-kms-auth-004` | `risk-kms-auth-004` | [tc-kms-auth-004](03-kms/07-authorization-implementations/tc-kms-auth-004/case.md#tc-kms-auth-004) — KMS contract ownership roles and upgrade controls | P0 |
<a id="req-kms-auth-005"></a><a id="risk-kms-auth-005"></a>| `req-kms-auth-005` | `risk-kms-auth-005` | [tc-kms-auth-005](03-kms/07-authorization-implementations/tc-kms-auth-005/case.md#tc-kms-auth-005) — KMS node registration and authorization lifecycle | P0 |
<a id="req-kms-auth-006"></a><a id="risk-kms-auth-006"></a>| `req-kms-auth-006` | `risk-kms-auth-006` | [tc-kms-auth-006](03-kms/07-authorization-implementations/tc-kms-auth-006/case.md#tc-kms-auth-006) — Application boot policy image and config matrix | P0 |
<a id="req-kms-auth-007"></a><a id="risk-kms-auth-007"></a>| `req-kms-auth-007` | `risk-kms-auth-007` | [tc-kms-auth-007](03-kms/07-authorization-implementations/tc-kms-auth-007/case.md#tc-kms-auth-007) — Ethereum finalized snapshot and reorg refresh | P0 |
<a id="req-kms-auth-008"></a><a id="risk-kms-auth-008"></a>| `req-kms-auth-008` | `risk-kms-auth-008` | [tc-kms-auth-008](03-kms/07-authorization-implementations/tc-kms-auth-008/case.md#tc-kms-auth-008) — Authorization API schema and error compatibility | P1 |
<a id="req-kms-auth-009"></a><a id="risk-kms-auth-009"></a>| `req-kms-auth-009` | `risk-kms-auth-009` | [tc-kms-auth-009](03-kms/07-authorization-implementations/tc-kms-auth-009/case.md#tc-kms-auth-009) — Contract event audit completeness | P1 |
<a id="req-kms-auth-010"></a><a id="risk-kms-auth-010"></a>| `req-kms-auth-010` | `risk-kms-auth-010` | [tc-kms-auth-010](03-kms/07-authorization-implementations/tc-kms-auth-010/case.md#tc-kms-auth-010) — Authorization decision freshness and scope isolation | P0 |

<a id="audit-section-kms-upgrade-onboard-compatibility"></a>
### Upgrade and Onboard Compatibility to 0.6.0

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-upgrade-001"></a><a id="risk-kms-upgrade-001"></a>| `req-kms-upgrade-001` | `risk-kms-upgrade-001` | [tc-kms-upgrade-001](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-001/case.md#tc-kms-upgrade-001) — 0.5.4 to 0.6.0 through 0.5.7 bridge | P0 |
<a id="req-kms-upgrade-002"></a><a id="risk-kms-upgrade-002"></a>| `req-kms-upgrade-002` | `risk-kms-upgrade-002` | [tc-kms-upgrade-002](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-002/case.md#tc-kms-upgrade-002) — Direct 0.5.4 to 0.6.0 incompatibility is explicit | P0 |
<a id="req-kms-upgrade-003"></a><a id="risk-kms-upgrade-003"></a>| `req-kms-upgrade-003` | `risk-kms-upgrade-003` | [tc-kms-upgrade-003](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-003/case.md#tc-kms-upgrade-003) — 0.5.8 direct onboard to 0.6.0 | P0 |
<a id="req-kms-upgrade-004"></a><a id="risk-kms-upgrade-004"></a>| `req-kms-upgrade-004` | `risk-kms-upgrade-004` | [tc-kms-upgrade-004](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-004/case.md#tc-kms-upgrade-004) — kms-v0.5.11 direct onboard to 0.6.0 | P0 |
<a id="req-kms-upgrade-005"></a><a id="risk-kms-upgrade-005"></a>| `req-kms-upgrade-005` | `risk-kms-upgrade-005` | [tc-kms-upgrade-005](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-005/case.md#tc-kms-upgrade-005) — Historical sources follow the verified lite-target compatibility matrix | P0 |
<a id="req-kms-upgrade-006"></a><a id="risk-kms-upgrade-006"></a>| `req-kms-upgrade-006` | `risk-kms-upgrade-006` | [tc-kms-upgrade-006](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-006/case.md#tc-kms-upgrade-006) — Legacy and auto targets preserve mixed-source cutover identity | P0 |
<a id="req-kms-upgrade-007"></a><a id="risk-kms-upgrade-007"></a>| `req-kms-upgrade-007` | `risk-kms-upgrade-007` | [tc-kms-upgrade-007](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-007/case.md#tc-kms-upgrade-007) — 0.5.4 age-matched ACPI diagnosis | P0 |
<a id="req-kms-upgrade-008"></a><a id="risk-kms-upgrade-008"></a>| `req-kms-upgrade-008` | `risk-kms-upgrade-008` | [tc-kms-upgrade-008](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-008/case.md#tc-kms-upgrade-008) — Source and target allowlist completeness | P0 |
<a id="req-kms-upgrade-009"></a><a id="risk-kms-upgrade-009"></a>| `req-kms-upgrade-009` | `risk-kms-upgrade-009` | [tc-kms-upgrade-009](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-009/case.md#tc-kms-upgrade-009) — Mixed-version KMS endpoint service consistency | P0 |
<a id="req-kms-upgrade-010"></a><a id="risk-kms-upgrade-010"></a>| `req-kms-upgrade-010` | `risk-kms-upgrade-010` | [tc-kms-upgrade-010](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-010/case.md#tc-kms-upgrade-010) — KMS replacement cutover and rollback window | P0 |
<a id="req-kms-upgrade-011"></a><a id="risk-kms-upgrade-011"></a>| `req-kms-upgrade-011` | `risk-kms-upgrade-011` | [tc-kms-upgrade-011](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-011/case.md#tc-kms-upgrade-011) — Measurement cache across KMS upgrade boundaries | P0 |
<a id="req-kms-upgrade-012"></a><a id="risk-kms-upgrade-012"></a>| `req-kms-upgrade-012` | `risk-kms-upgrade-012` | [tc-kms-upgrade-012](03-kms/08-upgrade-onboard-compatibility/tc-kms-upgrade-012/case.md#tc-kms-upgrade-012) — Post-KMS gateway 0.6.0 upgrade order | P0 |

<a id="audit-section-kms-certificate-transparency-log"></a>
### Certificate Transparency Log Files

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-ct-001"></a><a id="risk-kms-ct-001"></a>| `req-kms-ct-001` | `risk-kms-ct-001` | [tc-kms-ct-001](03-kms/09-certificate-transparency-log/tc-kms-ct-001/case.md#tc-kms-ct-001) — Concurrent certificate log append and iteration | P0 |

<a id="audit-section-kms-service-startup"></a>
### Service Startup and Mode Transition

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-startup-001"></a><a id="risk-kms-startup-001"></a>| `req-kms-startup-001` | `risk-kms-startup-001` | [tc-kms-startup-001](03-kms/10-service-startup/tc-kms-startup-001/case.md#tc-kms-startup-001) — Onboard, main, admin, metrics, and health listener startup | P0 |

<a id="audit-section-kms-auth-service-runtime"></a>
### Authorization Service Runtime and Deployment

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-runtime-001"></a><a id="risk-kms-runtime-001"></a>| `req-kms-runtime-001` | `risk-kms-runtime-001` | [tc-kms-runtime-001](03-kms/11-auth-service-runtime/tc-kms-runtime-001/case.md#tc-kms-runtime-001) — Ethereum authorization HTTP server schema and listener | P0 |
<a id="req-kms-runtime-002"></a><a id="risk-kms-runtime-002"></a>| `req-kms-runtime-002` | `risk-kms-runtime-002` | [tc-kms-runtime-002](03-kms/11-auth-service-runtime/tc-kms-runtime-002/case.md#tc-kms-runtime-002) — Bun and Node authorization implementation parity | P0 |
<a id="req-kms-runtime-003"></a><a id="risk-kms-runtime-003"></a>| `req-kms-runtime-003` | `risk-kms-runtime-003` | [tc-kms-runtime-003](03-kms/11-auth-service-runtime/tc-kms-runtime-003/case.md#tc-kms-runtime-003) — Authorization deployment and management scripts | P0 |
<a id="req-kms-runtime-004"></a><a id="risk-kms-runtime-004"></a>| `req-kms-runtime-004` | `risk-kms-runtime-004` | [tc-kms-runtime-004](03-kms/11-auth-service-runtime/tc-kms-runtime-004/case.md#tc-kms-runtime-004) — Authorization service container deployment | P1 |
<a id="req-kms-runtime-005"></a><a id="risk-kms-runtime-005"></a>| `req-kms-runtime-005` | `risk-kms-runtime-005` | [tc-kms-runtime-005](03-kms/11-auth-service-runtime/tc-kms-runtime-005/case.md#tc-kms-runtime-005) — DstackApp device compose TCB and upgrade-disable policy | P0 |

<a id="audit-section-kms-build"></a>
### KMS Build, Image, Auth, Contract, and Existing Regression Suite

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-kms-build-001"></a><a id="risk-kms-build-001"></a>| `req-kms-build-001` | `risk-kms-build-001` | [tc-kms-build-001](03-kms/12-kms-build/tc-kms-build-001/case.md#tc-kms-build-001) — KMS Build, Image, Auth, Contract, and Existing Regression Suite | P0 |

<a id="audit-chapter-gateway"></a>
## Gateway

<a id="audit-section-gateway-rpc-gateway"></a>
### Gateway RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gw-gateway-001"></a><a id="risk-gw-gateway-001"></a>| `req-gw-gateway-001` | `risk-gw-gateway-001` | [tc-gw-gateway-001](04-gateway/01-rpc-gateway/tc-gw-gateway-001/case.md#tc-gw-gateway-001) — Gateway.RegisterCvm | P0 |
<a id="req-gw-gateway-002"></a><a id="risk-gw-gateway-002"></a>| `req-gw-gateway-002` | `risk-gw-gateway-002` | [tc-gw-gateway-002](04-gateway/01-rpc-gateway/tc-gw-gateway-002/case.md#tc-gw-gateway-002) — Gateway.AcmeInfo | P1 |
<a id="req-gw-gateway-003"></a><a id="risk-gw-gateway-003"></a>| `req-gw-gateway-003` | `risk-gw-gateway-003` | [tc-gw-gateway-003](04-gateway/01-rpc-gateway/tc-gw-gateway-003/case.md#tc-gw-gateway-003) — Gateway.Info | P1 |
<a id="req-gw-gateway-004"></a><a id="risk-gw-gateway-004"></a>| `req-gw-gateway-004` | `risk-gw-gateway-004` | [tc-gw-gateway-004](04-gateway/01-rpc-gateway/tc-gw-gateway-004/case.md#tc-gw-gateway-004) — Gateway.GetPeers | P1 |

<a id="audit-section-gateway-rpc-debug"></a>
### Debug RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gw-debug-001"></a><a id="risk-gw-debug-001"></a>| `req-gw-debug-001` | `risk-gw-debug-001` | [tc-gw-debug-001](04-gateway/02-rpc-debug/tc-gw-debug-001/case.md#tc-gw-debug-001) — Debug.RegisterCvm | P0 |
<a id="req-gw-debug-002"></a><a id="risk-gw-debug-002"></a>| `req-gw-debug-002` | `risk-gw-debug-002` | [tc-gw-debug-002](04-gateway/02-rpc-debug/tc-gw-debug-002/case.md#tc-gw-debug-002) — Debug.Info | P1 |
<a id="req-gw-debug-003"></a><a id="risk-gw-debug-003"></a>| `req-gw-debug-003` | `risk-gw-debug-003` | [tc-gw-debug-003](04-gateway/02-rpc-debug/tc-gw-debug-003/case.md#tc-gw-debug-003) — Debug.GetSyncData | P1 |
<a id="req-gw-debug-004"></a><a id="risk-gw-debug-004"></a>| `req-gw-debug-004` | `risk-gw-debug-004` | [tc-gw-debug-004](04-gateway/02-rpc-debug/tc-gw-debug-004/case.md#tc-gw-debug-004) — Debug.GetProxyState | P1 |

<a id="audit-section-gateway-rpc-admin"></a>
### Admin RPC

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gw-admin-001"></a><a id="risk-gw-admin-001"></a>| `req-gw-admin-001` | `risk-gw-admin-001` | [tc-gw-admin-001](04-gateway/03-rpc-admin/tc-gw-admin-001/case.md#tc-gw-admin-001) — Admin.Status | P1 |
<a id="req-gw-admin-002"></a><a id="risk-gw-admin-002"></a>| `req-gw-admin-002` | `risk-gw-admin-002` | [tc-gw-admin-002](04-gateway/03-rpc-admin/tc-gw-admin-002/case.md#tc-gw-admin-002) — Admin.GetInfo | P1 |
<a id="req-gw-admin-003"></a><a id="risk-gw-admin-003"></a>| `req-gw-admin-003` | `risk-gw-admin-003` | [tc-gw-admin-003](04-gateway/03-rpc-admin/tc-gw-admin-003/case.md#tc-gw-admin-003) — Admin.Exit | P1 |
<a id="req-gw-admin-004"></a><a id="risk-gw-admin-004"></a>| `req-gw-admin-004` | `risk-gw-admin-004` | [tc-gw-admin-004](04-gateway/03-rpc-admin/tc-gw-admin-004/case.md#tc-gw-admin-004) — Admin.RenewCert | P1 |
<a id="req-gw-admin-005"></a><a id="risk-gw-admin-005"></a>| `req-gw-admin-005` | `risk-gw-admin-005` | [tc-gw-admin-005](04-gateway/03-rpc-admin/tc-gw-admin-005/case.md#tc-gw-admin-005) — Admin.ReloadCert | P1 |
<a id="req-gw-admin-006"></a><a id="risk-gw-admin-006"></a>| `req-gw-admin-006` | `risk-gw-admin-006` | [tc-gw-admin-006](04-gateway/03-rpc-admin/tc-gw-admin-006/case.md#tc-gw-admin-006) — Admin.SetCaa | P1 |
<a id="req-gw-admin-007"></a><a id="risk-gw-admin-007"></a>| `req-gw-admin-007` | `risk-gw-admin-007` | [tc-gw-admin-007](04-gateway/03-rpc-admin/tc-gw-admin-007/case.md#tc-gw-admin-007) — Admin.GetMeta | P1 |
<a id="req-gw-admin-008"></a><a id="risk-gw-admin-008"></a>| `req-gw-admin-008` | `risk-gw-admin-008` | [tc-gw-admin-008](04-gateway/03-rpc-admin/tc-gw-admin-008/case.md#tc-gw-admin-008) — Admin.SetNodeUrl | P1 |
<a id="req-gw-admin-009"></a><a id="risk-gw-admin-009"></a>| `req-gw-admin-009` | `risk-gw-admin-009` | [tc-gw-admin-009](04-gateway/03-rpc-admin/tc-gw-admin-009/case.md#tc-gw-admin-009) — Admin.SetNodeStatus | P1 |
<a id="req-gw-admin-010"></a><a id="risk-gw-admin-010"></a>| `req-gw-admin-010` | `risk-gw-admin-010` | [tc-gw-admin-010](04-gateway/03-rpc-admin/tc-gw-admin-010/case.md#tc-gw-admin-010) — Admin.WaveKvStatus | P1 |
<a id="req-gw-admin-011"></a><a id="risk-gw-admin-011"></a>| `req-gw-admin-011` | `risk-gw-admin-011` | [tc-gw-admin-011](04-gateway/03-rpc-admin/tc-gw-admin-011/case.md#tc-gw-admin-011) — Admin.GetInstanceHandshakes | P1 |
<a id="req-gw-admin-012"></a><a id="risk-gw-admin-012"></a>| `req-gw-admin-012` | `risk-gw-admin-012` | [tc-gw-admin-012](04-gateway/03-rpc-admin/tc-gw-admin-012/case.md#tc-gw-admin-012) — Admin.GetGlobalConnections | P1 |
<a id="req-gw-admin-013"></a><a id="risk-gw-admin-013"></a>| `req-gw-admin-013` | `risk-gw-admin-013` | [tc-gw-admin-013](04-gateway/03-rpc-admin/tc-gw-admin-013/case.md#tc-gw-admin-013) — Admin.GetNodeStatuses | P1 |
<a id="req-gw-admin-014"></a><a id="risk-gw-admin-014"></a>| `req-gw-admin-014` | `risk-gw-admin-014` | [tc-gw-admin-014](04-gateway/03-rpc-admin/tc-gw-admin-014/case.md#tc-gw-admin-014) — Admin.ListDnsCredentials | P1 |
<a id="req-gw-admin-015"></a><a id="risk-gw-admin-015"></a>| `req-gw-admin-015` | `risk-gw-admin-015` | [tc-gw-admin-015](04-gateway/03-rpc-admin/tc-gw-admin-015/case.md#tc-gw-admin-015) — Admin.GetDnsCredential | P1 |
<a id="req-gw-admin-016"></a><a id="risk-gw-admin-016"></a>| `req-gw-admin-016` | `risk-gw-admin-016` | [tc-gw-admin-016](04-gateway/03-rpc-admin/tc-gw-admin-016/case.md#tc-gw-admin-016) — Admin.CreateDnsCredential | P1 |
<a id="req-gw-admin-017"></a><a id="risk-gw-admin-017"></a>| `req-gw-admin-017` | `risk-gw-admin-017` | [tc-gw-admin-017](04-gateway/03-rpc-admin/tc-gw-admin-017/case.md#tc-gw-admin-017) — Admin.UpdateDnsCredential | P1 |
<a id="req-gw-admin-018"></a><a id="risk-gw-admin-018"></a>| `req-gw-admin-018` | `risk-gw-admin-018` | [tc-gw-admin-018](04-gateway/03-rpc-admin/tc-gw-admin-018/case.md#tc-gw-admin-018) — Admin.DeleteDnsCredential | P1 |
<a id="req-gw-admin-019"></a><a id="risk-gw-admin-019"></a>| `req-gw-admin-019` | `risk-gw-admin-019` | [tc-gw-admin-019](04-gateway/03-rpc-admin/tc-gw-admin-019/case.md#tc-gw-admin-019) — Admin.GetDefaultDnsCredential | P1 |
<a id="req-gw-admin-020"></a><a id="risk-gw-admin-020"></a>| `req-gw-admin-020` | `risk-gw-admin-020` | [tc-gw-admin-020](04-gateway/03-rpc-admin/tc-gw-admin-020/case.md#tc-gw-admin-020) — Admin.SetDefaultDnsCredential | P1 |
<a id="req-gw-admin-021"></a><a id="risk-gw-admin-021"></a>| `req-gw-admin-021` | `risk-gw-admin-021` | [tc-gw-admin-021](04-gateway/03-rpc-admin/tc-gw-admin-021/case.md#tc-gw-admin-021) — Admin.ListZtDomains | P1 |
<a id="req-gw-admin-022"></a><a id="risk-gw-admin-022"></a>| `req-gw-admin-022` | `risk-gw-admin-022` | [tc-gw-admin-022](04-gateway/03-rpc-admin/tc-gw-admin-022/case.md#tc-gw-admin-022) — Admin.GetZtDomain | P1 |
<a id="req-gw-admin-023"></a><a id="risk-gw-admin-023"></a>| `req-gw-admin-023` | `risk-gw-admin-023` | [tc-gw-admin-023](04-gateway/03-rpc-admin/tc-gw-admin-023/case.md#tc-gw-admin-023) — Admin.AddZtDomain | P1 |
<a id="req-gw-admin-024"></a><a id="risk-gw-admin-024"></a>| `req-gw-admin-024` | `risk-gw-admin-024` | [tc-gw-admin-024](04-gateway/03-rpc-admin/tc-gw-admin-024/case.md#tc-gw-admin-024) — Admin.UpdateZtDomain | P1 |
<a id="req-gw-admin-025"></a><a id="risk-gw-admin-025"></a>| `req-gw-admin-025` | `risk-gw-admin-025` | [tc-gw-admin-025](04-gateway/03-rpc-admin/tc-gw-admin-025/case.md#tc-gw-admin-025) — Admin.DeleteZtDomain | P1 |
<a id="req-gw-admin-026"></a><a id="risk-gw-admin-026"></a>| `req-gw-admin-026` | `risk-gw-admin-026` | [tc-gw-admin-026](04-gateway/03-rpc-admin/tc-gw-admin-026/case.md#tc-gw-admin-026) — Admin.RenewZtDomainCert | P1 |
<a id="req-gw-admin-027"></a><a id="risk-gw-admin-027"></a>| `req-gw-admin-027` | `risk-gw-admin-027` | [tc-gw-admin-027](04-gateway/03-rpc-admin/tc-gw-admin-027/case.md#tc-gw-admin-027) — Admin.ForceReleaseCertLock | P1 |
<a id="req-gw-admin-028"></a><a id="risk-gw-admin-028"></a>| `req-gw-admin-028` | `risk-gw-admin-028` | [tc-gw-admin-028](04-gateway/03-rpc-admin/tc-gw-admin-028/case.md#tc-gw-admin-028) — Admin.ListCertAttestations | P1 |
<a id="req-gw-admin-029"></a><a id="risk-gw-admin-029"></a>| `req-gw-admin-029` | `risk-gw-admin-029` | [tc-gw-admin-029](04-gateway/03-rpc-admin/tc-gw-admin-029/case.md#tc-gw-admin-029) — Admin.GetCertbotConfig | P1 |
<a id="req-gw-admin-030"></a><a id="risk-gw-admin-030"></a>| `req-gw-admin-030` | `risk-gw-admin-030` | [tc-gw-admin-030](04-gateway/03-rpc-admin/tc-gw-admin-030/case.md#tc-gw-admin-030) — Admin.SetCertbotConfig | P1 |
<a id="req-gw-admin-031"></a><a id="risk-gw-admin-031"></a>| `req-gw-admin-031` | `risk-gw-admin-031` | [tc-gw-admin-031](04-gateway/03-rpc-admin/tc-gw-admin-031/case.md#tc-gw-admin-031) — Admin.SetInstancePortPolicy | P1 |
<a id="req-gw-admin-032"></a><a id="risk-gw-admin-032"></a>| `req-gw-admin-032` | `risk-gw-admin-032` | [tc-gw-admin-032](04-gateway/03-rpc-admin/tc-gw-admin-032/case.md#tc-gw-admin-032) — Admin.ClearInstancePortPolicy | P1 |
<a id="req-gw-admin-033"></a><a id="risk-gw-admin-033"></a>| `req-gw-admin-033` | `risk-gw-admin-033` | [tc-gw-admin-033](04-gateway/03-rpc-admin/tc-gw-admin-033/case.md#tc-gw-admin-033) — Admin.GetInstancePortPolicy | P1 |

<a id="audit-section-gateway-registration-wireguard-policy"></a>
### Registration Wireguard Policy

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gw-registrati-001"></a><a id="risk-gw-registrati-001"></a>| `req-gw-registrati-001` | `risk-gw-registrati-001` | [tc-gw-registrati-001](04-gateway/04-registration-wireguard-policy/tc-gw-registrati-001/case.md#tc-gw-registrati-001) — Attested CVM registration and re-registration | P0 |
<a id="req-gw-registrati-002"></a><a id="risk-gw-registrati-002"></a>| `req-gw-registrati-002` | `risk-gw-registrati-002` | [tc-gw-registrati-002](04-gateway/04-registration-wireguard-policy/tc-gw-registrati-002/case.md#tc-gw-registrati-002) — WireGuard IP allocation and peer lifecycle | P1 |
<a id="req-gw-registrati-003"></a><a id="risk-gw-registrati-003"></a>| `req-gw-registrati-003` | `risk-gw-registrati-003` | [tc-gw-registrati-003](04-gateway/04-registration-wireguard-policy/tc-gw-registrati-003/case.md#tc-gw-registrati-003) — Restrict-mode port enforcement | P1 |
<a id="req-gw-registrati-004"></a><a id="risk-gw-registrati-004"></a>| `req-gw-registrati-004` | `risk-gw-registrati-004` | [tc-gw-registrati-004](04-gateway/04-registration-wireguard-policy/tc-gw-registrati-004/case.md#tc-gw-registrati-004) — Port policy fetch fallback compatibility | P1 |

<a id="audit-section-gateway-proxy-protocol-routing"></a>
### Proxy Protocol Routing

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gw-proxy-prot-001"></a><a id="risk-gw-proxy-prot-001"></a>| `req-gw-proxy-prot-001` | `risk-gw-proxy-prot-001` | [tc-gw-proxy-prot-001](04-gateway/05-proxy-protocol-routing/tc-gw-proxy-prot-001/case.md#tc-gw-proxy-prot-001) — Inbound Proxy Protocol v1/v2 parsing | P1 |
<a id="req-gw-proxy-prot-002"></a><a id="risk-gw-proxy-prot-002"></a>| `req-gw-proxy-prot-002` | `risk-gw-proxy-prot-002` | [tc-gw-proxy-prot-002](04-gateway/05-proxy-protocol-routing/tc-gw-proxy-prot-002/case.md#tc-gw-proxy-prot-002) — Outbound Proxy Protocol per-port opt-in | P1 |
<a id="req-gw-proxy-prot-003"></a><a id="risk-gw-proxy-prot-003"></a>| `req-gw-proxy-prot-003` | `risk-gw-proxy-prot-003` | [tc-gw-proxy-prot-003](04-gateway/05-proxy-protocol-routing/tc-gw-proxy-prot-003/case.md#tc-gw-proxy-prot-003) — TLS passthrough SNI address resolution | P1 |
<a id="req-gw-proxy-prot-004"></a><a id="risk-gw-proxy-prot-004"></a>| `req-gw-proxy-prot-004` | `risk-gw-proxy-prot-004` | [tc-gw-proxy-prot-004](04-gateway/05-proxy-protocol-routing/tc-gw-proxy-prot-004/case.md#tc-gw-proxy-prot-004) — TLS termination routing and HTTP semantics | P1 |
<a id="req-gw-proxy-prot-005"></a><a id="risk-gw-proxy-prot-005"></a>| `req-gw-proxy-prot-005` | `risk-gw-proxy-prot-005` | [tc-gw-proxy-prot-005](04-gateway/05-proxy-protocol-routing/tc-gw-proxy-prot-005/case.md#tc-gw-proxy-prot-005) — App-address namespace and content-addressed HTTPS | P0 |
<a id="req-gw-proxy-prot-006"></a><a id="risk-gw-proxy-prot-006"></a>| `req-gw-proxy-prot-006` | `risk-gw-proxy-prot-006` | [tc-gw-proxy-prot-006](04-gateway/05-proxy-protocol-routing/tc-gw-proxy-prot-006/case.md#tc-gw-proxy-prot-006) — Connection limits timeouts and recycling | P1 |
<a id="req-gw-select-007"></a><a id="risk-gw-select-007"></a>| `req-gw-select-007` | `risk-gw-select-007` | [tc-gw-select-007](04-gateway/05-proxy-protocol-routing/tc-gw-select-007/case.md#tc-gw-select-007) — Top-N backend selection DNS cache and failover | P0 |

<a id="audit-section-gateway-certificates-dns"></a>
### Certificates Dns

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gw-certificat-001"></a><a id="risk-gw-certificat-001"></a>| `req-gw-certificat-001` | `risk-gw-certificat-001` | [tc-gw-certificat-001](04-gateway/06-certificates-dns/tc-gw-certificat-001/case.md#tc-gw-certificat-001) — ACME account bootstrap and persistence | P1 |
<a id="req-gw-certificat-002"></a><a id="risk-gw-certificat-002"></a>| `req-gw-certificat-002` | `risk-gw-certificat-002` | [tc-gw-certificat-002](04-gateway/06-certificates-dns/tc-gw-certificat-002/case.md#tc-gw-certificat-002) — Distributed certificate issue renew and lock | P1 |
<a id="req-gw-certificat-003"></a><a id="risk-gw-certificat-003"></a>| `req-gw-certificat-003` | `risk-gw-certificat-003` | [tc-gw-certificat-003](04-gateway/06-certificates-dns/tc-gw-certificat-003/case.md#tc-gw-certificat-003) — DNS credential CRUD and default selection | P1 |
<a id="req-gw-certificat-004"></a><a id="risk-gw-certificat-004"></a>| `req-gw-certificat-004` | `risk-gw-certificat-004` | [tc-gw-certificat-004](04-gateway/06-certificates-dns/tc-gw-certificat-004/case.md#tc-gw-certificat-004) — ZT domain CRUD and certificate lifecycle | P1 |
<a id="req-gw-certificat-005"></a><a id="risk-gw-certificat-005"></a>| `req-gw-certificat-005` | `risk-gw-certificat-005` | [tc-gw-certificat-005](04-gateway/06-certificates-dns/tc-gw-certificat-005/case.md#tc-gw-certificat-005) — CAA publication and validation | P1 |
<a id="req-gw-certificat-006"></a><a id="risk-gw-certificat-006"></a>| `req-gw-certificat-006` | `risk-gw-certificat-006` | [tc-gw-certificat-006](04-gateway/06-certificates-dns/tc-gw-certificat-006/case.md#tc-gw-certificat-006) — Certificate store SNI wildcard and hot reload | P1 |
<a id="req-gw-certificat-007"></a><a id="risk-gw-certificat-007"></a>| `req-gw-certificat-007` | `risk-gw-certificat-007` | [tc-gw-certificat-007](04-gateway/06-certificates-dns/tc-gw-certificat-007/case.md#tc-gw-certificat-007) — Certificate attestation history and ACME info | P0 |

<a id="audit-section-gateway-cluster-admin-observability"></a>
### Cluster Admin Observability

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gw-cluster-ad-001"></a><a id="risk-gw-cluster-ad-001"></a>| `req-gw-cluster-ad-001` | `risk-gw-cluster-ad-001` | [tc-gw-cluster-ad-001](04-gateway/07-cluster-admin-observability/tc-gw-cluster-ad-001/case.md#tc-gw-cluster-ad-001) — WaveKV bootstrap replication and convergence | P1 |
<a id="req-gw-cluster-ad-002"></a><a id="risk-gw-cluster-ad-002"></a>| `req-gw-cluster-ad-002` | `risk-gw-cluster-ad-002` | [tc-gw-cluster-ad-002](04-gateway/07-cluster-admin-observability/tc-gw-cluster-ad-002/case.md#tc-gw-cluster-ad-002) — WaveKV sync endpoint authentication and replay | P1 |
<a id="req-gw-cluster-ad-003"></a><a id="risk-gw-cluster-ad-003"></a>| `req-gw-cluster-ad-003` | `risk-gw-cluster-ad-003` | [tc-gw-cluster-ad-003](04-gateway/07-cluster-admin-observability/tc-gw-cluster-ad-003/case.md#tc-gw-cluster-ad-003) — Node URL and status administration | P1 |
<a id="req-gw-cluster-ad-004"></a><a id="risk-gw-cluster-ad-004"></a>| `req-gw-cluster-ad-004` | `risk-gw-cluster-ad-004` | [tc-gw-cluster-ad-004](04-gateway/07-cluster-admin-observability/tc-gw-cluster-ad-004/case.md#tc-gw-cluster-ad-004) — Connection handshake and node statistics | P1 |
<a id="req-gw-cluster-ad-005"></a><a id="risk-gw-cluster-ad-005"></a>| `req-gw-cluster-ad-005` | `risk-gw-cluster-ad-005` | [tc-gw-cluster-ad-005](04-gateway/07-cluster-admin-observability/tc-gw-cluster-ad-005/case.md#tc-gw-cluster-ad-005) — Admin authentication and listener isolation | P1 |
<a id="req-gw-cluster-ad-006"></a><a id="risk-gw-cluster-ad-006"></a>| `req-gw-cluster-ad-006` | `risk-gw-cluster-ad-006` | [tc-gw-cluster-ad-006](04-gateway/07-cluster-admin-observability/tc-gw-cluster-ad-006/case.md#tc-gw-cluster-ad-006) — Debug service isolation | P1 |
<a id="req-gw-cluster-ad-007"></a><a id="risk-gw-cluster-ad-007"></a>| `req-gw-cluster-ad-007` | `risk-gw-cluster-ad-007` | [tc-gw-cluster-ad-007](04-gateway/07-cluster-admin-observability/tc-gw-cluster-ad-007/case.md#tc-gw-cluster-ad-007) — Health dashboard and graceful exit | P1 |
<a id="req-gw-cluster-ad-008"></a><a id="risk-gw-cluster-ad-008"></a>| `req-gw-cluster-ad-008` | `risk-gw-cluster-ad-008` | [tc-gw-cluster-ad-008](04-gateway/07-cluster-admin-observability/tc-gw-cluster-ad-008/case.md#tc-gw-cluster-ad-008) — TLS crypto provider and protocol matrix | P1 |
<a id="req-gw-kv-009"></a><a id="risk-gw-kv-009"></a>| `req-gw-kv-009` | `risk-gw-kv-009` | [tc-gw-kv-009](04-gateway/07-cluster-admin-observability/tc-gw-kv-009/case.md#tc-gw-kv-009) — WaveKV key encoding corruption persistence and watch semantics | P0 |

<a id="audit-section-gateway-startup-auth-routing-internals"></a>
### Startup, Authorization, and Routing Internals

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gw-internal-001"></a><a id="risk-gw-internal-001"></a>| `req-gw-internal-001` | `risk-gw-internal-001` | [tc-gw-internal-001](04-gateway/08-startup-auth-routing-internals/tc-gw-internal-001/case.md#tc-gw-internal-001) — Gateway startup certificate mode and resource limits | P0 |
<a id="req-gw-internal-002"></a><a id="risk-gw-internal-002"></a>| `req-gw-internal-002` | `risk-gw-internal-002` | [tc-gw-internal-002](04-gateway/08-startup-auth-routing-internals/tc-gw-internal-002/case.md#tc-gw-internal-002) — Gateway debug key generation artifact safety | P0 |
<a id="req-gw-internal-003"></a><a id="risk-gw-internal-003"></a>| `req-gw-internal-003` | `risk-gw-internal-003` | [tc-gw-internal-003](04-gateway/08-startup-auth-routing-internals/tc-gw-internal-003/case.md#tc-gw-internal-003) — Gateway authorization client allow deny and outage | P0 |
<a id="req-gw-internal-004"></a><a id="risk-gw-internal-004"></a>| `req-gw-internal-004` | `risk-gw-internal-004` | [tc-gw-internal-004](04-gateway/08-startup-auth-routing-internals/tc-gw-internal-004/case.md#tc-gw-internal-004) — Raw TLS ClientHello SNI parser boundaries | P0 |
<a id="req-gw-internal-005"></a><a id="risk-gw-internal-005"></a>| `req-gw-internal-005` | `risk-gw-internal-005` | [tc-gw-internal-005](04-gateway/08-startup-auth-routing-internals/tc-gw-internal-005/case.md#tc-gw-internal-005) — TLS termination local routes and stream bridge | P0 |
<a id="req-gw-internal-006"></a><a id="risk-gw-internal-006"></a>| `req-gw-internal-006` | `risk-gw-internal-006` | [tc-gw-internal-006](04-gateway/08-startup-auth-routing-internals/tc-gw-internal-006/case.md#tc-gw-internal-006) — Port-policy filtering fetch retry and PP decision | P0 |
<a id="req-gw-internal-007"></a><a id="risk-gw-internal-007"></a>| `req-gw-internal-007` | `risk-gw-internal-007` | [tc-gw-internal-007](04-gateway/08-startup-auth-routing-internals/tc-gw-internal-007/case.md#tc-gw-internal-007) — Dashboard connection counters and policy provenance | P1 |
<a id="req-gw-internal-008"></a><a id="risk-gw-internal-008"></a>| `req-gw-internal-008` | `risk-gw-internal-008` | [tc-gw-internal-008](04-gateway/08-startup-auth-routing-internals/tc-gw-internal-008/case.md#tc-gw-internal-008) — Combined route index RPC exposure | P0 |

<a id="audit-section-gateway-certbot-engine"></a>
### Certbot ACME and DNS Engine

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-gw-certbot-001"></a><a id="risk-gw-certbot-001"></a>| `req-gw-certbot-001` | `risk-gw-certbot-001` | [tc-gw-certbot-001](04-gateway/09-certbot-engine/tc-gw-certbot-001/case.md#tc-gw-certbot-001) — ACME account creation load and credential persistence | P0 |
<a id="req-gw-certbot-002"></a><a id="risk-gw-certbot-002"></a>| `req-gw-certbot-002` | `risk-gw-certbot-002` | [tc-gw-certbot-002](04-gateway/09-certbot-engine/tc-gw-certbot-002/case.md#tc-gw-certbot-002) — DNS-01 authorization propagation and cleanup | P0 |
<a id="req-gw-certbot-003"></a><a id="risk-gw-certbot-003"></a>| `req-gw-certbot-003` | `risk-gw-certbot-003` | [tc-gw-certbot-003](04-gateway/09-certbot-engine/tc-gw-certbot-003/case.md#tc-gw-certbot-003) — Cloudflare DNS record API boundaries | P0 |
<a id="req-gw-certbot-004"></a><a id="risk-gw-certbot-004"></a>| `req-gw-certbot-004` | `risk-gw-certbot-004` | [tc-gw-certbot-004](04-gateway/09-certbot-engine/tc-gw-certbot-004/case.md#tc-gw-certbot-004) — Certificate renewal threshold force and hook | P0 |
<a id="req-gw-certbot-005"></a><a id="risk-gw-certbot-005"></a>| `req-gw-certbot-005` | `risk-gw-certbot-005` | [tc-gw-certbot-005](04-gateway/09-certbot-engine/tc-gw-certbot-005/case.md#tc-gw-certbot-005) — Certbot workdir archive live and rollback layout | P0 |
<a id="req-gw-certbot-006"></a><a id="risk-gw-certbot-006"></a>| `req-gw-certbot-006` | `risk-gw-certbot-006` | [tc-gw-certbot-006](04-gateway/09-certbot-engine/tc-gw-certbot-006/case.md#tc-gw-certbot-006) — Certbot CLI once daemon config and signal lifecycle | P1 |

<a id="audit-section-gw-build"></a>
### Gateway, Certbot, Cluster Harness, and Existing Regression Suite

| Requirement | Risk | Case | Priority |
|---|---|---|---|

<a id="audit-chapter-verifier"></a>
## Verifier

<a id="audit-section-verifier-input-platform-verification"></a>
### Input Platform Verification

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-ver-input-plat-001"></a><a id="risk-ver-input-plat-001"></a>| `req-ver-input-plat-001` | `risk-ver-input-plat-001` | [tc-ver-input-plat-001](05-verifier/01-input-platform-verification/tc-ver-input-plat-001/case.md#tc-ver-input-plat-001) — Verification input precedence and canonicalization | P1 |
<a id="req-ver-input-plat-002"></a><a id="risk-ver-input-plat-002"></a>| `req-ver-input-plat-002` | `risk-ver-input-plat-002` | [tc-ver-input-plat-002](05-verifier/01-input-platform-verification/tc-ver-input-plat-002/case.md#tc-ver-input-plat-002) — TDX quote signature collateral and TCB | P0 |
<a id="req-ver-input-plat-003"></a><a id="risk-ver-input-plat-003"></a>| `req-ver-input-plat-003` | `risk-ver-input-plat-003` | [tc-ver-input-plat-003](05-verifier/01-input-platform-verification/tc-ver-input-plat-003/case.md#tc-ver-input-plat-003) — TDX event log replay and RTMR status | P0 |
<a id="req-ver-input-plat-004"></a><a id="risk-ver-input-plat-004"></a>| `req-ver-input-plat-004` | `risk-ver-input-plat-004` | [tc-ver-input-plat-004](05-verifier/01-input-platform-verification/tc-ver-input-plat-004/case.md#tc-ver-input-plat-004) — TDX-lite measurement verification | P0 |
<a id="req-ver-input-plat-005"></a><a id="risk-ver-input-plat-005"></a>| `req-ver-input-plat-005` | `risk-ver-input-plat-005` | [tc-ver-input-plat-005](05-verifier/01-input-platform-verification/tc-ver-input-plat-005/case.md#tc-ver-input-plat-005) — SEV-SNP certificate and report verification | P0 |
<a id="req-ver-input-plat-006"></a><a id="risk-ver-input-plat-006"></a>| `req-ver-input-plat-006` | `risk-ver-input-plat-006` | [tc-ver-input-plat-006](05-verifier/01-input-platform-verification/tc-ver-input-plat-006/case.md#tc-ver-input-plat-006) — Cloud TDX and Nitro TPM verification | P0 |
<a id="req-ver-input-plat-007"></a><a id="risk-ver-input-plat-007"></a>| `req-ver-input-plat-007` | `risk-ver-input-plat-007` | [tc-ver-input-plat-007](05-verifier/01-input-platform-verification/tc-ver-input-plat-007/case.md#tc-ver-input-plat-007) — Simulator trust-root isolation | P1 |
<a id="req-ver-nitro-008"></a><a id="risk-ver-nitro-008"></a>| `req-ver-nitro-008` | `risk-ver-nitro-008` | [tc-ver-nitro-008](05-verifier/01-input-platform-verification/tc-ver-nitro-008/case.md#tc-ver-nitro-008) — Nitro Enclave document verification and debug rejection | P0 |

<a id="audit-section-verifier-image-measurements"></a>
### Image Measurements

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-ver-image-meas-001"></a><a id="risk-ver-image-meas-001"></a>| `req-ver-image-meas-001` | `risk-ver-image-meas-001` | [tc-ver-image-meas-001](05-verifier/02-image-measurements/tc-ver-image-meas-001/case.md#tc-ver-image-meas-001) — Image download digest and extraction security | P1 |
<a id="req-ver-image-meas-002"></a><a id="risk-ver-image-meas-002"></a>| `req-ver-image-meas-002` | `risk-ver-image-meas-002` | [tc-ver-image-meas-002](05-verifier/02-image-measurements/tc-ver-image-meas-002/case.md#tc-ver-image-meas-002) — Measurement computation determinism | P1 |
<a id="req-ver-image-meas-003"></a><a id="risk-ver-image-meas-003"></a>| `req-ver-image-meas-003` | `risk-ver-image-meas-003` | [tc-ver-image-meas-003](05-verifier/02-image-measurements/tc-ver-image-meas-003/case.md#tc-ver-image-meas-003) — ACPI table measurement and swtpm policy | P1 |
<a id="req-ver-image-meas-004"></a><a id="risk-ver-image-meas-004"></a>| `req-ver-image-meas-004` | `risk-ver-image-meas-004` | [tc-ver-image-meas-004](05-verifier/02-image-measurements/tc-ver-image-meas-004/case.md#tc-ver-image-meas-004) — Artifact manifest and image hash binding | P1 |
<a id="req-ver-image-meas-005"></a><a id="risk-ver-image-meas-005"></a>| `req-ver-image-meas-005` | `risk-ver-image-meas-005` | [tc-ver-image-meas-005](05-verifier/02-image-measurements/tc-ver-image-meas-005/case.md#tc-ver-image-meas-005) — Measurement cache correctness and concurrency | P1 |
<a id="req-ver-strategy-006"></a><a id="risk-ver-strategy-006"></a>| `req-ver-strategy-006` | `risk-ver-strategy-006` | [tc-ver-strategy-006](05-verifier/02-image-measurements/tc-ver-strategy-006/case.md#tc-ver-strategy-006) — Platform-specific OS image verification and download strategy | P0 |

<a id="audit-section-verifier-cli-cert-output"></a>
### Cli Cert Output

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-ver-cli-cert-o-001"></a><a id="risk-ver-cli-cert-o-001"></a>| `req-ver-cli-cert-o-001` | `risk-ver-cli-cert-o-001` | [tc-ver-cli-cert-o-001](05-verifier/03-cli-cert-output/tc-ver-cli-cert-o-001/case.md#tc-ver-cli-cert-o-001) — One-shot JSON verification interface | P1 |
<a id="req-ver-cli-cert-o-002"></a><a id="risk-ver-cli-cert-o-002"></a>| `req-ver-cli-cert-o-002` | `risk-ver-cli-cert-o-002` | [tc-ver-cli-cert-o-002](05-verifier/03-cli-cert-output/tc-ver-cli-cert-o-002/case.md#tc-ver-cli-cert-o-002) — Certificate RA extension verification | P0 |
<a id="req-ver-cli-cert-o-003"></a><a id="risk-ver-cli-cert-o-003"></a>| `req-ver-cli-cert-o-003` | `risk-ver-cli-cert-o-003` | [tc-ver-cli-cert-o-003](05-verifier/03-cli-cert-output/tc-ver-cli-cert-o-003/case.md#tc-ver-cli-cert-o-003) — OS image hash verification modes | P1 |
<a id="req-ver-cli-cert-o-004"></a><a id="risk-ver-cli-cert-o-004"></a>| `req-ver-cli-cert-o-004` | `risk-ver-cli-cert-o-004` | [tc-ver-cli-cert-o-004](05-verifier/03-cli-cert-output/tc-ver-cli-cert-o-004/case.md#tc-ver-cli-cert-o-004) — Result schema completeness and diagnostics | P1 |
<a id="req-ver-cli-cert-o-005"></a><a id="risk-ver-cli-cert-o-005"></a>| `req-ver-cli-cert-o-005` | `risk-ver-cli-cert-o-005` | [tc-ver-cli-cert-o-005](05-verifier/03-cli-cert-output/tc-ver-cli-cert-o-005/case.md#tc-ver-cli-cert-o-005) — Configuration validation and trust roots | P1 |
<a id="req-ver-cli-cert-o-006"></a><a id="risk-ver-cli-cert-o-006"></a>| `req-ver-cli-cert-o-006` | `risk-ver-cli-cert-o-006` | [tc-ver-cli-cert-o-006](05-verifier/03-cli-cert-output/tc-ver-cli-cert-o-006/case.md#tc-ver-cli-cert-o-006) — Offline fixtures regression suite | P1 |
<a id="req-ver-tcb-007"></a><a id="risk-ver-tcb-007"></a>| `req-ver-tcb-007` | `risk-ver-tcb-007` | [tc-ver-tcb-007](05-verifier/03-cli-cert-output/tc-ver-tcb-007/case.md#tc-ver-tcb-007) — Canonical TCB status advisory and auth-policy projection | P0 |

<a id="audit-section-verifier-measurement-tools"></a>
### Measurement Tools and Library APIs

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-ver-tools-001"></a><a id="risk-ver-tools-001"></a>| `req-ver-tools-001` | `risk-ver-tools-001` | [tc-ver-tools-001](05-verifier/04-measurement-tools/tc-ver-tools-001/case.md#tc-ver-tools-001) — dstack-mr supported platform CLI matrix | P0 |
<a id="req-ver-tools-002"></a><a id="risk-ver-tools-002"></a>| `req-ver-tools-002` | `risk-ver-tools-002` | [tc-ver-tools-002](05-verifier/04-measurement-tools/tc-ver-tools-002/case.md#tc-ver-tools-002) — dstack-mr boot artifact and cmdline boundaries | P0 |
<a id="req-ver-tools-003"></a><a id="risk-ver-tools-003"></a>| `req-ver-tools-003` | `risk-ver-tools-003` | [tc-ver-tools-003](05-verifier/04-measurement-tools/tc-ver-tools-003/case.md#tc-ver-tools-003) — Attestation encode decode round trip and versioning | P0 |
<a id="req-ver-tools-004"></a><a id="risk-ver-tools-004"></a>| `req-ver-tools-004` | `risk-ver-tools-004` | [tc-ver-tools-004](05-verifier/04-measurement-tools/tc-ver-tools-004/case.md#tc-ver-tools-004) — Verifier library concurrent API isolation | P1 |
<a id="req-ver-tools-005"></a><a id="risk-ver-tools-005"></a>| `req-ver-tools-005` | `risk-ver-tools-005` | [tc-ver-tools-005](05-verifier/04-measurement-tools/tc-ver-tools-005/case.md#tc-ver-tools-005) — Collateral and trust-root update lifecycle | P0 |
<a id="req-ver-tools-006"></a><a id="risk-ver-tools-006"></a>| `req-ver-tools-006` | `risk-ver-tools-006` | [tc-ver-tools-006](05-verifier/04-measurement-tools/tc-ver-tools-006/case.md#tc-ver-tools-006) — Verifier denial-of-service input limits | P0 |

<a id="audit-section-verifier-build-deployment"></a>
### Verifier Build and Deployment

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-ver-build-002"></a><a id="risk-ver-build-002"></a>| `req-ver-build-002` | `risk-ver-build-002` | [tc-ver-build-002](05-verifier/05-build-deployment/tc-ver-build-002/case.md#tc-ver-build-002) — Verifier default configuration and CLI override precedence | P0 |

<a id="audit-section-ver-buildall"></a>
### Verifier and Measurement Tool Existing Regression Suite

| Requirement | Risk | Case | Priority |
|---|---|---|---|

<a id="audit-chapter-integration"></a>
## Cross-component and Compatibility

<a id="audit-section-integration-end-to-end"></a>
### End To End

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-int-end-to-end-001"></a><a id="risk-int-end-to-end-001"></a>| `req-int-end-to-end-001` | `risk-int-end-to-end-001` | [tc-int-end-to-end-001](06-integration/01-end-to-end/tc-int-end-to-end-001/case.md#tc-int-end-to-end-001) — New application deployment trust chain | P0 |
<a id="req-int-end-to-end-002"></a><a id="risk-int-end-to-end-002"></a>| `req-int-end-to-end-002` | `risk-int-end-to-end-002` | [tc-int-end-to-end-002](06-integration/01-end-to-end/tc-int-end-to-end-002/case.md#tc-int-end-to-end-002) — Application upgrade trust continuity | P0 |
<a id="req-int-end-to-end-003"></a><a id="risk-int-end-to-end-003"></a>| `req-int-end-to-end-003` | `risk-int-end-to-end-003` | [tc-int-end-to-end-003](06-integration/01-end-to-end/tc-int-end-to-end-003/case.md#tc-int-end-to-end-003) — Encrypted environment delivery | P0 |
<a id="req-int-end-to-end-004"></a><a id="risk-int-end-to-end-004"></a>| `req-int-end-to-end-004` | `risk-int-end-to-end-004` | [tc-int-end-to-end-004](06-integration/01-end-to-end/tc-int-end-to-end-004/case.md#tc-int-end-to-end-004) — Gateway certificate attestation verification | P0 |
<a id="req-int-end-to-end-005"></a><a id="risk-int-end-to-end-005"></a>| `req-int-end-to-end-005` | `risk-int-end-to-end-005` | [tc-int-end-to-end-005](06-integration/01-end-to-end/tc-int-end-to-end-005/case.md#tc-int-end-to-end-005) — Multi-instance load balancing and isolation | P0 |

<a id="audit-section-integration-compatibility-upgrade"></a>
### Compatibility Upgrade

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-int-compatibil-001"></a><a id="risk-int-compatibil-001"></a>| `req-int-compatibil-001` | `risk-int-compatibil-001` | [tc-int-compatibil-001](06-integration/02-compatibility-upgrade/tc-int-compatibil-001/case.md#tc-int-compatibil-001) — Persisted state migration from v0.5.4, v0.5.8, and v0.5.11 | P0 |
<a id="req-int-compatibil-002"></a><a id="risk-int-compatibil-002"></a>| `req-int-compatibil-002` | `risk-int-compatibil-002` | [tc-int-compatibil-002](06-integration/02-compatibility-upgrade/tc-int-compatibil-002/case.md#tc-int-compatibil-002) — Rolling VMM upgrade with running mixed guests | P0 |
<a id="req-int-compatibil-003"></a><a id="risk-int-compatibil-003"></a>| `req-int-compatibil-003` | `risk-int-compatibil-003` | [tc-int-compatibil-003](06-integration/02-compatibility-upgrade/tc-int-compatibil-003/case.md#tc-int-compatibil-003) — Rolling KMS cluster upgrade and key continuity | P0 |
<a id="req-int-compatibil-004"></a><a id="risk-int-compatibil-004"></a>| `req-int-compatibil-004` | `risk-int-compatibil-004` | [tc-int-compatibil-004](06-integration/02-compatibility-upgrade/tc-int-compatibil-004/case.md#tc-int-compatibil-004) — Rolling gateway cluster upgrade | P0 |
<a id="req-int-compatibil-005"></a><a id="risk-int-compatibil-005"></a>| `req-int-compatibil-005` | `risk-int-compatibil-005` | [tc-int-compatibil-005](06-integration/02-compatibility-upgrade/tc-int-compatibil-005/case.md#tc-int-compatibil-005) — Verifier compatibility across evidence versions | P0 |
<a id="req-int-compatibil-006"></a><a id="risk-int-compatibil-006"></a>| `req-int-compatibil-006` | `risk-int-compatibil-006` | [tc-int-compatibil-006](06-integration/02-compatibility-upgrade/tc-int-compatibil-006/case.md#tc-int-compatibil-006) — RPC unknown-field and optional-field compatibility | P0 |

<a id="audit-section-integration-failure-security"></a>
### Failure Security

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-int-failure-se-001"></a><a id="risk-int-failure-se-001"></a>| `req-int-failure-se-001` | `risk-int-failure-se-001` | [tc-int-failure-se-001](06-integration/03-failure-security/tc-int-failure-se-001/case.md#tc-int-failure-se-001) — KMS unavailable during boot and recovery | P0 |
<a id="req-int-failure-se-002"></a><a id="risk-int-failure-se-002"></a>| `req-int-failure-se-002` | `risk-int-failure-se-002` | [tc-int-failure-se-002](06-integration/03-failure-security/tc-int-failure-se-002/case.md#tc-int-failure-se-002) — Gateway unavailable registration and recovery | P0 |
<a id="req-int-failure-se-003"></a><a id="risk-int-failure-se-003"></a>| `req-int-failure-se-003` | `risk-int-failure-se-003` | [tc-int-failure-se-003](06-integration/03-failure-security/tc-int-failure-se-003/case.md#tc-int-failure-se-003) — VMM crash during every lifecycle transaction | P0 |
<a id="req-int-failure-se-004"></a><a id="risk-int-failure-se-004"></a>| `req-int-failure-se-004` | `risk-int-failure-se-004` | [tc-int-failure-se-004](06-integration/03-failure-security/tc-int-failure-se-004/case.md#tc-int-failure-se-004) — Certificate and clock boundary behavior | P0 |
<a id="req-int-failure-se-005"></a><a id="risk-int-failure-se-005"></a>| `req-int-failure-se-005` | `risk-int-failure-se-005` | [tc-int-failure-se-005](06-integration/03-failure-security/tc-int-failure-se-005/case.md#tc-int-failure-se-005) — Credential and secret redaction audit | P0 |
<a id="req-int-failure-se-006"></a><a id="risk-int-failure-se-006"></a>| `req-int-failure-se-006` | `risk-int-failure-se-006` | [tc-int-failure-se-006](06-integration/03-failure-security/tc-int-failure-se-006/case.md#tc-int-failure-se-006) — Resource exhaustion and backpressure | P0 |
<a id="req-int-failure-se-007"></a><a id="risk-int-failure-se-007"></a>| `req-int-failure-se-007` | `risk-int-failure-se-007` | [tc-int-failure-se-007](06-integration/03-failure-security/tc-int-failure-se-007/case.md#tc-int-failure-se-007) — Network partition consistency matrix | P0 |
<a id="req-int-failure-se-008"></a><a id="risk-int-failure-se-008"></a>| `req-int-failure-se-008` | `risk-int-failure-se-008` | [tc-int-failure-se-008](06-integration/03-failure-security/tc-int-failure-se-008/case.md#tc-int-failure-se-008) — Simulator versus hardware evidence separation | P0 |

<a id="audit-section-integration-pinned-mixed-version-matrix"></a>
### Pinned Mixed-Version Online Matrix

| Requirement | Risk | Case | Priority |
|---|---|---|---|
<a id="req-int-mixed-001"></a><a id="risk-int-mixed-001"></a>| `req-int-mixed-001` | `risk-int-mixed-001` | [tc-int-mixed-001](06-integration/04-pinned-mixed-version-matrix/tc-int-mixed-001/case.md#tc-int-mixed-001) — Latest VMM hosts the full pinned guest matrix | P0 |
<a id="req-int-mixed-002"></a><a id="risk-int-mixed-002"></a>| `req-int-mixed-002` | `risk-int-mixed-002` | [tc-int-mixed-002](06-integration/04-pinned-mixed-version-matrix/tc-int-mixed-002/case.md#tc-int-mixed-002) — Mixed KMS versions remain online during application operations | P0 |
<a id="req-int-mixed-003"></a><a id="risk-int-mixed-003"></a>| `req-int-mixed-003` | `risk-int-mixed-003` | [tc-int-mixed-003](06-integration/04-pinned-mixed-version-matrix/tc-int-mixed-003/case.md#tc-int-mixed-003) — Mixed gateway versions route old and new guests | P0 |
<a id="req-int-mixed-004"></a><a id="risk-int-mixed-004"></a>| `req-int-mixed-004` | `risk-int-mixed-004` | [tc-int-mixed-004](06-integration/04-pinned-mixed-version-matrix/tc-int-mixed-004/case.md#tc-int-mixed-004) — Gateway replacement matrix after KMS cutover | P0 |
<a id="req-int-mixed-005"></a><a id="risk-int-mixed-005"></a>| `req-int-mixed-005` | `risk-int-mixed-005` | [tc-int-mixed-005](06-integration/04-pinned-mixed-version-matrix/tc-int-mixed-005/case.md#tc-int-mixed-005) — Verifier evidence compatibility for pinned releases | P0 |
<a id="req-int-mixed-006"></a><a id="risk-int-mixed-006"></a>| `req-int-mixed-006` | `risk-int-mixed-006` | [tc-int-mixed-006](06-integration/04-pinned-mixed-version-matrix/tc-int-mixed-006/case.md#tc-int-mixed-006) — Rolling restart under four-version online mix | P0 |
<a id="req-int-mixed-007"></a><a id="risk-int-mixed-007"></a>| `req-int-mixed-007` | `risk-int-mixed-007` | [tc-int-mixed-007](06-integration/04-pinned-mixed-version-matrix/tc-int-mixed-007/case.md#tc-int-mixed-007) — Optional and unknown protobuf fields across pinned versions | P0 |
