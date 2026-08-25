This document describes the dstack defined information exchange channels between CVM and the outside world.

## Network layer

### Virtual Native Network
dstack currently uses QEMU's user-mode network stack to create a virtual network for the CVM. In this setup, QEMU (running on the host) simulates the gateway, DNS, and DHCP services. The CVM should treat these network components as untrusted.

### Wireguard Network
When dstack-gateway is enabled, it establishes a secure Wireguard network connection between the workload CVM and dstack-gateway CVM.
External clients connect to the workload CVM through dstack-gateway using the CVM's ZT-HTTPS domain. For clients, ZT-HTTPS ensures no man-in-the-middle attacks can occur between them and the workload CVM. However, workload developers should note that incoming traffic might come from either dstack-gateway or the QEMU native network.

## Host Shared Folder
dstack OS requires a host shared folder to be attached to the CVM. It copies the following files from the host shared folder to the CVM:

| File | Purpose |
|------|--------|
| app-compose.json | Main application configuration |
| .instance-info | Instance metadata |
| .sys-config.json | System configuration |
| .encrypted-env | Encrypted environment variables |
| .user-config | Application-specific configuration |

### app-compose.json
This is the main configuration file for the application in JSON format:

| Field | Since | Type | Description |
|-------|-------|------|-------------|
| manifest_version | 0.3.1 | integer | Schema version (currently defaults to "2") |
| name | 0.3.1 | string | Name of the instance |
| runner | 0.3.1 | string | Name of the runner (currently defaults to "docker-compose") |
| docker_compose_file | 0.3.1 | string | YAML string representing docker-compose config |
| docker_config | 0.3.1 | object | (Removed since 0.5.5) Additional docker settings (currently empty) |
| kms_enabled | 0.3.1 | boolean | Enable/disable KMS |
| gateway_enabled | 0.3.1 | boolean | Enable/disable gateway |
| local_key_provider_enabled | 0.3.1 | boolean | Use a local key provider |
| key_provider_id | 0.5.1 | string | Optional pin for the key provider identity (hex-encoded bytes). For `kms` this is the KMS CA public key; for `local` the sealing-provider MR. For `tpm` and `none` it must be an empty string — the TPM app-root public key is instance-specific and is not used as a provider id or measured as one. |
| public_logs | 0.3.3 | boolean | Whether logs are publicly visible |
| public_sysinfo | 0.3.3 | boolean | Whether system info is public |
| public_tcbinfo | 0.5.1 | boolean | Whether TCB info is public |
| allowed_envs | 0.4.2 | array of string | List of allowed environment variable names |
| no_instance_id | 0.4.2 | boolean | Disable instance ID generation |
| secure_time | 0.5.0 | boolean | Whether secure time is enabled |
| pre_launch_script | 0.4.0 | string | Prelaunch bash script that runs before `docker compose up`. It runs *after* dockerd, so containers restored by a Docker restart policy can already be running when it executes. Do not build security gates on it — see [security-best-practices.md](./security-best-practices.md#security-semantics-must-not-depend-on-pre_launch_script-running-first). |
| init_script | 0.5.5 (string), 0.6.0 (string[]) | string or string[] | Up to 5 Bash scripts executed in order prior to dockerd startup, so they always complete before any container starts, on every boot; a string is treated as a one-element array. Multiple scripts require string `manifest_version: "3"` so older guests fail closed. MrConfigV3 binds the hashes only for manifest v3. |
| storage_fs | 0.5.5 | string | Filesystem type for the data disk of the CVM. Supported values: "zfs", "ext4". default to "zfs". **ZFS:** Ensures filesystem integrity with built-in data protection features. **ext4:** Provides better performance for database applications with lower overhead and faster I/O operations, but no strong integrity protection. |
| swap_size | 0.5.5 | string/integer | The linux swap size. default to 0. Can be in byte or human-readable format (e.g., "1G", "256M"). |
| key_provider | 0.5.6 | string | Key provider type. Supported values: "none", "kms", "local", "tpm". GCP vTPM and AWS EC2 NitroTPM are part of their platform trust models. The Dstack platform can use VMM-managed swtpm for seal/unseal and restart persistence, but it offers no protection against the host and is intentionally not accepted by remote verifiers. |

The five-script limit bounds runtime-event-log and MrConfigV3 growth while
allowing several independently approved infrastructure initialization stages.

The hash of this file content is extended as the dstack `compose-hash` launch event. On TDX-family platforms the launch event is measured into RTMR3. On AWS NitroTPM it is measured into non-resettable SHA384 PCR14 before the `system-ready` launch boundary. Remote verifiers extract and replay this event during attestation.


### .instance-info
This file contains metadata about the application instance:

| Field | Description |
|-------|-------------|
| app_id | The application ID. This is the deploy-time `app_id` from this file; when it is unset it defaults to the SHA256 digest of the app-compose.json (truncated to the first 20 bytes). The deploy-time value is honored in all key-provider modes. |
| instance_id | The instance ID, determined by the SHA256 digest of the instance_id_seed || app_id (truncated to the first 20 bytes). Empty if no_instance_id is true in app-compose.json |
| instance_id_seed | The random seed that determines the instance ID |

The hash of this file is not extended as a single measurement. Instead, the `app_id` and `instance_id` are extended as separate dstack launch events named `app-id` and `instance-id`. On TDX-family platforms those events go into RTMR3. On AWS NitroTPM they go into SHA384 PCR14.

> Because `app_id` can be pinned at deploy time (it is not necessarily derived from
> `compose_hash`), a relying party that authorizes on `app_id` MUST also verify the
> `compose_hash` independently — the two are separate measurements.

### .sys-config.json

This file contains system configuration in JSON format:

| Field | Type | Description |
|-------|------|-------------|
| kms_urls | array of string | List of KMS service URLs |
| gateway_urls | array of string | List of gateway service URLs |
| pccs_url | string | URL of the PCCS service (used when dstack components need to verify a remote TD CVM or SGX enclave) |
| nvidia_attestation_proxy_url | string | Optional persistent OCSP and RIM cache used by NVIDIA local GPU attestation |
| docker_registry | string | URL of the docker registry |
| host_api_url | string | VSOCK URL of host API |
| vm_config | string | JSON string of VM configuration (os_image_hash, cpu_count, memory_size) |

The hash of this file is not extended to any RTMR because each field has its own security mechanism:

| Field | Security Mechanism |
|-------|-------------------|
| kms_urls | URLs themselves aren't security-critical. The trust anchor is the KMS root public key, which is extended as the `key-provider` launch event. On TDX-family platforms this is RTMR3; on AWS NitroTPM this is PCR14. Keys obtained from KMS will either successfully decrypt/encrypt the disk or fail-and-abort. |
| gateway_urls | URLs aren't security-critical. Trust is established through CA certificates from KMS. App CVM and dstack-gateway CVM verify each other's CA certificates to ensure they're under the same KMS authority. |
| pccs_url | URL isn't security-critical. Trust is anchored by the root public key pinned in the attestation verification program. |
| nvidia_attestation_proxy_url | The URL is not a collateral trust anchor. The measured guest verifies NVIDIA signatures and the signed OCSP validity window, and continues to require a fresh GPU evidence nonce. A bad endpoint can withhold collateral and cause a denial of service, but cannot forge a successful attestation or replay an expired `good` response. |
| docker_registry | Docker daemon verifies image integrity using the pinned image hashes in the docker-compose file. |
| host_api_url | Used only for reporting or encrypted sealing key transport. An incorrect URL doesn't create security vulnerabilities. |
| vm_config | Informs the CVM to report virtual hardware info to KMS when requesting keys. KMS uses this info to calculate expected RTMRs and verify image hash. If tampered with, image hash verification would fail and no keys would be distributed. |

It does not make sense to measure the entire sys-config.json, because it is not deterministic and measuring it would make the verification process troublesome.

### .encrypted-env
dstack uses encrypted environment variables to allow app developers to securely load sensitive configuration values into the CVM. Since these variables are temporarily stored on the host server before being loaded into the CVM, encryption ensures host servers cannot access the confidential data.

#### Encryption Workflow:

1. **Initial Setup**:
   - App developer specifies required environment variables in app-compose.json via VMM client Web UI or CLI

2. **Client-Side Encryption**:
   - VMM client fetches the App's encryption public key from KMS using the app_id
   - KMS provides the public key with an ECDSA k256 signature
   - VMM client verifies the signature to confirm the encryption public key is legitimate
   - VMM client then:
     * Converts environment variables to JSON bytes
     * Generates an ephemeral X25519 key pair
     * Computes a shared secret using the ephemeral private key and encryption public key
     * Uses the shared key as a 32-byte key for AESGCM
     * Encrypts the JSON with AESGCM using a random IV
     * Creates final encrypted value: ephemeral public key || IV || ciphertext

3. **Deployment**:
   - App developer deploys the App with all configuration and encrypted values
   - VMM server stores this as .encrypted-env in the shared host directory

4. **CVM Decryption Process**:
   - CVM requests app keys from KMS using env_crypt_key (equivalent to encryption public key's private key)
   - CVM derives the shared secret using the ephemeral public key via X25519 key exchange
   - CVM decrypts the ciphertext using AESGCM with the derived shared secret
   - CVM parses the JSON and only stores variables listed in allowed_envs from app-compose.json
   - CVM performs basic regex validation on values
   - Final result is stored as /dstack/.hostshared/.decrypted-env and loaded system-wide via app-compose.service

This file is not measured to RTMRs. But it is highly recommended to add application-specific integrity checks on encrypted environment variables at the application layer. See [security-best-practices.md](./security-best-practices.md) for more details.

### .user-config
This is an optional application-specific configuration file that applications inside the CVM can access. dstack OS simply stores it at /dstack/.host-shared/.user-config without any measurement or additional processing, unless `requirements.launch_token_hash` is set in app-compose.json — in that case the guest reads the launch token from JSON path `dstack.launch_token` in this file and fails closed at boot, before key provisioning, unless its SHA-256 matches the pinned hash.

Application developers should perform integrity checks on user_config at the application layer if necessary.

## APIs

dstack provides several API services for communication between components. These APIs define the boundaries and information exchange channels between the CVM and external systems.

### VSOCK-based Guest API Service

The dstack-guest-agent listens on VSOCK port 8000 inside the CVM, providing interfaces for the dstack-vmm to query guest information and gracefully shut down the guest.

| Service | Purpose |
|---------|--------|
| GuestApi | Provides guest information and control functions |

**Available Methods:**

| Method | Description | Return Type |
|--------|-------------|------------|
| Info | Get basic guest information | GuestInfo |
| SysInfo | Get system information | SystemInfo |
| NetworkInfo | Get network configuration | NetworkInformation |
| ListContainers | List running containers | ListContainersResponse |
| Shutdown | Gracefully shut down the guest | Empty |

Full specification: [guest_api.proto](../../dstack/guest-api/proto/guest_api.proto)

### VSOCK-based Host API Service

The dstack-vmm listens on a configured VSOCK port on the bare-metal host system. This service allows the CVM to report boot progress and retrieve keys from the local key provider.

| Service | Purpose |
|---------|--------|
| HostApi | Provides host information and key management |

**Available Methods:**

| Method | Description | Parameters | Return Type |
|--------|-------------|------------|------------|
| Info | Get host information | Empty | HostInfo |
| Notify | Send notification to host | Notification | Empty |
| GetSealingKey | Retrieve sealing key | GetSealingKeyRequest | GetSealingKeyResponse |

Full specification: [host_api.proto](../../dstack/host-api/proto/host_api.proto)

### HTTP-based Public Guest API Service

The dstack-guest-agent runs an HTTP server on port 8090 inside the CVM. This port is publicly accessible, allowing external clients to view basic CVM information.

Since dstack 0.6.0 the listener serves two API surfaces, selected by URL path
alone: the frozen v0.5.11 `Worker` service at `/prpc` (equivalently
`/prpc/v0`), and the versioned `dstack.guest.v1` `Worker` service at
`/prpc/v1`. The frozen surface is closed and never changes again; new
capability arrives only on v1. [guest-api-v1.md](../guest-api-v1.md) is the
normative specification of the v1 surface, including its status-code and
version-probing rules.

Neither surface returns key material, and no caller chooses what gets signed
or attested. That boundary, not the method list, is what makes this listener
safe to expose: key material and caller-chosen attestation live only on the
internal Unix socket (`/var/run/dstack.sock`), which is not a CVM boundary —
it is reachable only by the application itself. An application that re-exports
that socket has moved the boundary itself, and everything behind it moves with
it.

**Frozen `Worker` (`/prpc`, alias `/prpc/v0`):**

| Method | Description | Return Type |
|--------|-------------|------------|
| Info | Get application information | AppInfo |
| Version | Get guest agent version | WorkerVersion |
| GetAttestationForAppKey | Attest the key the agent derives for the app | GetQuoteResponse |

**v1 `Worker` (`/prpc/v1`):**

| Method | Description | Return Type |
|--------|-------------|------------|
| Info | Get application identity, plus configuration when `public_tcbinfo` is set | InfoResponse |
| Version | Get guest agent version | VersionResponse |
| Health | Report whether the application is serving | HealthResponse |

Everything on this listener is unauthenticated, so each method is bounded in
what it costs and in what it says:

- `Health` (v1) answers from a cache the agent refreshes on its own timer, so a
  call costs a lock and a clone however many callers there are. It reveals
  whether the app opted into health gating, its current verdict, and — when the
  app declared a `health_status_file` — the path it named and which parsing
  rule failed. That last part is a narrow oracle for whether a path exists and
  what shape its first two lines have; the path itself is already public, since
  it is measured into the compose hash. The file's *contents* are never quoted
  back. Container names and statuses were already public through the dashboard
  below.
- `GetAttestationForAppKey` (frozen) generates a fresh platform attestation per
  call. With the frozen `Info` below, it is one of the two methods here that
  let an anonymous caller drive quote generation. It has no v1 counterpart
  on purpose: a v1 application attests its own key through the internal socket
  (`/v1/GetKey`, then `/v1/Attest`) and serves the result itself, so the public
  listener never gained a second attestation-on-demand entry point.
- The frozen `Info` decodes identity out of a boot attestation per call, which
  costs a hardware quote under the agent's global quote lock. The v1 `Info`
  serves the same identity from a cache decoded once at startup, so an
  anonymous caller cannot drive quote generation through it; if the boot-time
  decode failed, retries are throttled to one attempt per interval. Of the two
  quote-generating methods, the frozen `Info` is the one worth rate-limiting
  first: it is what clients actually poll, and it replays the event log on top
  of the quote.
- Both `Info` methods honour the app's `public_tcbinfo` choice, with different
  reach. The frozen one blanks `tcb_info` and `vm_config` but always serves
  `key_provider_info`. The v1 one blanks `app_compose`, `vm_config`, and
  `key_provider_info`, and carries no measurement registers or event log at
  all — those are attestation data and belong to the internal `Attest`, where
  a quote vouches for them. Identity and the measurement hashes are always
  visible on both surfaces.

The service also provides a web dashboard at the root URL (`/`) showing basic CVM information. View the dashboard template [here](../../dstack/guest-agent/templates/dashboard.html).

Full specifications: [agent_rpc.proto](../../dstack/guest-agent/rpc/proto/agent_rpc.proto) for the frozen surface, [agent_rpc_v1.proto](../../dstack/guest-agent/rpc/proto/agent_rpc_v1.proto) for v1.
