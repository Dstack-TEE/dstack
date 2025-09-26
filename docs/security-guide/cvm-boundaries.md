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

| Field | Type | Description |
|-------|------|-------------|
| manifest_version | integer | Schema version (currently defaults to "2") |
| name | string | Name of the instance |
| runner | string | Name of the runner (currently defaults to "docker-compose") |
| docker_compose_file | string | YAML string representing docker-compose config |
| docker_config | object | Additional docker settings (currently empty) |
| kms_enabled | boolean | Enable/disable KMS |
| gateway_enabled | boolean | Enable/disable gateway |
| public_logs | boolean | Whether logs are publicly visible |
| public_sysinfo | boolean | Whether system info is public |
| public_tcbinfo | boolean | Whether TCB info is public |
| local_key_provider_enabled | boolean | Use a local key provider |
| allowed_envs | array of string | List of allowed environment variable names |
| no_instance_id | boolean | Disable instance ID generation |
| secure_time | boolean | Whether secure time is enabled |
| pre_launch_script | string | Prelaunch bash script that runs before execute `docker compose up` |
| init_script | string | Bash script that executed prior to dockerd startup |
| storage_fs | string | Filesystem type for the data disk of the CVM. Supported values: "zfs", "ext4". default to "zfs". **ZFS:** Ensures filesystem integrity with built-in data protection features. **ext4:** Provides better performance for database applications with lower overhead and faster I/O operations, but no strong integrity protection. |


The hash of this file content is extended to RTMR3 as event name `compose-hash`. Remote verifier can extract the compose-hash during remote attestation.


### .instance-info
This file contains metadata about the application instance:

| Field | Description |
|-------|-------------|
| app_id | The application ID, determined by the SHA256 digest of the app-compose.json (truncated to the first 20 bytes) |
| instance_id | The instance ID, determined by the SHA256 digest of the instance_id_seed || app_id (truncated to the first 20 bytes). Empty if no_instance_id is true in app-compose.json |
| instance_id_seed | The random seed that determines the instance ID |

The hash of this file is not extended to any RTMR. Instead, the `app_id` and `instance_id` are extended to RTMR3 as event name `app-id` and `instance-id` respectively.

### .sys-config.json

This file contains system configuration in JSON format:

| Field | Type | Description |
|-------|------|-------------|
| kms_urls | array of string | List of KMS service URLs |
| gateway_urls | array of string | List of gateway service URLs |
| pccs_url | string | URL of the PCCS service (used when dstack components need to verify a remote TD CVM or SGX enclave) |
| docker_registry | string | URL of the docker registry |
| host_api_url | string | VSOCK URL of host API |
| vm_config | string | JSON string of VM configuration (os_image_hash, cpu_count, memory_size) |

The hash of this file is not extended to any RTMR because each field has its own security mechanism:

| Field | Security Mechanism |
|-------|-------------------|
| kms_urls | URLs themselves aren't security-critical. The trust anchor is the KMS root public key, which is extended to RTMR3 as event name `key-provider`. Keys obtained from KMS will either successfully decrypt/encrypt the disk or fail-and-abort. |
| gateway_urls | URLs aren't security-critical. Trust is established through CA certificates from KMS. App CVM and dstack-gateway CVM verify each other's CA certificates to ensure they're under the same KMS authority. |
| pccs_url | URL isn't security-critical. Trust is anchored by the root public key pinned in the attestation verification program. |
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

This file is not measured to RTMRs. But it is highly recommended to add application-specific integrity checks on encrypted environment variables at the application layer. See [security-guide.md](security-guide.md) for more details.

### .user-config
This is an optional application-specific configuration file that applications inside the CVM can access. dstack OS simply stores it at /dstack/user-config without any measurement or additional processing.

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

Full specification: [guest_api.proto](../../guest-api/proto/guest_api.proto)

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

Full specification: [host_api.proto](../../host-api/proto/host_api.proto)

### HTTP-based Public Guest API Service

The dstack-guest-agent runs an HTTP server on port 8090 inside the CVM. This port is publicly accessible, allowing external clients to view basic CVM information.

| Service | Purpose |
|---------|--------|
| Worker | Provides public-facing app information |

**Available Methods:**

| Method | Description | Return Type |
|--------|-------------|------------|
| Info | Get application information | AppInfo |
| Version | Get guest agent version | WorkerVersion |

The service also provides a web dashboard at the root URL (`/`) showing basic CVM information. View the dashboard template [here](../../guest-agent/templates/dashboard.html).

Full specification: [agent_rpc.proto](../../guest-agent/rpc/proto/agent_rpc.proto)
