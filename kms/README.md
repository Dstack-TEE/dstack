# dstack - KMS Protocol

## Overview

CVMs running in dstack support three boot modes:
- **Non-KMS Mode** (stateless)
- **Local-Key-Provider Mode** (stateful, no upgrades)
- **KMS Mode** (stateful, upgradeable)

### Boot Mode Details

#### Non-KMS Mode
- Generates ephemeral app keys on startup
- No persistent disk state
- No external key provider required
- `app-id` must equal `compose-hash`
- `key-provider` in RTMR: `{"type": "none", "id": ""}`

#### Local-Key-Provider Mode
- Uses `gramine-sealing-key-provider` for app keys
- Maintains persistent disk state
- Validates key provider via SGX quote
- `key-provider` in RTMR: `{"type": "local-sgx", "id": "<sgx mrenclave>"}`
- `app-id` must equal `compose-hash`

#### KMS Mode
- Enables flexible `app-id` validation in KMS
- Supports application upgrades
- Requires control contract configuration
- `key-provider` in RTMR: `{"type": "kms", "id": "<kms-root-pubkey>"}`
- `app-id` is derived from the deployer's eth address + salt

## KMS Implementation

### Components
1. **dstack-kms**
   - Main RPC service for app key requests
   - Quote verification and boot info validation
   - Asks `dstack-kms-auth-eth` for permission
   - Builtin Replicator for root keys

2. **dstack-kms-auth-eth**
   - Chain interface for permission checks
   - Two-step validation:
     1. KMS control contract check
     2. App control contract check

3. **Authorization Contracts**
   - `DstackKms.sol`
      - Maintains a registry for all Applications
      - Maintains the allowed KMS Instance MRs
      - Maintains the allowed OS Images
      - Registers KMS root keys
   - `DstackApp.sol`
      - Apps can have either a dedicated `DstackApp` contract or share one with multiple apps
      - Controls permissions for individual apps
      - Maintains the allowed compose hashes for each app

### Deployment
The first two components are deployed as an dstack app on dstack in Local-Key-Provider mode.
The docker compose file would look like [this](dstack-app/docker-compose.yaml).

The solidity contracts are deployed on an ethereum compatible chain.


## Trustness

### Local-Key-Provider Mode
A instance of [`gramine-sealing-key-provider`](https://github.com/MoeMahhouk/gramine-sealing-key-provider) is required being deployed on the host machine. Can be deployed by [../key-provider-build](../key-provider-build/run.sh).

In this mode, the CVM obtains application keys from the `gramine-sealing-key-provider`, which runs within an SGX enclave. The provider derives the application keys using:
- The SGX sealing key
- CVM measurements, including:
  - MRTD + RTMR[0-2]: Base image and VM configuration measurements
  - RTMR[3]: Runtime application configuration

The key provisioning process:
1. The CVM validates the SGX quote from `gramine-sealing-key-provider`
2. After obtaining the keys, the CVM records the provider's MR enclave in RTMR3
3. Applications can verify trust by validating measurements in the TDX quote

### KMS Mode

KMS itself runs as a dstack app in Local-Key-Provider mode,
allowing it to persist keys on its local disk but not across machines.

On startup, the KMS node will either:
- Bootstrap: Set up a new KMS instance
- Onboard: Obtain root keys from an existing KMS instance

#### Bootstrapping
During bootstrapping, the KMS node generates two root keys:
1. CA root key: Used to issue x509 certificates for Apps, enabling HTTPS traffic
2. K256 root key: Used to derive Ethereum-compatible keys for Apps

After generating the root keys, their public portions can be obtained along with the corresponding TDX quote and registered in the DstackKms contract.

#### KMS Self Replication
When deploying a new KMS instance (`B`) using an existing instance (`A`), the process follows these steps:

1. **Prerequisites**
   - Register allowed MRs of instance `B` in the DstackKms contract

2. **Replication Flow**
   - Configure instance `B` with the URL of existing instance `A`
   - Instance `B` sends replication request to instance `A` via RA-TLS based RPC
   - Instance `A` validates instance `B`'s TDX quote
   - Instance `A` checks DstackKms contract for permissions
   - If approved, instance `A` transfers root keys to instance `B`

After the replication is complete, the KMS node becomes a fully functional KMS node.
Both instances now share identical root keys, and either instance can service App key requests.

#### App Key Provisioning

Once onboarded, the KMS node begins listening for app key provisioning requests.

When a KMS node receives a key provisioning request, it:
1. Validates the TDX quote of the requesting App
2. Queries the DstackKms contract for provisioning allowance
3. If allowed, generates and sends the keys to the App

### Attestation

#### Vanilla TDX Quote attestation

See [Attestation](../attestation.md) for more details.

#### Validating Apps via the KMS Auth Chain

The KMS performs TDX quote validation for Apps running in dstack and issues signed app keys to them.

As a simpler approach, an App can verify the signature chain using the KMS root key as the root trust anchor.

For example, given a message `M` signed by an App with signature `Sm`, the chain of trust works as follows:

1. The KMS maintains the root key `sK0`, with its corresponding public key `pK0` registered in the DstackKms contract
2. The App receives an app-key `sK1` from the KMS, along with signature `S1` (signed by `sK0`)
3. The App derives a purpose-specific key `sK2` from `sK1`, with signature `S2` (signed by `sK1`)
4. The App uses `sK2` to sign message `M`, producing signature `Sm`

To verify the signature chain, all of `M`, `Sm`, `S1`, and `S2` are required.

The verification process follows these steps:

1. Recover `pK2` from `Sm` and `M`
2. Recover `pK1` from `S2` and `pK2` + `<purpose-id>`
3. Recover `pK0` from `S1` and `pK1` + `<app-id>`
4. Compare the recovered `pK0` with the registered `pK0` in the DstackKms contract

## The RPC Interface

The KMS RPC interface is defined in [kms_rpc.proto](rpc/proto/kms_rpc.proto).

The core interface serving the dstack app are:
- `GetAppKey`: Requests an app key using the app ID and TDX quote
- `GetAppEnvEncryptPubKey`: Requests the app environment encryption public key using the app ID
- `SignCert`: Signs a certificate

Let's explain each one:

### GetAppKey

The `GetAppKey` RPC is used by the dstack app to request an app key. In this RPC, the KMS node will:

- Verify the TDX quote and extract the app ID and MRs from it
- Query the smart contract to check if the app is authorized to request the app key
- If authorized, derive the app keys from the root key and app ID
- Sign the app keys with the root key
- Return the app keys to the app


Note:
There are multiple keys derived for different usage, see [kms_rpc.proto](rpc/proto/kms_rpc.proto) for more details.
The root key is generated by a genesis KMS node in TEE and would be stored in the KMS node's encrypted local disk, replicated to other KMS nodes.
The keys are derived with app id which guarantees apps can not get the keys from other apps.

### GetAppEnvEncryptPubKey

The `GetAppEnvEncryptPubKey` RPC is used by the frontend web page to request the app environment encryption public key when deploying a new app. This key is used to encrypt the app environment variables, which can only be decrypted by the app in TEE.

### SignCert

The `SignCert` RPC is used by the dstack app to sign a TLS certificate. In this RPC, the KMS node will:

- Verify the TDX quote and extract the Certificate Signing Request (CSR)
- Verify the CSR signature
- Query the smart contract to check if the app is authorized
- If authorized, sign the CSR with the CA root key and return the certificate chain to the app
