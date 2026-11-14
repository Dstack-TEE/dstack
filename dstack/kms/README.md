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
- Uses `local-key-provider` for app keys
- Maintains persistent disk state
- Validates key provider via SGX quote
- `key-provider` in RTMR: `{"type": "local-sgx", "id": "<sgx mrenclave>"}`
- `app-id` must equal `compose-hash`

#### KMS Mode
- Enables flexible `app-id` validation in KMS
- Supports application upgrades
- Requires control contract configuration
- `key-provider` in RTMR: `{"type": "kms", "id": "<kms-root-pubkey>"}`
- `app-id` is equal to the address of the deployed App Smart Contract.

## Admin API authentication

The KMS public RPCs authenticate callers by RA-TLS attestation. Operator-facing
admin RPCs are instead served on a **separate admin
listener** (`[core.admin]` in `kms.toml`) behind the same shared HTTP
authenticator used by the VMM and gateway, configured identically to the gateway
admin API, so the credential travels in the `Authorization: Bearer <token>` or
`X-Admin-Token: <token>` header:

```toml
[core.admin]
enabled = true
address = "127.0.0.1"
port = 8001
# generate with: openssl rand -hex 32
auth_token = "<token>"
# htpasswd_file = "/etc/kms/admin.htpasswd"   # bcrypt (htpasswd -B), optional
insecure_no_auth = false

[core.admin.tls]
key = "/etc/kms/certs/rpc.key"
certs = "/etc/kms/certs/rpc.crt"
```

The token can also be supplied via the `DSTACK_KMS_ADMIN_TOKEN` or
`ADMIN_API_TOKEN` environment variables instead of the config file, or as its
hex SHA-256 in `auth_token_hash` (`printf '%s' "$TOKEN" | sha256sum`) for a
config that is not secret, such as a KMS app compose. The hash is then public,
so the token must be high-entropy random, such as `openssl rand -hex 32`: a
weak token can be brute-forced offline from its hash. The admin
listener fails closed: enabled with neither `auth_token` nor `htpasswd_file`
(and `insecure_no_auth = false`) refuses to start. With `[core.admin.tls]` the
listener serves HTTPS (use `http://` without it). Call it with, for example:

```bash
curl -k -X POST "https://127.0.0.1:8001/prpc/Admin.ClearImageCache?json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image_hash": "<hash>", "config_hash": "<hash>"}'
```

This admin authentication is separate from the on-chain / webhook authorization
below, which decides whether a CVM may boot and receive keys.

KMS-to-KMS onboarding calls `Admin.GetKmsKey` with a self-issued RA-TLS client
certificate plus the source's admin bearer token, so it requires
`[core.admin.tls]` and an admin address the new KMS can reach; other admin RPCs
need no client certificate. `core.onboard.public_key_handover` is off by default; set it to
`true` only to also serve `KMS.GetKmsKey` on the public listener for older
clients.

A KMS refuses to start serving without a handover path, so that other nodes can
always onboard from it: unless `public_key_handover = true`, it requires
`[core.admin] enabled = true` and `[core.admin.tls]` with `key` and `certs`, and
the error names the missing setting. The check runs at startup, before
onboarding or bootstrap, so a misconfigured node fails before it gets or
generates root keys. There is no opt-out, `auth_api = "dev"` included. The default `kms.toml`
enables the admin listener with TLS on the RPC key and certificate, so it
starts only once an admin token is set (`auth_token`,
`DSTACK_KMS_ADMIN_TOKEN` or `auth_token_hash`). The `dstack-app` composes and
`dstackup` set `auth_token_hash` from a token they generate.

Three settings relax authorization, each over a different scope:

| Setting | Effect |
|---------|--------|
| `core.enforce_self_authorization = false` | Skips only this KMS's self check. Root epochs are still checked against the registry (`servable_epoch`), and every app and caller is still authorized. |
| `core.auth_api.type = "dev"` | Allows everything: no backend is consulted for self, app or KMS checks. Development only. |
| `core.onboard.public_key_handover = true` | Only bypasses the admin listener for key handover: `KMS.GetKmsKey` stays on the public listener, still subject to the self, caller and key-release checks. |

The self check caches this KMS's own boot info for an hour, so a change to its
TCB status takes effect up to an hour later, and caches the backend's decision
for a second.

`GetAppEnvEncryptPubKey` and `GetSealedEnvPubKey` need no client certificate and
read the app epoch from the auth backend (`/app/:appId`). The KMS caches each
app's epoch for a second (up to 10,000 apps; failures are not cached), so
repeated requests for one app reach the backend once. Requests for random app
IDs still pass through and, on an Ethereum backend, cost chain RPC calls; rate
limit them per source in the reverse proxy or gateway in front of the KMS.


## KMS Implementation

### Components
1. **dstack-kms**
   - Main RPC service for app key requests
   - Quote verification and boot info validation
   - Asks the auth webhook ([`auth-eth`](auth-eth/)) for permission
   - Builtin Replicator for root keys

2. **[auth-eth](auth-eth/) webhook server**
   - Chain interface for permission checks
   - Two-step validation:
     1. KMS control contract check
     2. App control contract check

3. **Authorization Contracts** ([`auth-eth`](auth-eth/))
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
See [`compose-dev.yaml`](dstack-app/compose-dev.yaml) for the compose file and [`deploy-to-vmm.sh`](dstack-app/deploy-to-vmm.sh) for how to deploy it.

The solidity contracts are deployed on an ethereum compatible chain.


## Trustness

### Local-Key-Provider Mode
An instance of the in-tree [`local-key-provider`](../local-key-provider) must be deployed on the host. Use its [`build`](../local-key-provider/build/run.sh) directory to build and start it under Gramine.

In this mode, the CVM obtains application keys from the `local-key-provider`, which runs within an SGX enclave. The provider derives the application keys using:
- The SGX sealing key
- CVM measurements, including:
  - MRTD + RTMR[0-2]: Base image and VM configuration measurements
  - RTMR[3]: Runtime application configuration

The key provisioning process:
1. The CVM validates the SGX quote from `local-key-provider`
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

See [Intel TDX Attestation](../../docs/attestation-tdx.md) for more details.

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

The response includes:
- `public_key`: The X25519 public key for encrypting environment variables
- `timestamp`: Unix timestamp (seconds) when the response was generated
- `signature`: Legacy signature for backward compatibility
  - Signs: `Keccak256("dstack-env-encrypt-pubkey" + ":" + app_id + public_key)`
- `signature_v1`: New signature with timestamp to prevent replay attacks
  - Signs: `Keccak256("dstack-env-encrypt-pubkey" + ":" + app_id + timestamp_be_bytes + public_key)`

Clients should prefer verifying `signature_v1` with timestamp to protect against replay attacks. Fall back to `signature` only for backward compatibility with older KMS versions.

### SignCert

The `SignCert` RPC is used by the dstack app to sign a TLS certificate. In this RPC, the KMS node will:

- Verify the TDX quote and extract the Certificate Signing Request (CSR)
- Verify the CSR signature
- Query the smart contract to check if the app is authorized
- If authorized, sign the CSR with the CA root key and return the certificate chain to the app


## Authorization protocol

Authorization uses two explicit endpoints:

- `POST /authorizeKms` for KMS self-authorization and root-key handover.
- `POST /authorizeApp` for application keys and certificates.

The Ethereum backends call the matching `DstackKms` method. Both accept
`AuthorizationRequest` and return `AuthorizationResult`; no caller-kind flag is
sent. The KMS method checks the KMS policy; the app method applies registered app
policy.
KMS callers do not fetch contract metadata to decide which policy to use.

`requestedAppEpoch` selects the application's own key epoch, independently of KMS
root epochs. Omission uses `currentAppEpoch`; explicit zero selects app epoch zero.
Solidity uses `OptionalUint256 { isSet, value }` for both selectors. Future epochs
are denied; historical epochs remain subject to current authorization policy.
Rejection responses still carry the current epochs and root chain hash. See
[application key epochs](../../docs/app-key-epochs.md) for rotation and migration.

`requestedRootEpoch` is optional in the JSON request. Omit it to use the epoch in
this authorization result; an explicit `0` selects epoch 0. Solidity represents
it as `OptionalUint256 { isSet, value }` alongside `AppInfo` in the request. The
contract rejects future root epochs for application requests; historical epochs
remain available subject to the selected policy row. No serving epoch or serving
hash is sent. KMS-to-KMS handover explicitly selects the highest exported root
epoch, including a registered pending epoch. Approval in that row authorizes the
complete keyring, including older roots. KMS self-authorization omits the selector
and checks the current root epoch. The recipient separately authorizes the
source to `kms_export_keys` at the highest received epoch before importing it.

Every request includes a required `operation` describing what the attested
subject is authorized to do. JSON uses `snake_case`; the contract receives
`keccak256(bytes(operation))` as `bytes32`. Rust uses the shared serde-derived
`AuthorizationOperation` enum. Unknown operations and operations on the wrong
endpoint are rejected. The supported operations currently share the existing
material policy, leaving room for independent policies later:

| Endpoint | Operation | Subject |
| --- | --- | --- |
| `authorizeKms` | `kms_bootstrap` | KMS generating its first roots |
| `authorizeKms` | `kms_serve` | KMS serving app keys, public keys or certificates |
| `authorizeKms` | `kms_export_keys` | Source KMS handing over its keyring |
| `authorizeKms` | `kms_import_keys` | Recipient KMS receiving a keyring |
| `authorizeApp` | `app_get_key` | App receiving derived keys |
| `authorizeApp` | `app_get_cert` | App requesting a certificate |

The KMS chooses the operation from its code path, not an untrusted RPC field.
Self-authorization caches are keyed by operation. Legacy authorization endpoints
retain their existing semantics for old KMS binaries; fine-grained operation
policies cannot protect calls still served by those old binaries.

### Launch tickets

A launch ticket stops a party without it from launching an app, or onboarding a
KMS instance, even on an allowed OS image and device. The CVM presents the
ticket to the KMS, and the KMS sends its hash as `launchTicketHash`, zero when
none was presented:

| Endpoint | Hash | Checked for |
| --- | --- | --- |
| `authorizeApp` | `sha256("dstack-launch-ticket/v1:" \|\| ticket)` | `app_get_key`, `app_get_cert` |
| `authorizeKms` | `sha256("dstack-kms-launch-ticket/v1:" \|\| ticket)` | `kms_import_keys` |

Only the key import hands a joining KMS the root keys, so the other KMS
operations take no ticket. `DstackApp.setRequireLaunchTicket` and
`DstackKms.setRequireKmsLaunchTicket` turn the check on; `addLaunchTicket` and
`addKmsLaunchTicket` allow a hash, listed by `launchTickets()` and
`kmsLaunchTickets()`; their public label is only logged in the added event. The allowlists cover every app and
root epoch. A required ticket refuses the legacy `isAppAllowed` and
`isKmsAllowed`, whose callers cannot present one.

The ticket is a bearer secret: the host launching the CVM holds it. Use a fresh
random ticket per deployment, and remove it once the host stops serving it; a
KMS ticket is needed only while onboarding, so remove it once the instance has
joined. A guest sends its ticket before it has authenticated the KMS, so its
secrecy also rests on the network path between the CVM and the KMS.

App keys are deterministic, so a release before the requirement is set cannot
be taken back. Deploy the app contract without a compose hash, call
`setRequireLaunchTicket(true)` and `addLaunchTicket`, and only then add the
compose hash. Turning the requirement on for a running app leaves its CVMs
running, but their certificate requests fail until they restart with a ticket.

The response is an `AuthorizationResult`:

```json
{
  "authorized": true,
  "rejectionReason": "",
  "gatewayAppId": "0x...",
  "currentRootEpoch": 0,
  "currentAppEpoch": 0,
  "currentRootEpochHash": "0x...",
  "latestRootEpoch": 0,
  "latestRootEpochHash": "0x..."
}
```

Both successful and rejected decisions include the current epoch and chain hash
from the same contract call or dstack-auth configuration snapshot. `latestRootEpoch`
and `latestRootEpochHash` report the latest registered epoch, which may be pending
activation; onboarding refuses a source holding epochs beyond it and, when the source
holds it, requires its chain hash to match. Except for `kms_bootstrap`, with no
registered epoch the result is `authorized: false`,
`rejectionReason: "Root epoch not registered"`, epochs 0 and zero hashes. A zero hash
never authorizes key release or requests an epoch switch.

The KMS holds no serving-epoch snapshot. It verifies the returned current epoch
and chain hash against its keyring, then derives keys from `requestedRootEpoch` when
specified or the returned current epoch otherwise. Missing or mismatched roots
fail closed. Self-authorization retains its one-second cache of complete results.

The TLS listener has a separate lifetime: when an authorized current CA differs
from the running RPC certificate's issuer, the KMS requests a restart to refresh
that certificate and the caller must retry. The RPC CA does not select key
epochs. Application key responses and signed certificate chains report the
selected epoch's CA. CA certificates
are reloaded after renewal at startup.

Upgrade the contract and auth backend and register epoch 0 before using this
protocol for key release. Runtime authorization never falls back to the legacy
API if the new endpoint or contract method is unavailable. The old contract
methods and `/bootAuth/app` and `/bootAuth/kms` endpoints remain available for
older clients. Bootstrap uses the `kms_bootstrap` operation, which checks KMS policy at epoch zero
even before roots are registered. Other operations require registered roots.
Onboarding checks its source through `authorizeKms`, without a legacy fallback. For
`dstack-auth`, set `kmsContractAddr` to the attested KMS app ID and configure
`rootEpochs`. For development without a backend, use `[core.auth_api] type = "dev"`,
which allows everything.


## Direct attested key retrieval

`GetTempCaCert`, its original response fields, and the `temp_ca_key` handover
field remain available for existing OS images and legacy KMS onboarding. The
compatibility CA is stored in `tmp-ca.key`/`tmp-ca.crt`, independent of all root
epochs; existing files are reused and missing files are recreated. Its public
private key authenticates nobody. Client identity still requires attestation.
The returned `ca_cert` is the currently served root CA.

Upgrade contracts and auth backends, register the original roots as epoch 0,
then upgrade KMS nodes before guests. Keep root and app epochs at zero during
the mixed-version phase; rotate only after guests support key migration.

Guests and `dstack-util get-keys` generate their self-issued RA-TLS certificate
locally, then call `GetAppKey` directly. They verify the response connection's
attestation and `kms:rpc` usage, and verify that the returned root CA signed that
connection's certificate. Skipping CA-chain validation during this first request
still verifies the TLS handshake signature, so replaying an attested certificate
without its private key cannot impersonate the server. There is no `GetMeta` preflight or first unauthenticated
connection. The optional provider pin and the key-provider launch measurement
still bind the root identity; a valid quote alone is not a KMS policy decision.
`--root-ca` additionally pins the CLI connection before sending the request.

Onboarding with an admin token uses a self-issued client certificate. Tokenless
onboarding, which needs a source with `core.onboard.public_key_handover = true`,
obtains the source temp CA first so pre-0.6 sources remain usable.
Both paths check the source attestation captured from the key-carrying connection
against local KMS policy before importing anything. Retries and reconnects repeat
verification on the response connection; no assumption relies on one TCP session
lasting forever. All subsequent key requests pin the KMS CA established at startup, regardless
of whether the epoch selector is omitted or explicit. A supplied `trusted_ca`
always wins over the response CA. The selected epoch's CA never replaces this
lifetime pin; a TLS CA change requires a fresh boot/trust establishment rather
than silently trusting another KMS. Without a supplied pin, the response CA
must sign the actual RPC certificate, even when an epoch is explicitly selected.
