# dstack KMS auth-eth

On-chain authorization for the dstack KMS. This directory holds both halves:

- **Contracts** (`contracts/`, `test/`, `script/`): the upgradeable `DstackKms`
  and `DstackApp` contracts, built and tested with Foundry.
  - **DstackKms**: Key Management System contract with app registration and validation
  - **DstackApp**: Application-specific authentication contract with device and compose hash management
- **Webhook server** (`index.ts`): a single-file Bun + Hono + zod + viem server
  that reads those contracts and serves the KMS auth webhook (`/bootAuth/*`,
  `/authorizeKms`, `/authorizeApp`).

## Upgrade order

Upgrade the `DstackKms` contract before deploying the new auth backend or KMS.
An empty root epoch registry is supported on the upgraded contract; there is no
fallback for legacy contracts. Old KMS instances that omit the root epoch can
receive app authorization only while no epoch is registered or epoch 0 is current,
subject to the existing authorization policy.

## Webhook server

### Prerequisites

- [Bun](https://bun.sh)

### Development

```bash
bun install --frozen-lockfile

# run with hot reload
bun run dev

# run once
bun run start

# tests (watch mode / once)
bun run test
bun run test:run

# lint, lint with fixes, lint + tests
bun run lint
bun run lint:fix
bun run check
```

The Bun server sets `idleTimeout` to 255s (Bun's maximum). Bun's default of 10s closes the socket while a slow `eth_call` is still in flight, which surfaces on the KMS side as `connection closed before message completed`.

### Environment variables

- `ETH_RPC_URL` - ethereum RPC endpoint (default: http://localhost:8545)
- `KMS_CONTRACT_ADDR` - KMS contract address (default: 0x0000000000000000000000000000000000000000)
- `PORT` - server port (default: 3000)
- `ETH_CHAIN_ID` - reject every decision if the RPC reports a different chain ID (default: unset, no check)
- `ETH_BLOCK_TAG` - block policy is read at: `latest`, `safe` or `finalized` (default: `finalized`). each request resolves the tag to one block and reads all state there. the server resolves the tag once at startup and refuses to start if the RPC cannot serve it. a later tag delays every policy change, including emergency revocations, until that block is reached (about 13 minutes for `finalized` on Ethereum mainnet). use `finalized` on L1. set `latest` explicitly for an OP-stack chain read through the Helios light client, which tracks only the sequencer-signed unsafe head and serves neither `safe` nor `finalized`, and for local development chains such as Anvil, which finalizes 64 blocks behind its head. see [reorgs and the block tag](#reorgs-and-the-block-tag) before using `latest` or `safe`
- `ETH_FINALITY_CONFIRMATIONS` - read this many blocks further behind the block `ETH_BLOCK_TAG` resolves to (default: 0)

### Reorgs and the block tag

Only `finalized` protects policy from reorgs. With `latest` or `safe`, a reorg
can revert any policy transaction the server has already acted on, in both
directions:

- **Revocations roll back.** A removed OS image, compose hash or device, or a
  revoked KMS measurement, is authorized again until the revocation is
  re-included and the read block reaches it.
- **Activations roll back.** A root epoch activation or an app epoch increase
  can disappear. Neither this server nor the KMS keeps a high-water mark: the
  KMS only checks the reported epoch against its keyring's chain hash, so after
  a root epoch rollback it restarts once and serves the previous epoch as
  current, and apps again receive keys of their previous app epoch.

Keys released in that window stay released. `ETH_FINALITY_CONFIRMATIONS=N`
reads N blocks behind the tagged block, so a reorg shallower than N blocks is
never observed, at the cost of delaying every policy change, revocations
included, by N more blocks. A reorg deeper than N still rolls back, so this
narrows the risk with `latest` or `safe` but does not remove it. Through Helios
on an OP-stack chain, `latest` is the sequencer's unsafe head: choose N from
how deep a reorg of that head you are willing to accept, and send emergency
revocations with that delay in mind.

### Container image

Tagged releases are published by the `KMS auth-eth` workflow
(`.github/workflows/kms-auth-eth.yml`): pushing the tag
`kms-auth-eth-v<version>` builds this directory and publishes
`ghcr.io/dstack-tee/dstack-kms-auth-eth:<version>` with a build provenance
attestation. Pull requests that touch this directory run the audit, lint and
tests and build the image without pushing it.

The image listens on port 8000, which matches the KMS webhook default
`http://auth-api:8000`. Deploy it by digest:

```yaml
auth-api:
  image: ghcr.io/dstack-tee/dstack-kms-auth-eth:<version>@sha256:<digest>
  environment:
    - ETH_RPC_URL=https://...
    - KMS_CONTRACT_ADDR=0x...
    - ETH_CHAIN_ID=8453
```

To build it locally (the `.dockerignore` keeps the Foundry
project out of the build context):

```bash
docker build -t dstack-kms-auth-eth .
```

#### Reproducing a release image

Use a clean checkout of the release tag and BuildKit 0.20.2, matching the
workflow. COPY permissions are fixed independently of the checkout umask.
Export with the commit timestamp and timestamp rewriting; a plain
`docker build` does not reproduce the release digest.

```bash
docker buildx create --name auth-repro --driver docker-container \
  --driver-opt image=moby/buildkit:v0.20.2@sha256:c457984bd29f04d6acc90c8d9e717afe3922ae14665f3187e0096976fe37b1c8

git_revision=$(git rev-parse HEAD)
source_date_epoch=$(git show -s --format=%ct HEAD)
docker buildx build --builder auth-repro --platform linux/amd64 \
  --provenance=false \
  --build-arg "GIT_REV=$git_revision" \
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
  --label org.opencontainers.image.source=https://github.com/Dstack-TEE/dstack \
  --label "org.opencontainers.image.revision=$git_revision" \
  --label 'org.opencontainers.image.description=dstack KMS auth webhook backed by the DstackKms contract' \
  --tag ghcr.io/dstack-tee/dstack-kms-auth-eth:VERSION \
  --output type=oci,rewrite-timestamp=true,dest=/tmp/auth-eth.oci.tar .
```

Replace `VERSION` with the release version. These settings apply to releases
that include timestamp normalization; earlier tags used a different workflow.

Releases before the rename were published as
`ghcr.io/dstack-tee/dstack-kms-auth-eth-bun` from `kms-auth-eth-bun-v*` tags;
those images remain available.

### API endpoints

#### GET /
health check and system information

#### POST /bootAuth/app
application boot authentication

#### POST /bootAuth/kms
KMS boot authentication

### Request format

```json
{
  "tcbStatus": "string",
  "advisoryIds": ["string"],
  "mrAggregated": "string",
  "mrSystem": "string",
  "osImageHash": "string",
  "appId": "string",
  "composeHash": "string",
  "instanceId": "string",
  "deviceId": "string"
}
```

### Response format

```json
{
  "isAllowed": boolean,
  "reason": "string",
  "gatewayAppId": "string"
}
```

### API compatibility

this implementation keeps the API of the removed fastify + ethers server that used to live in this directory:

- **request/response schemas**: identical to original API
- **OpenAPI specification**: available in `openapi.json`
- **comprehensive testing**: vitest test suite validates compatibility
- **backward compatibility**: supports both minimal and full BootInfo formats

#### dstack-kms 0.6

dstack-kms 0.6 posts `dstack_verifier::PolicyBootInfo`: bytes as unprefixed
hex, plus `teeVariant` and `keyProviderInfo`. the legacy `/bootAuth/*` routes
drop both; `/authorizeKms` and `/authorizeApp` require `teeVariant` and pass it
to the contract unchanged, and always drop `keyProviderInfo`. the KMS checks
`appId`, `composeHash` and `instanceId` widths itself before calling the webhook. the `dstack-kms 0.6 bootAuth payload`
tests pin this contract.

#### OpenAPI specification

the complete API specification is available in `openapi.json` and includes:
- detailed schema definitions
- request/response examples
- compatibility notes

#### compatibility testing

The test suite (`index.test.ts`) validates:
- ✅ request/response format compatibility
- ✅ schema validation using OpenAPI spec
- ✅ error handling behavior
- ✅ hex encoding/decoding compatibility
- ✅ optional field handling

#### Authorization endpoints

`POST /authorizeKms` and `POST /authorizeApp` return `AuthorizationResult`, including `authorized`,
`rejectionReason`, `gatewayAppId`, `currentRootEpoch`, `currentRootEpochHash`, `currentAppEpoch`,
`latestRootEpoch`, and `latestRootEpochHash` (the latest registered epoch, which may be pending activation).
The selected endpoint determines the policy; the backend checks that the verified
`appId` matches that scope. Optional `requestedAppEpoch` selects the app epoch;
omission uses the current app epoch, explicit zero selects epoch zero, and future
values are denied. The optional
`requestedRootEpoch` selects historical keys; omission uses the returned current
epoch, and an explicit `0` selects epoch 0. See the
[KMS authorization protocol](../README.md#authorization-protocol) for registration,
bootstrap, and compatibility requirements. The legacy `/bootAuth/*` endpoints
remain available.

#### Authorization operations

`/authorizeKms` and `/authorizeApp` require an `operation` string. See the
[KMS authorization protocol](../README.md#authorization-protocol) for the names
and subject semantics. Bootstrap alone may authorize before root registration;
unknown operations are rejected. Legacy `/bootAuth/*` routes are unchanged.

## Contracts

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) - For smart contract development and testing
- Node.js/npx - Only for `@openzeppelin/upgrades-core`, which the upgrade-safety tests run through `npx` with `--ffi`

### Setup

```bash
# Fetch the Foundry dependencies (git submodules under lib/)
git submodule update --init --recursive lib/forge-std \
  lib/openzeppelin-contracts-upgradeable lib/openzeppelin-foundry-upgrades

# Fetch the OpenZeppelin upgrade-safety validator that `forge test --ffi` runs
# through npx. Do not `npm install` it here: package.json belongs to the Bun
# webhook server.
npx --yes @openzeppelin/upgrades-core@^1.37.0 --help > /dev/null

# Build the contracts
forge build
```

### Testing

```bash
# Run `forge clean` first: stale build-info files make the upgrade validator
# report the same contract twice.
forge clean
forge test --ffi
```

### Local chain

To try the contracts together with the webhook server, deploy them to a local
Anvil node and point the webhook server at the proxy:

```bash
# Terminal 1: local node
anvil

# Terminal 2: deploy with Anvil's first prefunded account; the output prints
# "DstackKms proxy deployed to: 0x..."
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  forge script script/Deploy.s.sol:DeployScript --broadcast --rpc-url http://127.0.0.1:8545

# Terminal 3: webhook server. Anvil finalizes 64 blocks behind its head, so read
# at the latest block.
bun install
ETH_RPC_URL=http://127.0.0.1:8545 ETH_BLOCK_TAG=latest KMS_CONTRACT_ADDR=0x... PORT=8000 \
  bun index.ts
```

### Contract Management

Use Foundry scripts for all contract operations instead of Cast commands:

#### Deployment
```bash
# Deploy both contracts
forge script script/Deploy.s.sol:DeployScript --broadcast --rpc-url http://localhost:8545

# Deploy to other networks
forge script script/Deploy.s.sol:DeployScript --broadcast --rpc-url <RPC_URL> --private-key <PRIVATE_KEY>
```

#### Management Operations
```bash
# Add KMS aggregated MR
KMS_CONTRACT_ADDR=0x... MR_AGGREGATED=0x1234... \
forge script script/Manage.s.sol:AddKmsAggregatedMr --broadcast --rpc-url $RPC_URL

# Deploy new app via factory
KMS_CONTRACT_ADDR=0x... APP_OWNER=0x... \
forge script script/Manage.s.sol:DeployApp --broadcast --rpc-url $RPC_URL
```

#### Query Operations
```bash
# Get KMS settings
KMS_CONTRACT_ADDR=0x... \
forge script script/Query.s.sol:GetKmsSettings --rpc-url $RPC_URL

# Check if device is allowed
APP_CONTRACT_ADDR=0x... DEVICE_ID=0x1234... \
forge script script/Query.s.sol:CheckAppDevice --rpc-url $RPC_URL
```

#### Safe Upgrades
```bash
# Upgrade KMS to V2
KMS_CONTRACT_ADDR=0x... \
forge script script/Upgrade.s.sol:UpgradeKmsToV2 --broadcast --rpc-url $RPC_URL --ffi
```

See `script/README.md` for complete documentation of all available scripts.

#### Epoch-scoped material approvals

Material approvals use exact root/app epoch rows; neither older nor newer rows
are implicitly authorized. Material setters name their rows: `*AtEpochs` a
range, and in `DstackApp` `*AtEpoch` one row; `DstackApp` reports them as
`IAppEpochManagement`.
The management scripts take `ROOT_EPOCH`/`APP_EPOCH`, or
`FROM_ROOT_EPOCH`/`TO_ROOT_EPOCH` and `FROM_APP_EPOCH`/`TO_APP_EPOCH`, and use
the epoch-less setters of app policies predating app epochs. Original bool mappings and events remain epoch-zero views after
upgrading; epoch-specific getters/events describe the new rows. KMS keyring
handover separately checks its highest exported root epoch, which authorizes the
whole keyring. See [epoch-scoped allowlists](../../../docs/app-key-epochs.md#epoch-scoped-allowlists)
for migration, upgrade order and compatibility.

### Static Analysis & Symbolic Verification

We run [Slither](https://github.com/crytic/slither) locally during
development. [Halmos](https://github.com/a16z/halmos) also runs in CI
(`.github/workflows/halmos.yml`, pinned Halmos and Forge versions) whenever
this directory changes.

```bash
pipx install slither-analyzer halmos
slither .
halmos --contract DstackAppSymbolicTest
halmos --contract DstackAppEpochSymbolicTest
halmos --contract DstackKmsSymbolicTest
halmos --contract DstackKmsEpochSymbolicTest
```

Forge 1.8 enables `dynamic_test_linking` by default, which compiles `new` in
tests to `vm.deployCode`, a cheat code Halmos 0.3.3 does not support. Disable
it for Halmos runs with `FOUNDRY_DYNAMIC_TEST_LINKING=false`.

Configuration lives in `slither.config.json` and `foundry.toml`.
See `docs/formal-verification.md` for the verification roadmap, what each
symbolic property proves, and the deeper-verification plan for a future
audit-firm engagement.

### Additional Commands

```bash
# Format code
forge fmt

# Gas snapshots
forge snapshot

# Start local node
anvil
```

Documentation: https://book.getfoundry.sh/
