# dstack KMS auth-eth-bun

a single-file implementation of the dstack KMS ethereum backend using bun + hono + zod.
it serves the KMS auth webhook from the `DstackKms` and `DstackApp` contracts, whose
source, tests and deployment scripts live in [`../auth-eth`](../auth-eth/).

## features

- 🚀 fast and lightweight with bun runtime
- 🔧 modern web framework with hono.js
- ✅ type-safe validation with zod.js
- 📦 single file implementation
- 🔐 ethereum smart contract integration with viem

## installation

```bash
# install dependencies
bun install
```

## Upgrade order

Upgrade the `DstackKms` contract before deploying the new auth backend or KMS.
An empty root epoch registry is supported on the upgraded contract; there is no
fallback for legacy contracts. Old KMS instances that omit the root epoch can
receive app authorization only while no epoch is registered or epoch 0 is current,
subject to the existing authorization policy.

## usage

### development
```bash
# run with hot reload
bun run dev
```

### production
```bash
# run directly
bun run start

# or build first
bun run build
```

### testing
```bash
# run tests (watch mode)
bun run test

# run tests once
bun run test:run
```

### code quality
```bash
# run linter
bun run lint

# run linter and fix issues
bun run lint:fix

# format code
bun run format

# run full check (lint + tests)
bun run check
```

## environment variables

- `ETH_RPC_URL` - ethereum RPC endpoint (default: http://localhost:8545)
- `KMS_CONTRACT_ADDR` - KMS contract address (default: 0x0000000000000000000000000000000000000000)
- `PORT` - server port (default: 3000)
- `ETH_CHAIN_ID` - reject every decision if the RPC reports a different chain ID (default: unset, no check)
- `ETH_BLOCK_TAG` - block policy is read at: `latest`, `safe` or `finalized` (default: `finalized`). each request resolves the tag to one block and reads all state there. the server resolves the tag once at startup and refuses to start if the RPC cannot serve it. a later tag survives reorgs but delays every policy change, including emergency revocations, until that block is reached (about 13 minutes for `finalized` on Ethereum mainnet). use `finalized` on L1. set `latest` explicitly for an OP-stack chain read through the Helios light client, which tracks only the sequencer-signed unsafe head and serves neither `safe` nor `finalized`, and for local development chains such as Anvil, which finalizes 64 blocks behind its head
- `ETH_FINALITY_CONFIRMATIONS` - read this many blocks further behind the block `ETH_BLOCK_TAG` resolves to (default: 0)

The Bun server sets `idleTimeout` to 255s (Bun's maximum). Bun's default of 10s closes the socket while a slow `eth_call` is still in flight, which surfaces on the KMS side as `connection closed before message completed`.

## container image

tagged releases are published by the `KMS auth-eth-bun` workflow
(`.github/workflows/kms-auth-eth-bun.yml`): pushing the tag
`kms-auth-eth-bun-v<version>` builds this directory and publishes
`ghcr.io/dstack-tee/dstack-kms-auth-eth-bun:<version>` with a build provenance
attestation. pull requests that touch this directory run the audit, lint and
tests and build the image without pushing it.

the image listens on port 8000, which matches the KMS webhook default
`http://auth-api:8000`. deploy it by digest:

```yaml
auth-api:
  image: ghcr.io/dstack-tee/dstack-kms-auth-eth-bun:<version>@sha256:<digest>
  environment:
    - ETH_RPC_URL=https://...
    - KMS_CONTRACT_ADDR=0x...
    - ETH_CHAIN_ID=8453
```

to build it locally:

```bash
docker build -t dstack-kms-auth-eth-bun .
```

### Reproducing a release image

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
  --tag ghcr.io/dstack-tee/dstack-kms-auth-eth-bun:VERSION \
  --output type=oci,rewrite-timestamp=true,dest=/tmp/auth-eth-bun.oci.tar .
```

Replace `VERSION` with the release version. These settings apply to releases
that include timestamp normalization; earlier tags used a different workflow.

## API endpoints

### GET /
health check and system information

### POST /bootAuth/app
application boot authentication

### POST /bootAuth/kms
KMS boot authentication

## request format

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

## response format

```json
{
  "isAllowed": boolean,
  "reason": "string",
  "gatewayAppId": "string"
}
```

## API compatibility

this implementation keeps the API of the removed fastify + ethers server that used to live in `../auth-eth`:

- **request/response schemas**: identical to original API
- **OpenAPI specification**: available in `openapi.json`
- **comprehensive testing**: vitest test suite validates compatibility
- **backward compatibility**: supports both minimal and full BootInfo formats

### dstack-kms 0.6

dstack-kms 0.6 posts `dstack_verifier::PolicyBootInfo`: bytes as unprefixed
hex, plus `teeVariant` and `keyProviderInfo`, which the contract does not take
and this backend drops. the KMS checks `appId`, `composeHash` and `instanceId`
widths itself before calling the webhook. the `dstack-kms 0.6 bootAuth payload`
tests pin this contract.

### OpenAPI specification

the complete API specification is available in `openapi.json` and includes:
- detailed schema definitions
- request/response examples
- compatibility notes

### compatibility testing

the test suite (`index.test.ts`) validates:
- ✅ request/response format compatibility
- ✅ schema validation using OpenAPI spec
- ✅ error handling behavior
- ✅ hex encoding/decoding compatibility
- ✅ optional field handling


### Authorization endpoints

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

### Authorization operations

`/authorizeKms` and `/authorizeApp` require an `operation` string. See the
[KMS authorization protocol](../README.md#authorization-protocol) for the names
and subject semantics. Bootstrap alone may authorize before root registration;
unknown operations are rejected. Legacy `/bootAuth/*` routes are unchanged.
