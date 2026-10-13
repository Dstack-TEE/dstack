# dstack KMS auth-eth-bun

a single-file implementation of the dstack KMS ethereum backend using bun + hono + zod.

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
- `ETH_FINALITY_CONFIRMATIONS` - read policy this many blocks behind the RPC head (default: 0, the head)

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

this implementation is fully compatible with the original fastify + ethers version:

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
