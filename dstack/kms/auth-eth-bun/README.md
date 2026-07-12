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