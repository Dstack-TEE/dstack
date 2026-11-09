# dstack KMS auth-mock

a mock implementation of the dstack KMS backend using bun + hono + zod. **this backend always returns success for all authentication requests** and does not interact with any blockchain.

## features

- 🚀 fast and lightweight with bun runtime
- 🔧 modern web framework with hono.js
- ✅ type-safe validation with zod.js
- 📦 single file implementation
- 🎭 **mock behavior**: all authentications succeed
- 🚫 **no blockchain interaction**: no dependencies on ethereum/contracts

## use cases

- 🧪 **development & testing**: test applications without blockchain setup
- 🚀 **rapid prototyping**: quickly validate integration workflows
- 🔍 **debugging**: isolate issues by removing blockchain dependencies
- 📚 **demos**: showcase functionality without complex infrastructure

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

- `PORT` - server port (default: 3000)
- `MOCK_GATEWAY_APP_ID` - mock gateway app ID (default: 0xmockgateway1234567890123456789012345678)
- `MOCK_CHAIN_ID` - mock blockchain chain ID (default: 1337)
- `MOCK_APP_IMPLEMENTATION` - mock app implementation address (default: 0xmockapp9876543210987654321098765432109)
- `MOCK_ROOT_EPOCH`, `MOCK_ROOT_EPOCH_HASH` - current KMS root epoch and its chain hash, reported by the info endpoint as `rootEpoch`/`rootEpochHash`; boot checks from a KMS serving another epoch are denied (default: none registered, only epoch 0 serves)
- `MOCK_LATEST_ROOT_EPOCH`, `MOCK_LATEST_ROOT_EPOCH_HASH` - latest registered root epoch and its chain hash, returned by `/authorizeKms` and `/authorizeApp` as `latestRootEpoch`/`latestRootEpochHash`; set both to simulate an epoch pending activation (default: the current epoch)

## API endpoints

### GET /
health check and mock system information

**response includes a `note` field indicating this is a mock backend**

### POST /bootAuth/app
application boot authentication - **always returns isAllowed=true**

### POST /bootAuth/kms
KMS boot authentication - **always returns isAllowed=true**

## request format

identical to the real backend:

```json
{
  "mrAggregated": "string",
  "osImageHash": "string",
  "appId": "string",
  "composeHash": "string",
  "instanceId": "string",
  "deviceId": "string",
  "tcbStatus": "string (optional)",
  "advisoryIds": ["string (optional)"],
  "mrSystem": "string (optional)"
}
```

## response format

```json
{
  "isAllowed": true,
  "reason": "mock app always allowed" | "mock KMS always allowed",
  "gatewayAppId": "0xmockgateway1234567890123456789012345678"
}
```

## mock behavior

### ✅ always succeeds
- all POST requests return `isAllowed: true`
- no validation against blockchain
- no actual security checks

### 📝 logs requests
- logs incoming requests with key identifiers
- helps with debugging and monitoring

### 🎯 consistent responses
- predictable mock values for testing
- same response format as real backend

## API compatibility

this implementation is fully API-compatible with the real backend:

- **request/response schemas**: identical to production API
- **OpenAPI specification**: available in `openapi.json`
- **comprehensive testing**: vitest test suite validates behavior
- **backward compatibility**: supports both minimal and full BootInfo formats

### differences from real backend

| aspect | real backend | mock backend |
|--------|-------------|--------------|
| blockchain interaction | ✅ calls smart contracts | ❌ no blockchain |
| authentication logic | ✅ validates against chain | ❌ always allows |
| security | ✅ enforces policies | ❌ bypasses all checks |
| performance | 🐌 depends on network | 🚀 instant responses |
| setup complexity | 🔧 requires ethereum setup | ✅ zero config |

## warnings

⚠️ **never use in production** - this backend bypasses all security checks

⚠️ **development only** - intended for testing and development environments

⚠️ **no security** - all requests are approved regardless of validity

## transitioning to real backend

to switch from mock to real backend:

1. replace `kms/auth-mock` with `kms/auth-eth-bun`
2. configure ethereum RPC endpoint
3. deploy smart contracts
4. update environment variables

the API remains identical, so no client code changes are needed.


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
