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