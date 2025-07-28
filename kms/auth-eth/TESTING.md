# Testing Guide for DStack KMS Auth

Complete testing with **Foundry only** - no Hardhat dependencies.

## 🏗️ Smart Contract Testing

```bash
npm run test:foundry:all    # All smart contract tests (36 tests)
```

Covers: Core logic, upgrades, authorization, gas optimization

## 🌐 API Server Testing

### Unit Tests (Fast)
```bash
npm test                    # Jest with mocked blockchain (4 tests)
```

### Integration Tests (Real Blockchain)
```bash
npm run test:full           # Complete: Anvil + Deploy + API tests + Cleanup
```

This automatically:
1. Starts Anvil node
2. Deploys contracts 
3. Starts API server
4. Tests all endpoints
5. Cleans up

## 🔧 Manual Testing

### Start Services
```bash
npm run test:full:keep      # Keep Anvil + API server running
```

### Test Endpoints
```bash
curl http://127.0.0.1:8000/                    # Health check
curl -X POST http://127.0.0.1:8000/bootAuth/app \
  -H "Content-Type: application/json" \
  -d '{"tcbStatus":"UpToDate","advisoryIds":[],"mrAggregated":"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef","osImageHash":"0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd","mrSystem":"0x9012901290129012901290129012901290129012901290129012901290129012","appId":"0x9012345678901234567890123456789012345678","composeHash":"0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd","instanceId":"0x3456789012345678901234567890123456789012","deviceId":"0xef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12ef12"}'
```

## 🚀 CI/CD Pipeline

```bash
npm test                    # Fast unit tests
npm run test:foundry:all    # Complete contract tests  
npm run build               # Build check
```