# Testing Guide

## Smart Contract Testing

```bash
# Run all tests (36 tests total)
forge test --ffi
```

## API Server Testing

### Unit Tests
```bash
npm test                    # Jest with mocked blockchain (4 tests)
```

### Integration Tests
```bash
npm run test:all           # Complete: Anvil + Deploy + API tests + Cleanup
```

This automatically:
1. Starts Anvil node
2. Deploys contracts 
3. Starts API server
4. Tests all endpoints
5. Cleans up

## Manual Testing

### Start Services
```bash
npm run test:setup         # Start Anvil and deploy contracts
npm run dev                # Start API server in development mode
```

### Test Endpoints
```bash
curl http://127.0.0.1:8000/                    # Health check
curl -X POST http://127.0.0.1:8000/bootAuth/app \
  -H "Content-Type: application/json" \
  -d '{"tcbStatus":"UpToDate","advisoryIds":[],"mrAggregated":"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef","osImageHash":"0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"}'
```

### Cleanup
```bash
npm run test:cleanup       # Stop all test processes
```