# Test Scripts

This directory contains automated test scripts for the DStack KMS Ethereum backend.

## Scripts Overview

### 🚀 setup-local-chain.sh
Sets up a local Anvil blockchain and deploys the DStack contracts.
- Starts Anvil on port 8545
- Deploys DstackKms and DstackApp contracts
- Saves configuration to `.env.test`

```bash
npm run test:setup
# or
./scripts/setup-local-chain.sh
```

### 🧪 run-tests.sh
Runs all tests against the deployed contracts on the local chain.
- Requires local chain to be already set up
- Runs Jest unit tests
- Runs integration tests
- Optionally runs Foundry tests

```bash
npm run test:run              # Run JS/TS tests only
npm run test:run:foundry      # Include Foundry tests
# or
./scripts/run-tests.sh
./scripts/run-tests.sh --with-foundry
```

### 🎯 test-all.sh
Complete test suite - sets up chain and runs all tests.
- Combines setup-local-chain.sh and run-tests.sh
- Perfect for CI/CD or fresh test runs

```bash
npm run test:all              # Complete test suite
npm run test:all:foundry      # Include Foundry tests
# or
./scripts/test-all.sh
./scripts/test-all.sh --with-foundry
```

### 🧹 cleanup.sh
Cleans up all test processes and temporary files.
- Stops Anvil and API server
- Removes temporary files and logs

```bash
npm run test:cleanup
# or
./scripts/cleanup.sh
```

## Typical Workflows

### One-time Setup, Multiple Test Runs
```bash
# Set up once
npm run test:setup

# Run tests multiple times
npm run test:run
npm run test:run
npm run test:run

# Clean up when done
npm run test:cleanup
```

### Complete Test Run
```bash
# Run everything in one go
npm run test:all

# Or with Foundry tests
npm run test:all:foundry
```

### Development Workflow
```bash
# Set up chain
npm run test:setup

# Keep chain running, develop and test
npm run test:run
# ... make changes ...
npm run test:run
# ... make more changes ...
npm run test:run

# Clean up when done
npm run test:cleanup
```

## Environment Variables

After running `setup-local-chain.sh`, the following environment variables are saved to `.env.test`:

- `ANVIL_PID` - Process ID of the Anvil instance
- `ETH_RPC_URL` - RPC endpoint (http://127.0.0.1:8545)
- `CHAIN_ID` - Chain ID (31337)
- `KMS_CONTRACT_ADDR` - Deployed KMS proxy contract address
- `APP_IMPLEMENTATION` - DstackApp implementation address
- `KMS_IMPLEMENTATION` - DstackKms implementation address
- `DEPLOYER_ADDRESS` - Address that deployed the contracts
- `DEPLOYER_PRIVATE_KEY` - Private key of the deployer

## Logs

The scripts generate the following log files:

- `anvil.log` - Anvil blockchain logs
- `deploy.log` - Contract deployment logs
- `server-test.log` - API server logs during tests

## Requirements

- Node.js and npm
- Foundry (forge, anvil)
- All npm dependencies installed (`npm install`)

