# dstack SDKs

Client libraries for interacting with the dstack guest agent from inside a TEE.

## HTTP API

All SDKs communicate with the guest agent via HTTP over a Unix socket (`/var/run/dstack.sock`). See the [HTTP API Reference](curl/api.md) for direct access using curl or any HTTP client.

## SDKs

| Language | Path |
|----------|------|
| [Python](python/) | `sdk/python` |
| [JavaScript/TypeScript](js/) | `sdk/js` |
| [Rust](rust/) | `sdk/rust` |
| [Go](go/) | `sdk/go` |

## Simulator

For local development without TDX hardware, use the simulator:

- [Download releases](https://github.com/Leechael/dstack-simulator/releases)
- [Docker image](https://hub.docker.com/r/phalanetwork/dstack-simulator)
