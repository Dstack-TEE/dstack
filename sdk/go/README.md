# dstack SDK

The dstack SDK for Go.

## Installation

```bash
go get github.com/Dstack-TEE/dstack/sdk/go
```

## Basic Usage

```go
package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

func main() {
	client := dstack.NewDstackClient(
		// dstack.WithEndpoint("http://localhost"),
		// dstack.WithLogger(slog.Default()),
	)

	// Get information about the dstack client instance
	info, err := client.Info(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(info.AppID)  // Application ID
	fmt.Println(info.TcbInfo.Mrtd)  // Access TCB info directly
	fmt.Println(info.TcbInfo.EventLog[0].Event)  // Access event log entries

	path := "/test"
	purpose := "test" // or leave empty

	// Derive a key with optional path and purpose
	deriveKeyResp, err := client.GetKey(context.Background(), path, purpose)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(deriveKeyResp.Key)

	// Generate TDX quote
	tdxQuoteResp, err := client.GetQuote(context.Background(), []byte("test"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(tdxQuoteResp.Quote)  // 0x0000000000000000000 ...

	rtmrs, err := tdxQuoteResp.ReplayRTMRs()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(rtmrs)  // map[0:00000000000000000 ...
}
```

## API Reference

### DstackClient

#### Constructor

```go
func NewDstackClient(opts ...DstackClientOption) *DstackClient
```

Options:
- `WithEndpoint(endpoint string)`: Sets the endpoint (Unix socket path or HTTP(S) URL). Defaults to '/var/run/dstack.sock'.
- `WithLogger(logger *slog.Logger)`: Sets the logger. Defaults to `slog.Default()`.

The client uses `DSTACK_SIMULATOR_ENDPOINT` environment variable if set.

NOTE: Leave endpoint empty in production. You only need to add `volumes` in your docker-compose file:

```yaml
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
```

#### Methods

- `Info(ctx context.Context) (*InfoResponse, error)`: Retrieves information about the CVM instance.
- `GetKey(ctx context.Context, path string, purpose string) (*GetKeyResponse, error)`: Derives a key for the given path and purpose.
- `GetQuote(ctx context.Context, reportData []byte) (*GetQuoteResponse, error)`: Generates a TDX quote using SHA512 as the hash algorithm.
- `GetTlsKey(ctx context.Context, path string, subject string, altNames []string, usageRaTls bool, usageServerAuth bool, usageClientAuth bool, randomSeed bool) (*GetTlsKeyResponse, error)`: Derives a key for the given path and purpose.

## Development

Set up [Go](https://go.dev/doc/install).

### Running the Simulator

For local development without TDX devices, you can use the simulator under `sdk/simulator`.

Run the simulator with:

```bash
cd sdk/simulator
./build.sh
./dstack-simulator
```

### Running Tests
```bash
DSTACK_SIMULATOR_ENDPOINT=$(realpath ../simulator/dstack.sock) go test -v ./dstack

# or for the old Tappd client
DSTACK_SIMULATOR_ENDPOINT=$(realpath ../simulator/tappd.sock) go test -v ./tappd
```

## License

Apache License
