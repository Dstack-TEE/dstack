# dstack SDKs

Client libraries for interacting with the dstack guest agent from inside a TEE.

## HTTP API

All SDKs communicate with the guest agent via HTTP over a Unix socket (`/var/run/dstack.sock`). See the [HTTP API Reference](curl/api.md) for direct access using curl or any HTTP client.

## Two API surfaces, two clients

The guest agent serves two surfaces on that socket, selected by URL path, and
every SDK mirrors both:

| Client | Surface | Paths |
|---|---|---|
| `ClientV0` | the frozen v0.5.11 API | `/GetKey`, also served at `/v0/GetKey` |
| `ClientV1` | `dstack.guest.v1` | `/v1/GetKey` |

The v0 surface is closed: it gains no methods and changes no behaviour, so a
v0.5.x program keeps working against a 0.6 agent unchanged. New work goes to v1,
which is specified byte-for-byte in
[`docs/guest-api-v1.md`](../docs/guest-api-v1.md).

The clients are transport mirrors, not a compatibility layer: neither translates
a call to the other, and each one's method set is exactly its surface's. v1 has
no `sign` and no `verify`, because any caller that can reach the socket can ask
`get_key` for the private key and do both locally.

> **v1 keys are not v0 keys.** Deriving under the same name through a `ClientV1`
> returns *different key material* than a `ClientV0` does. This is deliberate --
> the v0 KDF ignored the algorithm, so one secret served both curves -- and
> there is no compatibility mode. An application holding assets under a v0 key
> must migrate them with a transaction signed by the old key before cutting
> over.

### Verifying a signature chain

The SDKs ship no verification helper. Verifying needs no client and no
connection, and it is the relying party's job.
[`docs/guest-api-v1.md`](../docs/guest-api-v1.md) specifies the rules
normatively -- the claim encoding, the recovery step, and the trust anchor the
chain has to terminate at. `ClientV0.verify()` remains for single signatures on
the frozen surface, since that is what the v0 surface offers.

## SDKs

| Language | Path |
|----------|------|
| [Python](python/) | `sdk/python` |
| [JavaScript/TypeScript](js/) | `sdk/js` |
| [Rust](rust/) | `sdk/rust` |
| [Go](go/) | `sdk/go` |

## Simulator

For local development without TDX hardware, use the simulator:

- [Download releases](https://github.com/Dstack-TEE/dstack/releases?q=simulator-v&expanded=true)
- [Install as a systemd service](../dstack/guest-agent-simulator/install-systemd.sh)
- [Docker image](https://hub.docker.com/r/phalanetwork/dstack-simulator)
