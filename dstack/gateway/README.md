# dstack-gateway

The reverse proxy that gives deployed dstack apps zero-trust network access. It
terminates TLS, provisions certificates over ACME DNS-01, and routes traffic to
CVMs across a WireGuard mesh it manages itself.

## Ingress mapping

Apps are addressed as `<id>[-[<port>][s|g]].<base_domain>`:

| Form | Behaviour |
| --- | --- |
| `<id>.<base_domain>` | TLS terminated at the gateway, forwarded as TCP |
| `<id>-<port>s.<base_domain>` | TLS passthrough to the app |
| `<id>-<port>g.<base_domain>` | TLS terminated, forwarded as HTTP/2 (gRPC) |

`<id>` is the app ID or the instance ID; `<port>` defaults to 80.

## Configuration

`gateway.toml` holds the base domain, the certificate and WireGuard settings,
and the admin API credentials. Operator-facing admin RPCs are served on a
separate listener behind the shared HTTP authenticator, the same way the KMS and
VMM expose theirs.

## Running

Build and run from the workspace root:

```bash
cargo build --release -p dstack-gateway
sudo ./target/release/dstack-gateway -c gateway.toml
```

The gateway needs `CAP_NET_ADMIN` to manage its WireGuard interface, hence
`sudo`.

## Further reading

- [Cluster deployment](docs/cluster-deployment.md) — running a replicated gateway
- [Builder image](dstack-app/builder/README.md) — reproducible container image
- [Deployment guide](../../docs/deployment.md)
- [Security guide](../../docs/security-guide/security-guide.md)
