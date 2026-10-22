# Guest Agent API access control

The guest agent's external listener (port 8090) is reachable by anyone who can
route to the CVM. It refuses callers it cannot identify: every request names a
scope, and a scope is granted either by a signed token or by the host's
configuration.

This is an exposure control, not a confidentiality one. It decides who may
*ask*. Whether the answer may leave the TEE is decided by the app's measured
`public_logs` / `public_sysinfo` / `public_tcbinfo` switches, and a token can
only narrow what those allow. See
[the two gates](#the-two-gates) below.

## Scopes

| Scope | Grants |
|---|---|
| `guest:version` | `Worker.Version` on either pRPC surface |
| `guest:health` | `Worker.Health` (`/prpc/v1`) |
| `guest:info` | `Worker.Info` on either surface, and the identity block on the dashboard |
| `guest:attest-app-key` | the frozen `Worker.GetAttestationForAppKey` |
| `guest:dashboard` | the dashboard page itself |
| `guest:containers` | the container table on the dashboard |
| `guest:logs` | `/logs/<container>`, when the app sets `public_logs` |
| `guest:metrics` | `/metrics`, and the sysinfo block on the dashboard |

`/prpc`, `/prpc/v0` and `/prpc/v1` are matched after percent-decoding and
segment normalisation, so `/prpc/Worker.Info`, `/prpc/v0/Info` and
`/%70rpc/Info` all need `guest:info`. There is no spelling that reaches a
handler with a weaker check.

A route the vocabulary does not name needs no scope: nothing is mounted there,
and the router's 404 is the answer.

## Default: nothing anonymous

With no configuration, every scope above requires a token. The gateway still
works, because it is issued one internally; the dashboard, `/metrics` and the
log views stop answering to the public.

The app's own SDKs are unaffected: they use the internal Unix socket, which is
unauthenticated and reachable only by the application.

## Configuring anonymous access

Anonymous access is a host decision, made in sys-config. The VMM writes it from
`[cvm.guest_agent_api]`:

```toml
[cvm.guest_agent_api]
anonymous_scopes = ["guest:dashboard", "guest:version", "guest:health"]
```

The same block in the guest's `/dstack/.host-shared/.sys-config.json`:

```json
{
  "guest_agent_api": {
    "anonymous_scopes": ["guest:dashboard", "guest:version", "guest:health"]
  }
}
```

Listing `guest:dashboard` without `guest:containers`, `guest:info`, `guest:logs`
or `guest:metrics` gives an anonymous visitor the page with every block hidden.
Scopes are independent: each one adds exactly its own block.

An unknown name is a boot error rather than a permission that silently never
matches.

## External issuers

Other than its own token, the agent accepts tokens from issuers the host names:

```toml
[[cvm.guest_agent_api.external_issuers]]
name = "ops"
public_keys = ["2f8d...c1"]  # hex Ed25519 public keys, 32 bytes each
```

`name` is the exact `iss` claim a token must carry; `public_keys` is a list so a
key can be rotated by publishing the new one beside the old, waiting out the
longest token lifetime (one hour), then dropping the old one.

Tokens must be Ed25519. `alg: none`, HMAC, and headers carrying key material
(`jku`, `x5u`, `jwk`) are not rejected by policy -- the header is a constant,
so they cannot be expressed.

### Where the internal issuer comes from

The agent and the gateway both hold the app root key inside the TEE. The token
the gateway presents is minted in the guest's own setup (`dstack-util`) and
carried on registration, so it can be bound to the app id and expire:

1. Both derive the same Ed25519 key:
   `derive_app_key(app_root_key, "dstack:guest-api:issuer:v1", Ed25519)`.
2. `dstack-util` signs a token with `iss = "dstack:guest-api:<app_id>"`,
   `aud = <app_id>`, a 10-minute lifetime, and the `guest:health`, `guest:info`
   scopes.
3. Registration carries it to the gateway, which presents it on the v1 `Health`
   poll and on the lazy `Info` fetch that fills in a port policy the CVM did not
   report.

Nothing else gets a token: the gateway has no business on the dashboard or in
the logs.

The host cannot mint one: the signing key is derived from the app root key, which
is released to the guest by KMS only after the boot measurement is verified.

## The two gates

Two independent checks decide what a caller sees, and both must pass:

| Gate | Source | Measured | Answers |
|---|---|---|---|
| `public_logs`, `public_sysinfo`, `public_tcbinfo` | app-compose | yes | may this data leave the TEE at all? |
| scopes | sys-config | no | may this caller ask? |

They combine with `&&`. A token cannot reveal logs the app kept private -- with
`public_logs = false` the route is not even mounted -- and an anonymous caller
cannot see a block it was not granted, however public the app made it.

Scope configuration is deliberately unmeasured. Host-supplied sys-config is not
part of the attestation, so a host could grant a caller more than the operator
intended. That grants nothing beyond what anonymous 8090 access already granted
before this change: the data is still gated by the measured switches, which a
host cannot alter without changing the app id.

## Compatibility

A guest with this change answers 401 to an old gateway that presents no token. The
gateway counts that as unreachable and drops the instance after
`failure_threshold` consecutive polls, so a mixed cluster rebalances away from
new guests until the gateway is upgraded.

During the rollout, either upgrade the gateway first, or leave the host open:

```toml
[cvm.guest_agent_api]
anonymous_scopes = ["guest:version", "guest:health", "guest:info"]
```

`guest:info` is needed by gateways that did not report a port policy and fetch
it lazily.
