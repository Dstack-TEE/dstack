# Setup dstack-gateway for Production

> **This guide is for self-hosted deployments** on your own TDX hardware. For cloud deployments, see [Quickstart](./quickstart.md).

To set up dstack-gateway for production, you need a wildcard domain and a
Cloudflare API token. You do not need to obtain a certificate yourself: the
gateway links the `certbot` crate and runs ACME over dns-01 in its own process,
keeping the ACME account key and every certificate in its WaveKV store. The
`certbot` CLI under `dstack/certbot/cli` is a testing tool for the same crate
and has no part in this path.

## Step 1: Set up the wildcard domain

Set up a second-level wildcard domain using Cloudflare; make sure to disable proxy mode and use **DNS Only**.

![add-wildcard-domain](./assets/tproxy-add-wildcard-domain.jpg)

Then create an API token that can edit this zone's DNS records. The gateway uses
it to publish the `_acme-challenge` TXT records that answer dns-01, and the CAA
records that pin issuance to its own ACME account.

## Step 2: Configure `gateway.toml`

Focus on these fields in the `core.proxy` section:

- `base_domain`: the wildcard domain for the proxy
- `listen_addr` & `listen_port`: listen on `0.0.0.0` and preferably `443` in production. If using another port, specify it in the URL (see [URL Format](#url-format))

For example, if your base domain is `gateway.example.com`, app ID is `<app_id>`, listening on `80`, and dstack-gateway is on port 7777, the URL would be `https://<app_id>-80.gateway.example.com:7777`

Leave `cert_chain` and `cert_key` unset. They load a certificate you already
have from disk at startup, for the case where something else issues it; the
gateway's own issuance does not use them and does not write them.

Two more sections matter for certificates:

```toml
[core.admin]
enabled = true
address = "127.0.0.1:9016"
auth_token = "<paste output of: openssl rand -hex 32>"

[core.sync]
data_dir = "/var/lib/dstack-gateway/data"
```

The admin API is where the ACME settings, the Cloudflare token and the domain
list live — they are stored in the gateway's KV store and there is no file to
put them in, so certificates cannot be issued without it. See
[Admin API authentication](#admin-api-authentication) for the credential
options. `data_dir` is where the ACME account key and the issued certificates
are persisted; point it somewhere writable that survives restarts, or the
gateway asks the CA for a fresh certificate every time it starts and will run
into Let's Encrypt's rate limits. The section is named for cluster sync, but
this store is used whether or not `enabled` is set.

Start the gateway.

## Step 3: Give the gateway its ACME configuration

Open the admin dashboard at `http://<core.admin.address>` and fill in **Certbot
Configuration**, **DNS Credentials** and **ZT-Domains**, or do the same over the
admin API:

```bash
ADMIN_ADDR=127.0.0.1:9016
AUTH=(-H "Authorization: Bearer $ADMIN_API_TOKEN")

# Start on staging: its certificates are not browser-trusted, but its rate
# limits leave room for mistakes.
curl -sf -X POST "${AUTH[@]}" "http://$ADMIN_ADDR/prpc/SetCertbotConfig" \
  -H "Content-Type: application/json" \
  -d '{"acme_url":"https://acme-staging-v02.api.letsencrypt.org/directory",
       "renew_interval_secs":3600,"renew_before_expiration_secs":864000,
       "renew_timeout_secs":300}'

curl -sf -X POST "${AUTH[@]}" "http://$ADMIN_ADDR/prpc/CreateDnsCredential" \
  -H "Content-Type: application/json" \
  -d '{"name":"cloudflare","provider_type":"cloudflare",
       "cf_api_token":"'"$CF_API_TOKEN"'","set_as_default":true}'

curl -sf -X POST "${AUTH[@]}" "http://$ADMIN_ADDR/prpc/AddZtDomain" \
  -H "Content-Type: application/json" \
  -d '{"domain":"gateway.example.com","port":443,"priority":100}'
```

Add a ZT domain for every name the gateway terminates TLS on. An entry for
`gateway.example.com` gets a certificate covering `*.gateway.example.com`, which
is what app URLs live under — a certificate for `*.example.com` would not, since
a wildcard does not span a further label. `port` is the port that domain is
served on and `priority` breaks ties when more than one entry could be the
default base domain.

Certificates are requested on the next renewal round rather than the moment a
domain is added. Watch for them to arrive:

```bash
curl -sf "${AUTH[@]}" "http://$ADMIN_ADDR/prpc/ListZtDomains" \
  | jq '.domains[] | {domain: .config.domain, cert: .cert_status}'
```

`has_cert: true` with a `not_after` roughly 90 days out means the domain is
served. `POST /prpc/RenewCert` forces a round immediately instead of waiting for
`renew_interval_secs`.

Pin issuance with `POST /prpc/SetCaa`, which writes CAA records naming Let's
Encrypt and the gateway's ACME account URI for every configured domain, so no
other account can have a certificate issued for them.

Once the gateway serves traffic on staging certificates, switch to production:
`SetCertbotConfig` with `https://acme-v02.api.letsencrypt.org/directory`, then
`RotateAcmeCredentials` to register an account there and re-pin every domain's
CAA to it. Renewals refuse to run while the stored account and the configured
ACME URL disagree, so do not skip the rotation.

## Step 4: Adjust Configuration in `vmm.toml`

Open `vmm.toml` and adjust dstack-gateway configuration in the `gateway` section:

- `base_domain`: Same as `base_domain` from `gateway.toml`'s `core.proxy` section
- `port`: Same as `listen_port` from `gateway.toml`'s `core.proxy` section

## URL Format

The gateway supports the following URL format:
- `<app_id>[-<port>][<suffix>].<base_domain>`

Where:
- `<app_id>`: The application identifier
- `<port>`: Optional port number (defaults to 80 for HTTP, 443 for HTTPS)
- `<suffix>`: Optional suffix flags:
  - `s`: Enable TLS passthrough (proxy passes encrypted traffic directly to backend)
  - `g`: Enable HTTP/2 (gRPC) support (proxy advertises h2 via ALPN)

Examples:
- `<app_id>.gateway.example.com` - Default HTTP on port 80
- `<app_id>-8080.gateway.example.com` - HTTP on port 8080
- `<app_id>-s.gateway.example.com` - TLS passthrough on port 443
- `<app_id>-443s.gateway.example.com` - TLS passthrough on port 443
- `<app_id>-50051g.gateway.example.com` - HTTP/2/gRPC on port 50051

Note: The `s` and `g` suffixes cannot be used together

## Admin API authentication

The gateway exposes a separate admin API (used for sync, WireGuard peer management, and other operator RPCs). Configure it in the `core.admin` section of `gateway.toml`:

```toml
[core.admin]
enabled = true
address = "0.0.0.0:9016"
# generate with: openssl rand -hex 32
auth_token = "<paste output of: openssl rand -hex 32>"
# alternatively, an Apache bcrypt htpasswd file (htpasswd -B -c admin.htpasswd admin)
# htpasswd_file = "/etc/dstack/gateway-admin.htpasswd"
insecure_no_auth = false
```

- `enabled`: enable the admin API server.
- `address`: bind address/port for the admin API.
- `auth_token`: shared admin token. It can also be supplied via the environment variables `DSTACK_GATEWAY_ADMIN_TOKEN` or `ADMIN_API_TOKEN` instead of the config file. The older name `admin_token` is still accepted.
- `htpasswd_file`: path to an Apache bcrypt htpasswd file (create with `htpasswd -B -c admin.htpasswd admin`); only bcrypt entries are accepted. Can be used instead of, or alongside, `auth_token`.
- `insecure_no_auth`: development-only escape hatch that disables admin authentication. Never enable it on a network-reachable admin interface.

The admin server is fail-closed: if it is enabled with no `auth_token` and no `htpasswd_file`, and `insecure_no_auth` is `false`, it refuses to start rather than exposing an unauthenticated admin API.

Clients authenticate by sending `Authorization: Bearer <token>` or the `X-Admin-Token: <token>` header.

## Metrics

The admin server exposes Prometheus metrics at `GET /metrics`. It is part of the
admin API, so it is only reachable when `core.admin.enabled` is true and it
requires the same credentials — unless `insecure_no_auth` is set, which exposes
it along with the rest of the admin API. The series name domains, node ids and
instance counts, which is topology that should not be readable without
authentication.

```yaml
scrape_configs:
  - job_name: dstack-gateway
    static_configs:
      - targets: ["<core.admin.address>"]
    authorization:
      credentials: "<the admin token>"
```

### Cluster-scoped vs node-local series

`dstack_gateway_cluster_*` describes replicated state: every node in the cluster
reports the same value, so summing across targets multiplies it by the number of
nodes. Everything else describes what one process did and sums normally.

```promql
# Instances in the routing table — replicated, so take one node's view
max(dstack_gateway_cluster_instances)

# Connections across the fleet — node-local, so add them up
sum(dstack_gateway_connections)

# Nodes disagreeing about who is up: this is the replication-lag signal
max(dstack_gateway_cluster_nodes_active) - min(dstack_gateway_cluster_nodes_active)
```

### Series worth alerting on

| Metric | Why |
|---|---|
| `dstack_gateway_wg_reconfigure_failures_total` | The gateway could not push a WireGuard config: it failed to render, failed to write, or `wg syncconf` rejected the whole file over one bad peer stanza. Routing updates have stopped reaching the data plane while the gateway still looks healthy. |
| `dstack_gateway_kv_decode_failures_total` | A replicated record that fails to decode is skipped, which makes the CVM behind it silently unroutable. Labelled by key prefix. Alert on `> 0`; the magnitude counts how often a bad record was *read*, not how many are bad, so do not read it as a severity. |
| `dstack_gateway_kv_peer_buffered_logs` | Entries still buffered for a peer. Sustained growth means that peer stopped acknowledging and the two nodes are drifting apart. |
| `dstack_gateway_cluster_cert_not_after_seconds` | Certificate expiry per domain; alert on `- time()` falling under the renewal window. Capped at 256 series — compare `dstack_gateway_cluster_cert_domains` to see whether the cap was hit. |
| `dstack_gateway_kv_persist_failures_total` | Periodic snapshots are failing, so a restart replays a growing WAL. |
