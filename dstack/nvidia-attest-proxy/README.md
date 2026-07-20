# NVIDIA GPU Attestation Proxy

`dstack-nvidia-attest-proxy` is a persistent, PCCS-like cache for the two NVIDIA
services used by local GPU attestation:

- `POST /ocsp` caches DER OCSP responses by the request's certificate IDs. The
  per-request OCSP nonce is deliberately excluded from the key.
- `GET /v1/rim/<id>` caches version-addressed NVIDIA RIM documents.
- `GET /healthz` reports process health.
- `GET /info` reports fresh/stale entry counts per cache kind.

The proxy never signs or rewrites collateral. `nvattest` in the CVM still
verifies NVIDIA's certificate chains, OCSP signatures, response validity
window, RIM signatures, measurements, and the fresh GPU evidence nonce. Cache
entries are persisted so a warm cache survives both proxy and VM restarts.

## Run

```bash
cargo build --release -p dstack-nvidia-attest-proxy
sudo install -m 0755 target/release/dstack-nvidia-attest-proxy /usr/local/bin/
sudo install -d -m 0750 /var/cache/dstack/nvidia-attest-proxy

sudo /usr/local/bin/dstack-nvidia-attest-proxy \
  --listen 0.0.0.0:8090 \
  --cache-dir /var/cache/dstack/nvidia-attest-proxy
```

All options have environment-variable equivalents; see `--help`. In
particular, `NV_ATTESTATION_SERVICE_KEY` supplies an optional NVIDIA bearer
token without placing it on the command line.

Configure the VMM with a URL reachable during early guest boot:

```toml
[cvm]
nvidia_attestation_proxy_url = "http://10.0.2.2:8090"
```

For QEMU user-mode networking, `10.0.2.2` is normally the host address. Other
networking modes should use the corresponding host or fleet service address.

## Cache behavior

On a cold miss the original request is forwarded to NVIDIA. A successful OCSP
response is cached no later than its signed `nextUpdate` and no longer than
`--ocsp-max-ttl` (24 hours by default). Responses without `nextUpdate` use one
hour from `thisUpdate`, matching the pinned NVIDIA SDK. RIM documents default
to a 30-day TTL.

Two mechanisms keep entries warm, and they compose: a background sweep (every
`--refresh-interval`, 10 minutes by default) renews entries that have
consumed half their lifetime, so a warm cache rides through an NVIDIA outage
with close to a full validity window instead of only the remainder; entries
past their usefulness are dropped, not retried. As a synchronous fallback, an
OCSP response with less than `--ocsp-refresh-before` validity remaining
(five minutes by default) is refreshed in-line on the next request before it
is served — concurrent refreshes for the same entry are coalesced. If an
in-line refresh fails, the proxy keeps serving the old response only until
its existing signed expiry; it never extends or serves an expired one.

Expired OCSP entries are never served. Therefore a warm cache removes the
NVIDIA service from the boot path only for the signed validity period; it does
not turn revocation checking into an indefinite fail-open. RIM documents are
signed and version-addressed, so an expired RIM entry — unlike OCSP — may
still be served for up to `--rim-max-stale` (7 days by default) when the
upstream is unreachable or failing; the guest verifies its signature either
way. Response headers expose `X-Dstack-Cache: HIT|MISS|REFRESH|STALE`, `Age`,
and `X-Dstack-Cache-Expires` for operations.
Each cache kind is capped at 10,000 entries by default; the oldest entry is
evicted when the limit is reached. Use `--max-cache-entries-per-kind` to tune
the bound for a deployment.

Because a cached response contains the nonce from the request that populated
the cache, `nvattest` reports `x-nvidia-cert-ocsp-nonce-matches = false` on a
hit. When the proxy URL is configured, dstack selects NVIDIA's packaged
`allow_trust_outpost_ocsp.rego` policy. This relaxes only the OCSP nonce check;
the GPU attestation report's independent nonce remains required by dstack.
