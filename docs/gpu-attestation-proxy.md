# GPU Attestation Collateral Proxy

Local GPU attestation (`nvattest --verifier local`) makes live calls to two
NVIDIA services at every CVM boot: the OCSP responder
(`ocsp.ndis.nvidia.com`, one request per certificate in three chains) and the
RIM service (`rim.attestation.nvidia.com`, driver + VBIOS RIM documents).
Because the GPU attestation gate fails closed, anything that breaks those
calls — an egress-restricted or air-gapped network, an upstream outage, or a
middlebox — keeps every GPU CVM from booting.

`gpu-attest-proxy` is a small host-side (or site-level) caching proxy that
removes the guest's direct dependency on those services, in the same spirit
as Intel's PCCS for TDX collateral:

- **OCSP** requests are relayed byte-for-byte; successful responses are
  cached keyed by CertID until their `nextUpdate`, so repeat boots and
  fleets of CVMs sharing GPUs stop hitting the responder.
- **RIM** documents are cached by RIM id and re-fetched on a TTL; when the
  upstream is unreachable, a stale document keeps being served within a
  bounded window.
- A background refresher renews entries before they expire, so a warm cache
  rides through upstream outages with close to a full validity window.

Everything the proxy serves is signed collateral that the guest verifies
itself (OCSP response signatures and validity windows via
`OCSP_basic_verify`, RIM signatures and certificate chains by the attestation
SDK). The proxy needs no secrets and cannot forge responses; its worst
misbehavior is withholding service, which fails closed — the same outcome as
blocking NVIDIA's endpoints directly.

## Why the OCSP nonce check is relaxed

The attestation SDK adds a random nonce to every OCSP request and its
built-in appraisal policy requires the response to echo it
(`x-nvidia-cert-ocsp-nonce-matches`). A response cached for another request
can never echo this request's nonce, so caching is only possible if the
guest relaxes that single check.

When `gpu_attest_proxy_url` is set, `dstack-util` runs nvattest with
`--relying-party-policy` pointing at NVIDIA's
`allow_trust_outpost_ocsp.rego` (packaged in the image at
`/usr/share/nvattest/policies/`), which keeps every built-in check except
the nonce match. Freshness is then bounded by the response validity window
instead of the nonce: a revoked certificate may keep passing until the
cached response's `nextUpdate`. This is the same trade-off the SDK's own
in-process OCSP cache makes. Guests without the proxy configured keep the
default policy and the nonce check.

## Setup

Run the proxy somewhere every CVM can reach (typically on each host, next to
dstack-vmm):

```console
$ gpu-attest-proxy -c /etc/gpu-attest-proxy/gpu-attest-proxy.toml
```

See `dstack/gpu-attest-proxy/gpu-attest-proxy.toml` for the default
configuration (upstreams, cache directory, TTLs). The cache persists as one
JSON file per entry under `cache_dir`, so restarts keep it warm.

Point guests at it through `vmm.toml`:

```toml
[cvm]
gpu_attest_proxy_url = "http://<host-bridge-ip>:8090"
```

The VMM passes the URL to the guest via sys-config. At boot, `dstack-util`
derives the SDK endpoints from it:

- `--ocsp-url {base}/ocsp`
- `--rim-url {base}` (the SDK appends `/v1/rim/{rim_id}` itself)
- `--relying-party-policy /usr/share/nvattest/policies/allow_trust_outpost_ocsp.rego`

When the value is empty (default), guests talk to NVIDIA directly and the
built-in appraisal policy applies unchanged.

## Operational notes

- `GET /health` and `GET /info` expose liveness and cache statistics.
- A cold cache cannot help: the first boot after an outage begins still
  needs a reachable upstream. Keep the proxy running so entries stay warm;
  `refresh_margin` controls how far ahead of expiry entries are renewed.
- The guest-side clock check is unchanged: OCSP validity windows are
  verified by the guest, so an expired cached response never passes.
- Revocation visibility degrades from "immediate" (nonce) to the OCSP
  response validity window (`nextUpdate`). Measure the actual window for
  your certificate chains — it determines both how long an outage the cache
  can absorb and how long a revocation can go unnoticed.
