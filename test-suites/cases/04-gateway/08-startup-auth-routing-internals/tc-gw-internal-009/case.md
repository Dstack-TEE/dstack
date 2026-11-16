<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-gw-internal-009"></a>
# TC-GW-INTERNAL-009: Gateway listener configuration, PROXY protocol and audit lines

## Objective

Verify against a candidate gateway the listener configuration of #1587, the PROXY protocol on the gateway's own listeners (#1582), and the admin audit (#1588) and access (#1589) log lines.

## Preconditions

- Fixture profile `gateway-ready`: a candidate gateway with its config, guest simulator, admin token and an imported `localhost` proxy certificate.

## Procedure

1. Start the gateway binary with copies of the fixture config that set the old listener locations: a top-level `address`, `[tls]`, `[core.admin]`, `[core.debug] insecure_localhost_backend` and a top-level `proxy_protocol`. Each must exit non-zero naming `address -> listeners.guest.address`, `tls -> listeners.guest.tls`, `core.admin -> listeners.admin`, `-> core.proxy.insecure_localhost_backend` and `proxy_protocol -> listeners.default.proxy_protocol`.
2. Stop the fixture gateway and restart it from a copy of its config with `proxy_protocol = true` in `[listeners.admin]`. The guest listener, which does not set it, still serves `/health` without a header.
3. Admin listener: `Admin.Status` with the token gets no valid response without a PROXY header and HTTP 200 after a v1 header from `203.0.113.9`. `Admin.ImportCert` with an unparsable certificate after that header is refused.
4. The gateway log carries `remote` with `203.0.113.9` on the admin prpc request lines, and a `dstack_gateway::audit` `admin refused` line for `import_cert` whose remote is `203.0.113.9`.
5. A TLS connection to the proxy listener for `gateway.localhost` writes one `dstack_gateway::access` line.

## Expected results

Every row passes: the old locations are refused, the admin listener requires the header and records its source, and state-changing admin RPCs and proxied connections are logged.

## Cleanup

Stop the restarted gateway; the lease owns the rest of the fixture.
