<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-kms-kms-007"></a>
# TC-KMS-KMS-007: KMS listeners, public read-only listener and PROXY protocol

## Objective

Verify the KMS listener configuration introduced by #1580, #1582, #1583 and #1585 against a candidate KMS with initialized keys:

- `[listeners.public]` serves only `GetMeta`, `GetAppEnvEncryptPubKey`, `GetSealedEnvPubKey` and `/health`, with the same results as the guest listener;
- `proxy_protocol = true` in `[listeners.default]` applies to every listener that does not override it, and a listener may override it;
- the PROXY header's source address is the client address in the request logs and in the `dstack_kms::audit` lines;
- the old listener locations are refused at startup, naming the new ones.

## Preconditions

- Fixture profile `kms-ready`: a candidate KMS with initialized keys, its config, cert directory and guest simulator.
- Lease-owned ports `kms`, `onboard`, `debug` and `vmm` are free.

## Procedure

1. Copy the fixture KMS's config and cert directory. Start a second KMS from the copy with the guest, admin and public listeners on lease-owned ports, `[listeners.default] proxy_protocol = true`, and `proxy_protocol = false` in `[listeners.admin]`.
2. Guest listener: a connection without a PROXY header gets no response; with a v1 header (`TCP4 203.0.113.7`) `KMS.GetMeta` returns HTTP 200 with `Server: DStack KMS`.
3. Public listener, with a v2 header (`198.51.100.4`): `GetMeta`, `GetAppEnvEncryptPubKey` and `GetSealedEnvPubKey` for a 20-byte app id return the same keys as the guest listener, and `/health` returns 200. `GetAppKey`, `SignCert`, `GetTempCaCert`, `GetKmsKey`, `ClearImageCache`, the `KMS.`-qualified `KMS.GetMeta` and `/metrics` return 404: the listener serves the read-only RPCs at the bare `/prpc/<Method>` paths (or `ReadOnly.<Method>`) only.
4. Admin listener, which overrides `proxy_protocol = false`: `Admin.ClearImageCache` with the admin token returns 200 without a header; a connection that sends a PROXY header gets no valid response.
5. The second KMS's log carries `remote` with each PROXY source address on the prpc request lines, and a `dstack_kms::audit` `env public key served` line for each env public key request whose remote is the PROXY source address.
6. Start the KMS with configs that add `[rpc]`, `[core.admin]` and, in a config file, a top-level `log_level`: each exits non-zero naming `rpc -> listeners.guest`, `core.admin -> listeners.admin` and `log_level -> listeners.default.log_level`.

## Expected results

Every step's rows pass. No listener serves an RPC it does not own, and no connection without the expected PROXY header framing is served.

## Cleanup

Stop the second KMS and delete its config and cert copy; the fixture KMS is untouched.
