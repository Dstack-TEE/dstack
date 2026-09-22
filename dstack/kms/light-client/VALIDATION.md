# Validation record

Date: 2026-09-22 UTC. Repository base:
`ccd96638e334fb3df658661743bb641239ed6f71`.

## Conditions

- Cloud Linux x86_64, native Rust/Cargo 1.94.1, Node 20.20.2, Python 3.12.3,
  curl 8.5.0, Docker Server 29.5.3. No CVM, attestation or key release was tested.
- Helios base `d20aa4f4de5886b6c78004447ee197a1cf744362` plus `helios.patch`;
  op-revm 20.0.0, revm 38.0.0. Container toolchain/base images are digest-pinned
  in the Dockerfiles. Cargo dependencies are locked.
- Public Phala execution RPC `https://rpc.phala.network`, chain ID 2035, sequencer
  signer pinned in the patch. Signed blocks obtained from the public Conduit static
  peer documented in README. No credentials, chain writes or paid transactions.
- KMS proxy `0xae43c1d4814f665aa4e08ec3589309dff939a049`, an independently
  discovered **legacy** deployment, not a user-confirmed production target.
- Synthetic boot inputs from its public allowlist events. Tests do not represent
  successful TEE attestation or possession of a real KMS device identity.
- Auth read lag 2 blocks and max age 60 seconds. The Karst opcode comparison used
  lag 3 and the same fixed block 5569954 for local and remote calls.
- Local auth HTTP port 18000; internal relay/client ports only. Separate native
  fault-test clients had empty caches per mode. Fault proxies bound to loopback.

## Results

- Native TypeScript build passes; 13 Jest tests pass (existing API tests plus
  block pinning, chain mismatch, unavailable/stale/future state, expiration during
  in-flight contract calls, and no fallback).
- Two Rust tests pass: authentic Phala signed payload/header with signature/chain/
  payload/root negative cases and exact Jovian/Karst activation boundaries.
- Both images build. Real container HTTP KMS authorization returns allow for the
  public allowlist vector and deny for an unlisted MR.
- Upgraded Karst execution supports CLZ: `0x5f1e5f5260205ff3` returns 256.
  L1Block.number() and CLZ match the public RPC at the same authenticated height.
- Real auth API through the upgraded native client rejects corrupted account
  proofs, corrupted contract code, wrong chain ID, replayed stale genuine signed
  head, and unavailable execution RPC. The positive control allows.
- The observing execution proxy is programmed to lie on eth_call. Method counts
  showed proof/code/access-list RPC requests and **zero forwarded eth_call calls**.
- Stopping the Docker relay and waiting at least 75 seconds causes the previously
  allowed vector to be denied under the 60-second freshness limit. Restarting the
  relay restores fresh synchronization and allow; the negative vector remains denied.

## Limits / remaining acceptance

The trust model is sequencer authentication, not L1 settlement. The tests do not
validate a current KMS CVM, actual attestation/key release, or a user-selected
production contract. The tested legacy contract lacks appImplementation() and
uses old image-measurement semantics. Consequently this is not final sign-off on
current-repository production KMS compatibility; no health response or contract
implementation address was fabricated to hide the mismatch.

## Live contract reads

A fresh read-only acceptance run at 2026-09-22T14:43:10.310Z used the existing
Docker auth container's ethers client, connected exclusively to internal Helios
at http://helios:8545 (not directly to the public RPC). Chain ID was 2035; the
selected authenticated block was 5570092, two blocks behind the observed head,
31 seconds old, hash
0x4a6c928109fb0a203e2c76a8b095edd88aa38855ddf811424eeb87e51fc2a811.
The same Docker/toolchain, pinned signer, public peer and execution-provider
conditions listed above apply. No chain transactions, CVM or key release.

- KMS gatewayAppId() at 0xae43c1d4814f665aa4e08ec3589309dff939a049 returned
  29af9606ffff15d7b95cb1bfb774137d7445c59a.
- L1Block.number() at 0x4200000000000000000000000000000000000015 returned 26033691.

Both calls executed locally using proof-verified state under a sequencer-signed
root. This does not change the stated sequencer-trust/L1-settlement distinction.
