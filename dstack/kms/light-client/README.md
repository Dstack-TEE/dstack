# Phala KMS light client

Phala L2 light client for KMS authorization, with sequencer authentication,
proof verification, and local on-chain contract execution.

## Trust model

This integration verifies Phala sequencer signatures (chain ID 2035), reconstructs
and checks the signed block hash, verifies account/storage proofs and code hashes,
and executes `eth_call` locally. The execution RPC cannot invent an authorization
result. There is no fallback to unverified RPC execution.

**This is not L1-settled L2 consensus verification.** It trusts the pinned Phala
sequencer signer `0xF63ccBA1929a3eC32248B26c5a22D7C4c9bd3EEC`, initially obtained
from public SystemConfig observations. An operator must independently approve this
pin as part of the measured deployment. A signer change stops synchronization;
update the pin only after independent verification and redeploy. Do not enable
upstream's optional signer-discovery implementation: it is not used by this
configuration and has unresolved verification/readiness problems.

The signer and L1 SystemConfig are part of `helios.patch`; they are not accepted
from the execution RPC at runtime. The relay's static peer is only a data source,
not a trust anchor. A malicious relay can withhold blocks but cannot forge the
pinned sequencer signature.

Put **both Helios and auth-api inside the KMS CVM's measured compose**. Running
Helios on an untrusted external machine and trusting its JSON-RPC defeats this
verification boundary. A relay may be external because its output is verified.

## Build and local smoke deployment

Helios upstream revision, Cargo lockfile changes, and container base-image digests
are pinned. `helios.patch` includes a regression test against a real public Phala
signed block. The build copies its fixture and runs that test before compiling.

From this directory:

```sh
export KMS_CONTRACT_ADDR=0xYourPhalaKmsContract
# The address must have the ABI expected by ../auth-eth.
docker compose build
docker compose up -d
```

The smoke auth API is exposed only on `127.0.0.1:18000`; Helios and relay have no
host ports. The default [KMS Compose](../dstack-app/docker-compose.yaml) includes
these services alongside KMS without exposing their ports. Both Compose files
build the auth API from current local sources and require a repository checkout
for their build contexts. Set `KMS_CONTRACT_ADDR` explicitly to a Phala deployment
with the current auth ABI; no legacy contract is selected automatically.
Configure KMS to use `http://auth-api:8000`, never the public execution RPC.

## Read policy

`auth-eth` enables the verified-read policy when `ETH_CHAIN_ID` is set:

- `ETH_CHAIN_ID=2035`: reject another reported chain ID.
- `ETH_BLOCK_LAG=2`: read a slightly older **locally authenticated cached block**.
  This is proof-availability lag, not settlement finality. In observed public RPC
  samples, proofs for the latest head failed while previous-block proofs worked.
- `ETH_MAX_BLOCK_AGE_SECONDS=60`: reject missing, stale or more-than-five-seconds
  future blocks. Boot authorization and gateway ID use the same selected height.
  Freshness is checked again before returning the authorization result, so slow
  upstream requests cannot extend the acceptance window.

If the selected authenticated block or its proofs are unavailable, reject the
request. Do not increase lag/age arbitrarily to make failures disappear. Following
restart, allow time for sufficient authenticated blocks to enter the local cache.

The upstream client stores its own empty configuration under its isolated container
HOME. No external host configuration or credentials are mounted.

## Compatibility and outstanding acceptance

Phala currently gossips Isthmus-style V4 envelopes on `/optimism/2035/3/blocks`.
The patch adds that topic, Yamux transport, static peers with reconnect, payload
bounds, and fixes header reconstruction (including logs bloom and withdrawal root).
It is scoped to current V4 operation, not historical pre-Isthmus synchronization.

The patch upgrades op-revm to 20.0.0 and revm to 38.0.0 and selects Jovian/Karst
at Phala's actual activation timestamps. The Karst CLZ opcode and a verified
L1Block read were compared with the public RPC at the same height; the results
matched. eth_call disables the transaction-only gas cap, preserving simulation
behavior after the upgrade. This image is scoped to KMS read calls, not advertised
as a general-purpose transaction submission or gas-estimation service.

The discovered on-chain KMS used in initial read-only tests is
`0xae43c1d4814f665aa4e08ec3589309dff939a049`. It is an older contract, not a
user-confirmed current production deployment: its ABI has `mrImage` where this
repository uses `osImageHash`, and lacks `appImplementation()`. Boot endpoints can
be tested against it, but the current information endpoint will fail. No fallback
or fabricated implementation address was added to hide that incompatibility.

Before production sign-off:

1. Confirm the intended current KMS contract and semantics, or explicitly implement
   and test supported legacy compatibility.
2. Run target-contract acceptance inside the intended KMS CVM. Local container
   build, HTTP authorization, stale-head rejection and relay restart recovery pass.
3. Approve sequencer trust, signer update procedure and freshness policy for
   irreversible KMS key release.

## Validation

See [VALIDATION.md](VALIDATION.md) for test conditions, results and limitations.
The public signed-block regression fixture is in `fixtures/`.
