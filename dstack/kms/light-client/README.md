# Phala L2 light client

The default [KMS Compose](../dstack-app/docker-compose.yaml) runs KMS, auth-api,
Helios and its gossip relay inside the same CVM. All services use one published
KMS image; no deployment-time builds or source downloads are required. The KMS
builder pins the [Helios fork](https://github.com/Dstack-TEE/helios/pull/1) by commit.

## Deployment

Set these variables and render Compose before passing it to dstack:

- `KMS_IMAGE`: a reviewed, published KMS image digest.
- `KMS_CONTRACT_ADDR`: a Phala contract compatible with the current auth API.
- `ETH_MAX_BLOCK_AGE_SECONDS`: the maximum accepted age of authenticated state,
  enforced by both Helios and auth-api. It bounds how long revocations can be
  missed when the chain feed stalls, e.g. `300` (about 30 Phala blocks).
- `IMAGE_DOWNLOAD_URL`: the verified OS image download URL used by KMS.

```sh
docker compose -f dstack/kms/dstack-app/docker-compose.yaml config > kms-compose.yaml
```

The app must enable `secure_time` (`vmm-cli.py compose --secure-time`, as
`deploy-to-vmm.sh` does). Freshness checks rely on the guest clock; without
NTS-synchronized time, the host can roll the clock back and replay old signed
blocks to hide revocations. `secure_time` is part of `app-compose.json`, so only
approve KMS compose hashes whose `app-compose.json` sets it to `true`.

Only the KMS port is published.

## Trust and verification

Reads use **sequencer-authenticated state, not L1-settled state**:

1. Helios follows Ethereum mainnet with its sync-committee light client, starting
   from the pinned `--ethereum-checkpoint`.
2. Every minute it proves Phala's unsafe signer from the L1 `SystemConfig`
   contract (`0xeBf5859b7646ca9cf8A981613569bF28394F2571`) with an account and
   storage proof. No Phala block is accepted before the first proof, or once the
   latest proof is older than 15 minutes. A signer rotated on L1 therefore
   replaces the old key automatically.
3. Each Phala block must carry that signer's signature and a header that hashes to
   the signed block hash. Contract calls run locally against account, storage and
   code proofs; RPC servers cannot supply an unchecked `eth_call` result.
4. auth-api checks chain ID 2035, reads two blocks behind the head so proofs are
   available, pins one block for the whole decision, and rejects state older than
   `ETH_MAX_BLOCK_AGE_SECONDS`, including state that expires during the call.

The remaining trust is in the Phala sequencer key: a sequencer that signs a false
block can forge authorization results, because L1 settlement is not checked.
The relay, Ethereum RPCs and Phala RPC are data sources only.

## Operations

Operational failures fail closed with `authorization backend unavailable`:

- **Startup.** Authorization is unavailable until Helios proves the signer and
  caches three blocks, typically within a minute of boot.
- **Feed stalls.** The relay reconnects its static peer after 30 seconds without
  a higher signed block. Longer outages exceed the age limit.
- **L1 unavailable.** Without a fresh signer proof, Helios stops accepting blocks.
- **Signer rotation.** Helios follows L1, but the relay filters gossip by the
  signer pinned in the fork; update the fork and image.
- **Phala hard forks.** The fork schedule and header layout are pinned. A fork
  that changes headers stops Helios with `payload block hash mismatch`; one that
  only changes EVM rules can make local calls diverge. Update the fork and image
  before every activation.
- **Checkpoint age.** Refresh `--ethereum-checkpoint` (a finalized beacon block
  root) with each release; Helios warns once it is older than 14 days.

Monitor the auth-api `/` endpoint and Helios `failed to advance` logs.
