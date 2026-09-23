# Phala L2 light client

The default [KMS Compose](../dstack-app/docker-compose.yaml) runs KMS, auth-api,
Helios and its gossip relay inside the same CVM. All services use one published
KMS image; no deployment-time builds or source downloads are required. The KMS
builder pins the [Helios fork](https://github.com/Dstack-TEE/helios/pull/1) by commit.

## Deployment

Set these variables and render Compose before passing it to dstack:

- `KMS_IMAGE`: optional override for the pinned preview image digest. Use a
  reviewed release digest for production.
- `KMS_CONTRACT_ADDR`: a Phala contract compatible with the current auth API.
- `ETH_MAX_BLOCK_AGE_SECONDS`: the maximum accepted age of authenticated state.
  Choose explicitly based on acceptable revocation delay and observed latency.
- `IMAGE_DOWNLOAD_URL`: the verified OS image download URL used by KMS.

```sh
docker compose -f dstack/kms/dstack-app/docker-compose.yaml config > kms-compose.yaml
```

Only the KMS port is published. Helios verifies sequencer-signed blocks, account
and storage proofs, and code hashes, then executes contract calls locally. The
public execution RPC cannot supply an unchecked `eth_call` result. The auth API
checks chain ID 2035, uses a two-block proof-availability lag, and rejects stale
state, including when a call expires in flight. The lag is not settlement finality
and consumes part of the configured age budget. The relay reconnects its static
peer after 30 seconds without a valid signed commitment, before the recommended
60-second freshness limit expires. RPC outages, delayed proofs or relay stalls
still fail closed; startup needs enough authenticated blocks in the cache.

## Trust and compatibility

This is **sequencer authentication, not L1-settled consensus verification**.
The pinned signer is `0xF63ccBA1929a3eC32248B26c5a22D7C4c9bd3EEC`.
Approve this trust anchor independently; signer rotation requires a reviewed
fork update and image rebuild. The relay is only a data source and cannot forge
signatures. Helios and auth-api must remain inside the measured KMS boundary.

The observed legacy contract `0xae43c1d4814f665aa4e08ec3589309dff939a049`
permits read-only light-client checks, but lacks `appImplementation()` and uses
older image-measurement semantics. It is deliberately not a production default.
Live light-client contract calls were verified; CVM attestation and key release
are outside that validation scope.
