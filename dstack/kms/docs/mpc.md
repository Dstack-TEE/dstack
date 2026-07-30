# Multi-instance MPC KMS

## Security identity

MPC mode never loads or reconstructs a complete root private key. Its stable
`key_provider_id` is the SHA-256 domain-separated commitment to:

- the threshold P-256 root CA public key;
- the threshold K-256 signing public key;
- the threshold P-256 derivation public key; and
- the MPC protocol version and cluster ID.

Membership is deliberately excluded from this identity. A membership epoch is
a canonical manifest signed by the threshold K-256 key. Each member entry binds
the node ID, endpoint, quote-bound RA-TLS SubjectPublicKeyInfo, and a commitment
to that node's three public shares.

The verification chain is:

1. an application pins `key_provider_id` in its measured compose configuration;
2. `GetMeta` publishes the cluster identity, signed active manifest, and local
   node evidence;
3. the manifest signature verifies under the pinned K-256 group key;
4. the manifest binds the serving node's RA-TLS key and public-share
   commitment; and
5. the TEE quote binds the live TLS key to the measured KMS instance.

The threshold P-256 key signs the root certificate and all member RPC
certificates. A member certificate is issued only after every signer verifies
that its embedded attestation is valid and bound to the authorized TLS key.

## Genesis

Genesis is an all-member maintenance ceremony. Before starting it, provision
only transport material (`rpc.crt`, `rpc.key`, the temporary CA files), an
operator-reviewed genesis plan, and a CA used by the provisional transport.
Do not provision a root private key.

Example MPC configuration:

```toml
[core.mpc]
enabled = true
protocol_version = 1
cluster_id = "production-kms"
node_id = "kms-1"
identity_file = "/var/lib/dstack-kms/mpc-identity.json"
genesis_plan_file = "/var/lib/dstack-kms/genesis-plan.json"
genesis_tls_ca_cert = "/var/lib/dstack-kms/genesis-transport-ca.crt"
join_authorization_file = "/var/lib/dstack-kms/join-authorization.json"
client_cert_file = "/var/lib/dstack-kms/mpc-client.crt"
client_key_file = "/var/lib/dstack-kms/mpc-client.key"
manifest_file = "/var/lib/dstack-kms/epoch-manifest.json"
checkpoint_file = "/var/lib/dstack-kms/epoch-checkpoint.json"
p256_share_file = "/var/lib/dstack-kms/p256.share"
k256_share_file = "/var/lib/dstack-kms/k256.share"
derivation_share_file = "/var/lib/dstack-kms/derivation.share"
max_sessions = 128
session_ttl = "5m"
```

The canonical JSON genesis plan contains sorted members:

```json
{
  "protocol_version": 1,
  "cluster_id": "production-kms",
  "threshold": 3,
  "coordinator": "kms-1",
  "members": [
    {
      "node_id": "kms-1",
      "endpoint": "https://kms-1.example/prpc",
      "attestation_pubkey": "<hex DER SubjectPublicKeyInfo>"
    }
  ]
}
```

All members must receive the identical plan. The coordinator waits for every
attested peer and then runs distributed auxiliary generation and DKG for all
three keys. It threshold-signs the root CA, reissues each attested RPC
certificate under that root, signs epoch 1, and distributes the final bundle.
A durable genesis journal makes every node finish a crash-interrupted commit.
Processes shut down after commit and must be restarted by their supervisor.

`mpc-client.crt` must be accepted by `[rpc.tls.mutual].ca_certs`, contain a
valid RA-TLS attestation, and use the same key as `rpc.crt`. The server
certificate is reissued by the threshold root; the client certificate remains
under the mutual-TLS CA so Rocket can authenticate peer connections before the
RPC quote and manifest checks run.

Record and independently compare `key_provider_id` from multiple members before
placing it in application compose files.

## Normal operation

Signing uses an exact live threshold selected in canonical manifest order.
Two offline nodes are tolerated by a 3-of-5 cluster. Every protocol envelope is
bound to the epoch, protocol, session, request hash, sender, recipient, sequence
number, and expiry. Raw arbitrary-digest signing is not exposed.

Derivation is a verifiable threshold PRF. Each response carries a DLEQ proof
against the member's public derivation share; the coordinator combines only
verified partials. Disk, environment, application K-256, and application CA
keys use separate semantic domains.

## Revocation and subset resharing

For a target consisting only of current members:

1. call `Admin.PrepareReshare` with a canonical next-epoch `ResharePlan`;
2. construct an `EpochManifest` using the returned commitment for every target
   member;
3. call `Admin.SignEpochManifest`;
4. send the signed result to `Admin.ActivateEpoch` on every target and removed
   member; and
5. let the supervisor restart each process.

Exactly an old threshold acts as dealers. Their Lagrange-weighted random
polynomials preserve every group public key. Private evaluations are sent
point-to-point over RA-TLS and are verified against coefficient commitments.

Activation validates the signed chain, local pending share topology, stable
group keys, and local share commitment. It writes an activation journal before
changing active files. Startup completes an interrupted transaction before it
loads a manifest or share. Removed nodes install the signed epoch and then fail
closed because they are no longer members.

## Adding members

Adding a member is an explicitly authorized maintenance operation:

1. Create a sorted `ResharePlan` containing the target membership and exactly
   the old threshold in `dealers`. Existing node endpoints and attestation keys
   must remain unchanged. New members use freshly attested TLS keys.
2. Call `Admin.AuthorizeReshare`. The result is signed by the active threshold
   K-256 key and binds the predecessor, target epoch, threshold, dealers,
   endpoints, and quote-bound keys.
3. Provision the signed authorization, active signed manifest, cluster
   identity, root certificate, and provisional attested transport key on every
   target node. Place the authorization at `join_authorization_file`.
4. Restart every target. They enter maintenance join mode. The first authorized
   dealer coordinates fresh all-target auxiliary generation, point-to-point
   verifiable resharing, target manifest signing, and threshold issuance of
   each target RPC certificate.
5. Each target atomically activates the signed epoch, removes the authorization,
   and shuts down for a normal-mode restart.

The coordinator never receives all private recipient evaluations. A joining
node receives only the old public topology and its own evaluation from each
old dealer. The old root private key is never reconstructed.

## Migration and compatibility

The public KMS RPCs and guest key-delivery formats remain unchanged. MPC mode
adds metadata fields and admin methods without removing legacy fields.

Moving an existing single-root deployment to a newly generated MPC cluster is
a provider rotation: the `key_provider_id` and deterministically derived
application keys change. Existing encrypted disks therefore require an
application-level migration ceremony. Do not silently switch an existing
compose pin. Run old and new providers in parallel, migrate protected data,
then update and re-measure the compose pin.

MPC members reject legacy root-key export and handover. There is intentionally
no API that reconstructs threshold roots.

## Operational requirements

- Keep share, checkpoint, journal, identity, authorization, and manifest files
  on durable storage; secret shares and journals must be mode `0600`.
- Use authenticated admin listeners. Never enable `insecure_no_auth` in a
  network-reachable deployment.
- Require at least threshold 2; production deployments should use 3-of-5 or
  stronger.
- Monitor quorum availability and restart completion. Do not activate a target
  manifest until every retained member reports its expected commitment.
- Back up shares independently. A backup set smaller than the threshold cannot
  recover the root; losing threshold shares permanently loses the provider.
- Treat a same-epoch fork, skipped epoch, checkpoint permission failure, quote
  mismatch, share commitment mismatch, or group-key change as a security
  incident. The implementation fails closed for all of them.
