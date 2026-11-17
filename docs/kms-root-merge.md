# Merging two KMS roots (0.6.5-mrgk)

This build exists for one operation and is not part of any regular release.
It joins the roots of two independently bootstrapped KMS clusters into one
keyring: the existing cluster's roots stay epochs `0..N-1`, and the other
cluster's single root becomes epoch `N`. It is otherwise identical to 0.6.5.

The result is what a rotation would produce, except that epoch `N` is imported
instead of generated. Derived keys depend on the root keys and the app epoch,
never on the root epoch number, so every app of the merged cluster keeps its
keys once epoch `N` is current.

## Onboard

`Onboard` takes two extra fields:

- `merge_source_url`: a KMS holding exactly one root epoch, such as a 0.6.3 KMS.
- `merge_source_token`: optional bearer token for its admin listener.

They cannot be combined with `rotate`. The KMS then:

1. Imports the whole keyring from `source_url`, as an ordinary onboarding.
2. Fetches the merge source's keys, requires it to hold exactly one root epoch,
   and requires the auth API to authorize it for key export at epoch `N`.
3. Checks the merged keyring against governance as a join: the current epoch
   and epoch `N`, registered and pending activation, must both match their
   chain hashes.

The merge source is not pinned to a root CA: only the auth API knows epoch
`N`, by its chain hash, and the keys are checked against it before use. The
merge source still releases its keys only to an attested KMS its own auth API
allows, with or without its admin token.

The merged KMS serves the current epoch, so it serves the existing cluster's
roots until epoch `N` is activated. Ordinary 0.6.5 KMS instances then onboard
from it without `merge_source_url`; the merge build is retired afterwards.

## Procedure

1. Register epoch `N` with the merge source's root public keys and its
   bootstrap attestation as evidence. Do not activate it.
2. Allow the merge build's measurement to import keys from both clusters, and
   to export them on the merged cluster.
3. Onboard one merge build instance with both sources, then onboard 0.6.5
   instances from it, and retire the merge build.
4. Until activation, deny apps of the merge source's cluster on the merged
   cluster: it would serve them the old roots.
5. Activate epoch `N` with the rotation of the existing cluster's apps, then
   move the merge source's apps over. A CVM that booted on the merged cluster
   records epoch `N` on its disk and cannot return to the merge source.
