# local-key-provider

`local-key-provider` is dstack's SGX-backed bootstrap key provider for TDX
guests. It is protocol- and cryptography-compatible with the former external
`gramine-sealing-key-provider`, but its source and build are maintained in the
dstack repository.

For each request it:

1. verifies the guest's TDX quote with DCAP and refuses a TD that is in debug
   mode or was launched by a non-production TDX module;
2. checks that the SGX and TDX quotes carry the same quoting-enclave ID;
3. derives a 32-byte key as `SHA-256(SGX sealing key || MRTD || RTMR0..3)`;
4. encrypts the key using the libsodium sealed-box format and the X25519 public
   key in the TDX report data; and
5. returns the ciphertext with an SGX quote binding its SHA-256 digest.

The derivation covers MRTD and the RTMRs but not `TD_ATTRIBUTES`, and it stays
that way for compatibility with keys already in use. A debug TD running the
same image would therefore derive the production TD's key. dcap-qvl rejects
debug TDs by default; step 1 also checks the TD attributes and TDX module
itself, so the key does not depend on that default.

The wire protocol remains a four-byte big-endian JSON length followed by a
`{"quote":[...]}` request. The response contains `encrypted_key` and
`provider_quote` byte arrays.

Use the `build/` directory's Docker Compose configuration to build and run the
provider under Gramine. The container build uses the repository workspace's
`Cargo.toml` and `Cargo.lock` instead of a second build-only manifest or
lockfile.

Tagged releases (`local-key-provider-v*`) publish the image as
`ghcr.io/dstack-tee/local-key-provider:<version>`. The corresponding GitHub
release records the image digest and enclave measurements, attaches the full
SIGSTRUCT metadata, and links to its Sigstore build-provenance attestation.
