# local-key-provider

`local-key-provider` is dstack's SGX-backed bootstrap key provider for TDX
guests. It is protocol- and cryptography-compatible with the former external
`gramine-sealing-key-provider`, but its source and build are maintained in the
dstack repository.

For each request it:

1. verifies the guest's TDX quote with DCAP;
2. checks that the SGX and TDX quotes carry the same quoting-enclave ID;
3. derives a 32-byte key as `SHA-256(SGX sealing key || MRTD || RTMR0..3)`;
4. encrypts the key using the libsodium sealed-box format and the X25519 public
   key in the TDX report data; and
5. returns the ciphertext with an SGX quote binding its SHA-256 digest.

The wire protocol remains a four-byte big-endian JSON length followed by a
`{"quote":[...]}` request. The response contains `encrypted_key` and
`provider_quote` byte arrays.

Use the `build/` directory's Docker Compose configuration to build and run the
provider under Gramine. The container build uses the repository workspace's
`Cargo.toml` and `Cargo.lock` instead of a second build-only manifest or
lockfile.
