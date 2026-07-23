# mock-attestation

Development-only, cryptographically valid attestation evidence for CI and the
`dstack-tee-simulator` dev image.

The crate derives a development PKI from a 32-byte seed and dynamically signs evidence for:

- Intel TDX/DCAP, including TCB Info, QE Identity, PCK certificates and CRLs;
- AMD SEV-SNP, including ARK, ASK, VCEK and reports;
- TPM, including AK certificates, quotes, AIA and CRLs;
- AWS NSM, including the certificate bundle and COSE Sign1 document.

All evidence is verified in the test suite by the production QVLs. These keys
are test credentials and must never be copied into a production image.

## CLI

Generate matching public roots and `tee-simulator.json`:

```console
dstack-mock-attestation generate \
  --output ./mock-roots \
  --collateral-base-url http://HOST_REACHABLE_FROM_VERIFIER:8088
```

Use the generated simulator config for both the guest-side simulator and the
host-side Mock PCCS/KDS/AIA service:

```console
dstack-mock-attestation serve \
  --listen 127.0.0.1:8088 \
  --config ./mock-roots/tee-simulator.json \
  --output ./active-mock-roots
```

The server exposes only production-shaped public collateral endpoints. Evidence
is generated inside the development guest by `dstack-tee-simulator`; the HTTP
service deliberately provides no unauthenticated signing endpoint.

## Dev image

Select the platform in the development-only `.tee-simulator.json`; omission
defaults to TDX:

```json
{
  "platform": "dstack-amd-sev-snp",
  "mock_attestation_seed": "<64 hex characters>",
  "collateral_base_url": "http://HOST_REACHABLE_FROM_VERIFIER:8088"
}
```

Valid values mirror the supported attestation modes: `dstack-tdx`,
`dstack-gcp-tdx`, `dstack-amd-sev-snp`, `dstack-nitro-enclave`, and
`dstack-aws-nitro-tpm`. The simulator exposes
the production guest ABI for the selected platform (TSM configfs, vTPM, or an
NSM CUSE character device); attester libraries contain no mock HTTP or
environment-variable path. The guest only reads the
seed from `.tee-simulator.json`; it never writes credentials or roots back into
`/dstack/.host-shared`. CI retains the generated public roots and mounts them
into verifier/KMS/gateway. The independently running host collateral service
reconstructs the same hierarchy from the seed. Configure it under
`[attestation.urls]`: TDX uses `pccs`, and SEV-SNP uses `amd_kds`.

Every verifier process must also explicitly set
`attestation.insecure_allow_external_trust_anchors = true`. Merely mounting and
configuring a mock root is rejected at startup while this flag remains false.

The seed adds only 64 hex bytes (the simulator config is well below 1 KiB).

## Required negative tests

The crate tests ensure every platform rejects a different root and modified
signed bytes. SEV-SNP additionally performs expected `report_data` comparison
inside its QVL API. TDX/TPM/NSM expose their authenticated binding field for
the caller; the production `dstack-attest` layer performs the final equality
check.
