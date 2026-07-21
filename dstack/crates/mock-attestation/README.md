# mock-attestation

Development-only, cryptographically valid attestation evidence for CI and the
`dstack-tee-simulator` dev image.

The crate creates an ephemeral PKI and dynamically signs evidence for:

- Intel TDX/DCAP, including TCB Info, QE Identity, PCK certificates and CRLs;
- AMD SEV-SNP, including ARK, ASK, VCEK and reports;
- TPM, including AK certificates, quotes, AIA and CRLs;
- AWS NSM, including the certificate bundle and COSE Sign1 document.

All evidence is verified in the test suite by the production QVLs. These keys
are test credentials and must never be copied into a production image.

## CLI

Generate standalone roots:

```console
dstack-mock-attestation generate --output ./mock-roots
```

Start the combined Mock PCCS/KDS/AIA service and write the matching public
roots:

```console
dstack-mock-attestation serve \
  --listen 127.0.0.1:8088 \
  --output ./active-mock-roots
```

The server exposes production-shaped collateral endpoints and dynamic evidence
under `/attest/{tdx,sev-snp,tpm,nsm}`.

## Dev image

Select the platform in `.sys-config.json`; omission defaults to TDX:

```json
{
  "tee_simulator": { "platform": "sev-snp" }
}
```

Valid values are `tdx`, `sev-snp`, `tpm`, and `nsm`. The simulator publishes
the matching roots under:

```text
/dstack/.host-shared/.mock-attestation/
```

and starts collateral/evidence service at `http://127.0.0.1:8088`. CI must
mount the public roots into verifier/KMS/gateway and configure their existing
`root_ca` paths. TDX uses the service as `pccs_url`; SEV-SNP uses
`http://127.0.0.1:8088/vcek/v1` as its KDS base.

## Required negative tests

The crate tests ensure every platform rejects a different root and modified
signed bytes. SEV-SNP additionally performs expected `report_data` comparison
inside its QVL API. TDX/TPM/NSM expose their authenticated binding field for
the caller; the production `dstack-attest` layer performs the final equality
check.
