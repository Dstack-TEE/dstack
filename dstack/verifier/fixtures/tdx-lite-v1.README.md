# TDX lite v1 surface fixtures

These fixtures pin what the `dstack.guest.v1` surface hands out on real Intel TDX
hardware, next to the frozen v0 surface in the same boot. All four files come from
**one boot** of one CVM:

| File | Source | Wire form |
| --- | --- | --- |
| `tdx-lite-v1-attest.json` | `POST /v1/Attest` | MessagePack V1 |
| `tdx-lite-v0-attest.json` | `GET /Attest` | legacy SCALE V0 |
| `tdx-lite-v1-issue-cert.pem` | `POST /v1/IssueCert`, `usage_ra_tls` | leaf embeds MessagePack V1 |
| `tdx-lite-v0-get-tls-key.pem` | `POST /GetTlsKey`, `usage_ra_tls` | leaf embeds legacy SCALE V0 |

Both `Attest` calls request 64 bytes of `0x42` as report data. The certificate
files hold the chain the agent returned: the leaf, then the CVM's local CA
(`App Root Cert`). The private keys were not kept.

The CVM ran with `event_log_version` 1, so the platform itself produced the
legacy form. The v1 bytes are the guest agent's MessagePack re-encoding
(`AttestationWire::MsgpackV1`), which is exactly the case these fixtures exist
to cover.

## Environment

- Image: mkosi `prod` flavor built from git revision `452d04ee8365` (the guest
  agent reports `git:452d04ee8365c9d0f456` from `/v1/Version`),
  `kernel_header_normalized: true`,
  `os_image_hash = 98a3394699570adf5921eb17bafed62b37b4a63cad28eb5506b430b63af2e20e`
- `vm_config.tdx_attestation_variant = "lite"`, 2 vCPUs, 2 GiB, QEMU 8.2.2
- Key provider `none`, so certificates are signed by the in-CVM local CA and the
  CVM needs no KMS or gateway

## Capture

The VMM ran locally with `tdx_attestation_variant = "lite"`, and the app compose
carried a `pre_launch_script` that called the guest agent over
`/var/run/dstack.sock` and posted each response to a collector on the host
(`10.0.2.2` under QEMU user networking):

```bash
RD=$(printf '42%.0s' $(seq 1 64))
curl --unix-socket /var/run/dstack.sock -X POST -H 'Content-Type: application/json' \
  -d "{\"report_data\":\"$RD\"}" http://localhost/v1/Attest
curl --unix-socket /var/run/dstack.sock "http://localhost/Attest?report_data=$RD"
curl --unix-socket /var/run/dstack.sock -X POST -H 'Content-Type: application/json' \
  -d '{"subject":"v1-attest-e2e.local","alt_names":["v1-attest-e2e.local"],"usage_ra_tls":true,"usage_server_auth":true,"usage_client_auth":true}' \
  http://localhost/v1/IssueCert
curl --unix-socket /var/run/dstack.sock -X POST -H 'Content-Type: application/json' \
  -d '{"subject":"v0-attest-e2e.local","alt_names":["v0-attest-e2e.local"],"usage_ra_tls":true,"usage_server_auth":true,"usage_client_auth":true}' \
  http://localhost/GetTlsKey
```

## What the tests assert

- The two `Attest` results verify through `CvmVerifier` with no image download,
  with the quote, event log, OS image hash and ACPI tables all verified, and the
  two serialized responses are identical.
- Each leaf chains to its CA and passes `ra_tls::attestation::verify_der`, with
  the report data bound to the leaf's own public key. The embedded attestation
  passes the same full `CvmVerifier` check, and both certificates name the same
  CVM.
- The v1 certificate's attestation is rejected against the v0 leaf's key.

At capture time the same bytes also verified with the `dstack-attest`
verification path of v0.5.9 and v0.5.11: DCAP quote `UpToDate`, RTMR3 replay,
and identical app identity for the MessagePack and SCALE forms.
`dstack-verifier --verify-cert` does not apply to these leaves, because it
accepts only self-signed RA-TLS certificates.
