# @phala/dstack-verifier-wasm

This package checks a dstack 0.6.x Intel TDX CVM's OS locally. Given MRTD and
RTMR0-2 from a quote you already verified, plus the guest's `event_log` and
`vm_config`, it checks `vm_config.tdx_measurement` against `os_image_hash`,
regenerates the three RTMR0 ACPI digests from the declared VM shape, recomputes
MRTD/RTMR0-2, and compares them with the quote.

It does **not** verify the DCAP quote, apply TCB policy, bind `report_data` /
a nonce, replay RTMR3 (app/compose), or decide whether `osImageHash` is an
approved OS release. Those are the caller's job. `ok: true` means only that
the lite OS check passed. It does not mean the CVM is trusted.

## Scope

dstack 0.6.x Intel TDX CVMs whose `vm_config.tdx_attestation_variant` is
`lite`. The legacy TDX variant (full image download) and other platforms
(AMD SEV-SNP, GCP TDX, AWS Nitro) are out of scope.

A non-lite `vm_config` returns `ok: false` with reason
`vm_config is not a TDX lite attestation` (the default variant is `legacy`).
Lite without `tdx_measurement` returns
`tdx lite attestation requires vm_config.tdx_measurement`.

## Install

```bash
npm install @phala/dstack-verifier-wasm@0.1.0-beta.0
```

Requires Node `>=20.19.0`. The wasm bytes are embedded in the JS module: no
separate `.wasm` file, no wasm imports.

## Quick start

Inside the CVM, `GetQuote` returns the quote, event log, and vm_config.
`report_data` is at most 64 bytes (hex in JSON; shorter values are zero-padded).

```bash
curl --unix-socket /var/run/dstack.sock -X POST \
  http://dstack/GetQuote \
  -H 'Content-Type: application/json' \
  -d '{"report_data": "<64-byte nonce as hex>"}'
```

Response fields: `quote` (hex), `event_log` (JSON array as a string),
`report_data` (hex), `vm_config` (JSON object as a string). The JS SDK's
frozen v0 client is the same RPC: `DstackClientV0.getQuote(reportData)`.
v1 `DstackClient` has no `GetQuote`; it uses `attest()`.

Verify the quote with a DCAP library, then pass MRs from the **verified**
report into this package:

```js
import { getCollateralAndVerify } from '@phala/dcap-qvl'
import { verifyTdxLiteOs } from '@phala/dstack-verifier-wasm'

const quoteBytes = Buffer.from(getQuote.quote, 'hex')
const verified = await getCollateralAndVerify(quoteBytes)
// Caller applies TCB policy (verified.status, verified.advisory_ids)
// and checks verified.report's reportData against the nonce.

const td = verified.report.asTd10()
  ?? verified.report.asTd15()?.base
  ?? null
if (!td) {
  throw new Error('quote is not a TDX report')
}

const hex = (bytes) => Buffer.from(bytes).toString('hex')
const result = verifyTdxLiteOs({
  mrtd: hex(td.mrTd),
  rtmr0: hex(td.rtMr0),
  rtmr1: hex(td.rtMr1),
  rtmr2: hex(td.rtMr2),
  eventLog: getQuote.event_log,
  vmConfig: getQuote.vm_config,
})
if (!result.ok) {
  throw new Error(result.reason)
}
if (!approvedOsImageHashes.has(result.osImageHash)) {
  throw new Error(`unapproved OS ${result.osImageHash}`)
}
// Still replay RTMR3 (app/compose) yourself.
```

`getCollateralAndVerify` / `VerifiedReport.report.asTd10` are the public
`@phala/dcap-qvl` 0.7.x API. A different DCAP library is fine as long as MRs
come from a quote whose signature and collateral you verified.

## API

```ts
verifyTdxLiteOs(input: {
  mrtd: string
  rtmr0: string
  rtmr1: string
  rtmr2: string
  eventLog: string
  vmConfig: string
}): {
  ok: boolean
  osImageHash: string | null
  acpiTablesVerified: boolean
  reason: string | null
}
```

MRs are hex, any case, optional `0x` prefix, 48 bytes after decoding.
`eventLog` and `vmConfig` are the GetQuote `event_log` / `vm_config` strings
verbatim.

The call is synchronous. It never throws: bad input and wasm traps return
`{ ok: false, reason }`. A trap recreates the wasm instance before returning.
The module compiles on first import; the first `verifyTdxLiteOs` call is
typically a few milliseconds, later calls about 1 ms.

## Result reasons

`reason` is an anyhow chain (`outer: inner`). The main classes:

| `reason` contains | Meaning |
| --- | --- |
| `vm_config is not a TDX lite attestation` | `tdx_attestation_variant` is not `lite` (legacy, other platforms, missing field). |
| `tdx lite attestation requires vm_config.tdx_measurement` | Lite without measurement material. |
| `tdx lite measurement material does not match os_image_hash` | Attached CBOR does not commit to `os_image_hash`. |
| `TDX lite acpi-loader\|acpi-rsdp\|acpi-tables digest mismatch` | Regenerated ACPI digest disagrees with the named RTMR0 event. |
| `failed to recompute expected TDX lite ACPI table digests` | VM shape the generator cannot model (`swtpm`; QEMU older than 8.0). |
| `MRs do not match: MRTD\|RTMR0\|RTMR1\|RTMR2 mismatch` | Recomputed register disagrees with the quote. |

`osImageHash` is the hex `os_image_hash` from `vm_config` when that JSON
parsed; `acpiTablesVerified` is true only after the ACPI digests matched.

## Runtimes

CI on this repo runs the same accept/tamper cases on Node 20.19.0, 22, 24,
Bun 1.x, Electron 31 and current stable (main process, no renderer), and
Chromium / Firefox / WebKit (page main thread and a module worker). The wasm
module has zero imports.

## Versioning

The package version is independent of dstack's. Each release notes the dstack
commit it was built from. Pin an **exact** version.

Bump the package when dstack models new QEMU ACPI behaviour or VM topology, or
when the measurement-material format changes. A new OS image only needs the
caller to approve a new `osImageHash`; it does not require a new package
version.

## Verifying the build

The published wasm is built in a digest-pinned `linux/amd64` container
(`rust:1.92.0-bookworm@sha256:5c38a9e735664861e84ce6918e98ce7f05dbac210230d45381bcf870b2d58083`)
so the host toolchain binaries (LLVM codegen and/or rust-lld) cannot affect
it. Rebuild with `scripts/build-in-container.sh` on a **linux/amd64** host
(native or an x86_64 VM) and compare the sha256 of the decoded wasm. They
must match.

Emulated amd64 on arm64 hosts is not verified: qemu-user crashes rustc 1.92.0.
Docker on Apple Silicon is untested; do not assume it matches.

```bash
git clone https://github.com/Dstack-TEE/dstack
cd dstack
git checkout <tag-matching-the-package-version>
bash sdk/verifier-wasm/scripts/build-in-container.sh
python3 -c "import base64,hashlib,pathlib,re; t=pathlib.Path('sdk/verifier-wasm/src/wasm-bytes.js').read_text(); b=re.search(r\"wasmBase64 = '([^']+)'\", t).group(1); print(hashlib.sha256(base64.b64decode(b)).hexdigest())"
```

Unpack the published tarball (`npm pack @phala/dstack-verifier-wasm@<version>`)
and hash its `package/src/wasm-bytes.js` the same way. Once CI publishes with
provenance, check signatures:

```bash
npm audit signatures
```

`npm audit signatures` verifies [ECDSA registry signatures](https://docs.npmjs.com/about-ecdsa-registry-signatures).
Provenance, when present, is also on the version page at npmjs.com
(`dist.attestations` in `npm view @phala/dstack-verifier-wasm@<version>`).
