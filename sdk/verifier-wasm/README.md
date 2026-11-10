# @phala/dstack-verifier-wasm

Local TDX lite OS check for dstack 0.6.x CVMs. The caller verifies the DCAP
quote and replays RTMR3; this package checks `vm_config.tdx_measurement`
against `os_image_hash`, regenerates the three RTMR0 ACPI digests from
`vm_config`, recomputes MRTD/RTMR0-2, and compares them with the quote.

```js
import { verifyTdxLiteOs } from '@phala/dstack-verifier-wasm'

const result = verifyTdxLiteOs({
  mrtd,
  rtmr0,
  rtmr1,
  rtmr2,
  eventLog, // GetQuote event_log string
  vmConfig, // GetQuote vm_config string
})
// { ok, osImageHash, acpiTablesVerified, reason }
```

Does not judge os_image_hash approval, DCAP validity, or RTMR3. Never throws:
bad input and wasm traps return `{ ok: false, reason }`.

Build (pinned by the repo `rust-toolchain.toml`, currently 1.92 with
`wasm32-unknown-unknown`):

```bash
npm run build
npm test
```

The wasm bytes are embedded in the JS module. This package is not published to
npm from CI.
