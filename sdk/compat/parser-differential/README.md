<!--
SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>

SPDX-License-Identifier: Apache-2.0
-->

# Cross-language parser differential harness

Feeds one canned guest-agent response to the Rust, Python, Go and JavaScript
SDKs and tabulates what each does with it. Four implementations of one protocol
is the shape that produces parser differentials, and the only way to find them
is to run the same bytes through all four.

This is **not** part of `sdk/run-tests.sh`. It needs all four toolchains and it
answers a question — "do these agree?" — rather than asserting a fixed
expectation. Run it by hand when the wire format changes or when one SDK's
decoding is touched.

```
./run.sh
```

Findings from the first run are written up in
`.agent/PARSER-INVENTORY-sdk.md`.

## How it works

`server.py` listens on a unix socket and answers every POST with one entry from
`cases.json`, chosen by a preceding `POST /__case/<name>`. The four drivers each
select a case, call the SDK method under test, and print one line:

```
OK|<a summary of what was decoded>
ERR|<exception type>: <message>
PANIC|<...>            # Go only; the others cannot
CRASH(rc=N)|<...>      # the process died
```

`run.py` walks the cross product and writes `results.json`.

## Adding a case

Append to `cases.json`:

```json
"A99_my_case": {
  "method": "GetKey",       // GetKey | Info | Attest | v0GetKey | v0Info | v0TlsKey
  "status": 200,
  "body": "{\"key\": ...}"  // verbatim, so malformed JSON and duplicate keys are expressible
}
```

`body` is a **string**, not an object, on purpose: duplicate keys, trailing
commas and truncated documents all have to survive to the wire.

## Why not the simulator

`sdk/simulator` is the real guest agent with one trait swapped
(`dstack/guest-agent/src/backend.rs`), which is exactly what makes it
trustworthy — a test that passes against it cannot be rejected by a real agent
on validation grounds. Giving it a fault-injection mode would put test-only
branches inside the production handler and cost that property. So malformed
responses come from here instead.
