# SDK compatibility regression

dstack 0.6.0 froze the unversioned guest-agent API at exactly the surface
v0.5.11 served. `DstackGuest` and `Worker` in
`dstack/guest-agent/rpc/proto/agent_rpc.proto` take no new methods, no new
fields and no renumbering, and every new capability goes to `dstack.guest.v1`
instead. The promise that comes with the freeze is that a released 0.5.x SDK
keeps working, unchanged, against a 0.6 agent.

This directory is what turns that promise into a test.

## What it does

`run-compat-tests.sh <tag>` builds the agent-backed simulator from the **current
checkout**, then checks out the SDKs **as they shipped** at `<tag>` and runs
their own test suites against that simulator.

```
sdk/compat/run-compat-tests.sh v0.5.11
sdk/compat/run-compat-tests.sh v0.5.8 v0.5.11   # one simulator, both tags
```

The released SDKs come from `git worktree add <tag>`, so they are the published
code down to the byte, not a reconstruction. Nothing from the tag's tree is
built into the agent and nothing from the current tree is copied into the SDKs.
The only thing crossing between the two is the wire protocol, which is the
entire subject of the test.

That asymmetry is the point. A test suite pinned inside this repo drifts with
the repo: the assertion gets updated in the same commit that changes the
behaviour, and the break is invisible. A released client cannot be edited to
accommodate a change, so it fails when the surface moves — which is what a real
deployed 0.5.x application would do.

## What this does not catch

A released client only exercises what it already knew about, so this job sees
**breaking** drift and is blind to **additive** drift. Add a field to a frozen
message and every old client ignores it, exactly as JSON and protobuf intend:
the suites stay green. That is not a hypothetical — the comment at the top of
`agent_rpc.proto` records that the surface acquired `GpuInfo`, `AttestGpu` and
an `AttestArgs` field between v0.5.11 and 0.6.0, which is the drift this job
would have slept through.

Additions are caught one layer down, by the descriptor-digest test in
`dstack/guest-agent/rpc/tests/frozen_surface.rs`: it hashes every frozen
service's method list and the full field list of every message they reach, so a
*wire-compatible* addition fails CI even though no client would notice.

Neither check subsumes the other. The digest pins the shape and cannot see
behaviour changing underneath a stable shape; this job exercises behaviour and
cannot see the shape growing. Both are required, and a change that trips
neither is what "frozen" is allowed to mean.

The suites run the same four languages `sdk/run-tests.sh` runs — Rust, Go,
Python, JS — including their purely local tests (compose hashing, env
encryption, signature verification vectors). Those need no agent and should pass
unchanged; they are not skipped just because they are not client calls.

CI runs one tag per matrix job (`.github/workflows/sdk-compat.yaml`), over
`v0.5.11` — the tag the freeze is defined against — and `v0.5.8`, the newest
tag whose SDK clients and suites actually differ from it.

Check before adding a tag, and check the *sources*, not the tree hash. Several
release tags share an `sdk/` tree byte for byte (`git rev-parse v0.5.10:sdk
v0.5.11:sdk` prints one hash twice), and a tag can differ by a hash while
carrying an identical client: `v0.5.9` differs from `v0.5.11` by one line, a
reqwest dependency spec in `sdk/rust/Cargo.toml`, with every client and test
source in all four languages unchanged. Either one runs the same suites twice
and reports one agreement as two independent results, at the cost of a second
uncached four-language build. `git diff --stat <tag> v0.5.11 -- sdk/` is the
check worth running.

Passing several tags in one local invocation builds and starts the simulator
once and shares a Cargo target directory across them.

The JS leg is the one that is not hermetic: the released `sdk/js` ships a
`bun.lockb` but no `package-lock.json`, and pins `typescript` and `@types/node`
at `latest`, so `npm install` resolves fresh every run. A red JS suite here can
mean an npm publish rather than agent drift — check the diff before believing
it. The Rust, Go and Python legs are pinned by `Cargo.lock`, `go.sum` and
`pdm.lock`.

Three runners share the sockets and the binary under `sdk/simulator/`: this
one, `sdk/run-tests.sh` and `dstack/run-tests.sh` (the last is what `rust.yml`
invokes). All three `rm -f` the same four socket paths on cleanup and rebuild
the same binary, so running any two at once in one checkout will have them
delete each other's sockets and fail to overwrite a running binary. Use
separate checkouts, or run them one after the other.

Two things `sdk/run-tests.sh` does are deliberately left out: `pdm run check`
(it lints the released SDK's source with today's ruff and mypy, which says
nothing about the agent's wire surface and fails on tool version drift alone)
and the `no_std` build check (a compile-time property of the old types crate,
with no agent involved).

## The skip list

The script carries a per-language skip list. Every entry names a behaviour
0.6.0 deliberately changed on the frozen surface, with a pointer to where that
decision is recorded — a `CHANGELOG.md` entry, or `docs/guest-api-v1.md`.

Lists are keyed by tag (`set_skips_for_tag`), because a skip is a claim about
one released client rather than about the frozen surface in general. The two
tags in the matrix disagree about the same method, under the same test name, so
a global list could not express it.

The list has entries for exactly one thing, and reading them is the fastest way
to see what this job is for. **v0.5.11 skips nothing** — every released test and
example passes. **v0.5.8 skips four**, all `EmitEvent`, which 0.6.0 removed (`CHANGELOG.md`,
`[Unreleased]` / Removed: "runtime RTMR3 events are system-owned and cannot be
extended by apps"):

| Skipped at v0.5.8 | What it asserted | Against a 0.6.0 agent |
| --- | --- | --- |
| `tests/test_client.py::test_emit_event` | "This should not raise an error" | `HTTPStatusError` 400 |
| `tests/test_client.py::test_sync_emit_event` | same, sync client | `HTTPStatusError` 400 |
| `dstack_client_usage` (Rust example) | step 4 calls `emit_event(...).await?` | example exits non-zero |
| `tests/test_client.py::test_emit_event_validation` | empty event name raises `ValueError` | still passes — see below |

The first three are the one sanctioned break on the frozen surface, now
recorded rather than assumed. The fourth is collateral and is listed only
because pytest deselects by nodeid *prefix*: an entry for `::test_emit_event`
takes `::test_emit_event_validation` with it whether or not it is named. Naming
it keeps the list equal to what the run actually skips — otherwise pytest
reports `3 deselected` against two entries and nobody can see the difference.
It costs nothing: it raises before a request is built and never contacts the
agent, and the same client-side validation still runs in the Rust, Go and JS
suites.

It is also the whole argument for the tag pair. Every v0.5.11 assertion about
`EmitEvent` is vacuous under a simulator endpoint: Go and JS never test it,
`assert_emit_event_behavior` asserts HTTP 400 whether the method works or is a
stub, and the example swallows the error when `DSTACK_SIMULATOR_ENDPOINT` is
set. Those three accommodations were added across v0.5.9..v0.5.11 (`fix(ci):
restore simulator test stability`) so the suite would pass against a simulator
that could not extend an RTMR. v0.5.8 predates them and still asserts the call
succeeds. **A matrix that ran only v0.5.11 would report an empty skip list and
have checked nothing here** — which is exactly what it did before v0.5.8 was
added.

Examples skip at whole-binary granularity, since `cargo run --example` has no
name filter — so an entry must also say what the skip costs. For
`dstack_client_usage`, nothing: its other four steps (`Info`, `GetKey`,
`GetQuote`, `GetTlsKey`) are each covered by `tests/test_client.rs`, which runs
unskipped in the same leg.

**A growing skip list is the failure signal, not the fix.** The list existing at
all is a small admission that the freeze has exceptions; every addition to it
enlarges that admission. When an old suite fails, there are exactly two
outcomes:

1. The failure matches a sanctioned change. Add it, with a comment naming the
   change and the record it lives in.
2. It does not. Then the frozen surface has drifted, and the agent is what needs
   fixing.

There is no third case where a test is skipped because it is inconvenient. If
you cannot write the justification comment, you are looking at outcome 2.
