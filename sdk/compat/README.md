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
sdk/compat/run-compat-tests.sh v0.5.9 v0.5.11   # one simulator, both tags
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
`v0.5.11` — the tag the freeze is defined against — and `v0.5.9`, the newest
tag whose SDKs actually differ from it. Check before adding a tag: several
release tags share an SDK tree byte for byte (`git rev-parse v0.5.10:sdk
v0.5.11:sdk` prints one hash twice), and a pair like that runs the same suites
twice and reports the agreement as two independent results.

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
