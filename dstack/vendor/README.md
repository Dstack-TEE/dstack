# Vendored crates

Third-party crates carried in-tree because the published release does not build
for a target dstack ships. Each one is a copy of a specific crates.io release
plus a named upstream patch, so the diff against the release is small enough to
review and the directory can be deleted once upstream publishes the fix.

## ktls 6.0.2

**Why:** `ktls` 6.0.2 builds `libc::cmsghdr` and `libc::msghdr` with struct
literal syntax. That works on glibc, where those structs have exactly the
members the crate names, but musl's ABI declares `msg_iovlen` and
`msg_controllen` as `int`/`socklen_t` followed by explicit padding, and `libc`
models that faithfully with private `__pad1`/`__pad2` members. A struct literal
cannot name a private field, so the crate does not compile for
`x86_64-unknown-linux-musl` -- which is the target the gateway CVM app image is
built for:

```
error[E0063]: missing field `__pad1` in initializer of `cmsghdr`
error: cannot construct `msghdr` with struct literal syntax due to private fields
```

This is a permanent property of musl's ABI, not a transient `libc` bug, and
6.0.2 is the latest published release, so there is no version to bump to.

**Patch:** [rustls/ktls#70](https://github.com/rustls/ktls/pull/70) ("build: add
musl support"), open upstream since 2026-05-04. Both structs are built field by
field from `std::mem::zeroed()` instead of with a literal. The patch is applied
to the 6.0.2 release rather than to upstream `main`, so this copy differs from
crates.io only in those two functions; each hunk is marked with a
`dstack patch (rustls/ktls#70)` comment.

**Other differences from the crates.io package:** `[dev-dependencies]` are
dropped (upstream's test suite is not run here and would otherwise pull `rcgen`,
`test-case` and friends into this workspace's lock file), and `publish = false`
is set. `LICENSE-MIT` and `LICENSE-APACHE` are copied from the upstream
repository, which the crates.io package does not ship.

**Remove this when:** upstream merges #70 and publishes a release containing it.
At that point delete `vendor/ktls`, drop the workspace member, and point
`ktls` in the root `Cargo.toml` back at the crates.io version.
