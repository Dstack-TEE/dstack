# Legacy meta-dstack tools

This directory preserves host-side utilities imported from `meta-dstack` that
do not belong to a single monorepo component or guest-OS backend. They are
retained for compatibility and low-level debugging, not as supported deployment
entrypoints.

- `dev-stack.sh` is the historical all-in-one host build, Yocto build,
  configuration, and image-download helper.
- `vm-runner/` is the historical direct-QEMU runner and its GPU passthrough
  helper and sample.

Use `dstackup` for host installation, `dstack` for app deployment, and
`os/build.sh` or the repository Makefile for guest-OS builds.
