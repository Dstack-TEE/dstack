# Repository tools

This directory contains developer and operator utilities that do not belong to
one runtime component or one guest-OS backend.

- `add-spdx-attribution.py` updates SPDX attribution metadata.
- `mock-cf-dns-api/` provides a local Cloudflare DNS API test double.
- `sca/` builds self-contained application images.
- [`meta-dstack/`](meta-dstack/) preserves unsupported legacy host/deployment
  and direct-QEMU helpers imported during the monorepo migration. These tools
  are kept out of `os/yocto/` because they cross host, guest, and deployment
  boundaries. Use the Rust `dstack` and `dstackup` CLIs for supported
  workflows.
