# Repository tools

This directory contains developer and operator utilities that do not belong to
one runtime component or one guest-OS backend.

- `add-spdx-attribution.py` updates SPDX attribution metadata.
- `mock-cf-dns/` is the Cloudflare DNS API test double both E2E suites build:
  the API endpoints certbot calls, plus TXT answers on 53 over UDP and TCP so
  an ACME server can validate against the records it writes.
- `sca/` builds self-contained application images.
- `dev-stack.sh` preserves the unsupported legacy all-in-one host, guest, and
  deployment helper.
- `vm-runner/` preserves the unsupported legacy direct-QEMU runner and GPU
  passthrough helper.

The legacy tools are kept out of `os/yocto/` because they cross host, guest,
and deployment boundaries. Use the Rust `dstack` and `dstackup` CLIs for
supported workflows.
