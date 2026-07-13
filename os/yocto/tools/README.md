# Imported Yocto support tools

These are auxiliary host-side tools retained from `meta-dstack`. They are not
part of the guest-OS backend interface; the supported backend entrypoint is
[`../build.sh`](../build.sh).

- `dev-stack.sh` preserves the legacy all-in-one host/configuration helper.
- `fix-self-uid-map.sh` is an explicit host AppArmor workaround for affected
  Ubuntu installations; it is not part of the image build.
- `vm-runner/` preserves the legacy direct-QEMU image runner and its GPU sample.

Keeping these helpers under `tools/` prevents `dev-setup` from placing a second,
legacy command named `dstack` on `PATH`. Use the Rust `dstack` and `dstackup`
CLIs for supported deployment workflows.

Invoke a retained helper by its explicit path, for example
`os/yocto/tools/dev-stack.sh --help`.
