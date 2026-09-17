# Kernel module builder image

Toolchain image for building an out-of-tree kernel module against one dstack
guest OS image. It carries that image's exported kernel build tree
(`dstack-<version>-kernel-devel.tar.gz`) and a compiler installed from the same
pinned Debian snapshot the guest kernel was compiled with, so a module built
here matches the guest kernel's `vermagic` and `Module.symvers`.

Published by `.github/workflows/mkosi-build.yml` on a release tag as
`ghcr.io/dstack-tee/dstack-kernel-builder:<version>`, additionally tagged with
the kernel release (`6.18.x-dstack`). Application usage is documented in
[`../../../docs/building-guest-os.md`](../../../docs/building-guest-os.md#kernel-headers-for-out-of-tree-modules).

## Build it locally

The build script uses the repository's pinned toolchain snapshot and an isolated
build context containing only the kernel-devel archive.

```bash
source os/mkosi/versions.env
dist=os/mkosi/repro-build/build/out/prod
release=$(tar -xOf "$dist/dstack-$DSTACK_VERSION-kernel-devel.tar.gz" \
  "dstack-$DSTACK_VERSION-kernel-devel/kernel-devel.json" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["kernel_release"])')

./os/image/kernel-builder/build.sh \
  "$dist/dstack-$DSTACK_VERSION-kernel-devel.tar.gz" \
  "dstack-kernel-builder:$DSTACK_VERSION" "$release"
```

Then smoke-test module compilation and the target kernel release:

```bash
./os/tests/test-kernel-builder-image.sh "dstack-kernel-builder:$DSTACK_VERSION" "$release"
```

That script builds `os/tests/kmod-hello/` inside the image and fails unless the
resulting module's `vermagic` names the kernel the image claims to serve. CI
runs it before the image is pushed. This does not prove loadability: symbol
versions and other kernel compatibility requirements need a real guest load test.

Set `IMAGE_VERSION`, `OS_IMAGE_HASH`, and `GIT_REVISION` to override image labels.
`DOCKER` selects the Docker command for both scripts.

## What the image pins, and what it does not

The Debian snapshot pins the compiler, which is the part that has to agree with
the guest kernel build. `BASE_IMAGE` only supplies the file layout that
snapshot is installed into; the tag is mutable, so the image is not
bit-for-bit reproducible the way the guest OS artifacts are. The kernel build
tree it carries is: `os/mkosi/build.sh repro-check` compares
`dstack-<version>-kernel-devel.tar.gz` byte for byte across two independent
builds.
