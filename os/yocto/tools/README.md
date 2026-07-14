# Yocto host tools

This directory contains host-side utilities that are specific to building,
validating, or publishing artifacts from the Yocto backend. It is not part of
the guest-OS backend interface; the supported build entrypoint is
[`../build.sh`](../build.sh).

- `fix-self-uid-map.sh` is an explicit host AppArmor workaround for affected
  Ubuntu installations; it is not part of the image build.
- `aws/` contains **image-side** helpers only (hardening audit and release
  manifest generation). AWS EC2 **lifecycle** (AMI import, shared-disk deploy,
  start/stop/logs) lives in `dstack-cloud` (`dstack/scripts/bin/dstack-cloud`)
  with `platform: aws`. App/config binding is **not** baked into the UKI
  cmdline; shared-disk MrConfigV3 is measured into PCR8 at boot, and
  `measurement.aws.cbor` + `VmConfig.aws_measurement` provide the unified
  `os_image_hash = sha256(sha256sum.txt)`.

The legacy cross-cutting helpers live under [`../../../tools/`](../../../tools/)
instead of inside this backend.
