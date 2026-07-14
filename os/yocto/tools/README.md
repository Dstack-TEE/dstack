# Yocto host tools

This directory contains host-side utilities that are specific to building,
validating, or publishing artifacts from the Yocto backend. It is not part of
the guest-OS backend interface; the supported build entrypoint is
[`../build.sh`](../build.sh).

- `fix-self-uid-map.sh` is an explicit host AppArmor workaround for affected
  Ubuntu installations; it is not part of the image build.
- `aws/` contains AWS EC2 NitroTPM image validation, AMI promotion, live-smoke,
  and release-evidence helpers. These scripts are Yocto OS artifact consumers,
  so they stay with the backend rather than in the repository-wide `tools/`.
  App/config binding for AWS is **not** baked into the UKI cmdline; release
  packages should ship a shared-disk MrConfigV3 (measured into PCR8 at boot)
  and optional `aws_measurement` for unified `os_image_hash`.

The legacy cross-cutting helpers live under [`../../../tools/`](../../../tools/)
instead of inside this backend.
