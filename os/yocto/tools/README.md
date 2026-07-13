# Yocto host tools

This directory is reserved for host-side workarounds that are specific to
building the Yocto backend. It is not part of the guest-OS backend interface;
the supported backend entrypoint is [`../build.sh`](../build.sh).

- `fix-self-uid-map.sh` is an explicit host AppArmor workaround for affected
  Ubuntu installations; it is not part of the image build.

The legacy cross-cutting helpers live under [`../../../tools/`](../../../tools/)
instead of inside this backend.
