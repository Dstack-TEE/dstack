#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOTFS=$(realpath -m "${1:?rootfs tree required}")

# Match Yocto's production packaging policy: development inputs, translated
# messages and package-manager metadata are not part of the immutable guest.
# /var/cache and /var/lib are hidden by volatile bind mounts at runtime.
for path in \
  usr/include \
  usr/share/OVMF \
  usr/share/ovmf \
  usr/share/doc \
  usr/share/info \
  usr/share/locale \
  usr/share/man \
  var/cache/debconf \
  var/lib/dpkg \
  var/lib/ucf; do
  rm -rf "${ROOTFS:?}/$path"
done

# Static archives and libtool metadata are build inputs. All production
# consumers use the corresponding shared objects.
find "$ROOTFS/usr" -type f \( -name '*.a' -o -name '*.la' \) -delete
