#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# Give the read-only root writable /var subtrees without hiding what the image
# ships there.
#
# A plain "mount --bind" of a freshly created tmpfs directory masks the lower
# content instead of layering over it: /var/lib/chrony, /var/lib/docker,
# /var/lib/containerd and /var/lib/tpm2-tss/system/keystore are all present in
# the measured image and would become invisible, replaced by empty unmeasured
# directories. It also loses the lower directory's mode, which silently turned
# /var/tmp from 1777 into 0755.
#
# An overlay keeps the measured content readable and puts writes in the tmpfs,
# matching what poky's volatile-binds does for the Yocto image and what
# dstack-prepare.sh already does for /etc, /usr and /bin.
for name in cache lib log spool tmp; do
    lower=/var/$name
    state=/var/volatile/$name
    mkdir -p "$lower" "$state/upper" "$state/work"
    mountpoint -q "$lower" && continue
    mount -t overlay overlay \
      -o "lowerdir=$lower,upperdir=$state/upper,workdir=$state/work" "$lower"
done
