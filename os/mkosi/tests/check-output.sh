#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
out=${1:?assembled output directory required}
flavor=${2:-prod}
for file in bzImage initramfs.cpio.gz ovmf.fd ovmf-sev.fd rootfs.img.parted.verity \
 metadata.json measurement.tdx.cbor measurement.snp.cbor sha256sum.txt digest.txt; do
  [[ -s $out/$file ]] || { echo "missing compatible output: $file" >&2; exit 1; }
done
(cd "$out" && sha256sum -c sha256sum.txt)
grep -q 'dstack-rootfs' < <(sgdisk -p "$out/rootfs.img.parted.verity")
python3 - "$out/metadata.json" "$flavor" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
for k in ("bios","bios-sev","kernel","cmdline","initrd","rootfs","version","git_revision","builder","is_dev","ovmf_variant"):
    assert k in d, k
assert d["builder"] == "mkosi"
assert d["bios-sev"] == "ovmf-sev.fd"
assert d["is_dev"] == (sys.argv[2] == "dev")
PY
echo "Yocto-compatible release format accepted: $out"
