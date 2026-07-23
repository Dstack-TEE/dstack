#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Build the same pinned Intel TDX OVMF generation consumed by dstack-mr. A
# stock distro OVMF is not compatible with dstack's TDX measurement format.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
BUILD_DIR=${1:?build directory required}
OUT=${2:?output file required}
SEV_OUT=${3:?SEV output file required}
BUILD_DIR=$(realpath -m "$BUILD_DIR")
OUT=$(realpath -m "$OUT")
SEV_OUT=$(realpath -m "$SEV_OUT")
REV=fbe0805b2091393406952e84724188f8c1941837
src="$BUILD_DIR/edk2"
if [[ ! -d $src/.git ]]; then
  mkdir -p "$BUILD_DIR"
  git init -q "$src"
  git -C "$src" remote add origin https://github.com/tianocore/edk2.git
fi
git -C "$src" fetch -q --depth=1 origin "$REV"
git -C "$src" checkout -q --detach FETCH_HEAD
git -C "$src" submodule update --init --recursive --depth=1
git -C "$src" reset -q --hard "$REV"
patch -d "$src" -p1 --forward --fuzz=0 < \
  "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf/0004-Reproduciable.patch"
patch -d "$src" -p1 --forward --fuzz=0 < \
  "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf/0006-OvmfPkg-AmdSev-drop-embedded-grub.patch"

make -s -C "$src/BaseTools" -j"${JOBS:-$(nproc)}"
export WORKSPACE="$src" EDK_TOOLS_PATH="$src/BaseTools"
export PATH="$EDK_TOOLS_PATH/BinWrappers/PosixLike:$PATH"
export PYTHON_COMMAND=python3
# Yocto disables EDK2 LTO for deterministic link ordering.
sed -i -e 's/-flto/-fno-lto/g' -e 's/-DUSING_LTO//g' \
  "$src/BaseTools/Conf/tools_def.template"
sed -i 's/-Werror /-Werror -Wno-maybe-uninitialized -Wno-stringop-overflow /g' \
  "$src/BaseTools/Conf/tools_def.template"
rm -f "$src/Conf/tools_def.txt"
# shellcheck source=/dev/null
(cd "$src" && set +u && source edksetup.sh BaseTools >/dev/null && \
  build -a X64 -t GCC5 -b RELEASE -n "${JOBS:-$(nproc)}" \
    -p OvmfPkg/IntelTdx/IntelTdxX64.dsc)
install -Dm0644 "$src/Build/IntelTdx/RELEASE_GCC5/FV/OVMF.fd" "$OUT"
# shellcheck source=/dev/null
(cd "$src" && set +u && source edksetup.sh BaseTools >/dev/null && \
  build -a X64 -t GCC5 -b RELEASE -n "${JOBS:-$(nproc)}" \
    -p OvmfPkg/AmdSev/AmdSevX64.dsc)
install -Dm0644 "$src/Build/AmdSev/RELEASE_GCC5/FV/OVMF.fd" "$SEV_OUT"
touch -d "@${SOURCE_DATE_EPOCH:?}" "$OUT" "$SEV_OUT"
