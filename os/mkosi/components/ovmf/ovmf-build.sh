#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Build the same pinned Intel TDX OVMF generation consumed by dstack-mr. A
# stock distro OVMF is not compatible with dstack's TDX measurement format.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
# shellcheck source=/dev/null
source "$ROOT/os/mkosi/versions.env"
BUILD_DIR=${1:?build directory required}
OUT=${2:?output file required}
SEV_OUT=${3:?SEV output file required}
BUILD_DIR=$(realpath -m "$BUILD_DIR")
OUT=$(realpath -m "$OUT")
SEV_OUT=$(realpath -m "$SEV_OUT")
REV=${OVMF_REVISION:?OVMF_REVISION required}
src="$BUILD_DIR/edk2"
if [[ ! -d $src/.git ]]; then
  mkdir -p "$BUILD_DIR"
  git init -q "$src"
  git -C "$src" remote add origin https://github.com/tianocore/edk2.git
fi
git -C "$src" fetch -q --depth=1 origin "$REV"
git -C "$src" checkout -q --detach FETCH_HEAD
# --force so a shallow submodule whose working tree ended up ahead of the
# pinned commit is checked out anyway. Without it a partially completed update
# leaves the submodule dirty, and every later attempt fails with "local changes
# would be overwritten by checkout" instead of retrying the original error.
for attempt in 1 2 3; do
  if git -C "$src" submodule update --init --recursive --depth=1 --force; then
    break
  fi
  (( attempt < 3 )) || { echo 'failed to fetch OVMF submodules' >&2; exit 1; }
  # Discard whatever the failed attempt left behind so the retry starts from a
  # known state rather than inheriting the previous failure.
  git -C "$src" submodule foreach --recursive --quiet \
    'git reset -q --hard; git clean -qfdx' || true
  git -C "$src" submodule sync --recursive
  sleep $((attempt * 5))
done
git -C "$src" reset -q --hard "$REV"
# Same patch set as meta-dstack's dstack-ovmf_git.bb, minus 0001/0002 which
# only adapt BaseTools to bitbake's native-tooling layout.
#
#   0003 threads ENV(GCC_PREFIX_MAP)/ENV(NASM_PREFIX_MAP) into the tool
#        definitions, which is how the warning overrides and the debug prefix
#        map reach the compiler.
#   0005 backports edk2 9ccf8751 (push dword -> push qword). stable202502 does
#        not assemble with NASM 3.x without it, and the recipe comment records
#        that this pin must be kept for the pre202505 measurement layout. The
#        encoding is unchanged on NASM 2.x, so applying it also keeps this
#        build byte-comparable with the production one.
for patch in 0003-Debug-prefix-map 0004-Reproduciable \
  0005-UefiCpuPkg-CpuExceptionHandlerLib-fix-push-instructi \
  0006-OvmfPkg-AmdSev-drop-embedded-grub; do
  patch -d "$src" -p1 --forward --fuzz=0 < \
    "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf/$patch.patch"
done

export PYTHON_COMMAND=python3
make -s -C "$src/BaseTools" -j"${JOBS:-$(nproc)}"
export WORKSPACE="$src" EDK_TOOLS_PATH="$src/BaseTools"
export PATH="$EDK_TOOLS_PATH/BinWrappers/PosixLike:$PATH"
# Yocto disables EDK2 LTO for deterministic link ordering. Doing so surfaces
# warnings that -Werror turns fatal, which is why the recipe folds the
# overrides into GCC_PREFIX_MAP rather than patching them in separately.
sed -i -e 's/-flto/-fno-lto/g' -e 's/-DUSING_LTO//g' \
  "$src/BaseTools/Conf/tools_def.template"
export GCC_PREFIX_MAP="-ffile-prefix-map=$src=/usr/src/edk2 -Wno-stringop-overflow -Wno-maybe-uninitialized"
# Yocto carries a nasm patch that adds --debug-prefix-map; the Debian snapshot
# ships stock nasm, which rejects the option, so leave this empty. 0004 already
# removes the nondeterministic inputs from the assembled output.
export NASM_PREFIX_MAP=""
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
