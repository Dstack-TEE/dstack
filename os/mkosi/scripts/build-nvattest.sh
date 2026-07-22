#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SELF="$ROOT/os/mkosi"
# shellcheck source=/dev/null
source "$SELF/versions.env"
BUILD_DIR=${1:?build directory required}
STAGE=${2:?rootfs staging tree required}
src="$BUILD_DIR/attestation-sdk"
build="$BUILD_DIR/build"

if [[ ! -d $src/.git ]]; then
  mkdir -p "$BUILD_DIR"
  git init -q "$src"
  git -C "$src" remote add origin https://github.com/NVIDIA/attestation-sdk.git
fi
git -C "$src" fetch -q --depth=1 origin "$NVATTEST_REVISION"
git -C "$src" checkout -q --detach FETCH_HEAD
git -C "$src" reset -q --hard "$NVATTEST_REVISION"
patch -d "$src" -p1 --fuzz=0 < \
  "$ROOT/os/yocto/layers/meta-nvidia/recipes-graphics/nvattest/files/0001-validate-ocsp-response-freshness.patch"
patch -d "$src" -p1 --fuzz=0 < \
  "$SELF/patches/nvattest/0001-pin-fetchcontent-inputs.patch"

rm -rf "$build"
cmake -S "$src/nv-attestation-cli" -B "$build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
  -DNVAT_BUILD_TESTS=OFF -DNVAT_BUILD_SAMPLES=OFF \
  -DCMAKE_SKIP_RPATH=ON -DFETCHCONTENT_FULLY_DISCONNECTED=OFF \
  -DUSE_SYSTEM_DEPS=ON
install -m0644 \
  "$ROOT/os/yocto/layers/meta-nvidia/recipes-graphics/nvattest/files/regorus-ffi-Cargo.lock" \
  "$build/_deps/regorus-src/bindings/ffi/Cargo.lock"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$BUILD_DIR=/usr/src/nvattest -C strip=debuginfo"
cmake --build "$build" -j"${JOBS:-$(nproc)}"
cmp "$ROOT/os/yocto/layers/meta-nvidia/recipes-graphics/nvattest/files/regorus-ffi-Cargo.lock" \
  "$build/_deps/regorus-src/bindings/ffi/Cargo.lock"
DESTDIR="$STAGE" cmake --install "$build" --prefix /usr

install -Dm0644 \
  "$ROOT/os/yocto/layers/meta-nvidia/recipes-graphics/nvattest/files/10-nvidia-gpu-ordering.conf" \
  "$STAGE/usr/lib/systemd/system/dstack-prepare.service.d/10-nvidia-gpu-ordering.conf"
install -Dm0644 \
  "$src/relying_party_policy_examples/allow_trust_outpost_ocsp.rego" \
  "$STAGE/usr/share/nvattest/policies/allow_trust_outpost_ocsp.rego"
find "$STAGE/usr/lib" -maxdepth 1 -type f -name 'lib*.so*' ! -name 'libnvat.so*' -delete
find "$STAGE" -print0 | xargs -0r touch -h -d "@${SOURCE_DATE_EPOCH:?}"
