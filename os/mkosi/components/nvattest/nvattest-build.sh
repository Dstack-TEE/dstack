#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
SELF="$ROOT/os/mkosi"
# shellcheck source=/dev/null
source "$SELF/versions.env"
BUILD_DIR=${1:?build directory required}
STAGE=${2:?rootfs staging tree required}
BUILD_DIR=$(realpath -m "$BUILD_DIR")
STAGE=$(realpath -m "$STAGE")
checkout="$BUILD_DIR/attestation-sdk"
# Cargo includes the literal RUSTFLAGS in crate disambiguators. A prefix-map
# containing work-a/work-b would therefore change Rust symbol hashes even
# though the mapped paths are equal. Serialize this component in a stable,
# clean pathname and keep the per-build checkout as the verified input.
canonical=/var/tmp/dstack-mkosi-nvattest
exec 9>"$canonical.lock"
flock 9
src="$canonical/attestation-sdk"
build="$canonical/build"

if [[ ! -d $checkout/.git ]]; then
  mkdir -p "$BUILD_DIR"
  git init -q "$checkout"
  git -C "$checkout" remote add origin https://github.com/NVIDIA/attestation-sdk.git
fi
git -C "$checkout" fetch -q --depth=1 origin "$NVATTEST_REVISION"
git -C "$checkout" checkout -q --detach FETCH_HEAD
git -C "$checkout" reset -q --hard "$NVATTEST_REVISION"
git -C "$checkout" clean -qfdx
rm -rf "$canonical"
mkdir -p "$canonical"
cp -a "$checkout" "$src"
patch -d "$src" -p1 --fuzz=0 < \
  "$ROOT/os/yocto/layers/meta-nvidia/recipes-graphics/nvattest/files/0001-validate-ocsp-response-freshness.patch"
patch -d "$src" -p1 --fuzz=0 < \
  "$SELF/components/nvattest/patches/0001-pin-fetchcontent-inputs.patch"

rm -rf "$build"
export CFLAGS="${CFLAGS:-} -O2 -g0 -ffile-prefix-map=$canonical=/usr/src/nvattest -fmacro-prefix-map=$canonical=/usr/src/nvattest"
export CXXFLAGS="${CXXFLAGS:-} -O2 -g0 -ffile-prefix-map=$canonical=/usr/src/nvattest -fmacro-prefix-map=$canonical=/usr/src/nvattest"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$canonical=/usr/src/nvattest -C strip=debuginfo"
cmake -S "$src/nv-attestation-cli" -B "$build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
  -DNVAT_BUILD_TESTS=OFF -DNVAT_BUILD_SAMPLES=OFF \
  -DCMAKE_SKIP_RPATH=ON -DFETCHCONTENT_FULLY_DISCONNECTED=OFF \
  -DUSE_SYSTEM_DEPS=ON
install -m0644 \
  "$ROOT/os/yocto/layers/meta-nvidia/recipes-graphics/nvattest/files/regorus-ffi-Cargo.lock" \
  "$build/_deps/regorus-src/bindings/ffi/Cargo.lock"
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
