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
mkdir -p "$BUILD_DIR/downloads" "$STAGE/usr/bin"

checkout() {
  local url=$1 rev=$2 dir=$3
  if [[ ! -d $dir/.git ]]; then
    git init -q "$dir"; git -C "$dir" remote add origin "$url"
  fi
  git -C "$dir" fetch -q --depth=1 origin "$rev"
  git -C "$dir" checkout -q --detach FETCH_HEAD
  git -C "$dir" reset -q --hard "$rev"
  git -C "$dir" clean -qfdx
}
fetch_sha256() {
  local url=$1 sha=$2 output=$3
  [[ -f $output ]] || { curl -fL --retry 3 -o "$output.tmp" "$url"; mv "$output.tmp" "$output"; }
  echo "$sha  $output" | sha256sum -c --status || { echo "checksum mismatch: $output" >&2; exit 1; }
}

lnc="$BUILD_DIR/libnvidia-container"
checkout https://github.com/NVIDIA/libnvidia-container.git "$LIBNVIDIA_CONTAINER_REVISION" "$lnc"
patch -d "$lnc" -p1 --fuzz=0 < \
  "$SELF/components/container-stack/patches/0001-omit-prefix-map-from-build-flags.patch"
export CFLAGS="${CFLAGS:-} -O2 -g0 -ffile-prefix-map=$BUILD_DIR=/usr/src/container-stack -fmacro-prefix-map=$BUILD_DIR=/usr/src/container-stack"
export LDFLAGS="${LDFLAGS:-} -Wl,--build-id=none"
export CGO_CFLAGS="$CFLAGS"
export GOFLAGS="${GOFLAGS:-} -trimpath -buildvcs=false"
make -C "$lnc" -j"${JOBS:-$(nproc)}" LIB_VERSION=1.18.1 \
  WITH_NVCGO=yes WITH_LIBELF=yes WITH_TIRPC=yes all
# Upstream adds a CRC of its unshipped split-debug file. The debug file is not
# installed, and its CRC varies with the clean build directory.
objcopy --remove-section=.gnu_debuglink "$lnc/libnvidia-container.so.1.18.1"
install -m0755 "$lnc/nvidia-container-cli" "$STAGE/usr/bin/"
install -Dm0755 "$lnc/libnvidia-container.so.1.18.1" "$STAGE/usr/lib/x86_64-linux-gnu/libnvidia-container.so.1.18.1"
ln -sfn libnvidia-container.so.1.18.1 "$STAGE/usr/lib/x86_64-linux-gnu/libnvidia-container.so.1"

nct="$BUILD_DIR/nvidia-container-toolkit"
checkout https://github.com/NVIDIA/nvidia-container-toolkit.git "$NVIDIA_CONTAINER_TOOLKIT_REVISION" "$nct"
# The pinned revision already contains the Yocto patch semantically, split by
# platform; fail if the required Linux linker flags ever disappear.
grep -q '#cgo linux LDFLAGS: -Wl,--export-dynamic' "$nct/internal/cuda/cuda.go"
make -C "$nct" -j"${JOBS:-$(nproc)}" cmds
for bin in nvidia-container-runtime nvidia-container-runtime.cdi \
 nvidia-container-runtime-hook nvidia-container-runtime.legacy nvidia-ctk \
 nvidia-cdi-hook; do install -m0755 "$nct/$bin" "$STAGE/usr/bin/"; done
ln -sfn nvidia-container-runtime-hook "$STAGE/usr/bin/nvidia-container-toolkit"
install -Dm0644 "$ROOT/os/yocto/layers/meta-nvidia/recipes-graphics/nvidia-container-toolkit/files/config.toml" \
  "$STAGE/etc/nvidia-container-runtime/config.toml"

nerd="$BUILD_DIR/downloads/nerdctl-$NERDCTL_VERSION.tar.gz"
fetch_sha256 "https://github.com/containerd/nerdctl/releases/download/v$NERDCTL_VERSION/nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz" "$NERDCTL_SHA256" "$nerd"
tar -xOf "$nerd" nerdctl > "$STAGE/usr/bin/nerdctl"; chmod 0755 "$STAGE/usr/bin/nerdctl"
cni="$BUILD_DIR/downloads/cni-$CNI_VERSION.tgz"
fetch_sha256 "https://github.com/containernetworking/plugins/releases/download/v$CNI_VERSION/cni-plugins-linux-amd64-v$CNI_VERSION.tgz" "$CNI_SHA256" "$cni"
mkdir -p "$STAGE/usr/lib/cni"; tar -C "$STAGE/usr/lib/cni" -xf "$cni"

stargz="$BUILD_DIR/downloads/stargz-$STARGZ_VERSION.tar.gz"
fetch_sha256 "https://github.com/containerd/stargz-snapshotter/releases/download/v$STARGZ_VERSION/stargz-snapshotter-v$STARGZ_VERSION-linux-amd64.tar.gz" "$STARGZ_SHA256" "$stargz"
tar -xOf "$stargz" containerd-stargz-grpc > "$STAGE/usr/bin/containerd-stargz-grpc"
tar -xOf "$stargz" ctr-remote > "$STAGE/usr/bin/ctr-remote"
chmod 0755 "$STAGE/usr/bin/containerd-stargz-grpc" "$STAGE/usr/bin/ctr-remote"
install -Dm0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-containers/stargz-snapshotter/files/containerd-stargz-grpc.service" \
  "$STAGE/usr/lib/systemd/system/containerd-stargz-grpc.service"
install -Dm0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-containers/containerd-config/files/config.toml" \
  "$STAGE/etc/containerd/config.toml"
find "$STAGE" -print0 | xargs -0r touch -h -d "@${SOURCE_DATE_EPOCH:?}"
