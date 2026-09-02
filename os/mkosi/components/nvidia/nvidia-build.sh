#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
SELF="$ROOT/os/mkosi"
# shellcheck source=/dev/null
source "$SELF/versions.env"
BUILD_DIR=$(realpath -m "${1:?build directory required}")
KERNEL_SRC=$(realpath "${2:?kernel source required}")
KERNEL_BUILD=$(realpath "${3:?kernel build directory required}")
ROOT_STAGE=$(realpath -m "${4:?rootfs staging tree required}")
KERNEL_STAGE=$(realpath -m "${5:?kernel staging tree required}")
downloads="$BUILD_DIR/downloads"
src="$BUILD_DIR/NVIDIA-Linux-x86_64-$NVIDIA_VERSION"
mkdir -p "$downloads" "$ROOT_STAGE/usr/bin" "$ROOT_STAGE/usr/lib/x86_64-linux-gnu"

fetch_sha256() {
  local url=$1 sha=$2 output=$3
  if [[ ! -f $output ]]; then
    curl -fL --retry 3 --retry-all-errors --connect-timeout 30 \
      --max-time 300 -o "$output.tmp" "$url"
    mv "$output.tmp" "$output"
  fi
  echo "$sha  $output" | sha256sum -c --status || {
    echo "checksum mismatch: $output" >&2; exit 1;
  }
}

run="$downloads/NVIDIA-Linux-x86_64-$NVIDIA_VERSION.run"
fetch_sha256 "https://us.download.nvidia.com/tesla/$NVIDIA_VERSION/NVIDIA-Linux-x86_64-$NVIDIA_VERSION.run" \
  "$NVIDIA_RUN_SHA256" "$run"
rm -rf "$src"
chmod +x "$run"
"$run" -x --target "$src" >/dev/null
module_map="-fdebug-prefix-map=$BUILD_DIR=/usr/src/nvidia -fmacro-prefix-map=$BUILD_DIR=/usr/src/nvidia -fdebug-prefix-map=$KERNEL_SRC=/usr/src/linux -fmacro-prefix-map=$KERNEL_SRC=/usr/src/linux -fdebug-prefix-map=$KERNEL_BUILD=/usr/src/linux-build -fmacro-prefix-map=$KERNEL_BUILD=/usr/src/linux-build"
# gen-btf.sh cannot execute the space-containing PAHOLE wrapper for external
# modules (the awk program is passed with literal quotes). Keep BTF enabled
# for the kernel/in-tree modules, but omit it for NVIDIA's modules.
make -C "$src/kernel-open" -j"${JOBS:-$(nproc)}" \
  SYSSRC="$KERNEL_SRC" SYSOUT="$KERNEL_BUILD" \
  KCFLAGS="$module_map" CONFIG_DEBUG_INFO_BTF_MODULES= modules
make -C "$src/kernel-open" SYSSRC="$KERNEL_SRC" SYSOUT="$KERNEL_BUILD" \
  KCFLAGS="$module_map" CONFIG_DEBUG_INFO_BTF_MODULES= INSTALL_MOD_PATH="$KERNEL_STAGE" modules_install
if [[ -d $KERNEL_STAGE/lib/modules ]]; then
  mkdir -p "$KERNEL_STAGE/usr/lib/modules"
  cp -a "$KERNEL_STAGE/lib/modules/." "$KERNEL_STAGE/usr/lib/modules/"
  rm -rf "${KERNEL_STAGE:?}/lib"
fi
ln -sfn usr/lib "$KERNEL_STAGE/lib"
depmod -b "$KERNEL_STAGE" "$KERNEL_VERSION-dstack"
rm -f "$KERNEL_STAGE/lib"

libdir="$ROOT_STAGE/usr/lib/x86_64-linux-gnu"
for lib in libnvidia-ml libnvidia-allocator libnvidia-eglcore libnvidia-encode \
 libnvidia-glcore libnvidia-gpucomp libnvidia-ngx libnvidia-nvvm \
 libnvidia-opencl libnvidia-rtcore libnvidia-tls libnvidia-cfg \
 libnvidia-opticalflow libnvidia-glsi libnvidia-glvkspirv libcuda libnvcuvid \
 libnvidia-pkcs11-openssl3 libnvidia-pkcs11 libnvidia-ptxjitcompiler; do
  file="$src/$lib.so.$NVIDIA_VERSION"
  [[ -f $file ]] || { echo "missing NVIDIA library: $file" >&2; exit 1; }
  install -m0755 "$file" "$libdir/"
  ln -sfn "$lib.so.$NVIDIA_VERSION" "$libdir/$lib.so.1"
  ln -sfn "$lib.so.1" "$libdir/$lib.so"
done
install -m0755 "$src/libnvidia-api.so.1" "$libdir/"
ln -sfn libnvidia-api.so.1 "$libdir/libnvidia-api.so"
ln -sfn "libnvidia-nvvm.so.$NVIDIA_VERSION" "$libdir/libnvidia-nvvm.so.4"
for bin in nvidia-smi nvidia-debugdump nvidia-persistenced nvidia-modprobe; do
  install -m0755 "$src/$bin" "$ROOT_STAGE/usr/bin/$bin"
done
mkdir -p "$ROOT_STAGE/usr/lib/firmware/nvidia/$NVIDIA_VERSION"
cp -a "$src/firmware/." "$ROOT_STAGE/usr/lib/firmware/nvidia/$NVIDIA_VERSION/"

fm="$downloads/fabricmanager-$NVIDIA_VERSION.tar.xz"
fetch_sha256 "https://developer.download.nvidia.com/compute/nvidia-driver/redist/fabricmanager/linux-x86_64/fabricmanager-linux-x86_64-$NVIDIA_VERSION-archive.tar.xz" \
  "$NVIDIA_FABRICMANAGER_SHA256" "$fm"
fm_dir="$BUILD_DIR/fabricmanager"
rm -rf "$fm_dir"; mkdir -p "$fm_dir"; tar -C "$fm_dir" --strip-components=1 -xf "$fm"
install -m0755 "$fm_dir/bin/"{nv-fabricmanager,nvidia-fabricmanager-start.sh,nvswitch-audit} "$ROOT_STAGE/usr/bin/"
install -m0755 "$fm_dir/lib/libnvfm.so.1" "$libdir/"
ln -sfn libnvfm.so.1 "$libdir/libnvfm.so"
install -Dm0644 "$fm_dir/systemd/nvidia-fabricmanager.service" "$ROOT_STAGE/usr/lib/systemd/system/nvidia-fabricmanager.service"
mkdir -p "$ROOT_STAGE/usr/share/nvidia/nvswitch"
cp -a "$fm_dir/share/nvidia/nvswitch/." "$ROOT_STAGE/usr/share/nvidia/nvswitch/"
install -m0644 "$fm_dir/etc/fabricmanager"*.cfg "$ROOT_STAGE/usr/share/nvidia/nvswitch/"

nscq="$downloads/libnvidia-nscq-$NVIDIA_VERSION.tar.xz"
fetch_sha256 "https://developer.download.nvidia.com/compute/nvidia-driver/redist/libnvidia_nscq/linux-x86_64/libnvidia_nscq-linux-x86_64-$NVIDIA_VERSION-archive.tar.xz" \
  "$NVIDIA_NSCQ_SHA256" "$nscq"
nscq_dir="$BUILD_DIR/nscq"
rm -rf "$nscq_dir"; mkdir -p "$nscq_dir"; tar -C "$nscq_dir" --strip-components=1 -xf "$nscq"
install -m0755 "$nscq_dir/lib/libnvidia-nscq.so.$NVIDIA_VERSION" "$libdir/"
ln -sfn "libnvidia-nscq.so.$NVIDIA_VERSION" "$libdir/libnvidia-nscq.so.2.0"
ln -sfn libnvidia-nscq.so.2.0 "$libdir/libnvidia-nscq.so.2"
ln -sfn libnvidia-nscq.so.2 "$libdir/libnvidia-nscq.so"

# Payload shared with the yocto backend. Both backends must stage the same
# files to the same destinations; os/yocto/tests/test-nvidia-module-options.sh
# asserts that this list and the yocto recipes stay in step.
common="$ROOT/os/common/nvidia"
install -Dm0755 "$common/nvidia-gpu-detect" "$ROOT_STAGE/usr/bin/nvidia-gpu-detect"
install -Dm0755 "$common/nvidia-module-options" "$ROOT_STAGE/usr/bin/nvidia-module-options"
install -Dm0644 "$common/nvidia-persistenced.service" "$ROOT_STAGE/usr/lib/systemd/system/nvidia-persistenced.service"
install -Dm0644 "$common/nvidia-module-options.service" "$ROOT_STAGE/usr/lib/systemd/system/nvidia-module-options.service"
# Keeps udev from autoloading the driver before nvidia-module-options has
# written the options for this topology. This previously installed a
# modprobe.d `options` line into /etc/modules-load.d, where it did nothing at
# all except make systemd-modules-load look for a module named "options".
install -Dm0644 "$common/nvidia-blacklist.conf" "$ROOT_STAGE/usr/lib/modprobe.d/nvidia-blacklist.conf"
install -Dm0644 "$common/nvidia-fabricmanager-nvswitch-condition.conf" "$ROOT_STAGE/usr/lib/systemd/system/nvidia-fabricmanager.service.d/10-nvswitch-condition.conf"
find "$ROOT_STAGE" "$KERNEL_STAGE" -print0 | xargs -0r touch -h -d "@${SOURCE_DATE_EPOCH:?}"
