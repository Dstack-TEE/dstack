#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
SELF="$ROOT/os/mkosi"
# shellcheck source=/dev/null
source "$SELF/versions.env"
B=${1:?build directory required}
STAGE=${2:?rootfs staging tree required}
B=$(realpath -m "$B")
STAGE=$(realpath -m "$STAGE")
checkout() {
  local url=$1 rev=$2 dir=$3
  if [[ ! -d $dir/.git ]]; then git init -q "$dir"; git -C "$dir" remote add origin "$url"; fi
  git -C "$dir" fetch -q --depth=1 origin "$rev"
  git -C "$dir" checkout -q --detach FETCH_HEAD
  git -C "$dir" reset -q --hard "$rev"
  # reset --hard leaves untracked files, so on a revision bump in an existing
  # work directory the previous vendor/ tree and the copied-in generated
  # protobuf sources would survive and be linked into the new binaries. Every
  # other component with a git checkout already does this.
  git -C "$dir" clean -qfdx
}
mkdir -p "$B"
checkout https://github.com/nestybox/sysbox.git "$SYSBOX_REVISION" "$B/sysbox"
checkout https://github.com/nestybox/sysbox-runc.git "$SYSBOX_RUNC_REVISION" "$B/sysbox-runc"
checkout https://github.com/nestybox/sysbox-fs.git "$SYSBOX_FS_REVISION" "$B/sysbox-fs"
checkout https://github.com/nestybox/sysbox-mgr.git "$SYSBOX_MGR_REVISION" "$B/sysbox-mgr"
checkout https://github.com/nestybox/sysbox-ipc.git "$SYSBOX_IPC_REVISION" "$B/sysbox-ipc"
checkout https://github.com/nestybox/sysbox-libs.git "$SYSBOX_LIBS_REVISION" "$B/sysbox-libs"
checkout https://github.com/Dstack-TEE/fuse.git "$SYSBOX_FUSE_REVISION" "$B/sysbox-fuse"
rm -rf "$B/sysbox-fs/bazil"; ln -s "$B/sysbox-fuse" "$B/sysbox-fs/bazil"
install -m0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-sysbox/files/sysboxFsProtobuf.pb.go" \
  "$B/sysbox-ipc/sysboxFsGrpc/sysboxFsProtobuf/"
install -m0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-sysbox/files/sysboxMgrProtobuf.pb.go" \
  "$B/sysbox-ipc/sysboxMgrGrpc/sysboxMgrProtobuf/"
for mod in sysbox-runc sysbox-fs sysbox-mgr; do (cd "$B/$mod" && go mod vendor); done
ldflags="-buildid= -s -w -X 'main.edition=Community Edition (CE)' -X main.version=$SYSBOX_VERSION -X main.commitId=$SYSBOX_REVISION -X 'main.builtAt=1970-01-01T00:00:00Z' -X main.builtBy=dstack"
(cd "$B/sysbox-runc" && go build -mod=vendor -buildvcs=false -trimpath -tags 'seccomp idmapped_mnt' -ldflags "$ldflags" -o "$B/sysbox-runc-bin" .)
(cd "$B/sysbox-fs" && go build -mod=vendor -buildvcs=false -trimpath -ldflags "$ldflags" -o "$B/sysbox-fs-bin" ./cmd/sysbox-fs)
(cd "$B/sysbox-mgr" && go build -mod=vendor -buildvcs=false -trimpath -tags idmapped_mnt -ldflags "$ldflags" -o "$B/sysbox-mgr-bin" .)
for bin in runc fs mgr; do install -Dm0755 "$B/sysbox-$bin-bin" "$STAGE/usr/bin/sysbox-$bin"; done
for f in sysbox.service sysbox-fs.service sysbox-mgr.service; do
  install -Dm0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-sysbox/files/$f" "$STAGE/usr/lib/systemd/system/$f"
done
install -Dm0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-sysbox/files/99-sysbox-sysctl.conf" "$STAGE/etc/sysctl.d/99-sysbox-sysctl.conf"
install -Dm0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-sysbox/files/50-sysbox-mod.conf" "$STAGE/etc/modules-load.d/50-sysbox-mod.conf"
mkdir -p "$STAGE/var/lib/sysbox" "$STAGE/etc"
# Truncating, not appending: the staging tree is reused across dev-image runs,
# and duplicate entries here are a fatal parse error for some userns tooling.
printf 'sysbox:100000:65536\n' > "$STAGE/etc/subuid"
printf 'sysbox:100000:65536\n' > "$STAGE/etc/subgid"
find "$STAGE" -print0 | xargs -0r touch -h -d "@${SOURCE_DATE_EPOCH:?}"
