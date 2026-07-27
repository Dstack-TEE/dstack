#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
# shellcheck source=/dev/null
source "$ROOT/os/mkosi/versions.env"
DOWNLOADS=$(realpath -m "${1:?download directory required}")
PREFIX=/opt/dstack-toolchains
mkdir -p "$DOWNLOADS" "$PREFIX"

fetch() {
    local url=$1 sha=$2 output=$3
    # Verify before publishing the cached name. Renaming first meant a
    # truncated-but-non-empty transfer was cached under the final name, and
    # since the mismatch path did not remove it, every later build failed with
    # the same checksum error and no hint that the fix is to delete the file.
    if [[ ! -f $output ]]; then
        curl --fail --location --retry 3 --retry-all-errors \
          --connect-timeout 30 --max-time 600 -o "$output.tmp" "$url"
        echo "$sha  $output.tmp" | sha256sum --check --status || {
            rm -f "$output.tmp"
            echo "toolchain checksum mismatch after download: $url" >&2
            exit 1
        }
        mv "$output.tmp" "$output"
    fi
    echo "$sha  $output" | sha256sum --check --status || {
        rm -f "$output"
        echo "cached toolchain archive was corrupt and has been removed: $output" >&2
        echo "re-run the build to download it again" >&2
        exit 1
    }
}

install_rust_component() {
    local component=$1 sha=$2 archive base dir
    archive="$DOWNLOADS/$component-$RUST_TOOLCHAIN_VERSION-x86_64-unknown-linux-gnu.tar.xz"
    fetch "https://static.rust-lang.org/dist/${archive##*/}" "$sha" "$archive"
    base=${archive##*/}
    dir=$(mktemp -d "/var/tmp/$component.XXXXXX")
    tar -C "$dir" -xf "$archive"
    "$dir/${base%.tar.xz}/install.sh" \
      --prefix="$PREFIX/rust" --disable-ldconfig >/dev/null
    rm -rf "$dir"
}

install_rust_component rustc "$RUSTC_TOOLCHAIN_SHA256"
install_rust_component cargo "$CARGO_TOOLCHAIN_SHA256"
install_rust_component rust-std "$RUST_STD_TOOLCHAIN_SHA256"

go_archive="$DOWNLOADS/go$GO_TOOLCHAIN_VERSION.linux-amd64.tar.gz"
fetch "https://go.dev/dl/${go_archive##*/}" "$GO_TOOLCHAIN_SHA256" "$go_archive"
rm -rf "$PREFIX/go"
tar -C "$PREFIX" -xf "$go_archive"

export PATH="$PREFIX/rust/bin:$PREFIX/go/bin:$PATH"
rustc --version
cargo --version
go version
