#!/bin/sh

# SPDX-FileCopyrightText: 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

set -eu

DEFAULT_REPO="https://github.com/Dstack-TEE/dstack"
DEFAULT_REF="master"
DEFAULT_PREFIX="/usr/local"

usage() {
    cat <<'EOF'
Install dstackup from source.

Usage:
  scripts/install.sh [options]
  curl -fsSL https://raw.githubusercontent.com/Dstack-TEE/dstack/master/scripts/install.sh | sh

Options:
  --repo URL       Git repository to clone when not run from a checkout.
                  Default: https://github.com/Dstack-TEE/dstack
  --ref REF        Git ref to checkout when cloning or updating DSTACK_SRC.
                  Default: master
  --src DIR        Persistent source checkout to build from.
                  Default: a temporary checkout
  --prefix DIR     Install dstackup under DIR/bin. Use the same DIR with
                  dstackup install --prefix for a self-contained install.
                  Default: /usr/local
  --no-sudo        Do not use sudo for creating DIR/bin or installing binaries.
  -h, --help       Show this help.

Environment:
  DSTACK_REPO              Same as --repo.
  DSTACK_REF               Same as --ref.
  DSTACK_SRC               Same as --src.
  DSTACK_INSTALL_PREFIX    Same as --prefix.
EOF
}

repo=${DSTACK_REPO:-$DEFAULT_REPO}
ref=${DSTACK_REF:-$DEFAULT_REF}
src=${DSTACK_SRC:-}
prefix=${DSTACK_INSTALL_PREFIX:-$DEFAULT_PREFIX}
prefix_set=0
no_sudo=0
tmp_src=

if [ "${DSTACK_INSTALL_PREFIX+x}" = x ]; then
    prefix_set=1
fi

cleanup() {
    if [ -n "$tmp_src" ]; then
        rm -rf "$tmp_src"
    fi
}
trap cleanup EXIT INT TERM

while [ "$#" -gt 0 ]; do
    case "$1" in
        --repo)
            if [ "$#" -lt 2 ]; then
                echo "error: --repo requires a URL" >&2
                exit 1
            fi
            repo=$2
            shift 2
            ;;
        --ref)
            if [ "$#" -lt 2 ]; then
                echo "error: --ref requires a ref" >&2
                exit 1
            fi
            ref=$2
            shift 2
            ;;
        --src)
            if [ "$#" -lt 2 ]; then
                echo "error: --src requires a directory" >&2
                exit 1
            fi
            src=$2
            shift 2
            ;;
        --prefix|--root)
            if [ "$#" -lt 2 ]; then
                echo "error: --prefix requires a directory" >&2
                exit 1
            fi
            prefix=$2
            prefix_set=1
            shift 2
            ;;
        --no-sudo)
            no_sudo=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command not found: $1" >&2
        exit 1
    fi
}

is_checkout() {
    [ -f "$1/Cargo.toml" ] &&
        [ -d "$1/crates/dstackup" ] &&
        [ -d "$1/crates/dstack-cli" ] &&
        [ -d "$1/vmm" ] &&
        [ -d "$1/supervisor" ]
}

abs_dir() {
    (cd "$1" && pwd)
}

script_checkout() {
    case "$0" in
        */*)
            script_dir=$(dirname "$0")
            if [ -d "$script_dir/.." ] && is_checkout "$script_dir/.."; then
                abs_dir "$script_dir/.."
                return 0
            fi
            ;;
    esac
    return 1
}

resolve_source() {
    if is_checkout "."; then
        abs_dir "."
        return 0
    fi

    if checkout=$(script_checkout); then
        echo "$checkout"
        return 0
    fi

    need_cmd git

    if [ -n "$src" ] && [ -e "$src" ]; then
        if ! is_checkout "$src" || [ ! -d "$src/.git" ]; then
            echo "error: $src exists but is not a dstack git checkout" >&2
            exit 1
        fi
        echo "updating dstack source in $src"
        (
            cd "$src"
            git fetch --tags origin
            git checkout "$ref"
            if git rev-parse --verify "origin/$ref" >/dev/null 2>&1; then
                git pull --ff-only origin "$ref"
            fi
        )
    elif [ -n "$src" ]; then
        echo "cloning dstack source into $src"
        git clone "$repo" "$src"
        (
            cd "$src"
            git fetch --tags origin
            git checkout "$ref"
        )
    else
        need_cmd mktemp
        tmp_src=$(mktemp -d "${TMPDIR:-/tmp}/dstack-install.XXXXXX")
        src="$tmp_src/source"
        echo "cloning dstack source into a temporary checkout"
        git clone "$repo" "$src"
        (
            cd "$src"
            git fetch --tags origin
            git checkout "$ref"
        )
    fi

    abs_dir "$src"
}

validate_prefix() {
    case "$prefix" in
        /*) ;;
        *)
            echo "error: --prefix must be an absolute path" >&2
            exit 1
            ;;
    esac
    if [ "$prefix" = "/" ]; then
        echo "error: --prefix must not be /" >&2
        exit 1
    fi
    case "$prefix" in
        *"/../"*|*"/.."|*"/./"*|*"/.")
            echo "error: --prefix must not contain . or .. path components" >&2
            exit 1
            ;;
    esac
}

validate_prefix

if ! command -v cargo >/dev/null 2>&1 && [ -n "${HOME:-}" ] && [ -f "$HOME/.cargo/env" ]; then
    # Mirrors rustup's post-install shell setup when the current shell has not
    # loaded Cargo yet.
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

need_cmd cargo
need_cmd install

checkout=$(resolve_source)
bin_dir="$prefix/bin"

if [ "$no_sudo" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    sudo_cmd=sudo
else
    sudo_cmd=
fi

if [ -n "$sudo_cmd" ]; then
    need_cmd sudo
    $sudo_cmd install -d -m 0755 "$bin_dir"
else
    install -d -m 0755 "$bin_dir"
fi

echo "building dstackup from $checkout"
(
    cd "$checkout"
    cargo build --release \
        -p dstackup
)

install_bin() {
    src_bin="$checkout/target/release/$1"
    dest_bin="$bin_dir/$2"
    if [ ! -f "$src_bin" ]; then
        echo "error: expected binary not found: $src_bin" >&2
        exit 1
    fi
    if [ -n "$sudo_cmd" ]; then
        $sudo_cmd install -m 0755 "$src_bin" "$dest_bin"
    else
        install -m 0755 "$src_bin" "$dest_bin"
    fi
}

install_bin dstackup dstackup

if [ "$prefix_set" -eq 1 ]; then
    next_install="sudo $bin_dir/dstackup install --prefix $prefix"
else
    next_install="sudo $bin_dir/dstackup install"
fi

cat <<EOF

installed dstackup into $bin_dir:
  dstackup

next:
  $next_install

the dstackup install command builds and installs the local dstack CLI and host
daemon binaries, static assets, and host config.
EOF
