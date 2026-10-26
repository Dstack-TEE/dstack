#!/bin/bash

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

REPO="Dstack-TEE/dstack"
TARGET="x86_64-unknown-linux-musl"
INSTALL_ROOT="/opt/dstack-simulator"
SERVICE_NAME="dstack-simulator"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BIN_LINK="/usr/local/bin/dstack-simulator"
RUN_USER="root"
RUN_GROUP="root"
RUST_LOG="info"
VERSION=""
TARBALL=""
SKIP_SYSTEMD=0

usage() {
    cat <<'EOF'
Usage: install-systemd.sh [options]

Install dstack-simulator from a GitHub release tarball and register it as a systemd service.

Options:
  --version <version>         Release version to install (e.g. 0.5.8). Defaults to latest simulator release.
  --tarball <path-or-url>     Install from a local tarball or explicit URL.
  --repo <owner/repo>         GitHub repository to download from. Default: Dstack-TEE/dstack
  --target <triple>           Target triple asset to download. Default: x86_64-unknown-linux-musl
  --install-root <path>       Installation root. Default: /opt/dstack-simulator
  --service-name <name>       systemd service name. Default: dstack-simulator
  --service-file <path>       systemd unit path. Default: /etc/systemd/system/dstack-simulator.service
  --bin-link <path>           Binary symlink path. Default: /usr/local/bin/dstack-simulator
  --user <user>               Service user. Default: root
  --group <group>             Service group. Default: root
  --rust-log <level>          RUST_LOG value for the systemd unit. Default: info
  --skip-systemd              Install files but skip systemd daemon-reload/enable/start.
  -h, --help                  Show this help text.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --tarball)
            TARBALL="$2"
            shift 2
            ;;
        --repo)
            REPO="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --install-root)
            INSTALL_ROOT="$2"
            shift 2
            ;;
        --service-name)
            SERVICE_NAME="$2"
            SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
            shift 2
            ;;
        --service-file)
            SERVICE_FILE="$2"
            shift 2
            ;;
        --bin-link)
            BIN_LINK="$2"
            shift 2
            ;;
        --user)
            RUN_USER="$2"
            shift 2
            ;;
        --group)
            RUN_GROUP="$2"
            shift 2
            ;;
        --rust-log)
            RUST_LOG="$2"
            shift 2
            ;;
        --skip-systemd)
            SKIP_SYSTEMD=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root." >&2
    exit 1
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required command: $1" >&2
        exit 1
    }
}

need_cmd curl
need_cmd tar
need_cmd python3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_BUNDLE_DIR=""
if [[ -f "$SCRIPT_DIR/dstack-simulator" && -f "$SCRIPT_DIR/dstack.toml" ]]; then
    LOCAL_BUNDLE_DIR="$SCRIPT_DIR"
fi

cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

normalize_version() {
    local value="$1"
    value="${value#refs/tags/}"
    value="${value#simulator-v}"
    echo "$value"
}

latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=100" | python3 -c '
import json, sys
for release in json.load(sys.stdin):
    if release.get("draft") or release.get("prerelease"):
        continue
    tag = release.get("tag_name", "")
    if tag.startswith("simulator-v"):
        print(tag[len("simulator-v"):])
        break
else:
    raise SystemExit("No simulator release found")
'
}

guess_local_version() {
    local base
    base="$(basename "$LOCAL_BUNDLE_DIR")"
    base="${base#dstack-simulator-}"
    base="${base%-${TARGET}}"
    if [[ "$base" == "dstack-simulator" || -z "$base" ]]; then
        return 1
    fi
    echo "$base"
}

if [[ -z "$VERSION" ]]; then
    if [[ -n "$LOCAL_BUNDLE_DIR" ]]; then
        VERSION="$(guess_local_version || true)"
    fi
    if [[ -z "$VERSION" ]]; then
        VERSION="$(latest_version)"
    fi
fi
VERSION="$(normalize_version "$VERSION")"

ASSET_NAME="dstack-simulator-${VERSION}-${TARGET}.tar.gz"
TAG="simulator-v${VERSION}"
TMP_DIR="$(mktemp -d)"

fetch_to_file() {
    local source="$1"
    local dest="$2"
    if [[ "$source" =~ ^https?:// ]]; then
        curl -fsSL "$source" -o "$dest"
    else
        cp "$source" "$dest"
    fi
}

extract_tarball() {
    local tarball_path="$1"
    local dest_dir="$2"
    tar -xzf "$tarball_path" -C "$dest_dir"
}

BUNDLE_DIR=""
if [[ -n "$LOCAL_BUNDLE_DIR" && -z "$TARBALL" ]]; then
    BUNDLE_DIR="$LOCAL_BUNDLE_DIR"
else
    TARBALL_PATH="$TMP_DIR/$ASSET_NAME"
    CHECKSUM_PATH="$TMP_DIR/${ASSET_NAME}.sha256"

    if [[ -n "$TARBALL" ]]; then
        echo "Fetching simulator tarball from: $TARBALL"
        fetch_to_file "$TARBALL" "$TARBALL_PATH"
    else
        local_url="https://github.com/${REPO}/releases/download/${TAG}/${ASSET_NAME}"
        checksum_url="${local_url}.sha256"
        echo "Downloading simulator release ${TAG}"
        fetch_to_file "$local_url" "$TARBALL_PATH"
        if curl -fsSL "$checksum_url" -o "$CHECKSUM_PATH"; then
            (
                cd "$TMP_DIR"
                sha256sum -c "$(basename "$CHECKSUM_PATH")"
            )
        else
            echo "Warning: checksum asset not found, skipping checksum verification." >&2
        fi
    fi

    extract_tarball "$TARBALL_PATH" "$TMP_DIR"
    BUNDLE_DIR="$TMP_DIR/dstack-simulator-${VERSION}-${TARGET}"
fi

if [[ ! -f "$BUNDLE_DIR/dstack-simulator" || ! -f "$BUNDLE_DIR/dstack.toml" ]]; then
    echo "Bundle directory is missing expected simulator files: $BUNDLE_DIR" >&2
    exit 1
fi

VERSION_DIR="$INSTALL_ROOT/releases/$VERSION"
CURRENT_DIR="$INSTALL_ROOT/current"

mkdir -p "$INSTALL_ROOT/releases"
rm -rf "$VERSION_DIR"
mkdir -p "$VERSION_DIR"
cp -a "$BUNDLE_DIR/." "$VERSION_DIR/"
ln -sfn "$VERSION_DIR" "$CURRENT_DIR"

chown -R "$RUN_USER:$RUN_GROUP" "$VERSION_DIR"
ln -sfn "$CURRENT_DIR/dstack-simulator" "$BIN_LINK"

python3 - "$BUNDLE_DIR/dstack-simulator.service" "$SERVICE_FILE" "$CURRENT_DIR" "$RUN_USER" "$RUN_GROUP" "$RUST_LOG" <<'PY'
from pathlib import Path
import sys

template_path, output_path, install_dir, user, group, rust_log = sys.argv[1:]
template = Path(template_path).read_text()
rendered = (
    template
    .replace("@INSTALL_DIR@", install_dir)
    .replace("@USER@", user)
    .replace("@GROUP@", group)
    .replace("@RUST_LOG@", rust_log)
)
Path(output_path).write_text(rendered)
PY

echo "Installed dstack-simulator ${VERSION} to ${CURRENT_DIR}"
echo "Binary symlink: ${BIN_LINK}"
echo "Service file: ${SERVICE_FILE}"

if [[ "$SKIP_SYSTEMD" -eq 0 ]]; then
    need_cmd systemctl
    UNIT_NAME="$(basename "$SERVICE_FILE")"
    systemctl daemon-reload
    systemctl enable --now "$UNIT_NAME"
    echo "systemd service enabled and started: ${UNIT_NAME}"
else
    echo "Skipping systemd enable/start (--skip-systemd)."
fi
