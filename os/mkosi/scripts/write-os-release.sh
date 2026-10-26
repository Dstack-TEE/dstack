#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "Usage: $0 ROOT VERSION CODENAME" >&2
	exit 2
fi

root=$1
version=$2
codename=$3
install -d -m0755 "$root/usr/lib" "$root/etc"
cat > "$root/usr/lib/os-release" <<RELEASE
ID=dstack
ID_LIKE=debian
NAME="dstack"
VERSION="$version ($codename)"
VERSION_ID="$version"
VERSION_CODENAME="$codename"
PRETTY_NAME="dstack $version ($codename)"
CPE_NAME="cpe:/o:dstack:dstack:$version"
IMAGE_ID=dstack
IMAGE_VERSION="$version"
DEFAULT_HOSTNAME=dstack
RELEASE
ln -sfn ../usr/lib/os-release "$root/etc/os-release"
