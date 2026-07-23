#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
D=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/project/components/base" "$tmp/project/components/dependent"
printf one > "$tmp/project/input"

cat > "$tmp/project/components/base/base.sh" <<'EOF_COMPONENT'
COMPONENT_NAME=base
COMPONENT_CACHE_PATHS=(stages/base)
COMPONENT_ROOTFS_TREES=(stages/base)
COMPONENT_KERNEL_TREES=()
component_cache_key() { key_file "$ROOT/project/input"; }
component_build() {
    mkdir -p "$WORK/stages/base"
    printf x >> "$ROOT/base-count"
    cp "$ROOT/project/input" "$WORK/stages/base/value"
}
EOF_COMPONENT
cat > "$tmp/project/components/dependent/dependent.sh" <<'EOF_COMPONENT'
COMPONENT_NAME=dependent
COMPONENT_CACHE_PATHS=(stages/dependent)
COMPONENT_ROOTFS_TREES=(stages/dependent)
COMPONENT_KERNEL_TREES=()
component_cache_key() { key_dependency base; }
component_build() {
    mkdir -p "$WORK/stages/dependent"
    printf x >> "$ROOT/dependent-count"
    cp "$WORK/stages/base/value" "$WORK/stages/dependent/value"
}
EOF_COMPONENT
cat > "$tmp/run.sh" <<'EOF_DRIVER'
#!/bin/bash
set -euo pipefail
D=$1 ROOT=$2 WORK=$3
SELF=$D
source "$D/scripts/dev-cache.sh"
source "$D/scripts/component-framework.sh"
export SOURCE_DATE_EPOCH=1 DSTACK_DEV_CACHE_DIR="$ROOT/cache"
component_framework_init 1 "$ROOT" "$SELF" "$WORK" "$ROOT/rootfs" \
  "$ROOT/kernel" prod
COMPONENT_DIR="$ROOT/project/components"
component_run base
component_run dependent
EOF_DRIVER
chmod +x "$tmp/run.sh"

"$tmp/run.sh" "$D" "$tmp" "$tmp/work-1"
[[ $(cat "$tmp/base-count") == x ]]
[[ $(cat "$tmp/dependent-count") == x ]]
"$tmp/run.sh" "$D" "$tmp" "$tmp/work-2"
[[ $(cat "$tmp/base-count") == x ]]
[[ $(cat "$tmp/dependent-count") == x ]]
printf two > "$tmp/project/input"
"$tmp/run.sh" "$D" "$tmp" "$tmp/work-3"
[[ $(cat "$tmp/base-count") == xx ]]
[[ $(cat "$tmp/dependent-count") == xx ]]
[[ $(cat "$tmp/work-3/stages/dependent/value") == two ]]
echo 'component framework tests passed'
