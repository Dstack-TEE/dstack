#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SELF="$ROOT/os/mkosi"
# shellcheck source=/dev/null
source "$SELF/versions.env"
# shellcheck source=/dev/null
source "$SELF/scripts/dev-cache.sh"
# shellcheck source=/dev/null
source "$SELF/scripts/component-framework.sh"

use_cache=0
if [[ ${1:-} == --dev-cache ]]; then use_cache=1; shift; fi
work=${1:?work directory required}
stage=${2:?rootfs staging tree required}
kstage=${3:?kernel staging tree required}
flavor=${4:?flavor required}
component_framework_init "$use_cache" "$ROOT" "$SELF" \
  "$(realpath -m "$work")" "$(realpath -m "$stage")" \
  "$(realpath -m "$kstage")" "$flavor"

components=(
  dstack-rust
  container-stack
  sysbox
  nvattest
  kernel
  nvidia
  zfs
  ovmf
)

for component in "${components[@]}"; do component_run "$component"; done
component_assemble
