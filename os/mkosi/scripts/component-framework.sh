#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Shared API for self-describing mkosi components.

declare -Ag COMPONENT_KEYS=()
declare -ag COMPONENT_ROOTFS=() COMPONENT_KERNEL=()

component_framework_init() {
    COMPONENT_CACHE=$1
    ROOT=$2 SELF=$3 WORK=$4 STAGE=$5 KSTAGE=$6 FLAVOR=$7
    COMPONENT_DIR="$SELF/components"
    dev_cache_init "$COMPONENT_CACHE"
}

key_value() { printf 'value\0%s\0' "$*"; }

key_file() {
    local file
    for file; do
        printf 'file\0%s\0' "${file#"$ROOT/"}"
        sha256sum "$file"
    done
}

key_tree() {
    local path input
    for path; do
        git -C "$ROOT" ls-files -z --cached --others --exclude-standard -- "$path"
    done | sort -zu | while IFS= read -r -d '' input; do
        if [[ -f $ROOT/$input ]]; then
            key_file "$ROOT/$input"
        elif [[ -d $ROOT/$input ]]; then
            printf 'gitlink\0%s\0%s\0' "$input" \
              "$(git -C "$ROOT/$input" rev-parse HEAD)"
        else
            printf 'missing\0%s\0' "$input"
        fi
    done
}

key_tools() {
    local tool
    for tool; do
        printf 'tool\0%s\0' "$tool"
        case "$tool" in
            gcc|ld|cmake|make|autoconf|automake|tar) "$tool" --version | head -1 ;;
            go) go version ;;
            *) "$tool" --version ;;
        esac
    done
}

key_packages() {
    local package
    for package; do
        dpkg-query -W -f='package=${binary:Package}=${Version}\n' "$package"
    done | sort
}

key_dependency() {
    local dependency=$1
    [[ -n ${COMPONENT_KEYS[$dependency]:-} ]] || {
        echo "component dependency not built: $dependency" >&2; return 1;
    }
    printf 'dependency\0%s\0%s\0' "$dependency" "${COMPONENT_KEYS[$dependency]}"
}

component_run() {
    local name=$1 definition key
    COMPONENT_PATH="$COMPONENT_DIR/$name"
    definition="$COMPONENT_PATH/$name.sh"
    COMPONENT_NAME=''
    COMPONENT_CACHE_PATHS=()
    COMPONENT_ROOTFS_TREES=()
    COMPONENT_KERNEL_TREES=()
    unset -f component_cache_key component_build component_prepare_outputs 2>/dev/null || true
    # shellcheck source=/dev/null
    source "$definition"
    [[ $COMPONENT_NAME == "$name" ]]
    declare -F component_cache_key >/dev/null
    declare -F component_build >/dev/null

    key=$({
        key_value component-schema-v1 "$COMPONENT_NAME" "$FLAVOR" \
          "${SOURCE_DATE_EPOCH:?}" "$(uname -m)"
        key_file "$definition" "$SELF/scripts/component-framework.sh" \
          "$SELF/scripts/dev-cache.sh"
        component_cache_key
    } | sha256sum | cut -d' ' -f1)
    COMPONENT_KEYS[$name]=$key
    # shellcheck disable=SC2317 # Invoked indirectly by dev_cache_run.
    component_build_cached() {
        component_build
        if declare -F component_prepare_outputs >/dev/null; then
            component_prepare_outputs
        fi
    }
    dev_cache_run "$name" "$key" "$WORK" "${COMPONENT_CACHE_PATHS[@]}" -- \
      component_build_cached

    local tree
    for tree in "${COMPONENT_ROOTFS_TREES[@]}"; do
        COMPONENT_ROOTFS+=("$name=$WORK/$tree")
    done
    for tree in "${COMPONENT_KERNEL_TREES[@]}"; do
        COMPONENT_KERNEL+=("$name=$WORK/$tree")
    done
}

component_assemble() {
    "$SELF/scripts/merge-component-trees.py" "$STAGE" "${COMPONENT_ROOTFS[@]}"
    "$SELF/scripts/merge-component-trees.py" "$KSTAGE" "${COMPONENT_KERNEL[@]}"
}
