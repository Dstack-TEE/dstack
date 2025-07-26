#!/bin/bash
set -e

#NO_CACHE=--no-cache

extract-packages() {
    local name=$1
    local pkg_list_file=$2
    if [ -z "$pkg_list_file" ]; then
        return
    fi
    docker run --rm --entrypoint bash $name -c "dpkg -l | grep '^ii' | awk '{print \$2\"=\"\$3}' | sort" > "$pkg_list_file"
}

# Function to build Docker image and optionally extract package list
docker-build() {
    local name=$1
    local target=$2
    local pkg_list_file=$3
    # Get the commit timestamp for SOURCE_DATE_EPOCH
    local commit_timestamp=$(git show -s --format=%ct $GIT_REV)
    local build_args="--build-arg SOURCE_DATE_EPOCH=$commit_timestamp --build-arg DSTACK_REV=$GIT_REV"

    local args="--builder buildkit_20 $NO_CACHE $build_args"

    # Add target if specified
    if [ -n "$target" ]; then
        args="$args --target $target"
    fi

    # Build the image
    docker buildx build $args --output type=docker,name=$name,rewrite-timestamp=true --progress=plain .
    extract-packages $name $pkg_list_file
}

NAME=$1
if [ -z "$NAME" ]; then
    echo "Usage: $0 <name>[:<tag>]"
    exit 1
fi

# Check if buildkit_20 already exists before creating it
if ! docker buildx inspect buildkit_20 &>/dev/null; then
    docker buildx create --use --driver-opt image=moby/buildkit:v0.20.2 --name buildkit_20
fi

touch shared/builder-pinned-packages.txt
touch shared/pinned-packages.txt
GIT_REV=${GIT_REV:-HEAD}
GIT_REV=$(git rev-parse $GIT_REV)

docker-build "$NAME" "" "shared/pinned-packages.txt"
docker-build "gateway-builder-temp" "gateway-builder" "shared/builder-pinned-packages.txt"

git_status=$(git status --porcelain -- shared/)
if [ -n "$git_status" ]; then
    echo "The working tree is not clean, please commit or stash your changes before re-running the build"
    exit 1
fi

