#! /bin/bash
set -e

usage() {
    echo "Usage: $0 [-n]"
    echo "  -n: Don't check reproducibility"
    echo ""
    echo "Environment:"
    echo "  RELEASE_FLAVORS: space-separated flavors to build (default: prod)"
    echo "                  e.g. RELEASE_FLAVORS=\"prod dev\" $0"
}

NO_CHECK=0
while getopts ":n" opt; do
    case $opt in
        n)
            NO_CHECK=1
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            exit 1
            ;;
    esac
done


BUILDER_NAME=dstack-build
THIS_DIR=$(cd $(dirname $0); pwd)
REPO_ROOT=${REPO_ROOT:-$(dirname $THIS_DIR)}
GIT_DIR=$REPO_ROOT

HOST_BUILD_DIR_A=${THIS_DIR}/build-a
HOST_BUILD_DIR_B=${THIS_DIR}/build-b

# guest dirs
GUEST_BUILD_DIR=/dstack-build
GUEST_SRC_DIR=/meta-dstack

cd $THIS_DIR

mkdir -p .dummy
(cd .dummy && docker build --platform linux/amd64 -t $BUILDER_NAME -f ../Dockerfile.repro .)
rm -rf .dummy

build_to() {
    mkdir -p $1
    BUILD_CMD="${2} ${GUEST_SRC_DIR}/${META_SUBDIR}/build.sh guest ./bb-build"
    docker run --platform linux/amd64 --rm \
        --userns=host \
        --user $(id -u):$(id -g) \
        -v $REPO_ROOT:$GUEST_SRC_DIR \
        -v $1:$GUEST_BUILD_DIR \
        -w $GUEST_BUILD_DIR \
        $BUILDER_NAME bash -e -c "$BUILD_CMD"
}

# Build production by default; callers may override, e.g. RELEASE_FLAVORS="prod dev".
RELEASE_FLAVORS="${RELEASE_FLAVORS:-prod}"

build_to $HOST_BUILD_DIR_A "FLAVORS='$RELEASE_FLAVORS' DSTACK_TAR_RELEASE=1"

DIST_DIR=${THIS_DIR}/dist
mkdir -p $DIST_DIR
mv $HOST_BUILD_DIR_A/images/*.tar.gz $DIST_DIR/
if [ $NO_CHECK -eq 0 ]; then
    build_to $HOST_BUILD_DIR_B "FLAVORS='$RELEASE_FLAVORS'"
    ${THIS_DIR}/check.sh $HOST_BUILD_DIR_A $HOST_BUILD_DIR_B
fi

if [[ -n $(git -C $GIT_DIR status --porcelain) ]]; then
    echo "The working tree is not clean, skip generating reproducible build command"
    exit 0
fi

echo "Reproducible build commands:"
echo "==========================="
cat <<EOF | tee $DIST_DIR/reproduce.sh
#!/bin/bash
set -e

git clone https://github.com/Phala-Network/meta-dstack-cloud.git
cd meta-dstack-cloud/
git checkout $(git -C $THIS_DIR rev-parse HEAD)
git submodule update --init --recursive
cd repro-build && RELEASE_FLAVORS='${RELEASE_FLAVORS}' ./repro-build.sh -n
EOF
echo "==========================="

chmod +x $DIST_DIR/reproduce.sh

echo "Release tar files are in $THIS_DIR/dist/"
