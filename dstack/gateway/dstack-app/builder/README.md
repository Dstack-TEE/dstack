# dstack Gateway Builder

This directory contains the files needed to build the dstack-gateway Docker
image reproducibly.

## Overview

The builder produces a Docker image containing the dstack-gateway service
compiled from Rust source. The build pins its base images by digest, pins the
Debian package set (`shared/pinned-packages.txt`), and normalizes timestamps, so
the same revision always yields the same image.

## Prerequisites

- Docker with Buildx v0.13.0+ (the script creates a BuildKit v0.20.2 builder)
- Git

## Building the Image

```bash
./build-image.sh <image-name>[:<tag>]...
```

For example:

```bash
./build-image.sh my-org/dstack-gateway:dev
```

Optional environment variables:

| Variable | Purpose |
| --- | --- |
| `GIT_REV` | Revision to build (default `HEAD`) |
| `IMAGE_VERSION` | Version recorded in the image metadata (default `dev`) |
| `IMAGE_SOURCE_URL` | Repository URL recorded in the image metadata |
| `NO_CACHE` | Set to any value to build without the layer cache |
| `OCI_TAR` | Also write an OCI archive here, for digest comparison |
| `METADATA_FILE` | Write the validated OCI manifest digest and build metadata here |
| `PUSH` | Set to any value to push the tags instead of only loading them |

Publication and OCI export happen only after both package lists pass validation.
`NO_CACHE` applies to the validation builds; export then reuses their cached result.
Manual release workflows require an existing component release tag and check out
that tag, rather than building the branch selected in the workflow UI.

## Reproducing a released image

Release CI runs this same script, so a published image can be rebuilt and
checked digest-for-digest. Use a clean checkout of the release commit so the
Dockerfile, package lists, shared scripts and copied files also match the release.
From the repository root (fetch the tag first if it is not available locally):

```bash
git switch --detach "gateway-v0.6.0^{commit}"
cd dstack/gateway/dstack-app/builder

GIT_REV=HEAD \
IMAGE_VERSION=0.6.0 \
IMAGE_SOURCE_URL=https://github.com/Dstack-TEE/dstack \
OCI_TAR=/tmp/gateway.oci.tar \
  ./build-image.sh dstacktee/dstack-gateway:0.6.0

python3 -c 'import json,tarfile;t=tarfile.open("/tmp/gateway.oci.tar");print(json.load(t.extractfile("index.json"))["manifests"][0]["digest"])'
```

`IMAGE_VERSION` is part of the image metadata, so it must match the release for
the digests to match. The printed digest is what the registry reports for
`dstacktee/dstack-gateway:0.6.0`; compare it with:

```bash
docker buildx imagetools inspect dstacktee/dstack-gateway:0.6.0 --format '{{.Manifest.Digest}}'
```

## Image metadata

The image carries its provenance as OCI metadata in three places, all generated
from one definition in `dstack/build/shared/build-lib.sh`:

- config labels — `docker inspect -f '{{json .Config.Labels}}' <image>`
- manifest annotations — `docker buildx imagetools inspect <image>`
- `/etc/dstack-gateway/build-info` inside the image, readable from within the CVM

## Running the Built Image

The gateway is normally deployed as a dstack app; see
[`../deploy-to-vmm.sh`](../deploy-to-vmm.sh) and the
[gateway README](../../README.md).
