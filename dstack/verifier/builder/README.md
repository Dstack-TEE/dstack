# dstack Verifier Builder

This directory contains the files needed to build the dstack-verifier Docker
image reproducibly.

## Overview

The builder produces a Docker image containing the dstack-verifier service
compiled from Rust source. The build pins its base images by digest, pins the
Debian package set (`shared/pinned-packages.txt`), and normalizes timestamps, so
the same revision always yields the same image.

## Prerequisites

- Docker with BuildKit support (v20.10.0+)
- Git

## Building the Image

```bash
./build-image.sh <image-name>[:<tag>]...
```

For example:

```bash
./build-image.sh my-org/dstack-verifier:dev
```

Optional environment variables:

| Variable | Purpose |
| --- | --- |
| `GIT_REV` | Revision to build (default `HEAD`) |
| `IMAGE_VERSION` | Version recorded in the image metadata (default `dev`) |
| `IMAGE_SOURCE_URL` | Repository URL recorded in the image metadata |
| `NO_CACHE` | Set to any value to build without the layer cache |
| `OCI_TAR` | Also write an OCI archive here, for digest comparison |
| `PUSH` | Set to any value to push the tags instead of only loading them |

## Reproducing a released image

Release CI runs this same script, so a published image can be rebuilt and
checked digest-for-digest. Pass the release tag's revision and version:

```bash
GIT_REV=verifier-v0.6.0 \
IMAGE_VERSION=0.6.0 \
IMAGE_SOURCE_URL=https://github.com/Dstack-TEE/dstack \
OCI_TAR=/tmp/verifier.oci.tar \
  ./build-image.sh dstacktee/dstack-verifier:0.6.0

python3 -c 'import json,tarfile;t=tarfile.open("/tmp/verifier.oci.tar");print(json.load(t.extractfile("index.json"))["manifests"][0]["digest"])'
```

`IMAGE_VERSION` is part of the image metadata, so it must match the release for
the digests to match. The printed digest is what the registry reports for
`dstacktee/dstack-verifier:0.6.0`; compare it with:

```bash
docker buildx imagetools inspect dstacktee/dstack-verifier:0.6.0 --format '{{.Manifest.Digest}}'
```

Note that the release also publishes a `:latest` tag pointing at the same
digest.

## Image metadata

The image carries its provenance as OCI metadata in three places, all generated
from one definition in `dstack/build/shared/build-lib.sh`:

- config labels — `docker inspect -f '{{json .Config.Labels}}' <image>`
- manifest annotations — `docker buildx imagetools inspect <image>`
- `/etc/dstack-verifier/build-info` inside the image, readable from within the CVM

## Running the Built Image

See the [verifier README](../README.md) for configuration and the HTTP API.
