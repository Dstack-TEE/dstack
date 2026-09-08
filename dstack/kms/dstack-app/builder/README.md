# dstack KMS Builder

This directory contains the necessary files to build and run the dstack-kms Docker image for development.

## Overview

The builder creates a Docker image that includes:
- The dstack-kms service compiled from Rust source code
- Pure-Rust ACPI measurement support built into the dstack-kms binary

## Prerequisites

- Docker with BuildKit support (v20.10.0+)
- Git

## Building the Image

To build the KMS Docker image, use the provided `build-image.sh` script:

```bash
./build-image.sh <image-name>[:<tag>]...
```

For example:
```bash
./build-image.sh kvin/kms
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
GIT_REV=kms-v0.6.0 \
IMAGE_VERSION=0.6.0 \
IMAGE_SOURCE_URL=https://github.com/Dstack-TEE/dstack \
OCI_TAR=/tmp/kms.oci.tar \
  ./build-image.sh dstacktee/dstack-kms:0.6.0

python3 -c 'import json,tarfile;t=tarfile.open("/tmp/kms.oci.tar");print(json.load(t.extractfile("index.json"))["manifests"][0]["digest"])'
```

`IMAGE_VERSION` is part of the image metadata, so it must match the release for
the digests to match. The printed digest is what the registry reports for
`dstacktee/dstack-kms:0.6.0`; compare it with:

```bash
docker buildx imagetools inspect dstacktee/dstack-kms:0.6.0 --format '{{.Manifest.Digest}}'
```

This is the digest that `deploy-to-vmm.sh` pins in `KMS_IMAGE`, and that in turn
feeds the compose hash registered on chain.

## Image metadata

The image carries its provenance as OCI metadata in three places, all generated
from one definition in `dstack/build/shared/build-lib.sh`:

- config labels — `docker inspect -f '{{json .Config.Labels}}' <image>`
- manifest annotations — `docker buildx imagetools inspect <image>`
- `/etc/dstack-kms/build-info` inside the image, readable from within the CVM

## Running the Built Image

### Using Docker Compose

The easiest way to run the KMS service is using the provided `docker-compose.yaml`:

```yaml
services:
  kms:
    image: kvin/kms
    ports:
      - "8003:8000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./kms:/kms
    environment:
      - IMAGE_DOWNLOAD_URL=${IMAGE_DOWNLOAD_URL:-http://localhost:8001/mr_{OS_IMAGE_HASH}.tar.gz}
      - AUTH_TYPE=dev
      - DEV_DOMAIN=kms.1022.dstack.org
      - QUOTE_ENABLED=false
```

To start the service:

```bash
docker-compose up
```
