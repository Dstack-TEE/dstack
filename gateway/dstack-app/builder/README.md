# dstack KMS Builder

This directory contains the necessary files to build and run the dstack-kms Docker image for development.

## Overview

The builder creates a Docker image that includes:
- The dstack-kms service compiled from Rust source code
- Command line tool dstack-acpi-tables for generating ACPI tables for dstack CVM

## Prerequisites

- Docker with BuildKit support (v20.10.0+)
- Git

## Building the Image

To build the KMS Docker image, use the provided `build-image.sh` script:

```bash
./build-image.sh <image-name>[:<tag>]
```

For example:
```bash
./build-image.sh kvin/kms
```

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
      - DEV_DOMAIN=kms.1022.kvin.wang
      - QUOTE_ENABLED=false
```

To start the service:

```bash
docker-compose up
```
