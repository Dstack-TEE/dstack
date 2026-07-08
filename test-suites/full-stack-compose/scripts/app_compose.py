#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

"""Render app-compose manifests used by the full-stack E2E suite."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def write_manifest(path: Path, manifest: dict) -> None:
    """Write a manifest and print its derived identifiers."""
    body = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    path.write_text(body)
    digest = hashlib.sha256(body.encode()).hexdigest()
    print(json.dumps({"path": str(path), "composeHash": digest, "appId": digest[:40]}))


def nginx(args: argparse.Namespace) -> None:
    """Render an nginx app-compose manifest."""
    docker_compose = f"""services:
  web:
    image: {args.app_image}
    ports:
      - "80:80"
"""
    manifest = {
        "docker_compose_file": docker_compose,
        "gateway_enabled": True,
        "kms_enabled": True,
        "local_key_provider_enabled": False,
        "manifest_version": 2,
        "name": args.name,
        "no_instance_id": False,
        "public_logs": True,
        "public_sysinfo": True,
        "runner": "docker-compose",
        "secure_time": False,
    }
    write_manifest(Path(args.output), manifest)


def main() -> None:
    """Parse command-line arguments and render a manifest."""
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("nginx")
    p.add_argument("--name", required=True)
    p.add_argument("--app-image", required=True)
    p.add_argument("--output", required=True)
    p.set_defaults(func=nginx)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
