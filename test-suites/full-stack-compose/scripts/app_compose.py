#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

"""Render measured app-compose manifests used by the full-stack E2E suite."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def image_loader(artifact_port: int, archive: str) -> str:
    """Return a pre-launch script that imports one content-addressed image."""
    return f"""set -eu
archive=/tmp/{archive}
curl -fL --retry 5 --retry-delay 1 \\
  http://10.0.2.2:{artifact_port}/images/{archive} -o "$archive"
docker load -i "$archive"
rm -f "$archive"
"""


def write_manifest(path: Path, manifest: dict) -> None:
    """Write a manifest and print its byte-exact derived identifiers."""
    body = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    path.write_text(body)
    digest = hashlib.sha256(body.encode()).hexdigest()
    print(json.dumps({"path": str(path), "composeHash": digest, "appId": digest[:40]}))


def common_manifest(name: str, docker_compose: str, pre_launch_script: str) -> dict:
    """Return the production CVM manifest baseline used by service apps."""
    return {
        "docker_compose_file": docker_compose,
        "gateway_enabled": False,
        "kms_enabled": False,
        "local_key_provider_enabled": False,
        "manifest_version": 2,
        "name": name,
        "no_instance_id": True,
        "pre_launch_script": pre_launch_script,
        "public_logs": True,
        "public_sysinfo": True,
        "runner": "docker-compose",
        "secure_time": True,
        "storage_fs": "ext4",
    }


def kms(args: argparse.Namespace) -> None:
    """Render a KMS CVM using the production onboarding and verifier path."""
    config = f"""[rpc]
address = "0.0.0.0"
port = 8000

[rpc.tls]
key = "/kms/certs/rpc.key"
certs = "/kms/certs/rpc.crt"

[core]
cert_dir = "/kms/certs"
admin_token_hash = ""
pccs_url = ""
enforce_self_authorization = true

[core.image]
verify = true
cache_dir = "/kms/images"
download_url = "http://10.0.2.2:{args.artifact_port}/os/mr_{{OS_IMAGE_HASH}}.tar.gz"
download_timeout = "2m"

[core.metrics]
enabled = true

[core.auth_api]
type = "webhook"

[core.auth_api.webhook]
url = "http://10.0.2.2:{args.auth_port}"

[core.onboard]
enabled = true
auto_bootstrap_domain = ""
# Required by KMS 0.5.8. Current KMS ignores this retired field.
quote_enabled = true
address = "0.0.0.0"
port = 8000
"""
    docker_compose = f"""services:
  kms:
    image: {args.image_ref}
    volumes:
      - kms-volume:/kms
      - /var/run/dstack.sock:/var/run/dstack.sock
    ports:
      - "8000:8000"
    restart: unless-stopped
    configs:
      - source: kms_config
        target: /kms/kms.toml
    command: sh -c 'mkdir -p /kms/certs /kms/images && exec dstack-kms -c /kms/kms.toml'

volumes:
  kms-volume:

configs:
  kms_config:
    content: |
""" + "".join(f"      {line}\n" for line in config.splitlines())
    manifest = common_manifest(
        args.name,
        docker_compose,
        image_loader(args.artifact_port, args.image_archive),
    )
    manifest["local_key_provider_enabled"] = True
    write_manifest(Path(args.output), manifest)


def gateway(args: argparse.Namespace) -> None:
    """Render one production Gateway CVM node."""
    docker_compose = f"""services:
  gateway:
    image: {args.image_ref}
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - /dstack:/dstack
      - data:/data
    network_mode: host
    privileged: true
    environment:
      - WG_ENDPOINT=${{WG_ENDPOINT}}
      - MY_URL=${{MY_URL}}
      - BOOTNODE_URL=${{BOOTNODE_URL}}
      - WG_IP=${{WG_IP}}
      - WG_RESERVED_NET=${{WG_RESERVED_NET}}
      - WG_CLIENT_RANGE=${{WG_CLIENT_RANGE}}
      - NODE_ID=${{NODE_ID}}
      - RUST_LOG=info,certbot=debug
      - PCCS_URL=${{PCCS_URL}}
      - RPC_DOMAIN=${{RPC_DOMAIN}}
      - PROXY_LISTEN_PORT=443
      - PROXY_WORKERS=4
      - SYNC_INTERVAL=1s
      - SYNC_TIMEOUT=10s
      - SYNC_PERSIST_INTERVAL=1s
      - SYNC_CONNECTIONS_ENABLED=true
      - SYNC_CONNECTIONS_INTERVAL=1s
      - ADMIN_LISTEN_ADDR=0.0.0.0
      - ADMIN_LISTEN_PORT=8001
      - ADMIN_API_TOKEN=${{ADMIN_API_TOKEN}}
    restart: always

volumes:
  data:
"""
    manifest = common_manifest(
        args.name,
        docker_compose,
        image_loader(args.artifact_port, args.image_archive),
    )
    manifest["kms_enabled"] = True
    manifest["allowed_envs"] = [
        "ADMIN_API_TOKEN",
        "BOOTNODE_URL",
        "MY_URL",
        "NODE_ID",
        "PCCS_URL",
        "RPC_DOMAIN",
        "WG_CLIENT_RANGE",
        "WG_ENDPOINT",
        "WG_IP",
        "WG_RESERVED_NET",
    ]
    write_manifest(Path(args.output), manifest)


def nginx(args: argparse.Namespace) -> None:
    """Render a digest-pinned nginx application CVM."""
    docker_compose = f"""services:
  web:
    image: {args.image_ref}
    ports:
      - "80:80"
"""
    manifest = common_manifest(
        args.name,
        docker_compose,
        image_loader(args.artifact_port, args.image_archive),
    )
    manifest.update(
        {
            "gateway_enabled": True,
            "kms_enabled": True,
            "no_instance_id": False,
            "secure_time": False,
        }
    )
    if args.attestation_mode != "auto":
        # A string v3 manifest makes old guests fail closed instead of silently
        # ignoring the requested TDX quote mode.
        manifest["manifest_version"] = "3"
        manifest["requirements"] = {
            "tdx_measure_acpi_tables": args.attestation_mode == "legacy"
        }
    write_manifest(Path(args.output), manifest)


def add_image_args(parser: argparse.ArgumentParser) -> None:
    """Add the content-addressed container-image arguments shared by apps."""
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--image-archive", required=True)
    parser.add_argument("--artifact-port", required=True, type=int)
    parser.add_argument("--name", required=True)
    parser.add_argument("--output", required=True)


def main() -> None:
    """Parse command-line arguments and render a manifest."""
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("kms")
    add_image_args(p)
    p.add_argument("--auth-port", required=True, type=int)
    p.set_defaults(func=kms)

    p = sub.add_parser("gateway")
    add_image_args(p)
    p.set_defaults(func=gateway)

    p = sub.add_parser("nginx")
    add_image_args(p)
    p.add_argument(
        "--attestation-mode",
        choices=("auto", "legacy", "lite"),
        default="auto",
    )
    p.set_defaults(func=nginx)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
