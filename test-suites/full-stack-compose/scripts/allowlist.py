#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

"""Manage the mutable KMS authorization allowlist for the compose E2E suite."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def norm_hex(value: str) -> str:
    """Normalize a possibly prefixed hexadecimal string."""
    value = value.strip()
    if value.lower().startswith("0x"):
        value = value[2:]
    return value.lower()


def load(path: Path) -> dict:
    """Load an allowlist or return an empty default policy."""
    if path.exists():
        return json.loads(path.read_text())
    return {
        "osImages": [],
        "gatewayAppId": "",
        "kms": {"mrAggregated": [], "devices": [], "allowAnyDevice": True},
        "apps": {},
    }


def save(path: Path, data: dict) -> None:
    """Atomically write an allowlist to disk."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def add_app(args: argparse.Namespace) -> None:
    """Add an application and compose hash to the allowlist."""
    path = Path(args.path)
    data = load(path)
    apps = data.setdefault("apps", {})
    app_id = norm_hex(args.app_id)
    compose_hash = norm_hex(args.compose_hash)
    entry = apps.setdefault(
        app_id, {"composeHashes": [], "devices": [], "allowAnyDevice": True}
    )
    hashes = entry.setdefault("composeHashes", [])
    if not any(norm_hex(h) == compose_hash for h in hashes):
        hashes.append(compose_hash)
    entry.setdefault("devices", [])
    entry["allowAnyDevice"] = True
    if args.gateway_app_id is not None:
        data["gatewayAppId"] = norm_hex(args.gateway_app_id)
    save(path, data)
    print(json.dumps({"appId": app_id, "composeHash": compose_hash, "path": str(path)}))


def set_gateway(args: argparse.Namespace) -> None:
    """Set the allowlisted Gateway application ID."""
    path = Path(args.path)
    data = load(path)
    data["gatewayAppId"] = norm_hex(args.gateway_app_id)
    save(path, data)
    print(json.dumps({"gatewayAppId": data["gatewayAppId"], "path": str(path)}))


def main() -> None:
    """Parse command-line arguments and update the allowlist."""
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("add-app")
    p.add_argument("--path", required=True)
    p.add_argument("--app-id", required=True)
    p.add_argument("--compose-hash", required=True)
    p.add_argument("--gateway-app-id")
    p.set_defaults(func=add_app)
    p = sub.add_parser("set-gateway")
    p.add_argument("--path", required=True)
    p.add_argument("--gateway-app-id", required=True)
    p.set_defaults(func=set_gateway)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
