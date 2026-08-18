#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serve verifier archives and mutable, case-owned KMS authorization policies."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    """Load one policy snapshot without retaining stale state between requests."""
    return json.loads(path.read_text())


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    """Append one public authorization observation atomically under one process."""
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(value, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())


class Handler(SimpleHTTPRequestHandler):
    """Serve archives plus context-specific KMS boot authorization endpoints."""

    policy_path: Path
    observations_path: Path

    def do_GET(self) -> None:  # noqa: N802
        """Return webhook metadata or an immutable verifier archive."""
        if self.path.rstrip("/") in ("/source", "/target"):
            self.send_json(
                200,
                {
                    "status": "ok",
                    "kmsContractAddr": "case-owned-policy",
                    "ethRpcUrl": "",
                    "gatewayAppId": "any",
                    "chainId": 0,
                    "appImplementation": "case-owned-webhook",
                },
            )
            return
        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        """Authorize one observed KMS boot identity against current policy."""
        parts = self.path.strip("/").split("/")
        if len(parts) != 3 or parts[1] != "bootAuth" or parts[2] not in ("kms", "app"):
            self.send_error(404)
            return
        context = parts[0]
        if context not in ("source", "target"):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        policy = load_json(self.policy_path)[context]
        mr = body.get("mrAggregated", "")
        image = body.get("osImageHash", "")
        app_id = body.get("appId", "")
        compose_hash = body.get("composeHash", "")
        allowed_mrs = policy.get("allowedMrAggregated", [])
        allowed_images = policy.get("allowedOsImageHashes", [])
        reason = ""
        if policy.get("denyAll"):
            reason = f"{context}: discovery deny"
        elif policy.get("allowAll"):
            reason = ""
        elif not policy.get("allowPlatformAll") and mr not in allowed_mrs:
            reason = f"{context}: mrAggregated is not authorized"
        elif not policy.get("allowPlatformAll") and image not in allowed_images:
            reason = f"{context}: osImageHash is not authorized"
        elif (
            parts[2] == "app"
            and policy.get("allowedAppIds") is not None
            and app_id not in policy["allowedAppIds"]
        ):
            reason = f"{context}: appId is not authorized for upgrade"
        elif (
            parts[2] == "app"
            and policy.get("allowedComposeHashes") is not None
            and compose_hash not in policy["allowedComposeHashes"]
        ):
            reason = f"{context}: composeHash is not authorized for upgrade"
        append_jsonl(
            self.observations_path,
            {
                "context": context,
                "kind": parts[2],
                "mrAggregated": mr,
                "osImageHash": image,
                "appId": app_id,
                "composeHash": compose_hash,
                "allowed": not reason,
                "reason": reason,
            },
        )
        self.send_json(
            200,
            {"isAllowed": not reason, "gatewayAppId": "any", "reason": reason},
        )

    def send_json(self, status: int, value: dict[str, Any]) -> None:
        """Send one compact JSON response."""
        encoded = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: object) -> None:
        """Write bounded HTTP access records to the lease-owned log."""
        print(fmt % args, flush=True)


def main() -> None:
    """Run the lease-owned threaded fixture server."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    args = parser.parse_args()
    Handler.policy_path = args.policy.resolve()
    Handler.observations_path = args.observations.resolve()
    with tempfile.TemporaryDirectory(dir=args.directory.parent):
        server = ThreadingHTTPServer(
            ("0.0.0.0", args.port),
            lambda *a, **kw: Handler(*a, directory=str(args.directory), **kw),
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
