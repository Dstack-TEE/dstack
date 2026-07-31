#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Controllable lease-owned TCP passthrough for KMS endpoint fault injection."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path


async def copy(source: asyncio.StreamReader, target: asyncio.StreamWriter) -> None:
    """Copy one stream until EOF and close its peer writer."""
    try:
        while data := await source.read(65536):
            target.write(data)
            await target.drain()
    finally:
        target.close()


class Proxy:
    """Read the current target and enabled state for every accepted connection."""

    def __init__(self, config: Path):
        """Bind this proxy to its atomic control file."""
        self.config = config

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Reject a disabled endpoint or proxy it without terminating TLS."""
        try:
            value = json.loads(self.config.read_text())
            enabled = value.get("enabled") is True
            print(f"proxy connection accepted enabled={enabled}", flush=True)
            if not enabled:
                writer.close()
                await writer.wait_closed()
                return
            delay = float(value.get("connect_delay_seconds", 0))
            if delay < 0 or delay > 120:
                raise ValueError(f"invalid connect delay: {delay}")
            if delay:
                await asyncio.sleep(delay)
            upstream_reader, upstream_writer = await asyncio.open_connection(
                str(value["host"]), int(value["port"])
            )
            await asyncio.gather(
                copy(reader, upstream_writer), copy(upstream_reader, writer)
            )
        except Exception as error:  # noqa: BLE001
            print(
                f"proxy connection failed: {type(error).__name__}: {error}", flush=True
            )
            writer.close()


async def serve(port: int, config: Path) -> None:
    """Serve until terminated by fixture cleanup."""
    proxy = Proxy(config)
    server = await asyncio.start_server(proxy.handle, "0.0.0.0", port)
    print(f"kms upgrade proxy listening on {port}", flush=True)
    async with server:
        await server.serve_forever()


def main() -> None:
    """Parse the bounded listener and control-file arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(serve(args.port, args.config))


if __name__ == "__main__":
    main()
