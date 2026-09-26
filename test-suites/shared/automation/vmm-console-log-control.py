#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write controlled data to one registered lease-owned VM log channel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

CHANNELS = {"serial": "serial.log", "stdout": "stdout.log", "stderr": "stderr.log"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-path", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--channel", choices=sorted(CHANNELS), required=True)
    parser.add_argument("--text", required=True)
    parser.add_argument("--truncate", action="store_true")
    args = parser.parse_args()
    registered = json.loads(Path(args.registry).read_text())
    if args.id not in registered:
        raise RuntimeError("refusing to write an unregistered VM log")
    run_path = Path(args.run_path).resolve()
    vm_dir = (run_path / args.id).resolve()
    if vm_dir.parent != run_path or not vm_dir.is_dir():
        raise RuntimeError("registered VM work directory is unavailable")
    target = vm_dir / CHANNELS[args.channel]
    mode = "w" if args.truncate else "a"
    with target.open(mode, encoding="utf-8") as output:
        output.write(args.text)
        output.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
