#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Kill only the QEMU child of one lease-owned VMM launcher."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import signal
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--supervisor-client", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--run-path", required=True)
    parser.add_argument("--id", required=True)
    args = parser.parse_args()
    process = subprocess.run(
        [args.supervisor_client, "--base-url", args.base_url, "info", args.id],
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if process.returncode:
        raise RuntimeError("failed to query lease-owned launcher")
    info = json.loads(process.stdout)
    if not isinstance(info, dict) or str(info.get("config", {}).get("id")) != args.id:
        raise RuntimeError("Supervisor did not return the requested launcher")
    launcher_pid = int(info.get("state", {}).get("pid") or 0)
    if launcher_pid <= 1:
        raise RuntimeError("requested launcher has no live PID")
    children_path = pathlib.Path(f"/proc/{launcher_pid}/task/{launcher_pid}/children")
    children = [int(value) for value in children_path.read_text().split()]
    owned_path = str(pathlib.Path(args.run_path) / args.id)
    matches: list[int] = []
    for pid in children:
        cmdline_path = pathlib.Path(f"/proc/{pid}/cmdline")
        try:
            argv = [
                part.decode(errors="replace")
                for part in cmdline_path.read_bytes().split(b"\0")
                if part
            ]
        except FileNotFoundError:
            continue
        executable = pathlib.Path(argv[0]).name if argv else ""
        if executable.startswith("qemu-system-") and any(
            owned_path in arg for arg in argv
        ):
            matches.append(pid)
    if len(matches) != 1:
        raise RuntimeError(f"expected one lease-owned QEMU child, found {len(matches)}")
    os.kill(matches[0], signal.SIGKILL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
