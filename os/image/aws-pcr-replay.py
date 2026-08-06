#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Phala Network
# SPDX-License-Identifier: Apache-2.0

"""Build a NitroTPM PCR replay document from the pinned AWS tool trace."""

import argparse
import hashlib
import json
import re
from pathlib import Path

EVENT_RE = re.compile(r"\[PCR(4|7|12)\]\s+([A-Z0-9_]+):\s+SHA384:([0-9a-fA-F]{96})")


def extend(current: bytes, digest: bytes) -> bytes:
    """Extend a SHA-384 PCR value with one measured digest."""
    return hashlib.sha384(current + digest).digest()


def main() -> None:
    """Generate and validate the NitroTPM PCR replay document."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--measurements", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    events = []
    replayed = {4: bytes(48), 7: bytes(48), 12: bytes(48)}
    for match in EVENT_RE.finditer(args.trace.read_text()):
        pcr = int(match.group(1))
        digest = bytes.fromhex(match.group(3))
        replayed[pcr] = extend(replayed[pcr], digest)
        events.append(
            {"pcr": pcr, "event_type": match.group(2), "digest": digest.hex()}
        )

    if not events:
        raise SystemExit("no NitroTPM PCR events found in tool trace")

    computed = json.loads(args.measurements.read_text())["Measurements"]
    expected = {pcr: computed[f"PCR{pcr}"].lower() for pcr in replayed}
    for pcr, value in replayed.items():
        if value.hex() != expected[pcr]:
            raise SystemExit(
                f"PCR{pcr} replay mismatch: expected={expected[pcr]}, "
                f"replayed={value.hex()}"
            )

    document = {
        "version": 1,
        "events": events,
        "pcr4": expected[4],
        "pcr7": expected[7],
        "pcr12": expected[12],
    }
    args.output.write_text(json.dumps(document, indent=2) + "\n")


if __name__ == "__main__":
    main()
