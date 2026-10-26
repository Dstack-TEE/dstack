#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Phala Network
# SPDX-License-Identifier: Apache-2.0

"""Bind the GCP TPM event-log template to an assembled UKI."""

import argparse
from pathlib import Path

FIXTURE_UKI_HASH = bytes.fromhex(
    "9ab14a46f858662a89adc102d2a57a13f52f75c1769d65a4c34edbbfc8855f0f"
)


def main() -> None:
    """Generate an image-specific event log from the GCP template."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--uki-hash", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    uki_hash = bytes.fromhex(args.uki_hash.read_text().strip())
    if len(uki_hash) != 32:
        raise SystemExit("GCP UKI Authenticode hash must be SHA-256")

    event_log = args.template.read_bytes()
    occurrences = event_log.count(FIXTURE_UKI_HASH)
    if occurrences != 1:
        raise SystemExit(
            f"expected one UKI digest in GCP event-log template, found {occurrences}"
        )
    args.output.write_bytes(event_log.replace(FIXTURE_UKI_HASH, uki_hash, 1))


if __name__ == "__main__":
    main()
