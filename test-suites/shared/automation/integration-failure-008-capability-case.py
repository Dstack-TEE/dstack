#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute physical and simulated attestation separation checks."""

from __future__ import annotations

import os
from pathlib import Path

CASE_ID = "tc-int-failure-se-008"


def main() -> None:
    """Replace this process with the shared cross-platform controller."""
    controller = Path(__file__).with_name(
        "cross-platform-versioned-attestation-case.py"
    )
    os.execv(str(controller), [str(controller)])


if __name__ == "__main__":
    main()
