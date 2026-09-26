#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Upgrade a v0.5.11 Gateway in place on its retained data disk."""

from __future__ import annotations

import os
from pathlib import Path

CASE_ID = "tc-int-mixed-003"
ACTION = "Migrate v0.5.11 Gateway disk state during an in-place candidate upgrade"


def main() -> None:
    """Replace this process with the shared in-place Gateway upgrade controller."""
    controller = Path(__file__).with_name("kms_upgrade_matrix_case.py")
    os.execv(str(controller), [str(controller)])


if __name__ == "__main__":
    main()
