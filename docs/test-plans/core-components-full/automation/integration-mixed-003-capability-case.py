#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Route old and current Guests through a mixed Gateway cluster."""

from __future__ import annotations

import os
from pathlib import Path

CASE_ID = "tc-int-mixed-003"


def main() -> None:
    """Replace this process with the shared rolling Gateway controller."""
    controller = Path(__file__).with_name("kms_upgrade_matrix_case.py")
    os.execv(str(controller), [str(controller)])


if __name__ == "__main__":
    main()
