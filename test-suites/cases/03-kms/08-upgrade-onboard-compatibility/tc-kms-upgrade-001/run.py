#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Dispatch tc-kms-upgrade-001: 0.5.4 to 0.6.0 through 0.5.7 bridge."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "shared/automation"))

from kms_upgrade_matrix_case import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
