#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute tc-kms-upgrade-009: Mixed-version KMS endpoint service consistency."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "shared/automation"))

from kms_upgrade_matrix_case import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
