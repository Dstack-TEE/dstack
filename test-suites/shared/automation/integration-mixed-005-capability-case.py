#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reuse the exact verifier evidence compatibility matrix for the mixed case."""

from __future__ import annotations

import runpy
from pathlib import Path

CASE_ID = "tc-int-mixed-005"

runpy.run_path(
    str(Path(__file__).with_name("verifier-evidence-compatibility-case.py")),
    run_name="__main__",
)
