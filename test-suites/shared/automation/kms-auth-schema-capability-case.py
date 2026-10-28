#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compatibility entry point for the shared KMS authorization backend matrix."""

import runpy
from pathlib import Path

CASE_ID = "tc-kms-auth-008"

runpy.run_path(
    str(Path(__file__).with_name("kms-auth-backend-shared-case.py")),
    run_name="__main__",
)
