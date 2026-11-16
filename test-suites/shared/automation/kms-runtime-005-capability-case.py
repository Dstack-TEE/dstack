#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compatibility entry point for the shared KMS contract-policy matrix."""

import runpy
from pathlib import Path

CASE_ID = "tc-kms-runtime-005"
runpy.run_path(
    str(Path(__file__).with_name("kms-contract-policy-shared-case.py")),
    run_name="__main__",
)
