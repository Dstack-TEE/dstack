#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compatibility entry point for the KMS upgrade-authority matrix."""

import runpy
from pathlib import Path

CASE_ID = "tc-kms-attestatio-004"
runpy.run_path(
    str(Path(__file__).with_name("kms-upgrade-authority-case.py")), run_name="__main__"
)
