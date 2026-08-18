#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compatibility entry point for the attested GetKmsKey rotation matrix."""

import runpy
from pathlib import Path

CASE_ID = "tc-kms-keys-certs-003"
runpy.run_path(
    str(Path(__file__).with_name("kms-attested-rpc-case.py")),
    init_globals={"CASE_ID": CASE_ID},
    run_name="__main__",
)
