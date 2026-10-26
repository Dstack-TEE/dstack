# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

"""Focused regression tests for vmm-cli update request construction."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path


def load_vmm_cli():
    """Load the executable vmm-cli.py as a normal Python module."""
    path = Path(__file__).resolve().parents[1] / "vmm-cli.py"
    spec = importlib.util.spec_from_file_location("dstack_vmm_cli", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VMM_CLI = load_vmm_cli()


class UpdateVmTests(unittest.TestCase):
    """Verify update flags are not silently discarded by the CLI."""

    def test_kms_urls_are_sent_to_upgrade_app(self) -> None:
        """Send both the update flag and requested KMS URL list."""
        cli = VMM_CLI.VmmCLI("http://127.0.0.1:8080")
        calls: list[tuple[str, dict]] = []
        cli.rpc_call = lambda method, params=None: calls.append((method, params)) or {}

        with contextlib.redirect_stdout(io.StringIO()):
            cli.update_vm("vm-id", kms_urls=["https://kms.example:8000"])

        self.assertEqual(
            calls,
            [
                (
                    "UpgradeApp",
                    {
                        "id": "vm-id",
                        "update_kms_urls": True,
                        "kms_urls": ["https://kms.example:8000"],
                    },
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
