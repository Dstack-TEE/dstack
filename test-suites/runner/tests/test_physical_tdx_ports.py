# SPDX-FileCopyrightText: Copyright 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for physical TDX guest-port lease reservations."""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

PROVIDERS = Path(__file__).resolve().parents[2] / "shared/fixtures/providers"
sys.path.insert(0, str(PROVIDERS))
SPEC = importlib.util.spec_from_file_location(
    "physical_tdx_provider", PROVIDERS / "physical-tdx.py"
)
assert SPEC is not None and SPEC.loader is not None
physical_tdx = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(physical_tdx)


class GuestPortReservationTests(unittest.TestCase):
    def test_active_owner_prevents_reclaim_when_guest_port_is_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = root / "lease-active"
            owner.mkdir()
            marker = root / "19001.reserved"
            marker.write_text(str(owner) + "\n", encoding="utf-8")
            old = time.time() - physical_tdx.PORT_RESERVATION_STALE_SECONDS - 1
            os.utime(marker, (old, old))

            self.assertFalse(physical_tdx._reclaimable(marker, 19001, 1))

    def test_removed_owner_allows_reclaim_when_guest_port_is_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = root / "lease-removed"
            marker = root / "port.reserved"
            marker.write_text(str(owner) + "\n", encoding="utf-8")
            old = time.time() - physical_tdx.PORT_RESERVATION_STALE_SECONDS - 1
            os.utime(marker, (old, old))
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = int(probe.getsockname()[1])

            self.assertTrue(physical_tdx._reclaimable(marker, port, 1))

    def test_allocated_markers_record_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = root / "lease-active"
            owner.mkdir()
            reservations = root / "guest-ports"
            with (
                mock.patch.object(physical_tdx, "PORT_RESERVATION_DIR", reservations),
                mock.patch.object(physical_tdx, "PORT_BLOCK_START", 19001),
                mock.patch.object(physical_tdx, "PORT_BLOCK_END", 19010),
                mock.patch.object(physical_tdx, "_bindable", return_value=True),
            ):
                base = physical_tdx.find_port_block(owner, 3)

            self.assertEqual(base, 19001)
            for port in range(base, base + 3):
                self.assertEqual(
                    (reservations / f"{port}.reserved").read_text().strip(),
                    str(owner.resolve()),
                )


if __name__ == "__main__":
    unittest.main()
