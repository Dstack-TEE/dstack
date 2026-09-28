# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D100, D101, D102, E402

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from fixtures import (
    FixtureManager,  # noqa: E402
    FixtureUnavailable,  # noqa: E402
)


class FixtureTests(unittest.TestCase):
    def test_noop_lease_is_persisted_and_released(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manager = FixtureManager(Path(temporary))
            lease, manifest = manager.provision(
                "run-one", "tc-one", {"profile": "ready-target"}
            )
            self.assertEqual(lease.state, "READY")
            self.assertEqual(manifest["lease_id"], lease.lease_id)
            self.assertEqual(manifest["contract"]["profile"], "ready-target")
            manager.cleanup(lease)
            persisted = json.loads(manager.journal.path(lease.lease_id).read_text())
            self.assertEqual(persisted["state"], "RELEASED")
            self.assertEqual(manager.reconcile(), [])

    def test_process_fixture_cleanup_uses_owned_process_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manager = FixtureManager(Path(temporary))
            lease, manifest = manager.provision(
                "run-process",
                "tc-process",
                {
                    "profile": "local-process",
                    "provider": "process",
                    "command": [sys.executable, "-c", "import time; time.sleep(60)"],
                },
            )
            pid = manifest["values"]["process"]["pid"]
            self.assertTrue(Path(f"/proc/{pid}").exists())
            manager.cleanup(lease)
            persisted = manager.journal.load(lease.lease_id)
            self.assertEqual(persisted.state, "RELEASED")
            self.assertEqual(persisted.resources[0].state, "RELEASED")

    def test_reconcile_cleans_unfinished_process_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manager = FixtureManager(Path(temporary))
            lease, _ = manager.provision(
                "run-reconcile",
                "tc-reconcile",
                {
                    "provider": "process",
                    "command": [sys.executable, "-c", "import time; time.sleep(60)"],
                },
            )
            original_process = next(
                iter(manager.provider("process").processes.values())  # type: ignore[attr-defined]
            )
            released = FixtureManager(Path(temporary)).reconcile()
            # The replacement manager reaped the child through the persisted
            # identity; update this test process's stale Popen wrapper.
            original_process.returncode = -15
            self.assertEqual(released, [lease.lease_id])
            self.assertEqual(manager.journal.load(lease.lease_id).state, "RELEASED")

    def test_external_provider_requires_explicit_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manager = FixtureManager(
                Path(temporary),
                {"hardware": {"provider": "hardware-pool"}},
            )
            with self.assertRaises(FixtureUnavailable):
                manager.provision("run-hw", "tc-hw", {"profile": "hardware"})
            leases = list((Path(temporary) / "leases").glob("*.json"))
            self.assertEqual(len(leases), 1)
            self.assertEqual(json.loads(leases[0].read_text())["state"], "RELEASED")

    def test_local_simulator_provider_uses_checked_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = root / "plan"
            automation = plan / "shared" / "automation"
            automation.mkdir(parents=True)
            runtime_manifest = root / "runtime-manifest.json"
            state_root = root / "state"
            runtime_manifest.write_text(
                json.dumps({"environment": {"DSTACK_TEST_STATE_ROOT": str(state_root)}})
            )
            start = automation / "start-simulator.sh"
            start.write_text(
                '#!/bin/sh\nmkdir -p "$(dirname "$3")"\nprintf \'%s\\n\' \'{"services":{}}\' >"$3"\n'
            )
            stop = automation / "stop-simulator.sh"
            stop.write_text('#!/bin/sh\ntest -f "$1"\n')
            start.chmod(0o755)
            stop.chmod(0o755)
            manager = FixtureManager(root / "run")
            lease, manifest = manager.provision(
                "run-simulator",
                "tc-simulator",
                {
                    "profile": "no-tee-dev",
                    "provider": "local-simulator",
                    "_plan_root": str(plan),
                    "_runtime_manifest": str(runtime_manifest),
                },
            )
            self.assertEqual(manifest["values"], {"services": {}})
            fixture_path = Path(lease.resources[0].identity["fixture_path"])
            self.assertTrue(fixture_path.is_relative_to(state_root / "s"))
            manager.cleanup(lease)
            self.assertEqual(manager.journal.load(lease.lease_id).state, "RELEASED")


if __name__ == "__main__":
    unittest.main()
