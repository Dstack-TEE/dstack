# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D100, D101, D102, D103

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL_DIR = HERE.parent
FIXTURE = HERE / "fixtures" / "sample-plan"
CLI = TOOL_DIR / "dstack-test"
sys.path.insert(0, str(TOOL_DIR))

import dstack_test  # noqa: E402
import render  # noqa: E402


class DstackTestTests(unittest.TestCase):
    def copy_fixture(self, root: Path) -> Path:
        plan = root / "plan"
        shutil.copytree(FIXTURE, plan)
        return plan

    def test_validate_and_render_fixture(self) -> None:
        plan = render.load_plan(FIXTURE)
        valid = dstack_test.validate_run(plan, "run-demo")
        self.assertEqual(valid["cases"], 1)
        run, results = render.load_session_results(plan, "run-demo")
        output = render.render_report(plan, run, results)
        self.assertIn("Sample Gateway Test Plan", output)
        self.assertIn("Complete agent session (7 events)", output)
        self.assertIn("198.51.100.27:45678", output)
        self.assertIn("session-tc-gw-pp-001-event-2", output)

    def test_finalize_rebuilds_run_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            shutil.rmtree(plan_path / "results" / "run-demo")
            plan = render.load_plan(plan_path)
            run = dstack_test.finalize_run(
                plan, "run-demo", {"environment": {"level": "INTEGRATION"}}
            )
            self.assertEqual(run["status"], "COMPLETED")
            self.assertEqual(run["summary"]["by_status"]["PASS"]["count"], 1)
            self.assertEqual(
                dstack_test.validate_run(plan, "run-demo")["status"], "valid"
            )

    def test_invalid_session_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            session = (
                plan_path
                / "01-gateway/01-proxy-protocol/tc-gw-pp-001/results/run-demo/session.jsonl"
            )
            session.write_text("not json\n", encoding="utf-8")
            with self.assertRaises(dstack_test.DstackTestError):
                dstack_test.validate_run(render.load_plan(plan_path), "run-demo")

    def test_run_case_with_fake_codex(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.copy_fixture(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake = fake_bin / "codex"
            fake.write_text(
                """#!/usr/bin/env python3
import json, pathlib, re, sys
prompt=sys.argv[-1]
match=re.search(r'atomically write the summary to ([^\\n]+/result\\.json)',prompt)
if not match: raise SystemExit(9)
path=pathlib.Path(match.group(1).strip())
path.parent.mkdir(parents=True,exist_ok=True)
result={
 'schema_version':'1.0','case_id':'tc-gw-pp-001','status':'PASS','summary':'fake agent passed',
 'steps':[
  {'id':'tc-gw-pp-001-step-01','status':'PASS','observed':'policy matched'},
  {'id':'tc-gw-pp-001-step-02','status':'PASS','observed':'request matched'}],
 'artifacts':[],'remarks':''}
tmp=path.with_suffix('.tmp'); tmp.write_text(json.dumps(result)); tmp.replace(path)
print(json.dumps({'type':'thread.started','model':'fake-model'}))
print(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':'tc-gw-pp-001-step-01 tc-gw-pp-001-step-02'}}))
""",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
            completed = subprocess.run(
                [
                    str(CLI),
                    "run-case",
                    "--agent",
                    "codex",
                    "--plan",
                    str(plan),
                    "--case",
                    "tc-gw-pp-001",
                    "--run-id",
                    "run-fake",
                    "--workdir",
                    str(root),
                    "--",
                    "fake execution",
                ],
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result_dir = (
                plan / "01-gateway/01-proxy-protocol/tc-gw-pp-001/results/run-fake"
            )
            self.assertEqual(
                json.loads((result_dir / "result.json").read_text())["status"], "PASS"
            )
            runner = json.loads((result_dir / "runner.json").read_text())
            self.assertEqual(runner["agent"]["model"], "fake-model")
            self.assertTrue((result_dir / "session.jsonl").is_file())

    def test_package_zip_is_self_contained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan_path = self.copy_fixture(root)
            old_run = plan_path / "results" / "run-old"
            old_run.mkdir(parents=True)
            (old_run / "must-not-be-packaged.txt").write_text("old")
            output = root / "report.zip"
            dstack_test.package_plan(render.load_plan(plan_path), "run-demo", output)
            self.assertGreater(output.stat().st_size, 0)
            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
            self.assertIn("plan/results/run-demo/run.json", names)
            self.assertFalse(any("run-old" in name for name in names))


if __name__ == "__main__":
    unittest.main()
