# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D100, D101, D102, D103

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
TOOL_DIR = HERE.parent
FIXTURE = HERE / "fixtures" / "sample-plan"
CLI = TOOL_DIR / "dstack-test"
sys.path.insert(0, str(TOOL_DIR))

import render  # noqa: E402

spec = importlib.util.spec_from_loader(
    "dstack_test", SourceFileLoader("dstack_test", str(CLI))
)
if spec is None or spec.loader is None:
    raise RuntimeError(f"failed to load {CLI}")
dstack_test = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dstack_test)


class DstackTestTests(unittest.TestCase):
    def copy_fixture(self, root: Path) -> Path:
        plan = root / "plan"
        shutil.copytree(FIXTURE, plan)
        return plan

    def test_run_command_defaults(self) -> None:
        args = dstack_test.build_parser().parse_args(
            ["run-plan", "--plan", str(FIXTURE)]
        )
        self.assertEqual(args.agent, "codex")
        self.assertRegex(args.run_id, r"^run-\d{8}T\d{6}Z-[0-9a-f]{6}$")

    def test_codex_model_is_read_from_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "config.toml"
            config.write_text('model = "test-codex-model"\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {"CODEX_HOME": temporary}):
                self.assertEqual(
                    dstack_test.resolve_model("codex", None), "test-codex-model"
                )

    def test_orchestrator_can_record_dependency_skip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            plan = render.load_plan(plan_path)
            case = plan.cases[0]
            value = dstack_test.skip_case(
                case, "run-skip", "prerequisite case failed", ["tc-prereq-001"]
            )
            self.assertEqual(value["status"], "SKIPPED")
            result_dir = case.path / "results" / "run-skip"
            result = dstack_test.validate_summary(case, result_dir / "result.json")
            self.assertEqual(result["status"], "SKIPPED")
            self.assertIn("tc-prereq-001", (result_dir / "session.jsonl").read_text())

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

    def test_dashboard_exposes_historical_status_and_log(self) -> None:
        plan = render.load_plan(FIXTURE)
        state = dstack_test.dashboard_state(plan, "run-demo")
        self.assertEqual(state["cases"][0]["status"], "PASS")
        self.assertEqual(
            state["chapters"][0]["sections"][0]["cases"][0]["id"], "tc-gw-pp-001"
        )
        case = dstack_test.dashboard_case(plan, "tc-gw-pp-001")
        self.assertEqual(case["chapter"], "Gateway")
        self.assertIn("<h2>Steps</h2>", case["html"])
        log = dstack_test.dashboard_log(plan, "run-demo", "case:tc-gw-pp-001", 0)
        self.assertGreater(log["next_offset"], 0)
        self.assertIn("thread.started", log["text"])

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
