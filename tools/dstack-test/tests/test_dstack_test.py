# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D100, D101, D102, D103

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
TOOL_DIR = HERE.parent
FIXTURE = HERE / "fixtures" / "sample-plan"
CLI = TOOL_DIR / "dstack-test"
sys.path.insert(0, str(TOOL_DIR))

import fixtures  # noqa: E402
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

    def mark_completed(self, result_dir: Path) -> None:
        (result_dir / "runner.json").write_text(
            '{"result_valid":true}', encoding="utf-8"
        )
        (result_dir / "execution.json").write_text(
            '{"state":"COMPLETED"}', encoding="utf-8"
        )

    def add_script_executor(
        self, plan_path: Path, body: str, **execution: object
    ) -> Path:
        index_path = plan_path / "index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        case = index["chapters"][0]["sections"][0]["cases"][0]
        script = plan_path / case["path"] / "automation" / "run-test.py"
        script.parent.mkdir()
        script.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
        script.chmod(0o755)
        case["execution"] = {
            "entrypoint": str(script.relative_to(plan_path)),
            "args": [],
            "timeout_seconds": 10,
            **execution,
        }
        case["fixture"] = {"profile": "noop"}
        case["actions_under_test"] = ["Gateway.ProxyProtocol"]
        index_path.write_text(json.dumps(index), encoding="utf-8")
        return script

    def test_run_command_defaults(self) -> None:
        args = dstack_test.build_parser().parse_args(
            ["run-plan", "--plan", str(FIXTURE)]
        )
        self.assertEqual(args.agent, "codex")
        self.assertEqual(args.skip, [])
        self.assertIsNone(args.control_token)
        self.assertRegex(args.run_id, r"^run-\d{8}T\d{6}Z-[0-9a-f]{6}$")

    def test_run_plan_accepts_selective_resume_and_control_token(self) -> None:
        args = dstack_test.build_parser().parse_args(
            [
                "run-plan",
                "--plan",
                str(FIXTURE),
                "--resume",
                "--skip",
                "PASS",
                "--skip",
                "SKIPPED",
                "--web",
                "--control-token",
                "stable-token",
            ]
        )
        self.assertEqual(args.skip, ["PASS", "SKIPPED"])
        self.assertEqual(args.control_token, "stable-token")

    def test_sweep_accepts_serial_preflight_cases(self) -> None:
        args = dstack_test.build_parser().parse_args(
            [
                "sweep",
                "--plan",
                str(FIXTURE),
                "--preflight-case",
                "tc-gw-pp-001",
            ]
        )
        self.assertEqual(args.preflight_case, ["tc-gw-pp-001"])

    def test_sweep_postflight_rejects_unreleased_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            self.add_script_executor(
                plan_path,
                "import json, os, pathlib\n"
                "result = pathlib.Path(os.environ['DSTACK_TEST_RESULT_DIR'])\n"
                "value = {'schema_version':'1.0','case_id':'tc-gw-pp-001',"
                "'status':'PASS','summary':'ok','steps':[],"
                "'artifacts':[],'remarks':''}\n"
                "(result / 'result.json').write_text(json.dumps(value))\n",
            )
            plan = render.load_plan(plan_path)
            run_id = "leaked-sweep"
            runtime = plan.root / "runtime.json"
            runtime.write_text("{}\n", encoding="utf-8")

            def leaked_run(*_args: object, **_kwargs: object) -> dict[str, str]:
                leases = plan.root / "results" / run_id / "leases"
                leases.mkdir(parents=True, exist_ok=True)
                (leases / "lease-leaked.json").write_text(
                    json.dumps(
                        {
                            "case_id": "tc-gw-pp-001",
                            "state": "READY",
                            "resources": [],
                        }
                    ),
                    encoding="utf-8",
                )
                return {"case": "tc-gw-pp-001", "status": "PASS"}

            with mock.patch.object(dstack_test, "run_case", side_effect=leaked_run):
                summary = dstack_test.scripted_sweep(
                    plan,
                    run_id,
                    None,
                    1,
                    runtime,
                    False,
                    ["tc-gw-pp-001"],
                )
            self.assertEqual(summary["preflight"]["status"], "PASS")
            self.assertEqual(summary["postflight"]["status"], "FAIL")
            self.assertEqual(summary["failed"], ["<postflight>"])

    def test_resume_appends_existing_orchestrator_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            session = Path(temporary) / "orchestrator.jsonl"
            self.assertEqual(dstack_test.session_log_mode(session, True), "wb")
            session.write_text('{"type":"thread.started"}\n', encoding="utf-8")
            self.assertEqual(dstack_test.session_log_mode(session, True), "ab")
            self.assertEqual(dstack_test.session_log_mode(session, False), "wb")

    def test_selective_resume_archives_statuses_not_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            plan = render.load_plan(plan_path)
            case = plan.cases[0]
            run_id = "selective-resume"
            result_dir = render.case_result_dir(plan, run_id, case)
            result_dir.mkdir(parents=True)
            (result_dir / "result.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "case_id": case.id,
                        "status": "FAIL",
                        "summary": "mismatch",
                        "steps": [
                            {
                                "id": f"{case.id}-step-01",
                                "status": "FAIL",
                                "observed": "mismatch",
                            },
                            {
                                "id": f"{case.id}-step-02",
                                "status": "NOT_RUN",
                                "observed": "not run",
                            },
                        ],
                        "artifacts": [],
                        "remarks": "",
                    }
                ),
                encoding="utf-8",
            )
            self.mark_completed(result_dir)
            lifecycle = (
                plan.root / "results" / run_id / "case-lifecycle" / f"{case.id}.json"
            )
            lifecycle.parent.mkdir(parents=True)
            lifecycle.write_text('{"state":"FAIL"}', encoding="utf-8")

            rerun = dstack_test.prepare_selective_resume(plan, run_id, {"PASS"})

            self.assertEqual(rerun, [(case.id, "FAIL")])
            self.assertFalse(result_dir.exists())
            self.assertFalse(lifecycle.exists())
            attempts = list(
                (plan.root / "results" / run_id / "attempts").rglob("result.json")
            )
            self.assertEqual(len(attempts), 1)

    def test_selective_resume_retains_requested_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            plan = render.load_plan(plan_path)
            case = plan.cases[0]
            run_id = "selective-resume"
            result_dir = render.case_result_dir(plan, run_id, case)
            result_dir.mkdir(parents=True)
            (result_dir / "result.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "case_id": case.id,
                        "status": "PASS",
                        "summary": "passed",
                        "steps": [
                            {
                                "id": f"{case.id}-step-01",
                                "status": "PASS",
                                "observed": "ok",
                            },
                            {
                                "id": f"{case.id}-step-02",
                                "status": "PASS",
                                "observed": "ok",
                            },
                        ],
                        "artifacts": [],
                        "remarks": "",
                    }
                ),
                encoding="utf-8",
            )
            self.mark_completed(result_dir)

            rerun = dstack_test.prepare_selective_resume(plan, run_id, {"PASS"})

            self.assertEqual(rerun, [])
            self.assertTrue((result_dir / "result.json").is_file())

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
                plan, case, "run-skip", "prerequisite case failed", ["tc-prereq-001"]
            )
            self.assertEqual(value["status"], "SKIPPED")
            result_dir = render.case_result_dir(plan, "run-skip", case)
            result = dstack_test.validate_summary(case, result_dir / "result.json")
            self.assertEqual(result["status"], "SKIPPED")
            self.assertIn("tc-prereq-001", (result_dir / "session.jsonl").read_text())

    def test_control_state_does_not_retry_incomplete_case_in_round(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            plan = render.load_plan(plan_path)
            case = plan.cases[0]
            result_dir = render.case_result_dir(plan, "run-incomplete", case)
            result_dir.mkdir(parents=True)
            (result_dir / "session.jsonl").write_text(
                '{"type":"thread.started"}\n', encoding="utf-8"
            )
            (result_dir / "runner.json").write_text(
                json.dumps(
                    {
                        "exit_code": 1,
                        "result_valid": False,
                        "result_error": "agent completed without result.json",
                    }
                ),
                encoding="utf-8",
            )
            state = dstack_test.ControlState(
                plan, SimpleNamespace(run_id="run-incomplete"), None
            )

            value = state.next_case(announce=False)

            self.assertEqual(value["status"], "COMPLETE")
            self.assertEqual(value["completed"], 1)
            prior = state.prior()
            self.assertEqual(prior[0]["case_id"], case.id)
            self.assertEqual(prior[0]["status"], "INCOMPLETE")
            self.assertIn("without result.json", prior[0]["summary"])
            with self.assertRaises(dstack_test.DstackTestError):
                state.current(case.id)

    def test_orchestrator_prompt_forbids_incomplete_overwrite(self) -> None:
        prompt = dstack_test.orchestration_prompt(render.load_plan(FIXTURE), "")
        self.assertIn("retained in prior results as INCOMPLETE", prompt)
        self.assertIn("never pass --overwrite", prompt)
        self.assertIn("never unset DSTACK_TEST_CONTROL_DIR", prompt)

    def test_case_prompt_forbids_host_wide_scans(self) -> None:
        plan = render.load_plan(FIXTURE)
        prompt = dstack_test.build_prompt(plan, plan.cases[0], Path("/tmp/result"), "")
        self.assertIn("Do not recursively scan parent directories", prompt)
        self.assertIn("do not create or copy CARGO_HOME", prompt)
        self.assertIn("Source inspection is reserved", prompt)

    def test_step_markers_accept_chinese_agent_narration(self) -> None:
        started = dstack_test.STEP_EVENT_RE.search(
            "[tc-gos-tappd-003-step-02 开始] 执行矩阵"
        )
        finished = dstack_test.STEP_EVENT_RE.search(
            "[tc-gos-tappd-003-step-02 结束] FAIL：响应字段不符"
        )
        self.assertIsNotNone(started)
        self.assertTrue(dstack_test.step_event_starts(started.group("kind")))
        self.assertIsNotNone(finished)
        self.assertFalse(dstack_test.step_event_starts(finished.group("kind")))
        self.assertEqual(finished.group("status"), "FAIL")
        transitions = list(
            dstack_test.STEP_EVENT_RE.finditer(
                "[tc-gos-tappd-003-step-01 结束] PASS\n"
                "[tc-gos-tappd-003-step-02 开始] 执行矩阵"
            )
        )
        self.assertEqual(len(transitions), 2)
        self.assertTrue(dstack_test.step_event_starts(transitions[1].group("kind")))
        reverse = dstack_test.iter_step_events(
            "现在开始 `tc-gos-tappd-004-step-02`：执行矩阵"
        )
        self.assertEqual(len(reverse), 1)
        self.assertEqual(reverse[0].group("id"), "tc-gos-tappd-004-step-02")
        self.assertTrue(dstack_test.step_event_starts(reverse[0].group("kind")))

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
        with tempfile.TemporaryDirectory() as temporary:
            plan = render.load_plan(self.copy_fixture(Path(temporary)))
            state = dstack_test.dashboard_state(plan, "run-demo")
            self.assertEqual(state["cases"][0]["status"], "PASS")
            dstack_test.atomic_json(
                plan.root / "results" / "run-demo" / "run.json",
                {"status": "INCOMPLETE"},
            )
            live = dstack_test.dashboard_state(
                plan,
                "run-demo",
                {"enabled": True, "running": True, "current_case": "tc-gw-pp-001"},
            )
            self.assertEqual(live["run_status"], "RUNNING")
            self.assertEqual(live["orchestrator_status"], "RUNNING")
            self.assertEqual(live["log_agent"], "case:tc-gw-pp-001")
            self.assertEqual(
                state["chapters"][0]["sections"][0]["cases"][0]["id"],
                "tc-gw-pp-001",
            )
            case = dstack_test.dashboard_case(plan, "run-demo", "tc-gw-pp-001")
            self.assertEqual(case["chapter"], "Gateway")
            self.assertIn("<h2>Steps</h2>", case["html"])
            self.assertEqual(case["metadata"]["case_id"], "tc-gw-pp-001")
            self.assertIn("executor", case["metadata"])
            log = dstack_test.dashboard_log(plan, "run-demo", "case:tc-gw-pp-001", 0)
            self.assertGreater(log["next_offset"], 0)
            self.assertIn("thread.started", log["text"])
            result_dir = render.case_result_dir(plan, "run-demo", plan.cases[0])
            dstack_test.atomic_json(
                result_dir / "execution.json",
                {"state": "TERMINATED", "case_id": "tc-gw-pp-001"},
            )
            self.assertEqual(
                dstack_test.dashboard_state(plan, "run-demo")["cases"][0]["status"],
                "INCOMPLETE",
            )
        dashboard_html = (TOOL_DIR / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('class="selection-panel"', dashboard_html)
        for selection in ("selectAll", "selectFail", "selectPass", "selectPending"):
            self.assertIn(f'id="{selection}"', dashboard_html)
        self.assertIn('class="group-select"', dashboard_html)
        self.assertNotIn('id="selectVisible"', dashboard_html)
        self.assertIn("if (state.agent !== logAgent) switchAgent", dashboard_html)
        self.assertIn("<legend>Plan</legend>", dashboard_html)
        self.assertIn("<legend>Case</legend>", dashboard_html)
        self.assertIn("caseMetadataHTML(c)", dashboard_html)
        self.assertIn('id="runPicker"', dashboard_html)
        self.assertIn("/api/runs", dashboard_html)
        self.assertIn('data-open-key="evidence:', dashboard_html)
        self.assertIn("details.dataset.openKey", dashboard_html)
        self.assertIn("signature === state.caseResultSignature", dashboard_html)

    def test_dashboard_discovers_and_selects_central_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = render.load_plan(self.copy_fixture(Path(temporary)))
            other = plan.root / "results/run-other"
            other.mkdir()
            dstack_test.atomic_json(
                other / "run.json",
                {"id": "run-other", "status": "INCOMPLETE", "summary": {}},
            )
            runs = dstack_test.dashboard_runs(plan, "run-demo")
            self.assertEqual(runs[0]["id"], "run-demo")
            self.assertTrue(runs[0]["active"])
            self.assertEqual(
                dstack_test.selected_run_id(plan, "run-other", "run-demo"),
                "run-other",
            )
            with self.assertRaises(dstack_test.DstackTestError):
                dstack_test.selected_run_id(plan, "missing", "run-demo")

    def test_script_executor_streams_and_accepts_nonzero_with_valid_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            self.add_script_executor(
                plan_path,
                """import json, os, pathlib, sys
result_dir = pathlib.Path(os.environ['DSTACK_TEST_RESULT_DIR'])
print('STEP tc-gw-pp-001-step-01 START', flush=True)
print('EVIDENCE tc-gw-pp-001-step-01 - Proves the script output is streamed.', flush=True)
print('observed proxy address', flush=True)
print('STEP tc-gw-pp-001-step-01 END - PASS', flush=True)
result = {'schema_version':'1.0','case_id':'tc-gw-pp-001','status':'PASS','summary':'script pass','steps':[{'id':'tc-gw-pp-001-step-01','status':'PASS','observed':'proxy address preserved'}],'artifacts':[],'remarks':''}
(result_dir / 'result.json').write_text(json.dumps(result))
sys.exit(7)
""",
            )
            plan = render.load_plan(plan_path)
            value = dstack_test.run_case(
                plan,
                plan.cases[0],
                "run-script",
                "codex",
                None,
                plan_path,
                "",
                [],
                False,
            )
            self.assertEqual(value["status"], "PASS")
            result_dir = render.case_result_dir(plan, "run-script", plan.cases[0])
            runner = json.loads((result_dir / "runner.json").read_text())
            self.assertEqual(runner["executor"]["type"], "script")
            self.assertEqual(runner["exit_code"], 7)
            session = (result_dir / "session.jsonl").read_text()
            self.assertIn('"type": "stdout"', session)
            evidence = (result_dir / "evidence.jsonl").read_text()
            self.assertIn("Proves the script output is streamed", evidence)
            self.assertTrue((result_dir / "fixture/runtime-manifest.json").is_file())
            lease = json.loads((result_dir / "fixture/lease.json").read_text())
            self.assertEqual(lease["state"], "RELEASED")
            cleanup = json.loads((result_dir / "fixture/cleanup.json").read_text())
            self.assertEqual(cleanup["status"], "PASS")
            case_view = dstack_test.dashboard_case(plan, "run-script", "tc-gw-pp-001")
            self.assertEqual(case_view["fixture"]["lease"]["state"], "RELEASED")
            lifecycle = json.loads(
                (
                    plan.root / "results/run-script/case-lifecycle/tc-gw-pp-001.json"
                ).read_text()
            )
            self.assertEqual(lifecycle["state"], "PASS")

    def test_failed_script_can_retain_fixture_for_debugging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            self.add_script_executor(
                plan_path,
                """import json, os, pathlib
result_dir = pathlib.Path(os.environ['DSTACK_TEST_RESULT_DIR'])
result = {'schema_version':'1.0','case_id':'tc-gw-pp-001','status':'FAIL','summary':'diagnostic mismatch','steps':[{'id':'tc-gw-pp-001-step-01','status':'FAIL','observed':'retained mismatch'}],'artifacts':[],'remarks':''}
(result_dir / 'result.json').write_text(json.dumps(result))
""",
            )
            plan = render.load_plan(plan_path)
            value = dstack_test.run_case(
                plan,
                plan.cases[0],
                "run-retained",
                "codex",
                None,
                plan_path,
                "",
                [],
                False,
                True,
            )
            self.assertEqual(value["status"], "FAIL")
            result_dir = render.case_result_dir(plan, "run-retained", plan.cases[0])
            lease = json.loads((result_dir / "fixture/lease.json").read_text())
            cleanup = json.loads((result_dir / "fixture/cleanup.json").read_text())
            lifecycle = json.loads(
                (
                    plan.root / "results/run-retained/case-lifecycle/tc-gw-pp-001.json"
                ).read_text()
            )
            self.assertEqual(lease["state"], "READY")
            self.assertEqual(cleanup["status"], "RETAINED")
            self.assertEqual(lifecycle["state"], "RETAINED")
            manager = fixtures.FixtureManager(
                plan.root / "results/run-retained", plan.fixture_profiles, plan.root
            )
            self.assertEqual(manager.reconcile(), [lease["lease_id"]])
            released = json.loads(
                (
                    plan.root
                    / "results/run-retained/leases"
                    / f"{lease['lease_id']}.json"
                ).read_text()
            )
            self.assertEqual(released["state"], "RELEASED")

    def test_script_execution_schema_rejects_escape_and_bad_args(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            index_path = plan_path / "index.json"
            index = json.loads(index_path.read_text())
            case = index["chapters"][0]["sections"][0]["cases"][0]
            case["execution"] = {"entrypoint": "../../escape", "args": "bad"}
            index_path.write_text(json.dumps(index))
            with self.assertRaises(render.ReportError):
                render.load_plan(plan_path)

    def test_script_timeout_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            self.add_script_executor(
                plan_path,
                "import time\nprint('started', flush=True)\ntime.sleep(30)\n",
                timeout_seconds=1,
            )
            plan = render.load_plan(plan_path)
            with self.assertRaisesRegex(dstack_test.DstackTestError, "valid result"):
                dstack_test.run_case(
                    plan,
                    plan.cases[0],
                    "run-timeout",
                    "codex",
                    None,
                    plan_path,
                    "",
                    [],
                    False,
                )
            result_dir = render.case_result_dir(plan, "run-timeout", plan.cases[0])
            runner = json.loads((result_dir / "runner.json").read_text())
            execution = json.loads((result_dir / "execution.json").read_text())
            self.assertTrue(runner["timed_out"])
            self.assertEqual(execution["state"], "INCOMPLETE")

    def test_unavailable_fixture_finishes_as_blocked_without_executor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            fixtures_dir = plan_path / "fixtures"
            fixtures_dir.mkdir()
            (fixtures_dir / "profiles.json").write_text(
                json.dumps({"profiles": {"hardware": {"provider": "hardware-pool"}}})
            )
            index_path = plan_path / "index.json"
            index = json.loads(index_path.read_text())
            case_value = index["chapters"][0]["sections"][0]["cases"][0]
            case_value["fixture"] = {"profile": "hardware"}
            case_value["actions_under_test"] = ["hardware quote"]
            index_path.write_text(json.dumps(index))
            plan = render.load_plan(plan_path)
            value = dstack_test.run_case(
                plan,
                plan.cases[0],
                "run-blocked",
                "missing-agent",
                None,
                plan_path,
                "",
                [],
                False,
            )
            self.assertEqual(value["status"], "BLOCKED")
            result = json.loads(
                (
                    render.case_result_dir(plan, "run-blocked", plan.cases[0])
                    / "result.json"
                ).read_text()
            )
            self.assertIn("DSTACK_TEST_PROVIDER_HARDWARE_POOL", result["summary"])

    def test_evidence_jsonl_and_attachment_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            plan = render.load_plan(plan_path)
            case = plan.cases[0]
            result_dir = render.case_result_dir(plan, "run-demo", case)
            result = dstack_test.validate_summary(case, result_dir / "result.json")

            evidence = dstack_test.materialize_evidence(case, result_dir, result)

            self.assertTrue(any(item["kind"] == "pass" for item in evidence))
            attachment = next(item for item in evidence if item["kind"] == "attachment")
            self.assertEqual(attachment["path"], "artifacts/backend-capture.json")
            lines = (result_dir / "evidence.jsonl").read_text().splitlines()
            self.assertEqual(len(lines), len(evidence))
            (result_dir / "evidence.jsonl").unlink()
            case_value = dstack_test.dashboard_case(plan, "run-demo", case.id)
            self.assertEqual(case_value["result"]["status"], "PASS")
            self.assertEqual(len(case_value["evidence"]), len(evidence))
            self.assertTrue((result_dir / "evidence.jsonl").is_file())
            data, media_type, name = dstack_test.dashboard_attachment(
                plan, "run-demo", case.id, attachment["path"]
            )
            self.assertGreater(len(data), 0)
            self.assertEqual(media_type, "application/json")
            self.assertEqual(name, "backend-capture.json")

    def test_dashboard_streams_live_steps_evidence_and_attachments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            plan = render.load_plan(plan_path)
            case = plan.cases[0]
            result_dir = render.case_result_dir(plan, "run-live", case)
            artifacts = result_dir / "artifacts"
            artifacts.mkdir(parents=True)
            dstack_test.atomic_json(
                result_dir / "execution.json",
                {"state": "RUNNING", "case_id": case.id},
            )
            (result_dir / "session.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "type": "item.completed",
                                "item": {
                                    "type": "agent_message",
                                    "text": f"{case.id}-step-01 START",
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "item.completed",
                                "item": {
                                    "type": "agent_message",
                                    "text": f"EVIDENCE {case.id}-step-01 - Proves the command output is streamed live.",
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "item.completed",
                                "item": {
                                    "id": "cmd-1",
                                    "type": "command_execution",
                                    "command": "printf live",
                                    "aggregated_output": "live",
                                    "exit_code": 0,
                                },
                            }
                        ),
                    ]
                )
                + "\n"
            )
            (artifacts / "live.txt").write_text("attachment")
            dstack_test.atomic_json(
                artifacts / "manifest.json",
                {
                    "artifacts": [
                        {
                            "path": "artifacts/live.txt",
                            "step_id": f"{case.id}-step-01",
                            "name": "Live proof",
                            "description": "Proves the live attachment contract.",
                        }
                    ]
                },
            )

            value = dstack_test.dashboard_case(plan, "run-live", case.id)

            self.assertEqual(value["result"]["status"], "RUNNING")
            self.assertEqual(value["result"]["steps"][0]["status"], "RUNNING")
            self.assertTrue(
                any(item["kind"] == "command" for item in value["evidence"])
            )
            command = next(
                item for item in value["evidence"] if item["kind"] == "command"
            )
            self.assertEqual(command["step_id"], f"{case.id}-step-01")
            self.assertEqual(
                command["description"], "Proves the command output is streamed live."
            )
            attachment = next(
                item for item in value["evidence"] if item["kind"] == "attachment"
            )
            self.assertEqual(attachment["path"], "artifacts/live.txt")
            self.assertEqual(attachment["step_id"], f"{case.id}-step-01")
            self.assertEqual(attachment["summary"], "Live proof")
            self.assertIn("attachment contract", attachment["description"])
            data, media_type, name = dstack_test.dashboard_attachment(
                plan, "run-live", case.id, "artifacts/live.txt"
            )
            self.assertEqual(data, b"attachment")
            self.assertEqual(name, "live.txt")

    def test_finalize_rebuilds_run_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            (plan_path / "results/run-demo/run.json").unlink()
            (plan_path / "results/run-demo/SHA256SUMS").unlink()
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
                / "results/run-demo/cases/01-gateway/01-proxy-protocol/tc-gw-pp-001/session.jsonl"
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
                plan
                / "results/run-fake/cases/01-gateway/01-proxy-protocol/tc-gw-pp-001"
            )
            self.assertEqual(
                json.loads((result_dir / "result.json").read_text())["status"], "PASS"
            )
            runner = json.loads((result_dir / "runner.json").read_text())
            self.assertEqual(runner["agent"]["model"], "fake-model")
            self.assertTrue((result_dir / "session.jsonl").is_file())

    def test_valid_result_survives_nonzero_agent_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.copy_fixture(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake = fake_bin / "codex"
            fake.write_text(
                """#!/usr/bin/env python3
import json, pathlib, re, sys
match=re.search(r'atomically write the summary to ([^\\n]+/result\\.json)',sys.argv[-1])
path=pathlib.Path(match.group(1).strip())
result={'schema_version':'1.0','case_id':'tc-gw-pp-001','status':'FAIL','summary':'observed mismatch','steps':[{'id':'tc-gw-pp-001-step-01','status':'FAIL','observed':'mismatch'},{'id':'tc-gw-pp-001-step-02','status':'NOT_RUN','observed':'not run'}],'artifacts':[],'remarks':''}
path.write_text(json.dumps(result))
print(json.dumps({'type':'thread.started','model':'fake-model'}))
raise SystemExit(1)
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
                    "--plan",
                    str(plan),
                    "--case",
                    "tc-gw-pp-001",
                    "--run-id",
                    "run-nonzero",
                    "--workdir",
                    str(root),
                ],
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result_dir = (
                plan
                / "results/run-nonzero/cases/01-gateway/01-proxy-protocol/tc-gw-pp-001"
            )
            self.assertEqual(
                json.loads((result_dir / "result.json").read_text())["status"], "FAIL"
            )
            self.assertEqual(
                json.loads((result_dir / "runner.json").read_text())["exit_code"], 1
            )

    def test_provisional_result_is_not_accepted_as_completed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = self.copy_fixture(Path(temporary))
            plan = render.load_plan(plan_path)
            case = plan.cases[0]
            result_path = render.case_result_dir(plan, "run-demo", case) / "result.json"
            result = json.loads(result_path.read_text())
            result["remarks"] = "Provisional result; diagnostics remain in progress."
            result["provisional"] = False
            result_path.write_text(json.dumps(result))
            self.assertEqual(
                dstack_test.validate_summary(case, result_path)["status"], "PASS"
            )
            result["remarks"] = "最终结果；已删除用例级临时目录。"
            result["summary"] = "final result"
            result["provisional"] = False
            result_path.write_text(json.dumps(result, ensure_ascii=False))
            self.assertEqual(
                dstack_test.validate_summary(case, result_path)["status"], "PASS"
            )
            result["remarks"] = "临时结果：根因尚在调查。"
            result["provisional"] = True
            result_path.write_text(json.dumps(result, ensure_ascii=False))
            with self.assertRaisesRegex(
                dstack_test.DstackTestError, "provisional result"
            ):
                dstack_test.validate_summary(case, result_path)

    def test_serve_controller_runs_selected_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan_path = self.copy_fixture(root)
            plan = render.load_plan(plan_path)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake = fake_bin / "codex"
            fake.write_text(
                """#!/usr/bin/env python3
import json, pathlib, re, sys
match=re.search(r'atomically write the summary to ([^\\n]+/result\\.json)',sys.argv[-1])
path=pathlib.Path(match.group(1).strip())
result={'schema_version':'1.0','case_id':'tc-gw-pp-001','status':'PASS','summary':'controlled pass','steps':[{'id':'tc-gw-pp-001-step-01','status':'PASS','observed':'ok'},{'id':'tc-gw-pp-001-step-02','status':'PASS','observed':'ok'}],'artifacts':[],'remarks':''}
path.write_text(json.dumps(result))
print(json.dumps({'type':'thread.started','model':'fake-model'}))
""",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            args = SimpleNamespace(
                run_id="run-controlled",
                agent="codex",
                model=None,
                workdir=root,
                agent_arg=[],
                prompt=[],
                prompt_file=None,
            )
            controller = dstack_test.ServeController(plan, args)
            env = os.environ.copy()
            env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
            with mock.patch.dict(os.environ, env, clear=True):
                value = controller.start(
                    {
                        "case_ids": ["tc-gw-pp-001"],
                        "prompt": "controlled",
                        "investigate_failures": True,
                    }
                )
                self.assertTrue(value["enabled"])
                assert controller.worker is not None
                controller.worker.join(timeout=10)
            self.assertFalse(controller.worker.is_alive())
            result_dir = (
                plan_path
                / "results/run-controlled/cases/01-gateway/01-proxy-protocol/tc-gw-pp-001"
            )
            self.assertEqual(
                json.loads((result_dir / "result.json").read_text())["status"], "PASS"
            )
            self.assertTrue((result_dir / "evidence.jsonl").is_file())
            events = (
                plan_path / "results/run-controlled/serve-control.jsonl"
            ).read_text()
            self.assertIn("case.started", events)
            self.assertIn("case.finished", events)

    def test_serve_controller_stops_current_case_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan_path = self.copy_fixture(root)
            plan = render.load_plan(plan_path)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake = fake_bin / "codex"
            fake.write_text(
                """#!/usr/bin/env python3
import json, time
print(json.dumps({'type':'thread.started','model':'fake-model'}), flush=True)
time.sleep(60)
""",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            args = SimpleNamespace(
                run_id="run-stopped",
                agent="codex",
                model=None,
                workdir=root,
                agent_arg=[],
                prompt=[],
                prompt_file=None,
            )
            controller = dstack_test.ServeController(plan, args)
            env = os.environ.copy()
            env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
            with mock.patch.dict(os.environ, env, clear=True):
                controller.start({"case_ids": ["tc-gw-pp-001"]})
                deadline = time.monotonic() + 5
                while controller.process is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertIsNotNone(controller.process)
                dstack_test.atomic_json(
                    plan_path / "results/run-stopped/run.json", {"status": "PASS"}
                )
                restarted = dstack_test.dashboard_state(
                    plan, "run-stopped", controller.status()
                )
                self.assertEqual(restarted["orchestrator_status"], "RUNNING")
                self.assertEqual(restarted["log_agent"], "case:tc-gw-pp-001")
                controller.stop()
                assert controller.worker is not None
                controller.worker.join(timeout=10)
            self.assertFalse(controller.worker.is_alive())
            execution = json.loads(
                (
                    plan_path
                    / "results/run-stopped/cases/01-gateway/01-proxy-protocol/tc-gw-pp-001/execution.json"
                ).read_text()
            )
            self.assertEqual(execution["state"], "TERMINATED")
            # A new explicit UI start is a new round and may retry the case
            # without enabling overwrite; the interrupted attempt is archived.
            with mock.patch.dict(os.environ, env, clear=True):
                controller.start({"case_ids": ["tc-gw-pp-001"]})
                deadline = time.monotonic() + 5
                while controller.process is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertIsNotNone(controller.process)
                restarted = dstack_test.dashboard_state(
                    plan, "run-stopped", controller.status()
                )
                self.assertEqual(restarted["orchestrator_status"], "RUNNING")
                self.assertEqual(restarted["log_agent"], "case:tc-gw-pp-001")
                controller.stop()
                assert controller.worker is not None
                controller.worker.join(timeout=10)
            self.assertFalse(controller.worker.is_alive())
            attempts = (
                plan_path
                / "results/run-stopped/attempts/01-gateway/01-proxy-protocol/tc-gw-pp-001"
            )
            self.assertTrue(any(attempts.iterdir()))

    def test_serve_controller_stops_external_run_plan_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan_path = self.copy_fixture(root)
            plan = render.load_plan(plan_path)
            case = plan.cases[0]
            result_dir = render.case_result_dir(plan, "run-external", case)
            result_dir.mkdir(parents=True)
            process = subprocess.Popen(["sleep", "60"], start_new_session=True)
            try:
                dstack_test.atomic_json(
                    result_dir / "execution.json",
                    {
                        "state": "RUNNING",
                        "case_id": case.id,
                        "agent_pid": process.pid,
                        "agent_pgid": process.pid,
                        "agent_start_ticks": dstack_test.process_start_ticks(
                            process.pid
                        ),
                    },
                )
                args = SimpleNamespace(
                    run_id="run-external",
                    agent="codex",
                    model=None,
                    workdir=root,
                    agent_arg=[],
                    prompt=[],
                    prompt_file=None,
                )
                controller = dstack_test.ServeController(plan, args)
                self.assertTrue(controller.status()["running"])
                self.assertEqual(controller.status()["current_case"], case.id)
                controller.stop()
                process.wait(timeout=5)
                self.assertTrue((result_dir / ".stop-requested").is_file())
                self.assertEqual(
                    json.loads((result_dir / "execution.json").read_text())["state"],
                    "TERMINATED",
                )
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)

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
