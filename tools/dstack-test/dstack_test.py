#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D100, D101, D102, D103
"""Run, validate, package, and render dstack test plans."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import render

TERMINAL_STATUS = ("PASS", "FAIL", "BLOCKED", "NOT_RUN", "SKIPPED")


class DstackTestError(Exception):
    """A user-facing dstack-test error."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")
        temporary = Path(output.name)
    temporary.replace(path)


def find_case(plan: render.Plan, value: str) -> render.CaseEntry:
    candidate = Path(value).resolve()
    matches = [
        case for case in plan.cases if case.id == value or case.path == candidate
    ]
    if len(matches) != 1:
        raise DstackTestError(
            f"expected one indexed case for {value!r}, found {len(matches)}"
        )
    return matches[0]


def validate_summary(case: render.CaseEntry, path: Path) -> dict[str, Any]:
    result = render.load_json(path)
    if result.get("case_id") != case.id:
        raise DstackTestError(f"result case_id must be {case.id!r}: {path}")
    status = result.get("status")
    if status not in TERMINAL_STATUS:
        raise DstackTestError(f"invalid result status {status!r}: {path}")
    if not isinstance(result.get("summary"), str) or not result["summary"].strip():
        raise DstackTestError(f"result summary must be non-empty: {path}")
    steps = result.get("steps", [])
    if not isinstance(steps, list):
        raise DstackTestError(f"result steps must be an array: {path}")
    seen: set[str] = set()
    for step in steps:
        if not isinstance(step, dict):
            raise DstackTestError(f"invalid step in {path}")
        step_id = step.get("id")
        if not isinstance(step_id, str) or not step_id.startswith(case.id + "-step-"):
            raise DstackTestError(f"invalid step ID {step_id!r} in {path}")
        if step_id in seen:
            raise DstackTestError(f"duplicate step ID {step_id!r} in {path}")
        seen.add(step_id)
        if step.get("status") not in TERMINAL_STATUS:
            raise DstackTestError(f"invalid status for {step_id} in {path}")
        if not isinstance(step.get("observed"), str) or not step["observed"].strip():
            raise DstackTestError(f"missing observed summary for {step_id} in {path}")
    if status == "PASS" and (
        not steps or any(step["status"] != "PASS" for step in steps)
    ):
        raise DstackTestError(
            f"PASS result requires one or more all-PASS steps: {path}"
        )
    artifacts = result.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise DstackTestError(f"artifacts must be an array: {path}")
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not artifact.get("path"):
            raise DstackTestError(f"invalid artifact in {path}")
        artifact_path = render.safe_path(
            path.parent, artifact["path"], "result artifact"
        )
        try:
            artifact_path.relative_to(path.parent.resolve())
        except ValueError as error:
            raise DstackTestError(
                f"artifact escapes result directory: {artifact_path}"
            ) from error
        if not artifact_path.is_file():
            raise DstackTestError(f"missing result artifact: {artifact_path}")
    return result


def validate_session(path: Path) -> tuple[int, str | None]:
    if not path.is_file() or path.stat().st_size == 0:
        raise DstackTestError(f"missing or empty agent session: {path}")
    count = 0
    model: str | None = None
    with path.open(encoding="utf-8") as source:
        for line_no, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise DstackTestError(
                    f"invalid session JSONL at {path}:{line_no}: {error}"
                ) from error
            if not isinstance(event, dict):
                raise DstackTestError(
                    f"session event is not an object at {path}:{line_no}"
                )
            count += 1
            model = model or extract_model(event)
    if count == 0:
        raise DstackTestError(f"agent session contains no events: {path}")
    return count, model


def extract_model(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("model", "model_name"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
        for item in value.values():
            if found := extract_model(item):
                return found
    elif isinstance(value, list):
        for item in value:
            if found := extract_model(item):
                return found
    return None


def result_schema_text(case_id: str) -> str:
    return f'''{{
  "schema_version": "1.0",
  "case_id": "{case_id}",
  "status": "PASS|FAIL|BLOCKED|NOT_RUN|SKIPPED",
  "summary": "简短总结",
  "steps": [
    {{"id": "{case_id}-step-01", "status": "PASS|FAIL|BLOCKED|NOT_RUN|SKIPPED", "observed": "实际观察总结"}}
  ],
  "artifacts": [{{"name": "附件名称", "path": "artifacts/相对路径"}}],
  "remarks": ""
}}'''


def build_prompt(
    plan: render.Plan, case: render.CaseEntry, result_dir: Path, user_prompt: str
) -> str:
    return f"""你正在执行一个dstack规范测试用例。

测试计划说明：{plan.guide_path}
测试用例：{case.spec_path}
执行结果目录：{result_dir}
完整会话由外部runner自动保存，你不需要手工复制命令输出。

执行规则：
1. 先阅读测试计划说明，再阅读case.md。
2. 不得修改测试计划、index.json、case.md、fixtures或测试脚本。
3. 只能把测试产物写到本次结果目录或说明书明确允许的临时目录。
4. 严格按case.md逐步执行；每一步开始和结束时，在回复中包含对应step ID，方便会话索引。
5. 实际命令必须通过工具执行，不得用推测或总结代替执行。
6. 只要实际结果没有完全满足预期，该步骤和用例就是FAIL。
7. 前置环境阻止被测行为开始时为BLOCKED；不得使用PARTIAL。
8. 不得把模拟结果当作真实硬件结果。
9. 不得把token、私钥、密钥材料或其他secret输出到会话或附件。
10. 截图、日志和其他附件写入{result_dir / "artifacts"}。
11. 结束前把总结原子写入{result_dir / "result.json"}，不得写到其他位置。
12. result.json必须是以下浅层结构，不要嵌入命令输出：
{result_schema_text(case.id)}
13. 最终回复必须说明用例状态和result.json路径。

调用方附加要求：
{user_prompt.strip() or "无"}
"""


def agent_command(
    agent: str, model: str | None, workdir: Path, prompt: str, extra: list[str]
) -> list[str]:
    if agent == "codex":
        command = ["codex", "exec", "--json", "--color", "never", "-C", str(workdir)]
        if model:
            command += ["--model", model]
        command += extra
        command += [prompt]
        return command
    if agent == "claude":
        command = ["claude", "--print", "--verbose", "--output-format", "stream-json"]
        if model:
            command += ["--model", model]
        command += extra
        command += [prompt]
        return command
    raise DstackTestError(f"unsupported agent: {agent}")


def run_case(
    plan: render.Plan,
    case: render.CaseEntry,
    run_id: str,
    agent: str,
    model: str | None,
    workdir: Path,
    prompt: str,
    extra: list[str],
    overwrite: bool,
) -> dict[str, Any]:
    result_dir = case.path / "results" / run_id
    if result_dir.exists() and any(result_dir.iterdir()) and not overwrite:
        raise DstackTestError(
            f"result directory is not empty; pass --overwrite to replace it: {result_dir}"
        )
    if overwrite and result_dir.exists():
        shutil.rmtree(result_dir)
    (result_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    full_prompt = build_prompt(plan, case, result_dir, prompt)
    (result_dir / "prompt.md").write_text(full_prompt, encoding="utf-8")
    session_path = result_dir / "session.jsonl"
    stderr_path = result_dir / "agent-stderr.log"
    started_at = utc_now()
    start = time.monotonic_ns()
    command = agent_command(agent, model, workdir, full_prompt, extra)
    binary = shutil.which(command[0])
    if not binary:
        raise DstackTestError(f"agent CLI not found: {command[0]}")
    with session_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        completed = subprocess.run(
            command, cwd=workdir, stdout=stdout, stderr=stderr, check=False
        )
    duration_ms = (time.monotonic_ns() - start) // 1_000_000
    finished_at = utc_now()
    event_count, detected_model = validate_session(session_path)
    result_path = result_dir / "result.json"
    result_valid = False
    result_error = None
    try:
        result = validate_summary(case, result_path)
        result_valid = True
    except (DstackTestError, render.ReportError) as error:
        result = None
        result_error = str(error)
    runner = {
        "schema_version": "1.0",
        "run_id": run_id,
        "case_id": case.id,
        "agent": {"type": agent, "model": detected_model or model or "unknown"},
        "session": {
            "format": f"{agent}-jsonl",
            "path": "session.jsonl",
            "events": event_count,
        },
        "prompt_path": "prompt.md",
        "result_path": "result.json",
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": duration_ms,
        "exit_code": completed.returncode,
        "result_valid": result_valid,
        "result_error": result_error,
    }
    atomic_json(result_dir / "runner.json", runner)
    write_sha256s(result_dir)
    if completed.returncode != 0:
        raise DstackTestError(
            f"{agent} exited with {completed.returncode}; session preserved at {session_path}"
        )
    if not result_valid:
        raise DstackTestError(
            f"agent completed without a valid result.json: {result_error}"
        )
    return {"case": case.id, "status": result["status"], "result_dir": str(result_dir)}


def write_sha256s(root: Path) -> None:
    entries: list[str] = []
    for path in sorted(
        p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS"
    ):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text(
        "\n".join(entries) + ("\n" if entries else ""), encoding="utf-8"
    )


def verify_sha256s(root: Path) -> None:
    sums = root / "SHA256SUMS"
    if not sums.is_file():
        raise DstackTestError(f"missing SHA256SUMS: {sums}")
    expected_files: set[Path] = set()
    for line_no, line in enumerate(sums.read_text(encoding="utf-8").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise DstackTestError(f"invalid SHA256SUMS line at {sums}:{line_no}")
        path = render.safe_path(root, match.group(2), "SHA256SUMS")
        try:
            path.relative_to(root.resolve())
        except ValueError as error:
            raise DstackTestError(
                f"SHA256SUMS path escapes result directory: {path}"
            ) from error
        if not path.is_file():
            raise DstackTestError(f"SHA256SUMS references missing file: {path}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != match.group(1):
            raise DstackTestError(f"SHA-256 mismatch: {path}")
        expected_files.add(path)
    actual_files = {
        path.resolve()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if expected_files != actual_files:
        missing = sorted(
            str(path.relative_to(root)) for path in actual_files - expected_files
        )
        raise DstackTestError(f"files missing from SHA256SUMS in {root}: {missing}")


def context_value(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    value = render.load_json(path)
    return value


def finalize_run(
    plan: render.Plan, run_id: str, context: dict[str, Any] | None = None
) -> dict[str, Any]:
    case_results: list[dict[str, Any]] = []
    by_status = {status: {"count": 0, "case_refs": []} for status in TERMINAL_STATUS}
    started: list[str] = []
    finished: list[str] = []
    executors: list[dict[str, Any]] = []
    incomplete = False
    for case in plan.cases:
        result_dir = case.path / "results" / run_id
        result_path = result_dir / "result.json"
        runner_path = result_dir / "runner.json"
        if not result_path.is_file() or not runner_path.is_file():
            incomplete = True
            continue
        result = validate_summary(case, result_path)
        runner = render.load_json(runner_path)
        validate_session(result_dir / "session.jsonl")
        status = result["status"]
        by_status[status]["count"] += 1
        by_status[status]["case_refs"].append(f"#result-{case.id}")
        case_results.append(
            {
                "id": case.id,
                "anchor": f"result-{case.id}",
                "status": status,
                "result_path": os.path.relpath(
                    result_path, plan.root / "results" / run_id
                ),
            }
        )
        if runner.get("started_at"):
            started.append(runner["started_at"])
        if runner.get("finished_at"):
            finished.append(runner["finished_at"])
        if runner.get("agent") and runner["agent"] not in executors:
            executors.append(runner["agent"])
    run_dir = plan.root / "results" / run_id
    total = len(plan.cases)
    run = {
        "schema_version": "1.0",
        "id": run_id,
        "anchor": run_id,
        "plan_id": plan.index["id"],
        "status": "INCOMPLETE"
        if incomplete or len(case_results) != total
        else "COMPLETED",
        "started_at": min(started) if started else None,
        "finished_at": max(finished) if finished else None,
        "executors": executors,
        "software_under_test": (context or {}).get("software_under_test", {}),
        "environment": (context or {}).get("environment", {}),
        "summary": {
            "total": total,
            "completed": len(case_results),
            "by_status": by_status,
        },
        "case_results": case_results,
    }
    atomic_json(run_dir / "run.json", run)
    if context:
        atomic_json(run_dir / "context.json", context)
    write_sha256s(run_dir)
    return run


def validate_run(plan: render.Plan, run_id: str) -> dict[str, Any]:
    run_path = plan.root / "results" / run_id / "run.json"
    run = render.load_json(run_path)
    if run.get("plan_id") != plan.index["id"] or run.get("id") != run_id:
        raise DstackTestError("run/plan ID mismatch")
    actual = {status: [] for status in TERMINAL_STATUS}
    for item in run.get("case_results", []):
        case = find_case(plan, str(item.get("id")))
        result_path = (run_path.parent / str(item.get("result_path", ""))).resolve()
        try:
            result_path.relative_to(plan.root)
        except ValueError as error:
            raise DstackTestError(
                f"case result escapes plan root: {result_path}"
            ) from error
        result = validate_summary(case, result_path)
        result_dir = result_path.parent
        validate_session(result_dir / "session.jsonl")
        runner = render.load_json(result_dir / "runner.json")
        if not runner.get("result_valid"):
            raise DstackTestError(f"runner marks invalid result for {case.id}")
        verify_sha256s(result_dir)
        actual[result["status"]].append(f"#result-{case.id}")
    summary = run.get("summary", {})
    if summary.get("total") != len(plan.cases):
        raise DstackTestError("summary total does not match plan")
    for status in TERMINAL_STATUS:
        item = summary.get("by_status", {}).get(status, {})
        if (
            item.get("count") != len(actual[status])
            or item.get("case_refs") != actual[status]
        ):
            raise DstackTestError(f"summary mismatch for {status}")
    verify_sha256s(run_path.parent)
    return {
        "status": "valid",
        "plan_id": plan.index["id"],
        "run_id": run_id,
        "cases": len(run.get("case_results", [])),
    }


def package_plan(plan: render.Plan, run_id: str, output: Path) -> None:
    validate_run(plan, run_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    files = []
    for path in sorted(item for item in plan.root.rglob("*") if item.is_file()):
        relative = path.relative_to(plan.root)
        parts = relative.parts
        # A package is one immutable execution report, not an archive of all
        # historical executions that happen to live beside the plan.
        if "results" in parts:
            index = parts.index("results")
            if len(parts) > index + 1 and parts[index + 1] != run_id:
                continue
        files.append((path, Path("plan") / relative))
    suffix = output.name.lower()
    if suffix.endswith(".tar.gz") or suffix.endswith(".tgz"):
        with tarfile.open(output, "w:gz") as archive:
            for path, archive_path in files:
                archive.add(path, arcname=archive_path, recursive=False)
    elif suffix.endswith(".tar"):
        with tarfile.open(output, "w") as archive:
            for path, archive_path in files:
                archive.add(path, arcname=archive_path, recursive=False)
    elif suffix.endswith(".zip"):
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path, archive_path in files:
                archive.write(path, archive_path)
    else:
        raise DstackTestError("package output must end in .tar.gz, .tgz, .tar, or .zip")


def add_common_plan(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plan", type=Path, required=True, help="test-plan directory")
    parser.add_argument("--run-id", required=True, help="shared run identifier")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dstack-test", description=__doc__)
    sub = parser.add_subparsers(dest="subcommand", required=True)
    run_case_parser = sub.add_parser(
        "run-case", help="run one indexed case in a fresh AI session"
    )
    add_common_plan(run_case_parser)
    run_case_parser.add_argument(
        "--case", required=True, help="case ID or indexed case directory"
    )
    run_case_parser.add_argument("--agent", choices=("codex", "claude"), required=True)
    run_case_parser.add_argument("--model")
    run_case_parser.add_argument("--workdir", type=Path, default=Path.cwd())
    run_case_parser.add_argument("--prompt-file", type=Path)
    run_case_parser.add_argument("--agent-arg", action="append", default=[])
    run_case_parser.add_argument("--overwrite", action="store_true")
    run_case_parser.add_argument("prompt", nargs=argparse.REMAINDER)

    run_plan = sub.add_parser(
        "run-plan", help="run every indexed case in its own AI session"
    )
    add_common_plan(run_plan)
    run_plan.add_argument("--agent", choices=("codex", "claude"), required=True)
    run_plan.add_argument("--model")
    run_plan.add_argument("--workdir", type=Path, default=Path.cwd())
    run_plan.add_argument("--prompt-file", type=Path)
    run_plan.add_argument(
        "--context",
        type=Path,
        help="run-level JSON with software_under_test/environment",
    )
    run_plan.add_argument("--agent-arg", action="append", default=[])
    run_plan.add_argument("--overwrite", action="store_true")
    run_plan.add_argument("prompt", nargs=argparse.REMAINDER)

    finalize = sub.add_parser("finalize", help="materialize run.json from case results")
    add_common_plan(finalize)
    finalize.add_argument("--context", type=Path)

    validate = sub.add_parser("validate", help="validate a finalized test run")
    add_common_plan(validate)

    package = sub.add_parser(
        "package", help="validate and package a test plan and its results"
    )
    add_common_plan(package)
    package.add_argument("--output", type=Path, required=True)

    render_parser = sub.add_parser(
        "render", help="render a validated run to one offline HTML file"
    )
    add_common_plan(render_parser)
    render_parser.add_argument("--output", type=Path, required=True)
    return parser


def prompt_text(args: argparse.Namespace) -> str:
    values = list(args.prompt)
    if values and values[0] == "--":
        values = values[1:]
    text = " ".join(values)
    if args.prompt_file:
        file_text = args.prompt_file.read_text(encoding="utf-8")
        text = f"{file_text}\n\n{text}" if text else file_text
    return text


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    plan = render.load_plan(args.plan)
    if args.subcommand == "run-case":
        value = run_case(
            plan,
            find_case(plan, args.case),
            args.run_id,
            args.agent,
            args.model,
            args.workdir.resolve(),
            prompt_text(args),
            args.agent_arg,
            args.overwrite,
        )
    elif args.subcommand == "run-plan":
        values = []
        for case in plan.cases:
            try:
                values.append(
                    run_case(
                        plan,
                        case,
                        args.run_id,
                        args.agent,
                        args.model,
                        args.workdir.resolve(),
                        prompt_text(args),
                        args.agent_arg,
                        args.overwrite,
                    )
                )
            except DstackTestError as error:
                values.append({"case": case.id, "runner_error": str(error)})
        run = finalize_run(plan, args.run_id, context_value(args.context))
        value = {"cases": values, "run": run}
    elif args.subcommand == "finalize":
        value = finalize_run(plan, args.run_id, context_value(args.context))
    elif args.subcommand == "validate":
        value = validate_run(plan, args.run_id)
    elif args.subcommand == "package":
        package_plan(plan, args.run_id, args.output)
        value = {
            "status": "packaged",
            "output": str(args.output),
            "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        }
    elif args.subcommand == "render":
        validate_run(plan, args.run_id)
        run, results = render.load_session_results(plan, args.run_id)
        rendered = render.render_report(plan, run, results)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        value = {
            "status": "rendered",
            "output": str(args.output),
            "bytes": args.output.stat().st_size,
        }
    else:
        raise AssertionError(args.subcommand)
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DstackTestError, render.ReportError) as error:
        print(
            json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False),
            file=sys.stderr,
        )
        raise SystemExit(2)
