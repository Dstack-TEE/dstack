#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Lift a passing agent attempt into a deterministic replay spec.

An agent that drove a case to PASS recorded the operations it ran into the
case artifacts: subprocess argv with return codes, and pRPC calls with status
codes and response bodies.  Those recordings are reproducible evidence that was
being thrown away; every re-verification paid for a fresh agent session instead.

This tool reads a passing result directory, extracts the operations in step
order, replaces the lease-specific literals (workspace paths, allocated ports,
the candidate repository) with templates, and writes a spec that
`replay-case.py` can execute against a fresh lease.

Only operations the tool can fully template are emitted.  A recording that
still contains an un-templated absolute path or a generated identifier is
reported as unminable rather than turned into a harness that would pass once
and fail on the next lease.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import tempfile
from typing import Any

# A body is only pinned when it carries nothing that legitimately varies
# between leases; otherwise the harness would fail on a timestamp or a
# generated VM ID rather than on a product change.
VOLATILE_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # uuid
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}"  # timestamp
    r"|[0-9a-f]{32,}"  # digest
)
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON so a reader never observes a partial document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", dir=path.parent, delete=False, encoding="utf-8"
    ) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = handle.name
    os.replace(temporary, path)


def build_templates(
    manifest: dict[str, Any], runtime: dict[str, Any], plan_root: str = ""
) -> list[tuple[str, str]]:
    """Longest-first literal-to-template pairs for this recorded lease."""
    pairs: list[tuple[str, str]] = []
    if plan_root:
        pairs.append((plan_root, "${plan_root}"))
    substrate = (manifest.get("values") or {}).get("component_substrate") or {}
    for key in ("config_dir", "data_dir", "log_dir", "run_dir", "workspace"):
        if isinstance(substrate.get(key), str) and substrate[key]:
            pairs.append((substrate[key], f"${{{key}}}"))
    repository = runtime.get("repository")
    if isinstance(repository, str) and repository:
        pairs.append((repository, "${repository}"))
    if sys.executable:
        pairs.append((sys.executable, "${python}"))
    for name, port in (substrate.get("ports") or {}).items():
        pairs.append((f":{port}", f":${{ports.{name}}}"))
    # Replace the longest literal first so a workspace prefix does not shadow
    # the config directory nested inside it.
    pairs.sort(key=lambda pair: len(pair[0]), reverse=True)
    return pairs


def templatize(value: str, pairs: list[tuple[str, str]]) -> str:
    """Replace every known lease literal with its template name."""
    for literal, template in pairs:
        if literal:
            value = value.replace(literal, template)
    return value


# vmm-create-stopped.py takes the VM creation command from the fixture
# manifest and accepts only bounded overrides on the command line. Earlier
# attempts passed the whole wrapped command as arguments; replaying that
# verbatim makes argparse reject it as unrecognized. Keep the overrides that
# express test intent, and drop the wrapped command along with the
# lease-specific values the fixture already supplies.
HELPER_VALUE_OPTIONS = frozenset(
    {"--vcpu", "--memory", "--disk-size", "--simulated-tee"}
)
HELPER_FLAG_OPTIONS = frozenset({"--hugepages", "--pin-numa", "--stopped", "--no-tee"})


def normalize_helper(argv: list[str]) -> list[str]:
    """Reduce a recorded plan-helper call to its current supported interface."""
    for index, part in enumerate(argv):
        if not part.endswith("/vmm-create-stopped.py"):
            continue
        kept: list[str] = []
        rest = argv[index + 1 :]
        position = 0
        while position < len(rest):
            token = rest[position]
            if token in HELPER_FLAG_OPTIONS:
                kept.append(token)
                position += 1
            elif token in HELPER_VALUE_OPTIONS and position + 1 < len(rest):
                kept += [token, rest[position + 1]]
                position += 2
            else:
                position += 1
        return [*argv[: index + 1], *kept]
    return argv


def is_portable(value: str, plan_root: str) -> bool:
    """Reject strings that still pin one lease or one run."""
    if UUID_RE.search(value):
        return False
    for marker in ("/tmp/dstack-test-", "lease-", "/home/"):
        if marker in value and plan_root not in value:
            return False
    return True


def collect_operations(node: Any, out: list[dict[str, Any]]) -> None:
    """Walk an artifact document and gather every recorded operation."""
    if isinstance(node, dict):
        if isinstance(node.get("argv"), list) and all(
            isinstance(part, str) for part in node["argv"]
        ):
            out.append({"_kind": "argv", "_node": node})
        elif isinstance(node.get("command"), list) and all(
            isinstance(part, str) for part in node["command"]
        ):
            out.append({"_kind": "command", "_node": node})
        elif "status" in node and "body_text" in node:
            out.append({"_kind": "http", "_node": node})
        for key, value in node.items():
            if key not in ("argv", "command"):
                collect_operations(value, out)
    elif isinstance(node, list):
        for value in node:
            collect_operations(value, out)


def mine_case(
    case_dir: pathlib.Path,
    plan_root: pathlib.Path,
    run_id: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Build a replay spec for one passing case, or explain why it cannot be."""
    problems: list[str] = []
    result = json.loads((case_dir / "result.json").read_text(encoding="utf-8"))
    if result.get("status") != "PASS":
        return None, [f"source status is {result.get('status')}, not PASS"]
    case_id = result["case_id"]
    manifest_path = case_dir / "fixture" / "runtime-manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    runtime = {}
    run_manifest = plan_root / "results" / run_id / "runtime-manifest.json"
    if run_manifest.is_file():
        runtime = json.loads(run_manifest.read_text())
    pairs = build_templates(manifest, runtime, str(plan_root))

    # Artifacts are named per step; keep the recorded order so the replay
    # reproduces the sequence the agent actually performed.
    step_ops: dict[str, list[dict[str, Any]]] = {}
    for artifact in sorted((case_dir / "artifacts").glob("*.json")):
        if artifact.name == "manifest.json":
            continue
        try:
            document = json.loads(artifact.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            problems.append(f"unreadable artifact {artifact.name}")
            continue
        raw: list[dict[str, Any]] = []
        collect_operations(document, raw)
        if not raw:
            continue
        step_id = None
        for step in result.get("steps", []):
            token = step["id"].rsplit("-", 1)[-1]
            if f"step{token}" in artifact.name or step["id"] in artifact.name:
                step_id = step["id"]
                break
        step_id = step_id or result["steps"][0]["id"]
        step_ops.setdefault(step_id, []).extend(raw)

    if not step_ops:
        return None, ["no replayable operation was recorded"]

    # An operation the miner cannot template is coverage the replay would not
    # perform. Emitting the spec anyway would promote a harness that tests less
    # than the attempt it claims to reproduce, while still reporting PASS.
    dropped: list[str] = []
    steps: list[dict[str, Any]] = []
    for step in result.get("steps", []):
        raw = step_ops.get(step["id"])
        if not raw:
            continue
        operations: list[dict[str, Any]] = []
        for item in raw:
            node = item["_node"]
            if item["_kind"] in ("argv", "command"):
                key = "argv" if item["_kind"] == "argv" else "command"
                argv = normalize_helper([templatize(part, pairs) for part in node[key]])
                if not all(is_portable(part, str(plan_root)) for part in argv):
                    dropped.append(f"{step['id']}: argv still pins one lease")
                    continue
                operation: dict[str, Any] = {
                    "kind": "argv",
                    "label": str(node.get("label", key)),
                    "argv": argv,
                    "expect": {},
                }
                if isinstance(node.get("returncode"), int):
                    operation["expect"]["returncode"] = node["returncode"]
                operations.append(operation)
            else:
                url = node.get("url") or node.get("route") or ""
                if not url:
                    dropped.append(
                        f"{step['id']}: response recorded without its target"
                    )
                    continue
                url = templatize(str(url), pairs)
                if not url.startswith(("http://", "https://")):
                    # A relative route does not say which listener served it,
                    # and guessing a base URL would silently point the replay
                    # at the wrong component.
                    dropped.append(
                        f"{step['id']}: {url} is relative to an unknown host"
                    )
                    continue
                if not is_portable(url, str(plan_root)):
                    dropped.append(f"{step['id']}: request URL still pins one lease")
                    continue
                operation = {
                    "kind": "http",
                    "label": str(node.get("label", "call")),
                    "url": url,
                    "content_type": str(node.get("content_type", "application/json")),
                    "body": templatize(str(node.get("request_body", "")), pairs),
                    "expect": {"status": int(node["status"])},
                }
                body_text = node.get("body_text")
                if isinstance(body_text, str) and not VOLATILE_RE.search(body_text):
                    operation["expect"]["body_text"] = body_text
                operations.append(operation)
        if not operations:
            continue
        steps.append(
            {
                "id": step["id"],
                "observed": step["observed"],
                "evidence": f"Replays the operations that produced: {step['observed']}",
                "ops": operations,
            }
        )
    if dropped:
        return None, problems + dropped
    if not steps:
        return None, problems or ["every recorded operation was lease-specific"]
    spec = {
        "schema_version": "1.0",
        "case_id": case_id,
        "source_run": run_id,
        "summary": result.get("summary", "Mined replay of a recorded passing attempt."),
        "remarks": result.get("remarks", ""),
        "steps": steps,
    }
    return spec, problems


def main() -> int:
    """Mine one or more passing cases into replay specs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=pathlib.Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--case", action="append", default=None)
    parser.add_argument("--all", action="store_true", help="mine every passing case")
    parser.add_argument("--write", action="store_true", help="persist the specs")
    args = parser.parse_args()

    plan_root = args.plan.resolve()
    run_dir = plan_root / "results" / args.run_id
    wanted = set(args.case or [])
    report: dict[str, Any] = {"mined": [], "unminable": {}}
    for result_path in sorted(run_dir.glob("cases/*/*/*/result.json")):
        case_dir = result_path.parent
        case_id = case_dir.name
        if wanted and case_id not in wanted:
            continue
        if not wanted and not args.all:
            continue
        try:
            spec, problems = mine_case(case_dir, plan_root, args.run_id)
        except (OSError, KeyError, json.JSONDecodeError) as error:
            report["unminable"][case_id] = [f"{type(error).__name__}: {error}"]
            continue
        if spec is None:
            report["unminable"][case_id] = problems
            continue
        report["mined"].append(
            {"case_id": case_id, "steps": len(spec["steps"]), "warnings": problems}
        )
        if args.write:
            atomic_json(
                plan_root / "shared" / "automation" / "replay" / f"{case_id}.json",
                spec,
            )
    report["mined_count"] = len(report["mined"])
    report["unminable_count"] = len(report["unminable"])
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
