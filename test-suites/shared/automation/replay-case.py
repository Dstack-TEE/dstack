#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Replay a mined operation log as a deterministic case harness.

A case that an agent drove to PASS recorded the exact operations it ran:
subprocess argv with return codes, and pRPC calls with status codes and bodies.
`mine-passing-attempt.py` lifts those operations into a replay spec with the
lease-specific literals templated out.  This harness resolves the templates
against the live fixture manifest and replays the operations, so the case is
reproducible without an agent.

The spec asserts only what a rerun can legitimately guarantee: the recorded
process return code, the recorded HTTP status, and a response body when the
miner proved it carries no volatile content.  Anything else is captured as
evidence rather than asserted, because pinning a timestamp or a generated VM ID
would produce a harness that fails for reasons unrelated to the product.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any

# Recorded request bodies are JSON and routinely contain braces, and some
# carry literal placeholder text such as {http_code}. Templates therefore use
# a ${...} sigil that no recorded payload has been observed to use.
TEMPLATE_RE = re.compile(r"\$\{([a-z_]+(?:\.[a-z0-9_]+)?)\}")


class ReplayMismatch(AssertionError):
    """A replayed operation diverged from what the passing attempt recorded.

    Carries the observation so the failing operation is preserved in the
    artifact rather than lost with the exception; a harness that reports only
    "returned 2, recorded 0" forces the next reader to reproduce it by hand.
    """

    def __init__(self, message: str, observed: dict[str, Any]) -> None:
        """Record the mismatch message alongside the observation."""
        super().__init__(message)
        self.observed = observed


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


def build_scope(manifest: dict[str, Any], runtime: dict[str, Any]) -> dict[str, str]:
    """Map template names to this lease's concrete values."""
    scope: dict[str, str] = {
        "python": sys.executable,
        "case_id": str(manifest.get("case_id", "")),
        "lease_id": str(manifest.get("lease_id", "")),
        "repository": str(runtime.get("repository", "")),
        "plan_root": os.environ.get("DSTACK_TEST_PLAN_DIR", ""),
        "result_dir": os.environ.get("DSTACK_TEST_RESULT_DIR", ""),
    }
    substrate = (manifest.get("values") or {}).get("component_substrate") or {}
    for key in ("workspace", "config_dir", "data_dir", "log_dir", "run_dir"):
        if isinstance(substrate.get(key), str):
            scope[key] = substrate[key]
    for name, port in (substrate.get("ports") or {}).items():
        scope[f"ports.{name}"] = str(port)
    services = (manifest.get("values") or {}).get("services") or {}
    for name, service in services.items():
        if isinstance(service, dict):
            for field in ("socket", "route", "url"):
                if isinstance(service.get(field), str):
                    scope[f"service.{name}_{field}"] = service[field]
    return scope


def resolve(value: str, scope: dict[str, str]) -> str:
    """Substitute ${name} placeholders, failing loudly on an unknown one."""

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in scope:
            raise KeyError(f"replay spec references unknown template ${{{name}}}")
        return scope[name]

    return TEMPLATE_RE.sub(replace, value)


def run_argv(operation: dict[str, Any], scope: dict[str, str]) -> dict[str, Any]:
    """Execute a recorded subprocess and compare its return code."""
    argv = [resolve(str(part), scope) for part in operation["argv"]]
    timeout = int(operation.get("timeout_seconds", 120))
    process = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        cwd=operation.get("cwd") and resolve(str(operation["cwd"]), scope) or None,
    )
    expected = operation.get("expect", {})
    observed = {
        "label": operation.get("label", ""),
        "argv": argv,
        "returncode": process.returncode,
        "stdout_sha256": hashlib.sha256(process.stdout.encode()).hexdigest(),
        "stderr_excerpt": process.stderr[-400:],
    }
    if "returncode" in expected and process.returncode != expected["returncode"]:
        raise ReplayMismatch(
            f"{operation.get('label', 'command')} returned "
            f"{process.returncode}, recorded {expected['returncode']}",
            observed,
        )
    if (
        "stdout_contains" in expected
        and expected["stdout_contains"] not in process.stdout
    ):
        raise ReplayMismatch(
            f"{operation.get('label', 'command')} stdout no longer contains "
            f"{expected['stdout_contains']!r}",
            observed,
        )
    return observed


def run_http(operation: dict[str, Any], scope: dict[str, str]) -> dict[str, Any]:
    """Issue a recorded pRPC call and compare status, then body when pinned."""
    url = resolve(str(operation["url"]), scope)
    body = resolve(str(operation.get("body", "")), scope).encode()
    request = urllib.request.Request(
        url,
        data=body,
        method=str(operation.get("method", "POST")),
        headers={"Content-Type": operation.get("content_type", "application/json")},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status, payload = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, payload = error.code, error.read()
    except urllib.error.URLError as error:
        raise AssertionError(
            f"{operation.get('label', 'call')} was unreachable: {error}"
        )
    expected = operation.get("expect", {})
    observed = {
        "label": operation.get("label", ""),
        "url": url,
        "status": status,
        "body_sha256": hashlib.sha256(payload).hexdigest(),
        "body_length": len(payload),
    }
    if "status" in expected and status != expected["status"]:
        raise ReplayMismatch(
            f"{operation.get('label', 'call')} returned HTTP {status}, "
            f"recorded HTTP {expected['status']}",
            observed,
        )
    if "body_text" in expected:
        actual = payload.decode("utf-8", errors="replace")
        if actual != expected["body_text"]:
            observed["body_excerpt"] = actual[:400]
            raise ReplayMismatch(
                f"{operation.get('label', 'call')} body changed; recorded "
                f"{expected['body_text']!r}, observed {actual[:120]!r}",
                observed,
            )
    return observed


def main() -> int:
    """Replay the mined spec for the case under test."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)

    spec_path = plan_root / "shared" / "automation" / "replay" / f"{case_id}.json"
    if not spec_path.is_file():
        raise SystemExit(f"no replay spec for {case_id}: {spec_path}")
    spec = json.loads(spec_path.read_text(encoding="utf-8"))

    manifest_path = os.environ.get("DSTACK_TEST_CASE_MANIFEST")
    manifest = (
        json.loads(pathlib.Path(manifest_path).read_text()) if manifest_path else {}
    )
    runtime_path = os.environ.get("DSTACK_TEST_RUNTIME_MANIFEST")
    runtime = json.loads(pathlib.Path(runtime_path).read_text()) if runtime_path else {}
    scope = build_scope(manifest, runtime)

    steps: list[dict[str, Any]] = []
    status = "PASS"
    failure: str | None = None
    log: dict[str, Any] = {"case_id": case_id, "source_run": spec.get("source_run")}

    for step in spec["steps"]:
        step_id = step["id"]
        if status != "PASS":
            steps.append(
                {
                    "id": step_id,
                    "status": "NOT_RUN",
                    "observed": "Not run after earlier failure.",
                }
            )
            continue
        print(f"STEP {step_id} START", flush=True)
        records: list[dict[str, Any]] = []
        try:
            for operation in step["ops"]:
                kind = operation["kind"]
                if kind == "argv":
                    records.append(run_argv(operation, scope))
                elif kind == "http":
                    records.append(run_http(operation, scope))
                else:
                    raise AssertionError(f"unsupported replay operation: {kind}")
        except Exception as error:  # noqa: BLE001 - recorded as a case failure
            status = "FAIL"
            failure = f"{type(error).__name__}: {error}"
            if isinstance(error, ReplayMismatch):
                records.append(error.observed)
            steps.append({"id": step_id, "status": "FAIL", "observed": failure})
            log[step_id] = records
            print(
                f"EVIDENCE {step_id} - Captures the first replay mismatch.", flush=True
            )
            print(json.dumps(records, sort_keys=True), flush=True)
            print(failure, file=sys.stderr, flush=True)
            print(f"STEP {step_id} END - FAIL", flush=True)
            continue
        log[step_id] = records
        steps.append({"id": step_id, "status": "PASS", "observed": step["observed"]})
        print(f"EVIDENCE {step_id} - {step['evidence']}", flush=True)
        print(json.dumps(records, sort_keys=True), flush=True)
        print(f"STEP {step_id} END - PASS", flush=True)

    log["status"] = status
    log["failure"] = failure
    atomic_json(artifacts / "replay-log.json", log)
    artifact = {
        "name": "Replay operation log",
        "path": "artifacts/replay-log.json",
        "step_id": spec["steps"][0]["id"],
        "description": (
            "Records every replayed operation with its observed return code, HTTP "
            "status, and response digest, proving the mined case reproduces."
        ),
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": spec["summary"] if status == "PASS" else failure,
            "steps": steps,
            "artifacts": [artifact],
            "remarks": spec.get("remarks", ""),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
