#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify dashboard metrics and exact case-owned container log filtering."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any

CASE_ID = "tc-gos-observabil-001"
TIMESTAMP_RE = re.compile(r"^(\S+)\s+(.*)$")


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def ssh(
    ssh_argv: list[str], script: str, timeout: int = 90
) -> subprocess.CompletedProcess[str]:
    """Run a bounded script in the lease-owned guest."""
    return subprocess.run(
        [*ssh_argv, "bash", "-s"],
        input=script,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def get(url: str, timeout: int = 30) -> tuple[int, bytes, str]:
    """Fetch one bounded HTTP endpoint including HTTP error bodies."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read(), response.headers.get_content_type()
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers.get_content_type()


def log_url(base: str, container: str, **query: Any) -> str:
    """Build one encoded log query."""
    encoded = urllib.parse.urlencode(
        {
            key: str(value).lower() if isinstance(value, bool) else value
            for key, value in query.items()
        }
    )
    return f"{base}/logs/{urllib.parse.quote(container, safe='')}?{encoded}"


def json_lines(body: bytes) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON log output."""
    rows = []
    for line in body.decode(errors="strict").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise AssertionError("log line was not a JSON object")
        rows.append(value)
    return rows


def marker_times(
    completed: subprocess.CompletedProcess[str], markers: list[str]
) -> dict[str, int]:
    """Extract integer Unix seconds from Docker RFC3339 log timestamps."""
    combined = completed.stdout.splitlines() + completed.stderr.splitlines()
    found: dict[str, int] = {}
    for line in combined:
        match = TIMESTAMP_RE.match(line)
        if not match:
            continue
        timestamp, message = match.groups()
        for marker in markers:
            if marker in message:
                normalized = timestamp.replace("Z", "+00:00")
                found[marker] = int(datetime.fromisoformat(normalized).timestamp())
    if set(found) != set(markers):
        raise AssertionError("Docker timestamp baseline omitted a marker")
    return found


def require_markers(
    body: bytes, expected: list[str], absent: list[str] | None = None
) -> None:
    """Require and exclude marker strings in an HTTP body."""
    text = body.decode(errors="replace")
    for marker in expected:
        if marker not in text:
            raise AssertionError(f"log response omitted marker {marker[-12:]}")
    for marker in absent or []:
        if marker in text:
            raise AssertionError(
                f"log response unexpectedly included marker {marker[-12:]}"
            )


def main() -> int:
    """Run dashboard metrics and container log filtering acceptance."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    values = manifest.get("values", {})
    services = values.get("services", {})
    dashboard = services.get("Dashboard") if isinstance(services, dict) else None
    status = "PASS"
    summary = "Dashboard, metrics, and exact case-owned log filters were verified."
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    ssh_argv: list[str] = []
    container = ""
    stage = "capability"
    try:
        capable = (
            values.get("destructive_actions_allowed") is True
            and isinstance(values.get("ssh_argv"), list)
            and isinstance(dashboard, dict)
            and isinstance(dashboard.get("url"), str)
        )
        if not capable:
            status = "BLOCKED"
            summary = "fixture lacks a case-owned dashboard log lifecycle guest"
            observations["missing_capability"] = "dashboard-log-lifecycle-guest"
        else:
            ssh_argv = [*map(str, values["ssh_argv"])]
            base = str(dashboard["url"]).rstrip("/")
            run_hash = hashlib.sha256(
                os.environ["DSTACK_TEST_RUN_ID"].encode()
            ).hexdigest()
            container = f"dstack-log-{run_hash[:20]}"
            markers = [
                f"plain-{run_hash[:24]}",
                f"ansi-{run_hash[24:48]}",
                f"stderr-{run_hash[40:64]}",
            ]
            stage = "dashboard-baseline"
            dashboard_code, dashboard_body, dashboard_type = get(base + "/")
            metrics_code, metrics_body, metrics_type = get(base + "/metrics")
            if (
                dashboard_code != 200
                or b"<!DOCTYPE html" not in dashboard_body[:500].upper()
            ):
                # Templates can use lowercase HTML without a doctype; require a real page below.
                if dashboard_code != 200 or b"<html" not in dashboard_body.lower():
                    raise AssertionError("dashboard root did not return HTML")
            metrics_text = metrics_body.decode(errors="strict")
            required_metrics = (
                "system_num_cpus",
                "system_memory_total",
                "system_uptime",
            )
            if metrics_code != 200 or any(
                name not in metrics_text for name in required_metrics
            ):
                raise AssertionError("metrics endpoint omitted required live resources")
            stage = "container-fixture"
            fixture = ssh(
                ssh_argv,
                f"""set -eu
name={container}
image=ubuntu:latest
docker image inspect "$image" >/dev/null
docker run --rm --entrypoint sh "$image" -c true
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --entrypoint sh "$image" -c 'printf "%s\\n" "{markers[0]}"; sleep 2; printf "\\033[31m%s\\033[0m\\n" "{markers[1]}"; sleep 2; printf "%s\\n" "{markers[2]}" >&2' >/dev/null
for _ in $(seq 1 30); do
  state=$(docker inspect -f '{{{{.State.Status}}}}' "$name")
  [ "$state" = exited ] && break
  sleep 1
done
[ "$(docker inspect -f '{{{{.State.Status}}}}' "$name")" = exited ]
docker logs --timestamps "$name"
""",
                90,
            )
            if fixture.returncode:
                raise AssertionError("failed to create timestamped log fixture")
            timestamps = marker_times(fixture, markers)
            ordered = [timestamps[marker] for marker in markers]
            if not (ordered[0] < ordered[1] < ordered[2]):
                raise AssertionError("fixture log timestamps were not strictly ordered")
            stage = "json-channels"
            code, body, content_type = get(
                log_url(base, container, text=True, bare=False, tail="all")
            )
            rows = json_lines(body)
            if code != 200 or not rows:
                raise AssertionError("structured text log query failed")
            messages = {str(row.get("message", "")): row.get("channel") for row in rows}
            if not any(
                markers[0] in message and channel == "stdout"
                for message, channel in messages.items()
            ):
                raise AssertionError(
                    "stdout channel marker was not structured correctly"
                )
            if not any(
                markers[2] in message and channel == "stderr"
                for message, channel in messages.items()
            ):
                raise AssertionError(
                    "stderr channel marker was not structured correctly"
                )
            stage = "base64"
            code, body, _ = get(
                log_url(base, container, text=False, bare=False, tail="all")
            )
            encoded_rows = json_lines(body)
            decoded = [
                base64.b64decode(str(row["message"])).decode(errors="replace")
                for row in encoded_rows
            ]
            if code != 200 or not all(
                any(marker in value for value in decoded) for marker in markers
            ):
                raise AssertionError("base64 log query did not decode to all markers")
            stage = "ansi"
            code, stripped, _ = get(
                log_url(base, container, text=True, bare=True, ansi=False, tail="all")
            )
            require_markers(stripped, markers)
            if b"\x1b[31m" in stripped:
                raise AssertionError("ansi=false retained an ANSI escape")
            code_ansi, preserved, _ = get(
                log_url(base, container, text=True, bare=True, ansi=True, tail="all")
            )
            if code != 200 or code_ansi != 200 or b"\x1b[31m" not in preserved:
                raise AssertionError("ansi=true did not preserve the ANSI escape")
            stage = "tail"
            code, tail_body, _ = get(
                log_url(base, container, text=True, bare=True, tail="1")
            )
            if code != 200:
                raise AssertionError("tail query failed")
            require_markers(tail_body, [markers[2]], markers[:2])
            stage = "absolute-boundaries"
            since_value = ordered[0] + 1
            until_value = ordered[1] + 1
            _, since_body, _ = get(
                log_url(
                    base, container, text=True, bare=True, since=since_value, tail="all"
                )
            )
            require_markers(since_body, markers[1:], [markers[0]])
            _, until_body, _ = get(
                log_url(
                    base, container, text=True, bare=True, until=until_value, tail="all"
                )
            )
            require_markers(until_body, markers[:2], [markers[2]])
            stage = "relative-follow-timestamps"
            _, relative_body, _ = get(
                log_url(base, container, text=True, bare=True, since="1h", tail="all")
            )
            require_markers(relative_body, markers)
            _, follow_body, _ = get(
                log_url(base, container, text=True, bare=True, follow=True, tail="1"),
                30,
            )
            require_markers(follow_body, [markers[2]], markers[:2])
            _, timestamp_body, _ = get(
                log_url(
                    base, container, text=True, bare=True, timestamps=True, tail="1"
                )
            )
            if not re.search(rb"\d{4}-\d{2}-\d{2}T", timestamp_body):
                raise AssertionError("timestamps=true omitted RFC3339 timestamp")
            stage = "invalid-inputs"
            _, malformed, _ = get(
                log_url(base, container, text=True, bare=True, since="not-a-time")
            )
            malformed_value = json.loads(malformed)
            if malformed_value.get("error") != "Invalid since":
                raise AssertionError("malformed since did not return structured error")
            traversal_code, traversal_body, _ = get(
                f"{base}/logs/{urllib.parse.quote('../' + container, safe='')}?text=true"
            )
            if traversal_code == 200 and any(
                marker.encode() in traversal_body for marker in markers
            ):
                raise AssertionError("container-name traversal exposed fixture logs")
            stage = "cleanup-health"
            cleanup = ssh(
                ssh_argv,
                f"docker rm -f {container} >/dev/null\ndocker info >/dev/null\n",
                60,
            )
            if cleanup.returncode:
                raise AssertionError("failed to clean case-owned log container")
            container = ""
            final_dashboard, final_body, _ = get(base + "/")
            final_metrics, final_metrics_body, _ = get(base + "/metrics")
            if (
                final_dashboard != 200
                or final_metrics != 200
                or not final_body
                or not final_metrics_body
            ):
                raise AssertionError("dashboard or metrics unhealthy after cleanup")
            observations.update(
                {
                    "dashboard": {
                        "status": dashboard_code,
                        "content_type": dashboard_type,
                        "body_sha256": hashlib.sha256(dashboard_body).hexdigest(),
                    },
                    "metrics": {
                        "status": metrics_code,
                        "content_type": metrics_type,
                        "required_metrics": list(required_metrics),
                        "body_sha256": hashlib.sha256(metrics_body).hexdigest(),
                    },
                    "fixture": {
                        "timestamp_ordered": True,
                        "marker_hashes": [
                            hashlib.sha256(item.encode()).hexdigest()
                            for item in markers
                        ],
                    },
                    "structured_channels": ["stdout", "stderr"],
                    "base64_decoded": True,
                    "ansi_stripped_and_preserved": True,
                    "tail_exact": True,
                    "absolute_since_until_exact": True,
                    "relative_since": True,
                    "follow_stopped_container": True,
                    "timestamps_present": True,
                    "malformed_since_error": True,
                    "traversal_status": traversal_code,
                    "traversal_rejected": True,
                    "container_removed": True,
                    "service_healthy_after": True,
                }
            )
    except (
        AssertionError,
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        urllib.error.URLError,
    ) as error:
        status = "FAIL"
        summary = f"{stage}: {error}"
        observations["failure"] = str(error)
        observations["failure_stage"] = stage
    finally:
        if container and ssh_argv:
            ssh(ssh_argv, f"docker rm -f {container} >/dev/null 2>&1 || true\n", 30)
    artifact = {
        "path": "artifacts/dashboard-log-filtering.json",
        "step_id": f"{case_id}-step-01",
        "name": "Dashboard metrics and log filtering",
        "description": "Redacted endpoint hashes, metric names, marker hashes, filter booleans, channels, and cleanup state.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "Dashboard, metrics, Docker health, and a clean case-owned container baseline were checked.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Text/Base64, bare/structured, ANSI, channel, tail, timestamp, since/until, relative, and follow filters were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Malformed time, traversal rejection, container cleanup, and final endpoint health were verified.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Only a uniquely named lease-owned container is created; raw log fixtures are not retained in artifacts.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
