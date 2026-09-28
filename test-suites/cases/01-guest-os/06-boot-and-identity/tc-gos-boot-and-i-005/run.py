#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify ordered boot and shutdown notifications for one lease-owned guest."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-gos-boot-and-i-005"
UNKNOWN_VM_ID = "00000000-0000-4000-8000-000000000000"


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


def varint(value: int) -> bytes:
    """Encode a protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode_id(vm_id: str) -> bytes:
    """Encode the protobuf Id request."""
    raw = vm_id.encode()
    return b"\x0a" + varint(len(raw)) + raw


def request(url: str, vm_id: str) -> tuple[int, bytes]:
    """Call the binary ProxiedGuestApi Shutdown method."""
    call = urllib.request.Request(
        url,
        data=encode_id(vm_id),
        headers={"content-type": "application/octet-stream"},
    )
    try:
        with urllib.request.urlopen(call, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def query(argv: list[str]) -> dict[str, Any]:
    """Query one lease-owned VM through the candidate CLI."""
    completed = subprocess.run(
        argv, text=True, capture_output=True, timeout=30, check=False
    )
    if completed.returncode:
        raise AssertionError("failed to query lease VM")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise AssertionError("lease VM query returned a non-object")
    return value


def event_projection(events: Any) -> list[dict[str, Any]]:
    """Return only safe notification fields after validating their schema."""
    if not isinstance(events, list):
        raise AssertionError("VMM event buffer is not a list")
    projected = []
    previous = 0
    for item in events:
        if not isinstance(item, dict):
            raise AssertionError("VMM event is not an object")
        event = str(item.get("event", ""))
        body = str(item.get("body", ""))
        timestamp = int(item.get("timestamp", 0))
        if not event or not body or timestamp <= 0:
            raise AssertionError("VMM event lacks event, body, or timestamp")
        if timestamp < previous:
            raise AssertionError("VMM event timestamps are not ordered")
        previous = timestamp
        projected.append(
            {
                "event": event,
                "body": body,
                "timestamp": timestamp,
            }
        )
    return projected


def main() -> int:
    """Run the notification lifecycle acceptance check."""
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
    recorder = values.get("host_notify_recorder")
    status = "PASS"
    summary = "Lease guest emitted ordered boot and one terminal shutdown notification."
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    try:
        if (
            not isinstance(recorder, dict)
            or not recorder.get("destructive_actions_allowed")
            or not values.get("destructive_actions_allowed")
        ):
            status = "BLOCKED"
            summary = "fixture lacks a destructive lease-owned HostApi recorder"
            observations["missing_capability"] = "lease-host-notify-recorder"
        else:
            vm_id = str(recorder["vm_id"])
            info_argv = [*map(str, recorder["info_argv"])]
            initial = event_projection(recorder.get("initial_events", []))
            if any(
                event["event"] == "shutdown.progress"
                and event["body"] == "powering off"
                for event in initial
            ):
                raise AssertionError(
                    "initial recorder already contains terminal shutdown"
                )
            cli = [*map(str, values["vmm_cli_argv"])]
            url_index = cli.index("--url") + 1
            shutdown_url = cli[url_index].rstrip("/") + "/guest/Shutdown"
            before = query(info_argv)
            before_events = event_projection(before.get("events", []))
            boot_events = [
                event for event in before_events if event["event"] == "boot.progress"
            ]
            if not boot_events or boot_events[-1]["body"] != "done":
                raise AssertionError("boot progress did not terminate at done")
            if any(event["event"] == "boot.error" for event in before_events):
                raise AssertionError("boot event buffer contains boot.error")

            rejected_code, rejected_body = request(shutdown_url, UNKNOWN_VM_ID)
            if rejected_code < 400:
                raise AssertionError("unknown VM shutdown was accepted")
            if query(info_argv).get("status") != "running":
                raise AssertionError("rejected shutdown disturbed lease guest")
            shutdown_code, shutdown_body = request(shutdown_url, vm_id)
            if shutdown_code != 200 or shutdown_body:
                raise AssertionError("valid shutdown response was not empty HTTP 200")

            deadline = time.monotonic() + 90
            after = query(info_argv)
            while time.monotonic() < deadline:
                events = event_projection(after.get("events", []))
                terminal = [
                    event
                    for event in events
                    if event["event"] == "shutdown.progress"
                    and event["body"] == "powering off"
                ]
                if terminal and after.get("status") != "running":
                    break
                time.sleep(1)
                after = query(info_argv)
            else:
                raise AssertionError("terminal shutdown notification did not settle")
            events = event_projection(after.get("events", []))
            terminal = [
                event
                for event in events
                if event["event"] == "shutdown.progress"
                and event["body"] == "powering off"
            ]
            if len(terminal) != 1:
                raise AssertionError("terminal shutdown notification count was not one")
            settled = query(info_argv)
            if event_projection(settled.get("events", [])) != events:
                raise AssertionError("settled event buffer was not idempotent")
            observations.update(
                {
                    "initial_event_count": len(initial),
                    "boot_progress": [event["body"] for event in boot_events],
                    "event_count": len(events),
                    "event_sequence_sha256": hashlib.sha256(
                        json.dumps(events, sort_keys=True).encode()
                    ).hexdigest(),
                    "timestamps_ordered": True,
                    "unknown_shutdown_http": rejected_code,
                    "unknown_shutdown_response_bytes": len(rejected_body),
                    "valid_shutdown_http": shutdown_code,
                    "terminal_shutdown_count": 1,
                    "final_status": after.get("status"),
                    "shutdown_progress": after.get("shutdown_progress"),
                    "settled_idempotent": True,
                }
            )
    except (
        AssertionError,
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        status = "FAIL"
        summary = str(error)
        observations["failure"] = summary

    artifact = {
        "path": "artifacts/host-notification-lifecycle.json",
        "step_id": f"{case_id}-step-01",
        "name": "Host notification lifecycle",
        "description": "Ordered public event fields, counts, statuses, and sequence hash.",
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
                    "observed": "Lease recorder capability and initial event boundary were checked.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Ordered boot progress, rejected unknown VM, and graceful shutdown were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "One terminal shutdown event and stable settled buffer were verified.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Only the lease-owned guest is shut down; fixture cleanup owns removal.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
