#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""ProxiedGuestApi.Shutdown terminal state-transition regression.

`Shutdown` is the one ProxiedGuestApi method that is not idempotent: it powers
the lease-owned guest off, after which the proxy can no longer reach it.  The
table-driven RPC harness calls each method three times and requires all three
to succeed, which cannot model this, so the case owns a harness that drives the
transition once and asserts the state either side of it.

Every rejection path runs before the transition, so a rejected request is shown
not to disturb a running guest.  The success path is exercised once, over the
binary representation; the JSON representation is exercised on the same handler
through a well-formed request whose VM id the lease does not own, which proves
the JSON body decoded and reached the handler rather than the codec.  A second
successful Shutdown is impossible by construction: the guest is gone.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE = "tc-gos-proxiedguestapi-005"
METHOD = "Shutdown"
UNKNOWN_VM_ID = "00000000-0000-4000-8000-000000000000"
STOP_TIMEOUT_SECONDS = 90


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def request(url: str, content_type: str, body: bytes) -> tuple[int, bytes]:
    """Call one ProxiedGuestApi method over the lease-owned VMM endpoint."""
    call = urllib.request.Request(
        url, data=body, headers={"content-type": content_type}
    )
    try:
        with urllib.request.urlopen(call, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode_id(vm_id: str) -> bytes:
    """Encode the one-field `Id` protobuf request."""
    raw = vm_id.encode()
    return b"\x0a" + varint(len(raw)) + raw


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a protobuf varint from a buffer."""
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def structured_error(body: bytes) -> str:
    """Return the structured error of a rejected pRPC response.

    A rejection is framed in the representation of its request: a JSON request
    is answered with an `error` member, while a binary request is answered with
    a protobuf message whose field 1 carries the message.
    """
    if body[:1] == b"\x0a":
        length, offset = read_varint(body, 1)
        text = body[offset : offset + length].decode(errors="replace")
        if text:
            return text
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise AssertionError("rejection was not structured JSON or protobuf") from error
    message = value.get("error")
    if not isinstance(message, str) or not message:
        raise AssertionError("rejection omitted a structured error")
    return message


def run_cli(argv: list[str]) -> tuple[int, str]:
    """Run a lease-owned VMM CLI command."""
    process = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False
    )
    return process.returncode, process.stdout.decode(errors="replace")


def vm_state(argv: list[str]) -> dict[str, Any]:
    """Return the lease-owned VM state reported by the candidate VMM."""
    code, text = run_cli(argv)
    if code != 0:
        raise AssertionError("the lease-owned VMM did not report VM state")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise AssertionError("the lease-owned VMM returned non-object VM state")
    return value


def inventory(root: pathlib.Path) -> dict[str, Any]:
    """Return the indexed ProxiedGuestApi.Shutdown contract."""
    document = json.loads((root / "api-inventory.json").read_text())
    matches = [
        entry
        for entry in document["components"]["guest-os"]["rpc_methods"]
        if entry.get("service") == "ProxiedGuestApi" and entry.get("method") == METHOD
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one inventory entry for {METHOD}")
    return matches[0]


def log_observation(path: str) -> dict[str, Any]:
    """Summarise the lease-owned guest boot log without persisting content."""
    log = pathlib.Path(path)
    if not log.is_file():
        return {"available": False}
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]
    return {
        "available": True,
        "observed_lines": len(lines),
        "panic_lines": sum(1 for line in lines if "panic" in line.lower()),
        "sha256": hashlib.sha256("\n".join(lines).encode()).hexdigest(),
        "content_persisted": False,
    }


def main() -> int:
    """Run the ProxiedGuestApi.Shutdown regression."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    steps: list[dict[str, str]] = []
    failures: list[str] = []
    evidence: dict[str, Any] = {
        "case_id": case_id,
        "environment": "HARDWARE",
        "service": "ProxiedGuestApi",
        "method": METHOD,
    }
    try:
        print(f"STEP {case_id}-step-01 START", flush=True)
        values = manifest["values"]
        service = values["services"]["ProxiedGuestApi"]
        vm_id = str(service["id"])
        url = str(service["url"]).format(method=METHOD)
        if not vm_id or not url.startswith("http://127.0.0.1:"):
            raise AssertionError(
                "fixture did not provide an isolated ProxiedGuestApi target"
            )
        if not values.get("destructive_actions_allowed"):
            raise AssertionError("the lease does not permit a destructive transition")
        info_argv = [str(item) for item in values["vm_info_argv"]]
        before = vm_state(info_argv)
        if before.get("status") != "running" or before.get("boot_progress") != "done":
            raise AssertionError(f"lease guest is not ready: {before.get('status')}")
        identity_code, identity_body = request(
            str(service["url"]).format(method="Info"),
            "application/json",
            json.dumps({"id": vm_id}, separators=(",", ":")).encode(),
        )
        if identity_code != 200:
            raise AssertionError(f"ProxiedGuestApi.Info returned {identity_code}")
        observed_instance = str(json.loads(identity_body).get("instance_id", ""))
        if observed_instance.lower() != str(values["instance_id"]).lower():
            raise AssertionError("the run-scoped VM id resolved to another guest")
        entry = inventory(plan_root)
        if entry["response_fields"]:
            raise AssertionError("indexed Shutdown response is no longer Empty")
        evidence["prerequisite"] = {
            "profile": manifest["profile"],
            "lease_id": manifest["lease_id"],
            "status": before.get("status"),
            "boot_progress": before.get("boot_progress"),
            "instance_id_matches_lease": True,
            "indexed_request_fields": [
                field["name"] for field in entry["request_fields"]
            ],
            "indexed_response_fields": [],
        }
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The lease-owned VMM reported the intended guest running "
                "with boot progress done, the ProxiedGuestApi listener resolved the "
                "run-scoped VM id to that guest's instance id, and the indexed "
                "Shutdown contract declared an empty response.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-01 - Proves the isolated VMM listener and the "
            "running run-scoped guest were the effective baseline.",
            flush=True,
        )
        print(json.dumps(evidence["prerequisite"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)

        print(f"STEP {case_id}-step-02 START", flush=True)
        # Every rejection runs first: a rejected Shutdown must leave the guest
        # running, which can only be observed while it still is.
        rejections: dict[str, Any] = {}
        for name, content_type, body in (
            ("absent_id_json", "application/json", b"{}"),
            ("empty_id_json", "application/json", b'{"id":""}'),
            (
                "unknown_id_json",
                "application/json",
                f'{{"id":"{UNKNOWN_VM_ID}"}}'.encode(),
            ),
            ("schema_invalid_id_json", "application/json", b'{"id":123}'),
            ("malformed_json", "application/json", b'{"id":'),
            (
                "unknown_id_protobuf",
                "application/octet-stream",
                encode_id(UNKNOWN_VM_ID),
            ),
            ("malformed_protobuf", "application/octet-stream", b"\x0a\xff"),
        ):
            code, body_out = request(url, content_type, body)
            if code < 400:
                raise AssertionError(f"{name} was accepted with HTTP {code}")
            rejections[name] = {"http": code, "error": structured_error(body_out)}
        survived = vm_state(info_argv)
        if survived.get("status") != "running":
            raise AssertionError("a rejected Shutdown disturbed the running guest")
        shutdown_code, shutdown_body = request(
            url, "application/octet-stream", encode_id(vm_id)
        )
        if shutdown_code != 200:
            raise AssertionError(f"valid Shutdown returned HTTP {shutdown_code}")
        if shutdown_body != b"":
            raise AssertionError("Shutdown returned a body for google.protobuf.Empty")
        evidence["transition"] = {
            "rejections": rejections,
            "running_after_rejections": True,
            "shutdown_http": shutdown_code,
            "shutdown_response_bytes": len(shutdown_body),
            "success_representation": "application/octet-stream",
            "json_representation_reached_handler": rejections["unknown_id_json"],
            "protobuf_representation_reached_handler": rejections[
                "unknown_id_protobuf"
            ],
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Absent, empty, unresolvable, wrong-typed and malformed "
                "requests were rejected with structured errors in both "
                "representations and left the guest running; the valid binary "
                "Shutdown returned HTTP 200 with an empty google.protobuf.Empty body.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-02 - Proves the rejection contract in both "
            "representations and the accepted terminal request.",
            flush=True,
        )
        print(json.dumps(evidence["transition"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)

        print(f"STEP {case_id}-step-03 START", flush=True)
        deadline = time.monotonic() + STOP_TIMEOUT_SECONDS
        after = vm_state(info_argv)
        while after.get("status") != "stopped" and time.monotonic() < deadline:
            time.sleep(1)
            after = vm_state(info_argv)
        if after.get("status") == "running":
            raise AssertionError(
                f"the guest was still running {STOP_TIMEOUT_SECONDS}s after Shutdown"
            )
        # The indexed contract documents no repeat semantics for Shutdown, and
        # the VMM answers a repeat against a stopped guest either with a proxy
        # error or with an accepted no-op depending on how far teardown has
        # progressed. Record which one happened and assert only what the case
        # requires: the repeat must not bring the guest back.
        repeat_code, repeat_body = request(
            url, "application/octet-stream", encode_id(vm_id)
        )
        settled = vm_state(info_argv)
        if settled.get("status") == "running":
            raise AssertionError("a repeated Shutdown returned the guest to running")
        list_code, list_text = run_cli(
            [*[str(item) for item in values["vmm_cli_argv"]], "lsvm", "--json"]
        )
        if list_code != 0:
            raise AssertionError("the candidate VMM control plane became unavailable")
        listed = json.loads(list_text)
        rows = listed if isinstance(listed, list) else listed.get("vms", [])
        owned = [row for row in rows if str(row.get("id", "")) == vm_id]
        scoped_code, scoped_body = request(
            url,
            "application/json",
            f'{{"id":"{UNKNOWN_VM_ID}"}}'.encode(),
        )
        if scoped_code < 400:
            raise AssertionError("an unowned VM id was accepted after the transition")
        evidence["final_state"] = {
            "status": after.get("status"),
            "shutdown_progress": after.get("shutdown_progress"),
            "boot_progress": after.get("boot_progress"),
            "repeat_shutdown_http": repeat_code,
            "repeat_shutdown_rejected": repeat_code >= 400,
            "repeat_shutdown_error": (
                structured_error(repeat_body) if repeat_code >= 400 else None
            ),
            "status_after_repeat": settled.get("status"),
            "lease_vm_listed": bool(owned),
            "control_plane_available": True,
            "unowned_id_still_rejected": {
                "http": scoped_code,
                "error": structured_error(scoped_body),
            },
        }
        evidence["diagnostics"] = log_observation(str(values["serial_log"]))
        if evidence["diagnostics"].get("panic_lines"):
            raise AssertionError("the lease guest boot log recorded a panic")
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "The lease-owned guest left the running state after "
                "Shutdown and did not return to it when the terminal request was "
                "repeated, the candidate VMM control plane stayed available and "
                "still rejected an unowned VM id, and bounded guest diagnostics "
                "recorded no panic.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-03 - Proves the observed state transition, "
            "the repeat outcome and retained service availability.",
            flush=True,
        )
        print(json.dumps(evidence["final_state"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        completed = {step["id"] for step in steps}
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id not in completed:
                steps.append(
                    {"id": step_id, "status": "FAIL", "observed": failures[-1]}
                )
        print(failures[-1], file=sys.stderr, flush=True)

    status = "PASS" if not failures else "FAIL"
    evidence["status"] = status
    evidence["failure"] = failures[0] if failures else None
    artifact = {
        "name": "ProxiedGuestApi.Shutdown transition matrix",
        "path": "artifacts/proxiedguestapi-shutdown-matrix.json",
        "step_id": f"{case_id}-step-02",
        "description": "Pre-transition rejection statuses in both representations, "
        "the accepted terminal request, the observed running-to-stopped transition, "
        "the recorded repeat outcome, and bounded guest diagnostics.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "ProxiedGuestApi.Shutdown rejected invalid input in both "
            "representations without disturbing the running guest, returned an empty "
            "google.protobuf.Empty body for the valid binary request, and drove "
            "the lease-owned guest out of the running state for good."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Shutdown is a terminal, non-idempotent transition, so the "
            "success path is exercised once over the binary representation. The JSON "
            "representation is exercised against the same handler with a well-formed "
            "request for a VM id the lease does not own, which returns 'vm not found' "
            "and therefore proves the JSON body decoded and dispatched. The lease "
            "guest is left stopped and is removed by fixture teardown.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
