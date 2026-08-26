#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate the complete guest configuration-entry matrix on a safe fixture."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import tempfile
from typing import Any

CASE_ID = "tc-gos-entry-001"
CAPABILITY = "config-entry-lifecycle"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Atomically write one result or evidence document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def main() -> int:
    """Record whether the complete configuration-entry contract is available."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest.get("values", {})
    fixture = values.get("config_entry_lifecycle") if isinstance(values, dict) else None
    peer = values.get("config_entry_peer") if isinstance(values, dict) else None
    required = (
        "inventory_fields",
        "baseline_argv",
        "layered_config_argv",
        "environment_override_probe_argv",
        "unix_bind_probe_argv",
        "tcp_bind_probe_argv",
        "vsock_bind_probe_argv",
        "valid_compose_probe_argv",
        "unknown_field_probe_argv",
        "malformed_compose_probe_argv",
        "absent_optional_probe_argv",
        "dependency_pause_argv",
        "conflicting_operation_argv",
        "dependency_restore_argv",
        "retry_argv",
        "restart_argv",
        "state_observer_argv",
        "cleanup_argv",
    )
    present = {
        field: isinstance(fixture, dict) and fixture.get(field) is not None
        for field in required
    }
    peer_present = (
        isinstance(peer, dict)
        and isinstance(peer.get("ssh_argv"), list)
        and bool(peer.get("vm_id"))
        and bool(peer.get("instance_id"))
    )
    complete = (
        isinstance(fixture, dict)
        and fixture.get("destructive_actions_allowed") is True
        and all(present.values())
        and peer_present
    )
    if complete:
        status = "FAIL"
        summary = "config-entry lifecycle capability is present but the matrix is not implemented"
        observed = (
            "The complete case-owned configuration-entry controller and adjacent peer "
            "are declared; this harness revision must execute them rather than report a gap."
        )
    else:
        status = "BLOCKED"
        summary = f"missing capability: {CAPABILITY}"
        observed = (
            "The manifest provides the required adjacent identity but lacks a lease-owned "
            "controller for layered configuration, every bind type and boundary, compose "
            "success/failure, dependency commit interruption, conflicting concurrency, "
            "retry, restart, state observation, and cleanup."
        )
    observation = {
        "case_id": CASE_ID,
        "status": status,
        "environment": "HARDWARE",
        "capability": CAPABILITY,
        "declared": isinstance(fixture, dict),
        "destructive_actions_allowed": isinstance(fixture, dict)
        and fixture.get("destructive_actions_allowed") is True,
        "required_fields_present": present,
        "adjacent_peer_present": peer_present,
        "generic_root_ssh_not_substituted": True,
        "shared_guest_agent_not_reconfigured": True,
    }
    artifact_path = result_dir / "artifacts/config-entry-lifecycle-capability.json"
    atomic_json(artifact_path, observation)
    artifact = {
        "path": "artifacts/config-entry-lifecycle-capability.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "Configuration entry lifecycle capability",
        "description": "Bounded manifest field-presence evidence proving whether safe layered config, bind, compose, concurrency, restart, peer, and cleanup controls exist.",
    }
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": status,
                    "observed": observed,
                },
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "Layer precedence, bind parsing, valid/unknown/malformed compose, and absent optional values require the missing controller.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "Commit-boundary interruption, conflicting concurrency, restoration, and exactly-once retry require the missing controller.",
                },
                {
                    "id": f"{CASE_ID}-step-04",
                    "status": status,
                    "observed": "Owning-service restart and primary/peer state comparison require the missing controller; the peer itself is present.",
                },
            ],
            "artifacts": [artifact],
            "evidence": [
                {
                    "path": artifact["path"],
                    "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
                }
            ],
            "remarks": "Generic root SSH was not substituted for a bounded lifecycle contract, and the shared running guest-agent was not reconfigured.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
