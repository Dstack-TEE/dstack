#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify ordered Compose startup and isolated validation failures."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-storage-an-003"
GUEST_PROBE = r"""
set -eu
work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

compose=/dstack/docker-compose.yaml
test -s "$compose"
docker compose -f "$compose" config --format json >"$work/config.json"
services=$(jq -c '.services | keys' "$work/config.json")
service_count=$(jq 'length' <<<"$services")
[ "$service_count" -ge 2 ]
edges=$(jq -c '[.services | to_entries[] | .key as $service | (.value.depends_on // {}) | keys[] | {service:$service,depends_on:.}]' "$work/config.json")
edge_count=$(jq 'length' <<<"$edges")
[ "$edge_count" -ge 1 ]

verifier_id=$(docker compose -f "$compose" ps -q dstack-verifier)
agent_id=$(docker compose -f "$compose" ps -q dstack-agent)
[ -n "$verifier_id" ]
[ -n "$agent_id" ]
[ "$(docker inspect -f '{{.State.Running}}' "$verifier_id")" = true ]
[ "$(docker inspect -f '{{.State.Running}}' "$agent_id")" = true ]
verifier_started=$(docker inspect -f '{{.State.StartedAt}}' "$verifier_id")
agent_started=$(docker inspect -f '{{.State.StartedAt}}' "$agent_id")
[[ "$verifier_started" < "$agent_started" || "$verifier_started" = "$agent_started" ]]

inventory_before=$(docker ps -aq | sort | sha256sum | awk '{print $1}')
project_before=$(docker compose -f "$compose" ps -aq | sort | sha256sum | awk '{print $1}')
printf 'services:\n  broken: [\n' >"$work/malformed.yaml"
printf 'services:\n  broken:\n    image: scratch\n    definitely_unsupported_field: true\n' >"$work/unsupported.yaml"

set +e
docker compose -f "$work/malformed.yaml" config >"$work/malformed.out" 2>&1
malformed_rc=$?
docker compose -f "$work/unsupported.yaml" config >"$work/unsupported.out" 2>&1
unsupported_rc=$?
set -e
[ "$malformed_rc" -ne 0 ]
[ "$unsupported_rc" -ne 0 ]
[ -s "$work/malformed.out" ]
[ -s "$work/unsupported.out" ]

inventory_after=$(docker ps -aq | sort | sha256sum | awk '{print $1}')
project_after=$(docker compose -f "$compose" ps -aq | sort | sha256sum | awk '{print $1}')
[ "$inventory_before" = "$inventory_after" ]
[ "$project_before" = "$project_after" ]
[ "$(docker inspect -f '{{.State.Running}}' "$verifier_id")" = true ]
[ "$(docker inspect -f '{{.State.Running}}' "$agent_id")" = true ]

compose_hash=$(sha256sum "$compose" | awk '{print $1}')
malformed_hash=$(sha256sum "$work/malformed.out" | awk '{print $1}')
unsupported_hash=$(sha256sum "$work/unsupported.out" | awk '{print $1}')
jq -cn --argjson services "$services" --argjson edges "$edges"     --arg verifier_started "$verifier_started" --arg agent_started "$agent_started"     --arg compose_hash "$compose_hash" --argjson malformed_rc "$malformed_rc"     --arg malformed_hash "$malformed_hash" --argjson unsupported_rc "$unsupported_rc"     --arg unsupported_hash "$unsupported_hash" --arg inventory "$inventory_after"     '{services:$services,dependency_edges:$edges,verifier_started_at:$verifier_started,agent_started_at:$agent_started,dependency_ordered:true,compose_sha256:$compose_hash,malformed_exit_code:$malformed_rc,malformed_diagnostic_sha256:$malformed_hash,unsupported_exit_code:$unsupported_rc,unsupported_diagnostic_sha256:$unsupported_hash,container_inventory_sha256:$inventory,original_project_stable:true}'
"""


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


def main() -> int:
    """Run Compose validation and startup acceptance."""
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
    ssh_argv = manifest.get("values", {}).get("ssh_argv")
    status = "PASS"
    summary = (
        "Compose dependency startup and isolated validation failures were verified."
    )
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    try:
        if not isinstance(ssh_argv, list):
            status = "BLOCKED"
            summary = "fixture lacks a lease-owned Compose guest"
            observations["missing_capability"] = "compose-validation-guest"
        else:
            completed = subprocess.run(
                [*map(str, ssh_argv), "bash", "-s"],
                input=GUEST_PROBE,
                text=True,
                capture_output=True,
                timeout=90,
                check=False,
            )
            if completed.returncode:
                raise AssertionError(
                    f"Compose guest probe failed with exit {completed.returncode}"
                )
            probe = json.loads(completed.stdout)
            if len(probe["services"]) < 2 or not probe["dependency_edges"]:
                raise AssertionError(
                    "positive Compose input lacks multi-service dependency"
                )
            if probe["malformed_exit_code"] == 0 or probe["unsupported_exit_code"] == 0:
                raise AssertionError("invalid Compose input was accepted")
            if not probe["original_project_stable"]:
                raise AssertionError("negative validation disturbed original project")
            source = (
                pathlib.Path(runtime["repository"]) / "os/common/rootfs/app-compose.sh"
            ).read_text()
            guards = [
                "validate_runner",
                "ensure_compose_file",
                'docker compose -f "$COMPOSE_FILE" up --remove-orphans -d --build',
            ]
            if any(guard not in source for guard in guards):
                raise AssertionError("candidate startup script lacks Compose guards")
            observations.update(probe)
            observations["source_guards"] = len(guards)
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
        "path": "artifacts/compose-validation-startup.json",
        "step_id": f"{case_id}-step-01",
        "name": "Compose validation and startup",
        "description": "Service names, dependency edges, timestamps, exit codes, and hashes without environment values.",
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
                    "observed": "Materialized multi-service Compose structure and running baseline were checked.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Dependency startup order and malformed/unsupported validation rejection were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Original project state and redacted container inventory remained stable.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Negative inputs remain under a unique guest /tmp directory and never replace the deployed Compose file.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
