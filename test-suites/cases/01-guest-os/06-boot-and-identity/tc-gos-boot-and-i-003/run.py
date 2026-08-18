#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify guest configuration materialization without exposing values."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-boot-and-i-003"
GUEST_PROBE = r"""
set -eu
marker_name="$1"
phase=initialization
on_error() {
    rc=$?
    jq -cn --arg phase "$phase" --argjson rc "$rc" '{probe_error_phase:$phase,probe_exit_code:$rc}'
    exit 0
}
trap on_error ERR

metadata() {
    path="$1"
    if [ ! -e "$path" ]; then
        jq -cn '{exists:false,regular:false,symlink:false,uid:null,gid:null,mode:null,size_positive:false}'
        return
    fi
    uid=$(stat -Lc %u "$path")
    gid=$(stat -Lc %g "$path")
    mode=$(stat -Lc %a "$path")
    size=$(stat -Lc %s "$path")
    regular=false
    symlink=false
    [ -f "$path" ] && regular=true
    [ -L "$path" ] && symlink=true
    mode_decimal=$((8#$mode))
    size_positive=false
    [ "$size" -gt 0 ] && size_positive=true
    jq -cn --argjson regular "$regular" --argjson symlink "$symlink" \
        --argjson uid "$uid" --argjson gid "$gid" --argjson mode "$mode_decimal" \
        --argjson size_positive "$size_positive" \
        '{exists:true,regular:$regular,symlink:$symlink,uid:$uid,gid:$gid,mode:$mode,size_positive:$size_positive}'
}

root=/dstack/.host-shared
phase=host_metadata
host=$(jq -cn \
    --argjson compose "$(metadata "$root/app-compose.json")" \
    --argjson sys "$(metadata "$root/.sys-config.json")" \
    --argjson user "$(metadata "$root/.user-config")" \
    --argjson encrypted "$(metadata "$root/.encrypted-env")" \
    '{"app-compose.json":$compose,".sys-config.json":$sys,".user-config":$user,".encrypted-env":$encrypted}')
phase=consumer_metadata
consumers=$(jq -cn \
    --argjson compose "$(metadata /dstack/app-compose.json)" \
    --argjson user "$(metadata /dstack/user_config)" \
    --argjson agent "$(metadata /dstack/agent.json)" \
    --argjson docker "$(metadata /dstack/docker-compose.yaml)" \
    '{"/dstack/app-compose.json":$compose,"/dstack/user_config":$user,"/dstack/agent.json":$agent,"/dstack/docker-compose.yaml":$docker}')

json_keys() {
    jq -c 'if type == "object" then keys else null end' "$1" 2>/dev/null || printf 'null'
}
phase=marker_hash
marker_hash=
if [ -f "$root/.decrypted-env.json" ]; then
    marker_value=$(jq -r --arg key "$marker_name" '.[$key] // empty' "$root/.decrypted-env.json")
    if [ -n "$marker_value" ]; then
        marker_hash=$(printf %s "$marker_value" | sha256sum | awk '{print $1}')
    fi
fi
phase=service_state
service=$(systemctl show dstack-prepare.service --property=ActiveState \
    --property=SubState --property=Result --property=ExecMainStatus --no-pager |
    jq -Rsc 'split("\n") | map(select(contains("=")) | split("=") | {(.[0]): .[1]}) | add')
phase=final_json
absent=true
[ -e "$root/.dstack-test-absent-optional" ] && absent=false
jq -cn --argjson host "$host" --argjson consumers "$consumers" \
    --argjson compose_keys "$(json_keys /dstack/app-compose.json)" \
    --argjson user_keys "$(json_keys /dstack/user_config)" \
    --argjson agent_keys "$(json_keys /dstack/agent.json)" \
    --argjson decrypted_env_keys "$(json_keys "$root/.decrypted-env.json")" \
    --arg marker_hash "$marker_hash" --argjson service "$service" --argjson absent "$absent" \
    '{host_inputs:$host,consumer_files:$consumers,compose_keys:$compose_keys,user_config_keys:$user_keys,agent_keys:$agent_keys,decrypted_env_keys:$decrypted_env_keys,environment_marker_sha256:$marker_hash,service:$service,absent_optional_preserved:$absent}'
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
    """Run the lease-owned materialization acceptance check."""
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
    capability = values.get("configuration_materialization")
    ssh_argv = values.get("ssh_argv")
    status = "PASS"
    summary = (
        "Lease guest materialized configuration with safe metadata and marker proof."
    )
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    try:
        if not isinstance(capability, dict) or not isinstance(ssh_argv, list):
            status = "BLOCKED"
            summary = "fixture lacks configuration-materialization-guest capability"
            observations["missing_capability"] = "configuration-materialization-guest"
        else:
            completed = subprocess.run(
                [
                    *map(str, ssh_argv),
                    "bash",
                    "-s",
                    "--",
                    str(capability["environment_marker_name"]),
                ],
                input=GUEST_PROBE,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            if completed.returncode:
                raise AssertionError(
                    "guest metadata probe failed without configuration value capture"
                )
            probe = json.loads(completed.stdout)
            if "probe_error_phase" in probe:
                raise AssertionError(
                    f"guest probe failed in safe phase {probe['probe_error_phase']} "
                    f"with exit code {probe['probe_exit_code']}"
                )
            files = {**probe["host_inputs"], **probe["consumer_files"]}
            missing = [
                path
                for path, metadata in files.items()
                if not metadata["exists"] or not metadata["regular"]
            ]
            if missing:
                raise AssertionError(
                    f"required materialized files are absent: {missing}"
                )
            unsafe = [
                path
                for path, metadata in files.items()
                if metadata["uid"] != 0 or metadata["mode"] & 0o022
            ]
            if unsafe:
                raise AssertionError(f"configuration file metadata is unsafe: {unsafe}")
            invalid_json = [
                name
                for name in ["compose_keys", "user_config_keys", "agent_keys"]
                if probe[name] is None
            ]
            if invalid_json:
                raise AssertionError(
                    f"materialized JSON objects are invalid: {invalid_json}"
                )
            observations.update(
                {
                    "host_inputs": probe["host_inputs"],
                    "decrypted_env_keys": probe["decrypted_env_keys"],
                    "environment_marker_present": bool(
                        probe["environment_marker_sha256"]
                    ),
                    "environment_marker_expected_sha256": capability[
                        "environment_marker_sha256"
                    ],
                    "environment_marker_observed_sha256": probe[
                        "environment_marker_sha256"
                    ],
                }
            )
            if (
                probe["environment_marker_sha256"]
                != capability["environment_marker_sha256"]
            ):
                raise AssertionError("decrypted environment marker hash mismatched")
            service = probe["service"]
            if (
                service.get("Result") != "success"
                or service.get("ExecMainStatus") != "0"
            ):
                raise AssertionError("dstack-prepare did not finish successfully")
            if not probe["absent_optional_preserved"]:
                raise AssertionError("absent optional path unexpectedly materialized")
            if sorted(probe["host_inputs"]) != sorted(
                capability["expected_host_share_inputs"]
            ):
                raise AssertionError("host-share inventory mismatched fixture contract")
            source = (
                pathlib.Path(runtime["repository"])
                / "dstack/dstack-util/src/system_setup.rs"
            ).read_text()
            guards = [
                "HOST_SHARED_DIR_NAME",
                'join("agent.json")',
                'HostShared::copy("/tmp/.host-shared".as_ref()',
            ]
            if any(guard not in source for guard in guards):
                raise AssertionError("candidate source lacks materialization guards")
            observations.update(
                {
                    "host_inputs": probe["host_inputs"],
                    "consumer_files": probe["consumer_files"],
                    "compose_keys": probe["compose_keys"],
                    "user_config_keys": probe["user_config_keys"],
                    "agent_keys": probe["agent_keys"],
                    "environment_marker_matches": True,
                    "service": service,
                    "absent_optional_preserved": True,
                    "source_guards": len(guards),
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
        "path": "artifacts/configuration-materialization.json",
        "step_id": f"{case_id}-step-01",
        "name": "Configuration materialization metadata",
        "description": "Metadata, field names, service state, and marker hash match only; no values.",
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
                    "observed": "Lease capability, input inventory, and prepare service state were checked.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "File ownership, modes, types, and JSON field names were checked.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Marker hash, absent optional input, source guards, and health were checked without values.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Fixture-owned cleanup; read-only inspection never records configuration values.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
