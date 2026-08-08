#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify Gateway's current on-demand TLS-key artifact safety model."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import time
from typing import Any

import tomllib

CASE_ID = "tc-gw-internal-002"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def replace_path(text: str, section: str, field: str, new: pathlib.Path) -> str:
    """Replace one path field within an unambiguous TOML section."""
    lines = text.splitlines(keepends=True)
    current = ""
    matches: list[int] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
        elif current == section and stripped.split("=", 1)[0].strip() == field:
            matches.append(index)
    if len(matches) != 1:
        raise AssertionError(f"TLS {section}.{field} field was ambiguous")
    ending = "\n" if lines[matches[0]].endswith("\n") else ""
    lines[matches[0]] = f'{field} = "{new}"{ending}'
    return "".join(lines)


def main() -> int:
    """Check removal, live artifacts, and dependency-failure publication safety."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    gateway = values["gateway"]
    workspace = pathlib.Path(values["component_substrate"]["workspace"])
    repository = pathlib.Path(runtime["repository"])
    binary = pathlib.Path(values["prepared_binaries"]["dstack_gateway"]["path"])
    config_path = pathlib.Path(gateway["config"])
    config_text = config_path.read_text()
    config = tomllib.loads(config_text)
    tls = config["tls"]
    debug = config["core"]["debug"]
    legacy_source = repository / "dstack/gateway/src/gen_debug_key.rs"
    legacy_binary = pathlib.Path(runtime["cargo_target_dir"]) / "release/gen_debug_key"
    live_paths = [
        pathlib.Path(tls["key"]),
        pathlib.Path(tls["certs"]),
        pathlib.Path(tls["mutual"]["ca_certs"]),
    ]
    failure_dir = workspace / "data/on-demand-tls-failure"
    failure_dir.mkdir(parents=True, exist_ok=False)
    failure_paths = [
        failure_dir / "gateway.key",
        failure_dir / "gateway.cert",
        failure_dir / "gateway-ca.cert",
    ]
    failure_config = workspace / "config/gateway-on-demand-failure.toml"
    failure_text = replace_path(config_text, "tls", "key", failure_paths[0])
    failure_text = replace_path(failure_text, "tls", "certs", failure_paths[1])
    failure_text = replace_path(
        failure_text,
        "tls.mutual",
        "ca_certs",
        failure_paths[2],
    )
    failure_config.write_text(failure_text)
    environment = {
        **os.environ,
        "DSTACK_AGENT_ADDRESS": f"unix:{failure_dir / 'absent-agent.sock'}",
    }
    status = "FAIL"
    summary = "Gateway on-demand TLS-key matrix did not complete"
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    try:
        failed = subprocess.run(
            [str(binary), "--config", str(failure_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=15,
            check=False,
        )
        live_modes = [stat.S_IMODE(path.stat().st_mode) for path in live_paths]
        source_main = (repository / "dstack/gateway/src/main.rs").read_text()
        checks = {
            "legacy_generator_source_absent": not legacy_source.exists(),
            "legacy_generator_binary_absent": not legacy_binary.exists(),
            "legacy_debug_key_config_absent": "key_file" not in debug,
            "legacy_kms_config_absent": "kms_url" not in config["core"],
            "on_demand_guest_rpc_present": "get_tls_key(GetTlsKeyArgs" in source_main,
            "live_tls_artifacts_complete": all(
                path.is_file() and path.stat().st_size > 0 for path in live_paths
            ),
            "live_tls_artifacts_restricted": live_modes == [0o600, 0o600, 0o600],
            "dependency_failure_rejected": failed.returncode != 0,
            "dependency_failure_published_nothing": not any(
                path.exists() for path in failure_paths
            ),
            "legacy_artifact_not_published": not list(
                workspace.glob("**/debug_key.json")
            ),
            "temporary_files_removed": not list(failure_dir.glob(".*.tmp")),
        }
        if not all(checks.values()):
            raise AssertionError(
                "on-demand TLS-key checks failed: "
                f"{sorted(key for key, value in checks.items() if not value)}"
            )
        observation = {
            "candidate_commit": runtime["candidate_commit"],
            "checks": checks,
            "live_artifact_count": len(live_paths),
            "live_artifact_modes": live_modes,
            "dependency_failure_returncode_nonzero": failed.returncode != 0,
            "failure_artifact_count": sum(path.exists() for path in failure_paths),
        }
        evidence_path = result_dir / "artifacts/gateway-on-demand-tls-key.json"
        atomic_json(evidence_path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-on-demand-tls-key.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "Gateway on-demand TLS-key safety matrix",
                "description": "Architecture flags, return-code class, permissions, and counts only; no key, certificate, endpoint, path, credential, or native output is retained.",
            }
        )
        steps = [
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The candidate has no legacy debug-key generator, binary, configuration, or published artifact.",
            },
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "The live Gateway obtained three complete TLS artifacts from DstackGuest and restricted each to mode 0600.",
            },
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "An unavailable DstackGuest dependency caused startup failure before any destination TLS artifact was published.",
            },
            {
                "id": f"{CASE_ID}-step-04",
                "status": "PASS",
                "observed": "No legacy debug-key artifact, partial destination, temporary file, or private value entered case evidence.",
            },
        ]
        status = "PASS"
        summary = "Gateway on-demand DstackGuest TLS-key generation, restricted publication, legacy removal, dependency failure, and redaction passed."
    except Exception as error:  # noqa: BLE001
        steps = [
            {
                "id": f"{CASE_ID}-step-{number:02d}",
                "status": "FAIL" if number == 1 else "NOT_RUN",
                "observed": str(error) if number == 1 else "Not run after failure.",
            }
            for number in range(1, 5)
        ]
        summary = f"Gateway on-demand TLS-key matrix failed: {error}"
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    evidence = [
        {
            "path": item["path"],
            "sha256": hashlib.sha256((result_dir / item["path"]).read_bytes()).hexdigest(),
        }
        for item in artifacts
    ]
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "evidence": evidence,
            "remarks": "No private key, certificate, simulator address, path, credential, environment value, or native process output is retained.",
            "duration_seconds": round(time.monotonic() - started, 3),
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
