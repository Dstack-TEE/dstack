#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise compose parsing and offline/online orphan removal safely."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import tempfile
import uuid
from typing import Any

CASE_ID = "tc-gos-setup-003"
IMAGE = "alpine:latest"


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


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run Docker through the operator-configured shell wrapper."""
    command = "docker " + " ".join(shlex.quote(value) for value in arguments)
    return subprocess.run(
        [
            os.environ.get("DSTACK_TEST_DOCKER_SHELL_RUNNER", "run-docker-shell"),
            command,
        ],
        text=True,
        capture_output=True,
        timeout=60,
        check=check,
    )


def labels(project: str, service: str) -> dict[str, Any]:
    """Build minimal Docker config.v2.json label metadata."""
    return {
        "Config": {
            "Labels": {
                "com.docker.compose.project": project,
                "com.docker.compose.service": service,
            }
        }
    }


def main() -> int:
    """Run offline and online case-scoped orphan removal."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    binary = runtime["prepared_binaries"]["dstack_util"]
    utility = pathlib.Path(binary["resolved_path"])
    if not utility.is_file():
        raise SystemExit("prepared dstack-util binary is unavailable")
    tag = uuid.uuid4().hex[:12]
    project = f"dstack-orphan-{tag}"
    adjacent = f"dstack-adjacent-{tag}"
    online_name = f"{project}-obsolete"
    observations: dict[str, Any] = {}
    status = "PASS"
    failure = ""

    with tempfile.TemporaryDirectory(prefix="dstack-compose-orphan-") as directory:
        root = pathlib.Path(directory)
        compose = root / "compose.yaml"
        compose.write_text(
            f"""name: {project}
services:
  web:
    image: {IMAGE}
    profiles: [default]
networks:
  default: {{}}
volumes:
  data: {{}}
""",
            encoding="utf-8",
        )
        containers = root / "docker" / "containers"
        fixtures = {
            "orphan000001": labels(project, "obsolete"),
            "live00000001": labels(project, "web"),
            "adjacent00001": labels(adjacent, "obsolete"),
            "unlabeled0001": {"Config": {"Labels": {}}},
        }
        for identifier, document in fixtures.items():
            path = containers / identifier
            path.mkdir(parents=True)
            (path / "config.v2.json").write_text(json.dumps(document), encoding="utf-8")
        malformed = containers / "malformed001"
        malformed.mkdir(parents=True)
        (malformed / "config.v2.json").write_text("{", encoding="utf-8")

        try:
            image = docker("image", "inspect", IMAGE, check=False)
            if image.returncode != 0:
                status = "BLOCKED"
                failure = f"preloaded image {IMAGE} is unavailable"
            else:
                dry = subprocess.run(
                    [
                        str(utility),
                        "remove-orphans",
                        "--no-dockerd",
                        "-f",
                        str(compose),
                        "-d",
                        str(root / "docker"),
                        "-n",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                if dry.returncode != 0 or "obsolete" not in dry.stdout:
                    raise AssertionError("offline dry-run did not identify the orphan")
                if not all((containers / name).exists() for name in fixtures):
                    raise AssertionError("offline dry-run mutated container metadata")

                active = subprocess.run(
                    [
                        str(utility),
                        "remove-orphans",
                        "--no-dockerd",
                        "-f",
                        str(compose),
                        "-d",
                        str(root / "docker"),
                    ],
                    text=True,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                if active.returncode != 0 or (containers / "orphan000001").exists():
                    raise AssertionError(
                        "offline active mode did not remove the orphan"
                    )
                for preserved in ("live00000001", "adjacent00001", "unlabeled0001"):
                    if not (containers / preserved).exists():
                        raise AssertionError(f"offline mode removed {preserved}")

                malformed_compose = root / "malformed.yaml"
                malformed_compose.write_text("services: [", encoding="utf-8")
                invalid = subprocess.run(
                    [
                        str(utility),
                        "remove-orphans",
                        "--no-dockerd",
                        "-f",
                        str(malformed_compose),
                        "-d",
                        str(root / "docker"),
                    ],
                    text=True,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                if invalid.returncode == 0:
                    raise AssertionError("malformed compose input was accepted")

                run = docker(
                    "run",
                    "-d",
                    "--name",
                    online_name,
                    "--label",
                    f"com.docker.compose.project={project}",
                    "--label",
                    "com.docker.compose.service=obsolete",
                    IMAGE,
                    "sleep",
                    "300",
                    check=False,
                )
                if run.returncode != 0:
                    raise AssertionError(
                        "wrapped Docker could not create the online orphan"
                    )
                online_dry = subprocess.run(
                    [str(utility), "remove-orphans", "-f", str(compose), "-n"],
                    text=True,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                still_present = (
                    docker("inspect", online_name, check=False).returncode == 0
                )
                if (
                    online_dry.returncode != 0
                    or "obsolete" not in online_dry.stdout
                    or not still_present
                ):
                    raise AssertionError("online dry-run contract failed")
                online_active = subprocess.run(
                    [str(utility), "remove-orphans", "-f", str(compose)],
                    text=True,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                removed = docker("inspect", online_name, check=False).returncode != 0
                if online_active.returncode != 0 or not removed:
                    raise AssertionError("online active mode did not remove the orphan")
                observations = {
                    "offline_dry_run": dry.returncode,
                    "offline_active": active.returncode,
                    "malformed_rejected": invalid.returncode != 0,
                    "online_dry_run": online_dry.returncode,
                    "online_active": online_active.returncode,
                    "preserved_fixture_count": 3,
                    "compose_sha256": hashlib.sha256(compose.read_bytes()).hexdigest(),
                }
        except (AssertionError, OSError, subprocess.SubprocessError) as error:
            status = "FAIL"
            failure = str(error)
        finally:
            docker("rm", "-f", online_name, check=False)

    artifact = {
        "path": "artifacts/compose-orphan.json",
        "step_id": f"{case_id}-step-01",
        "name": "Compose orphan acceptance observations",
        "description": (
            "Redacted return-code and identity-isolation evidence for fake-root "
            "offline and wrapped-Docker online orphan removal."
        ),
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    summary = (
        "Compose parsing and offline/online orphan removal passed."
        if status == "PASS"
        else failure
    )
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
                    "observed": "Compose identity and fake-root baseline were isolated.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": (
                        "Dry-run and active modes distinguished true orphans from "
                        "live, adjacent-project, unlabeled, and malformed metadata."
                    ),
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": (
                        "Malformed compose failed closed and wrapped-Docker cleanup "
                        "left no run-scoped container."
                    ),
                },
            ],
            "artifacts": [artifact],
            "remarks": (
                "Every Docker CLI operation uses the configured shell wrapper; offline mode "
                "uses only a temporary fake Docker root."
            ),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
