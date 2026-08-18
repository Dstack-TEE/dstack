#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare case-owned v0.5.7 bridge and candidate KMS OCI images."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shlex
import socket
import subprocess


def run(
    command: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 1800,
) -> str:
    """Run one bounded build/preparation command."""
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed rc={completed.returncode}: {' '.join(command)}\n{completed.stdout[-4000:]}"
        )
    return completed.stdout


def docker(command: str, timeout: int = 1800) -> str:
    """Run Docker through the operator-configured shell wrapper."""
    return run(
        [
            os.environ.get("DSTACK_TEST_DOCKER_SHELL_RUNNER", "run-docker-shell"),
            f"docker {command}",
        ],
        timeout=timeout,
    )


def free_port() -> int:
    """Reserve a loopback port long enough to choose a registry listener."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def sha256(path: pathlib.Path) -> str:
    """Hash a prepared public binary artifact."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    """Build pinned binaries, publish images, and emit a bounded cleanup handle."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--workspace", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--include-gateway", action="store_true")
    args = parser.parse_args()
    runtime = json.loads(args.runtime_manifest.read_text())
    candidate_repo = pathlib.Path(runtime["repository"]).resolve()
    candidate_commit = str(runtime["candidate_commit"])
    candidate_head = run(
        ["git", "rev-parse", "HEAD"], cwd=candidate_repo, timeout=30
    ).strip()
    if candidate_head != candidate_commit:
        raise RuntimeError(
            "stale runtime manifest: candidate repository HEAD "
            f"{candidate_head} != recorded commit {candidate_commit}"
        )
    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    context = workspace / "upgrade-images"
    context.mkdir(exist_ok=True)
    worktree = candidate_repo.parent / "kms-upgrade-v057"
    expected_bridge = run(
        ["git", "rev-parse", "v0.5.7^{commit}"], cwd=candidate_repo, timeout=30
    ).strip()
    if worktree.exists():
        observed = run(["git", "rev-parse", "HEAD"], cwd=worktree, timeout=30).strip()
        if observed != expected_bridge:
            raise RuntimeError(
                f"v0.5.7 worktree mismatch: {observed} != {expected_bridge}"
            )
    else:
        run(
            ["git", "worktree", "add", "--detach", str(worktree), expected_bridge],
            cwd=candidate_repo,
            timeout=120,
        )

    cargo_home = str(pathlib.Path.home() / ".cargo")
    base_env = {
        **os.environ,
        "PATH": f"{cargo_home}/bin:{os.environ.get('PATH', '')}",
        "RUSTUP_TOOLCHAIN": "1.92.0",
    }
    bridge_target = workspace.parent.parent / "version-cache/targets/v0.5.7"
    bridge_env = {**base_env, "CARGO_TARGET_DIR": str(bridge_target)}
    run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "--target",
            "x86_64-unknown-linux-musl",
            "-p",
            "dstack-kms",
        ],
        cwd=worktree,
        env=bridge_env,
    )
    candidate_target = pathlib.Path(runtime["cargo_target_dir"])
    candidate_env = {**base_env, "CARGO_TARGET_DIR": str(candidate_target)}
    historical_gateway_binary = None
    historical_gateway_source = None
    if args.include_gateway:
        historical_gateway_source = candidate_repo.parent / "gateway-upgrade-v0511"
        expected_gateway = run(
            ["git", "rev-parse", "v0.5.11^{commit}"], cwd=candidate_repo, timeout=30
        ).strip()
        if historical_gateway_source.exists():
            observed = run(
                ["git", "rev-parse", "HEAD"],
                cwd=historical_gateway_source,
                timeout=30,
            ).strip()
            if observed != expected_gateway:
                raise RuntimeError(
                    f"v0.5.11 Gateway worktree mismatch: {observed} != {expected_gateway}"
                )
        else:
            run(
                [
                    "git",
                    "worktree",
                    "add",
                    "--detach",
                    str(historical_gateway_source),
                    expected_gateway,
                ],
                cwd=candidate_repo,
                timeout=120,
            )
        historical_gateway_target = (
            workspace.parent.parent / "version-cache/targets/v0.5.11"
        )
        run(
            [
                "cargo",
                "build",
                "--release",
                "--locked",
                "--target",
                "x86_64-unknown-linux-musl",
                "-p",
                "dstack-gateway",
            ],
            cwd=historical_gateway_source,
            env={**base_env, "CARGO_TARGET_DIR": str(historical_gateway_target)},
        )
        historical_gateway_binary = (
            historical_gateway_target
            / "x86_64-unknown-linux-musl/release/dstack-gateway"
        )
    candidate_packages = ["dstack-kms"]
    if args.include_gateway:
        candidate_packages.append("dstack-gateway")
    command = [
        "cargo",
        "build",
        "--release",
        "--locked",
        "--target",
        "x86_64-unknown-linux-musl",
    ]
    for package in candidate_packages:
        command.extend(["-p", package])
    run(command, cwd=candidate_repo / "dstack", env=candidate_env)

    bridge_binary = bridge_target / "x86_64-unknown-linux-musl/release/dstack-kms"
    candidate_binary = candidate_target / "x86_64-unknown-linux-musl/release/dstack-kms"
    bridge_context = context / "bridge"
    candidate_context = context / "candidate"
    bridge_context.mkdir(exist_ok=True)
    candidate_context.mkdir(exist_ok=True)
    (bridge_context / "dstack-kms").write_bytes(bridge_binary.read_bytes())
    (candidate_context / "dstack-kms").write_bytes(candidate_binary.read_bytes())
    (bridge_context / "Dockerfile").write_text(
        "FROM dstacktee/dstack-kms:0.5.8\nCOPY --chmod=0555 dstack-kms /usr/local/bin/dstack-kms\n"
    )
    (candidate_context / "Dockerfile").write_text(
        "FROM dstacktee/dstack-kms:0.5.11\nCOPY --chmod=0555 dstack-kms /usr/local/bin/dstack-kms\n"
    )

    port = free_port()
    suffix = hashlib.sha256(str(workspace).encode()).hexdigest()[:12]
    registry = f"dstack-upgrade-registry-{suffix}"
    docker(f"rm -f {shlex.quote(registry)}", timeout=60) if subprocess.run(
        [
            os.environ.get("DSTACK_TEST_DOCKER_SHELL_RUNNER", "run-docker-shell"),
            f"docker inspect {shlex.quote(registry)}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0 else None
    docker(
        f"run -d --name {shlex.quote(registry)} -p 127.0.0.1:{port}:5000 registry:2",
        timeout=180,
    )
    host_prefix = f"127.0.0.1:{port}/dstack-kms"
    guest_prefix = f"10.0.2.2:{port}/dstack-kms"
    bridge_tag = f"{host_prefix}:0.5.7-bridge"
    candidate_tag = f"{host_prefix}:candidate-{candidate_commit[:12]}"
    docker(f"build -t {shlex.quote(bridge_tag)} {shlex.quote(str(bridge_context))}")
    docker(
        f"build -t {shlex.quote(candidate_tag)} {shlex.quote(str(candidate_context))}"
    )
    docker(f"push {shlex.quote(bridge_tag)}")
    docker(f"push {shlex.quote(candidate_tag)}")
    candidate_gateway_tag = ""
    candidate_gateway_sha256 = ""
    historical_gateway_tag = ""
    historical_gateway_sha256 = ""
    if args.include_gateway:
        assert historical_gateway_binary is not None
        assert historical_gateway_source is not None
        historical_gateway_context = context / "historical-gateway"
        historical_gateway_context.mkdir(exist_ok=True)
        (historical_gateway_context / "dstack-gateway").write_bytes(
            historical_gateway_binary.read_bytes()
        )
        historical_gateway_entrypoint = (
            historical_gateway_source / "gateway/dstack-app/builder/entrypoint.sh"
        )
        (historical_gateway_context / "entrypoint.sh").write_bytes(
            historical_gateway_entrypoint.read_bytes()
        )
        (historical_gateway_context / "Dockerfile").write_text(
            "FROM dstacktee/dstack-gateway:0.5.8\n"
            "COPY --chmod=0555 dstack-gateway /usr/local/bin/dstack-gateway\n"
            "COPY --chmod=0555 entrypoint.sh /app/entrypoint.sh\n"
        )
        historical_gateway_tag = f"127.0.0.1:{port}/dstack-gateway:historical-v0.5.11"
        docker(
            f"build -t {shlex.quote(historical_gateway_tag)} "
            f"{shlex.quote(str(historical_gateway_context))}"
        )
        docker(f"push {shlex.quote(historical_gateway_tag)}")
        historical_gateway_sha256 = sha256(historical_gateway_binary)
        candidate_gateway_binary = (
            candidate_target / "x86_64-unknown-linux-musl/release/dstack-gateway"
        )
        gateway_context = context / "candidate-gateway"
        gateway_context.mkdir(exist_ok=True)
        (gateway_context / "dstack-gateway").write_bytes(
            candidate_gateway_binary.read_bytes()
        )
        candidate_gateway_entrypoint = (
            candidate_repo / "dstack/gateway/dstack-app/builder/entrypoint.sh"
        )
        (gateway_context / "entrypoint.sh").write_bytes(
            candidate_gateway_entrypoint.read_bytes()
        )
        (gateway_context / "Dockerfile").write_text(
            "FROM dstacktee/dstack-gateway:0.5.8\n"
            "COPY --chmod=0555 dstack-gateway /usr/local/bin/dstack-gateway\n"
            "COPY --chmod=0555 entrypoint.sh /app/entrypoint.sh\n"
        )
        candidate_gateway_tag = (
            f"127.0.0.1:{port}/dstack-gateway:candidate-{candidate_commit[:12]}"
        )
        docker(
            f"build -t {shlex.quote(candidate_gateway_tag)} "
            f"{shlex.quote(str(gateway_context))}"
        )
        docker(f"push {shlex.quote(candidate_gateway_tag)}")
        candidate_gateway_sha256 = sha256(candidate_gateway_binary)
    value = {
        "schema_version": "1.0",
        "candidate_commit": candidate_commit,
        "bridge_commit": expected_bridge,
        "registry_container": registry,
        "registry_host": f"127.0.0.1:{port}",
        "registry_guest": f"10.0.2.2:{port}",
        "bridge_image": f"{guest_prefix}:0.5.7-bridge",
        "candidate_image": f"{guest_prefix}:candidate-{candidate_commit[:12]}",
        "bridge_binary_sha256": sha256(bridge_binary),
        "candidate_binary_sha256": sha256(candidate_binary),
    }
    if args.include_gateway:
        value.update(
            {
                "old_gateway_image": "dstacktee/dstack-gateway:0.5.8",
                "gateway_0_5_11_image": historical_gateway_tag.replace(
                    "127.0.0.1", "10.0.2.2", 1
                ),
                "gateway_0_5_11_binary_sha256": historical_gateway_sha256,
                "candidate_gateway_image": candidate_gateway_tag.replace(
                    "127.0.0.1", "10.0.2.2", 1
                ),
                "candidate_gateway_binary_sha256": candidate_gateway_sha256,
            }
        )
    args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
