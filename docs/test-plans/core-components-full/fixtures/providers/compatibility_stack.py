#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Case-owned current KMS, Gateway, and VMM stack for version matrices."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tarfile
from types import ModuleType
from typing import Any


def load_provider(name: str) -> ModuleType:
    """Load a sibling provider whose filename is not an importable module name."""
    path = pathlib.Path(__file__).resolve().parent / name
    spec = importlib.util.spec_from_file_location(f"dstack_test_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load provider helper: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def start(
    workspace: pathlib.Path,
    lease_id: str,
    runtime: dict[str, Any],
    runtime_manifest: pathlib.Path,
    images: list[str],
) -> dict[str, Any]:
    """Start one lease-owned dependency stack and return public fixture handles."""
    tdx = load_provider("tdxlab-isolated.py")
    isolated = load_provider("isolated-component.py")
    repository = pathlib.Path(str(runtime["repository"])).resolve()
    image_store = pathlib.Path(os.environ["DSTACK_TEST_IMAGE_STORE"]).resolve()
    vmm_cli = repository / "dstack/vmm/src/vmm-cli.py"
    settings = {
        "runtime": runtime,
        "runtime_manifest": runtime_manifest,
        "repository": repository,
        "image_store": image_store,
        "image": images[-1],
        "cli": vmm_cli,
    }
    seed = secrets.token_hex(32)
    collateral_port, kms_port, onboard_port, admin_port = tdx.reserve_ports(4)
    kms_output = workspace / "case-kms.json"
    kms_state = workspace / "case-kms"
    helper = repository / (
        "docs/test-plans/core-components-full/automation/start-mkosi-kms-fixture.py"
    )
    completed = subprocess.run(
        [
            str(helper),
            "--runtime-manifest",
            str(runtime_manifest),
            "--state",
            str(kms_state),
            "--seed",
            seed,
            "--collateral-port",
            str(collateral_port),
            "--kms-port",
            str(kms_port),
            "--onboard-port",
            str(onboard_port),
            "--admin-port",
            str(admin_port),
            "--output",
            str(kms_output),
            "--guest-attestation",
            "hardware",
            "--rpc-attestation",
            "compatibility-unverified",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"case KMS failed to start: {completed.stderr[-1000:]}")
    kms = json.loads(kms_output.read_text(encoding="utf-8"))
    handle: dict[str, Any] | None = None
    try:
        handle = tdx.start_vmm(
            workspace,
            lease_id,
            settings,
            "compatibility-matrix",
            simulator_seed="",
            simulator_collateral_url="",
            simulator_tdx_root_ca="",
            extra_images=images,
            allow_udp_port_mapping=True,
        )
        simulator = json.loads(
            pathlib.Path(str(kms["simulator_fixture"])).read_text(encoding="utf-8")
        )
        gateway_workspace = workspace / "gateway"
        for name in ("config", "data", "logs", "run"):
            (gateway_workspace / name).mkdir(parents=True, exist_ok=True)
        identity = isolated.generate_simulator_client_identity(
            simulator,
            gateway_workspace / "data/identity",
            alt_names=["localhost", "10.0.2.2"],
        )
        # Guests authenticate to Gateway with app certificates signed by this
        # case KMS root. Keep the Gateway server identity, but use that app root
        # as the inbound mTLS trust anchor.
        gateway_identity = {
            **identity,
            "ca_cert": str(kms_state / "certs/root-ca.crt"),
        }
        gateway_ports = dict(
            zip(
                ("rpc", "admin", "debug", "proxy"),
                tdx.reserve_ports(4),
                strict=True,
            )
        )
        gateway_config = gateway_workspace / "config/gateway.toml"
        isolated.write_gateway_config(
            repository / "dstack/gateway/gateway.toml",
            gateway_config,
            gateway_workspace,
            gateway_ports,
            secrets.token_hex(32),
            tls_identity=gateway_identity,
        )
        wg_private = subprocess.run(
            ["wg", "genkey"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=True,
        ).stdout.strip()
        wg_public = subprocess.run(
            ["wg", "pubkey"],
            input=wg_private + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=True,
        ).stdout.strip()
        gateway_text = gateway_config.read_text(encoding="utf-8")
        if (
            gateway_text.count('public_key = ""') != 1
            or gateway_text.count('private_key = ""') != 1
        ):
            raise RuntimeError("Gateway fixture WireGuard key fields are not unique")
        gateway_config.write_text(
            gateway_text.replace(
                'public_key = ""', f'public_key = "{wg_public}"', 1
            ).replace('private_key = ""', f'private_key = "{wg_private}"', 1),
            encoding="utf-8",
        )
        gateway_config.chmod(0o600)
        gateway_binary = pathlib.Path(
            str(runtime["prepared_binaries"]["dstack_gateway"]["path"])
        ).resolve()
        gateway = tdx.start_component(
            [str(gateway_binary), "--config", str(gateway_config)],
            gateway_workspace / "logs/gateway.log",
            gateway_ports["rpc"],
            env={
                "DSTACK_AGENT_ADDRESS": (
                    f"unix:{simulator['services']['DstackGuest']['socket']}"
                )
            },
        )
        archive_source = image_store / images[-1]
        checksum = archive_source / "sha256sum.txt"
        digest = (archive_source / "digest.txt").read_text().strip()
        archive_root = workspace / "image-archives"
        archive_root.mkdir()
        archive_path = archive_root / f"{digest}.tar.gz"
        members = ["sha256sum.txt"]
        members.extend(
            line.split()[1].lstrip("*")
            for line in checksum.read_text().splitlines()
            if line.split()
        )
        with tarfile.open(archive_path, "w:gz") as archive:
            for member in members:
                archive.add(archive_source / member, arcname=member)
        archive_port = tdx.reserve_ports(1)[0]
        policy_path = workspace / "kms-upgrade-policy.json"
        policy_path.write_text(
            json.dumps(
                {
                    context: {
                        "allowedMrAggregated": [],
                        "allowedOsImageHashes": [],
                        "denyAll": True,
                    }
                    for context in ("source", "target")
                },
                indent=2,
            )
            + "\n"
        )
        observations_path = workspace / "kms-upgrade-policy-observations.jsonl"
        observations_path.touch()
        server_script = (
            repository
            / "docs/test-plans/core-components-full/automation/kms-upgrade-fixture-server.py"
        )
        archive_server = tdx.start_component(
            [
                sys.executable,
                str(server_script),
                "--port",
                str(archive_port),
                "--directory",
                str(archive_root),
                "--policy",
                str(policy_path),
                "--observations",
                str(observations_path),
            ],
            workspace / "logs/image-archive.log",
            archive_port,
        )
        proxy_script = (
            repository
            / "docs/test-plans/core-components-full/automation/kms-upgrade-tcp-proxy.py"
        )
        proxy_ports = tdx.reserve_ports(4)
        proxy_configs: list[pathlib.Path] = []
        proxy_processes = []
        for index, proxy_port in enumerate(proxy_ports):
            proxy_config = workspace / f"kms-upgrade-proxy-{index}.json"
            proxy_config.write_text(
                json.dumps({"enabled": False, "host": "127.0.0.1", "port": 1}, indent=2)
                + "\n"
            )
            proxy_configs.append(proxy_config)
            proxy_processes.append(
                tdx.start_component(
                    [
                        sys.executable,
                        str(proxy_script),
                        "--port",
                        str(proxy_port),
                        "--config",
                        str(proxy_config),
                    ],
                    workspace / f"logs/kms-upgrade-proxy-{index}.log",
                    proxy_port,
                )
            )
        handle["pids"].extend([int(pid) for pid in kms["pids"]])
        handle["pids"].extend(
            [gateway.pid, archive_server.pid, *(item.pid for item in proxy_processes)]
        )
        handle["extra_paths"] = [str(kms["simulator_runtime"])]
        return {
            "vmm_url": str(handle["url"]),
            "kms_guest_url": str(kms["guest_url"]),
            "gateway_guest_url": f"https://10.0.2.2:{gateway_ports['rpc']}",
            "image_archive_guest_url": f"http://10.0.2.2:{archive_port}/{{OS_IMAGE_HASH}}.tar.gz",
            "image_archive_digest": digest,
            "kms_upgrade_policy_guest_urls": {
                context: f"http://10.0.2.2:{archive_port}/{context}"
                for context in ("source", "target")
            },
            "kms_upgrade_policy_path": str(policy_path),
            "kms_upgrade_policy_observations": str(observations_path),
            "kms_upgrade_proxies": [
                {
                    "port": port,
                    "guest_url": f"https://10-0-2-2.sslip.io:{port}",
                    "config": str(config),
                }
                for port, config in zip(proxy_ports, proxy_configs, strict=True)
            ],
            "image_archive_path": str(archive_path),
            "port_mapping": {
                "protocol": "tcp",
                "from": tdx.PORT_MAPPING_START,
                "to": tdx.PORT_BLOCK_END,
            },
            "handle": handle,
            "logs": {
                "vmm": str(handle["log"]),
                "kms": str(kms["kms_log"]),
                "gateway": str(gateway_workspace / "logs/gateway.log"),
            },
        }
    except BaseException:
        if handle is None:
            tdx.terminate_pids({int(pid) for pid in kms.get("pids", [])})
        else:
            handle.setdefault("pids", []).extend(
                int(pid) for pid in kms.get("pids", [])
            )
            handle["extra_paths"] = [str(kms.get("simulator_runtime", ""))]
            tdx.release_vmm(handle, workspace)
        raise


def stop(workspace: pathlib.Path, handle: dict[str, Any]) -> None:
    """Stop every process and remove all VM state owned by the stack."""
    load_provider("tdxlab-isolated.py").release_vmm(handle, workspace)
