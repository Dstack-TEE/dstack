#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Allocate a case-owned local substrate for component integration tests."""
# ruff: noqa: D103

from __future__ import annotations

import atexit
import base64
import hashlib
import io
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

from image_provenance import require_image_backend
from vmm_fixture import (
    fail,
    link_image_store,
    reserve_ports,
    serialize_port_provisioning,
    start_component,
    terminate_pids,
    wait_port,
    write_vmm_config,
)

STATE_ROOT = Path(
    os.environ.get("DSTACK_TEST_STATE_ROOT", "").strip()
    or str(Path.home() / ".cache/dstack-test/runtime-state")
)
ROOT = STATE_ROOT / "component-fixtures"
GUEST_CONTAINER_IMAGE = "ubuntu:latest"
GUEST_CONTAINER_ARCHIVE = (
    Path.home() / ".cache/dstack-test/fixture-images/isolated-guest-ubuntu.tar"
)


def start_guest_image_server(
    workspace: Path,
) -> tuple[subprocess.Popen[str], str]:
    """Serve a host-cached container image to lease-owned guests."""
    GUEST_CONTAINER_ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
    if not GUEST_CONTAINER_ARCHIVE.is_file():
        temporary = GUEST_CONTAINER_ARCHIVE.with_suffix(f".tmp-{os.getpid()}")
        command = f"docker save --output {temporary} {GUEST_CONTAINER_IMAGE}"
        exported = subprocess.run(
            ["sudo", "su", "kvin", "-c", command],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        if exported.returncode:
            temporary.unlink(missing_ok=True)
            fail(
                "failed to export prepared guest container image: "
                f"{exported.stderr[-500:]}"
            )
        temporary.replace(GUEST_CONTAINER_ARCHIVE)
    server_root = workspace / "guest-image-http"
    server_root.mkdir()
    (server_root / "fixture-image.tar").symlink_to(GUEST_CONTAINER_ARCHIVE)
    port = reserve_ports(1)[0]
    process = start_component(
        [
            sys.executable,
            "-m",
            "http.server",
            str(port),
            "--bind",
            "127.0.0.1",
            "--directory",
            str(server_root),
        ],
        workspace / "logs/guest-image-http.log",
        port,
    )
    return process, f"http://10.0.2.2:{port}"


def endpoint_ready(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def write_kms_config(
    path: Path,
    cert_dir: Path,
    rpc_port: int,
    onboard_port: int,
    admin_port: int,
    admin_token: str,
    auto_bootstrap: bool,
    mutual_ca_cert: Path | None = None,
    attestation_root: Path | None = None,
    collateral_url: str = "",
    historical_keys: list[tuple[Path, Path]] | None = None,
) -> None:
    client_ca = mutual_ca_cert or cert_dir / "tmp-ca.crt"
    attestation = ""
    if attestation_root is not None:
        attestation = f'''
[core.attestation]
insecure_allow_external_trust_anchors = true
[core.attestation.urls]
pccs = "{collateral_url}"
[core.attestation.root_ca]
tdx = "{attestation_root}"
'''
    historical = "".join(
        f'[[core.historical_keys]]\nca_key = "{ca_key}"\nk256_key = "{k256_key}"\n'
        for ca_key, k256_key in (historical_keys or [])
    )
    path.write_text(
        f'''[rpc]
address = "127.0.0.1"
port = {rpc_port}
[rpc.tls]
key = "{cert_dir / "rpc.key"}"
certs = "{cert_dir / "rpc.crt"}"
[rpc.tls.mutual]
ca_certs = "{client_ca}"
mandatory = false
[core]
cert_dir = "{cert_dir}"
{historical}enforce_self_authorization = false
[core.image]
verify = false
cache_dir = "{cert_dir.parent / "image-cache"}"
download_url = "http://127.0.0.1:1/{{OS_IMAGE_HASH}}.tar.gz"
download_timeout = "2s"
[core.metrics]
enabled = true
[core.admin]
enabled = true
address = "127.0.0.1"
port = {admin_port}
auth_token = "{admin_token}"
[core.auth_api]
type = "dev"
[core.auth_api.dev]
gateway_app_id = "any"
[core.onboard]
enabled = true
auto_bootstrap_domain = "{"localhost" if auto_bootstrap else ""}"
address = "127.0.0.1"
port = {onboard_port}
{attestation}''',
        encoding="utf-8",
    )


def write_gateway_config(
    source: Path,
    destination: Path,
    workspace: Path,
    ports: dict[str, int],
    admin_token: str,
    *,
    sync_node_id: int | None = None,
    sync_bootnode: str = "",
    tls_identity: dict[str, str] | None = None,
    app_address_dns_servers: list[str] | None = None,
    proxy_stress: bool = False,
    fast_recycle: bool = False,
    enable_debug: bool = True,
    exercise_startup: bool = False,
) -> None:
    text = source.read_text(encoding="utf-8")
    replacements = {
        'address = "127.0.0.1:8010"': f'address = "127.0.0.1:{ports["rpc"]}"',
        "set_ulimit = true": (
            "set_ulimit = true" if exercise_startup else "set_ulimit = false"
        ),
        '[core.admin]\nenabled = false\naddress = "127.0.0.1:8011"': f'[core.admin]\nenabled = true\naddress = "127.0.0.1:{ports["admin"]}"',
        'auth_token = ""': f'auth_token = "{admin_token}"',
        "[core.debug]\ninsecure_enable_debug_rpc = false\ninsecure_skip_attestation = false": (
            "[core.debug]\ninsecure_enable_debug_rpc = true\ninsecure_skip_attestation = true"
            if enable_debug
            else "[core.debug]\ninsecure_enable_debug_rpc = false\ninsecure_skip_attestation = false"
        ),
        'address = "127.0.0.1:8012"': f'address = "127.0.0.1:{ports["debug"]}"',
        'listen_addr = "0.0.0.0"': 'listen_addr = "127.0.0.1"',
        "listen_port = 8443": f"listen_port = {ports['proxy']}",
        'interface = "wg0"': 'interface = "lo"',
        'config_path = "/etc/wireguard/wg0.conf"': f'config_path = "{workspace / "run/wireguard.conf"}"',
        "listen_port = 51820": f"listen_port = {ports['proxy']}",
        'data_dir = "/dstack-gateway/data"': f'data_dir = "{workspace / "data/sync"}"',
    }
    for old, new in replacements.items():
        if old not in text:
            fail(f"candidate Gateway config is missing expected field: {old}")
        text = text.replace(old, new, 1)
    if exercise_startup:
        startup_replacements = {
            'rpc_domain = ""': 'rpc_domain = "localhost"',
        }
        for old, new in startup_replacements.items():
            if old not in text:
                fail(f"candidate Gateway config is missing startup field: {old}")
            text = text.replace(old, new, 1)
    if fast_recycle:
        recycle_replacements = {
            '[core.recycle]\nenabled = true\ninterval = "5m"': '[core.recycle]\nenabled = true\ninterval = "1s"',
            'timeout = "10h"': 'timeout = "2s"',
        }
        for old, new in recycle_replacements.items():
            if old not in text:
                fail(f"candidate Gateway config is missing recycle field: {old}")
            text = text.replace(old, new, 1)
    if proxy_stress:
        stress_replacements = {
            "max_connections_per_app = 2000": "max_connections_per_app = 2",
            'handshake = "5s"': 'handshake = "1s"',
            'idle = "10m"': 'idle = "1s"',
            'write = "5s"': 'write = "1s"',
            'shutdown = "5s"': 'shutdown = "1s"',
            'total = "5h"': 'total = "3s"',
        }
        for old, new in stress_replacements.items():
            if old not in text:
                fail(f"candidate Gateway config is missing stress field: {old}")
            text = text.replace(old, new, 1)
    if sync_node_id is not None:
        sync_replacements = {
            "[core.sync]\nenabled = false": "[core.sync]\nenabled = true",
            "node_id = 0": f"node_id = {sync_node_id}",
            'my_url = "https://localhost:8011"': (
                f'my_url = "https://localhost:{ports["rpc"]}"'
            ),
            'interval = "1m"': 'interval = "1s"',
            'bootnode = ""': f'bootnode = "{sync_bootnode}"',
            'persist_interval = "5m"': 'persist_interval = "1s"',
        }
        for old, new in sync_replacements.items():
            if old not in text:
                fail(f"candidate Gateway config is missing sync field: {old}")
            text = text.replace(old, new, 1)
    cert_dir = workspace / "data/gateway-certs"
    tls_identity = tls_identity or {
        "key": str(cert_dir / "server.key"),
        "cert": str(cert_dir / "server.crt"),
        "ca_cert": str(cert_dir / "server.crt"),
    }
    proxy_anchor = "[core.proxy]\n"
    if proxy_anchor not in text:
        fail("candidate Gateway config is missing core.proxy section")
    app_address_dns_line = (
        "app_address_dns_servers = ["
        + ", ".join(f'"{server}"' for server in app_address_dns_servers)
        + "]\n"
        if app_address_dns_servers
        else ""
    )
    text = text.replace(
        proxy_anchor,
        proxy_anchor
        + 'base_domain = "localhost"\n'
        + app_address_dns_line
        + f'cert_chain = "{tls_identity["cert"]}"\n'
        + f'cert_key = "{tls_identity["key"]}"\n',
        1,
    )
    text += (
        f'\n[tls]\nkey = "{tls_identity["key"]}"\n'
        f'certs = "{tls_identity["cert"]}"\n'
        f'[tls.mutual]\nca_certs = "{tls_identity["ca_cert"]}"\n'
    )
    destination.write_text(text, encoding="utf-8")


def generate_gateway_cert(cert_dir: Path) -> None:
    cert_dir.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(cert_dir / "server.key"),
            "-out",
            str(cert_dir / "server.crt"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode:
        fail(
            f"failed to generate Gateway fixture certificate: {completed.stderr[-500:]}"
        )


def start_kms(
    binary: Path, config: Path, log: Path, listen_port: int, agent_url: str
) -> subprocess.Popen[str]:
    stream = log.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [str(binary), "--config", str(config)],
        stdout=stream,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
        env={**os.environ, "DSTACK_AGENT_ADDRESS": agent_url},
    )
    wait_port(listen_port, process)
    return process


def generate_simulator_client_identity(
    simulator_values: dict[str, Any],
    destination: Path,
    *,
    usage_ra_tls: bool = False,
    alt_names: list[str] | None = None,
) -> dict[str, str]:
    service = simulator_values.get("services", {}).get("DstackGuest", {})
    socket_path = str(service.get("socket", ""))
    route = str(service.get("route", "")).replace("<Method>", "GetTlsKey")
    if not socket_path or not route:
        fail("simulator fixture does not expose DstackGuest.GetTlsKey")
    request_body = json.dumps(
        {
            "subject": "dstack-test-gateway-client",
            "alt_names": alt_names or ["localhost"],
            "usage_ra_tls": usage_ra_tls,
            "usage_server_auth": True,
            "usage_client_auth": True,
            "with_app_info": True,
        },
        separators=(",", ":"),
    )
    response = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--unix-socket",
            socket_path,
            "--request",
            "POST",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            request_body,
            f"http://localhost{route}",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if response.returncode:
        fail(f"failed to obtain simulator client identity: {response.stderr[-500:]}")
    try:
        identity = json.loads(response.stdout)
        key = str(identity["key"])
        chain = identity["certificate_chain"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        fail(f"invalid simulator client identity response: {error}")
    if (
        not isinstance(chain, list)
        or not chain
        or not all(isinstance(item, str) for item in chain)
    ):
        fail("simulator client certificate chain is empty")
    destination.mkdir(parents=True, exist_ok=True)
    key_path = destination / "client.key"
    cert_path = destination / "client.crt"
    ca_path = destination / "ca.crt"
    key_path.write_text(key, encoding="utf-8")
    cert_path.write_text("\n".join(chain) + "\n", encoding="utf-8")
    ca_path.write_text(chain[-1] + "\n", encoding="utf-8")
    key_path.chmod(0o600)
    cert_path.chmod(0o600)
    ca_path.chmod(0o600)
    return {"key": str(key_path), "cert": str(cert_path), "ca_cert": str(ca_path)}


def query_simulator_app_info(simulator_values: dict[str, Any]) -> dict[str, str]:
    """Return the public app identity exposed by the case-owned simulator."""
    service = simulator_values.get("services", {}).get("DstackGuest", {})
    socket_path = str(service.get("socket", ""))
    route = str(service.get("route", "")).replace("<Method>", "Info")
    if not socket_path or not route:
        fail("simulator fixture does not expose DstackGuest.Info")
    response = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--unix-socket",
            socket_path,
            "--request",
            "POST",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "{}",
            f"http://localhost{route}",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if response.returncode:
        fail(f"failed to query simulator app identity: {response.stderr[-500:]}")
    try:
        info = json.loads(response.stdout)
        app_id = str(info["app_id"])
        instance_id = str(info["instance_id"])
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        fail(f"invalid simulator app identity response: {error}")
    if not app_id or not instance_id:
        fail("simulator app identity is empty")
    return {"app_id": app_id, "instance_id": instance_id}


def register_gateway_fixture(
    rpc_url: str,
    registration_client: dict[str, str],
    simulator_values: dict[str, Any],
    port_policy: dict[str, Any] | None = None,
    client_public_key: str | None = None,
) -> dict[str, str]:
    """Register the simulator identity and return its public identifiers."""
    identity = query_simulator_app_info(simulator_values)
    client_public_key = (
        client_public_key or base64.b64encode(secrets.token_bytes(32)).decode()
    )
    request = {"client_public_key": client_public_key}
    if port_policy is not None:
        request["port_policy"] = port_policy
    request_body = json.dumps(request, separators=(",", ":"))
    response = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--insecure",
            "--cert",
            registration_client["cert"],
            "--key",
            registration_client["key"],
            "--request",
            "POST",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            request_body,
            f"{rpc_url}/Gateway.RegisterCvm?json",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if response.returncode:
        fail(f"failed to register gateway fixture identity: {response.stderr[-500:]}")
    try:
        payload = json.loads(response.stdout)
    except json.JSONDecodeError as error:
        fail(f"invalid gateway registration response: {error}")
    if not isinstance(payload.get("wg"), dict):
        fail("gateway registration response lacks WireGuard configuration")
    client_ip = str(payload["wg"].get("client_ip", ""))
    if not client_ip:
        fail("gateway registration response lacks an assigned client address")
    return {**identity, "client_ip": client_ip, "client_public_key": client_public_key}


def request() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        fail(f"invalid provider request: {error}")
    if not isinstance(value, dict):
        fail("provider request must be an object")
    return value


@serialize_port_provisioning
def prepare(value: dict[str, Any]) -> dict[str, Any]:
    lease = value.get("lease", {})
    lease_id = str(lease.get("lease_id", ""))
    case_id = str(lease.get("case_id", ""))
    requested = value.get("request", {})
    if not lease_id.startswith("lease-") or not case_id:
        fail("lease identity is missing")
    workspace = ROOT / lease_id
    workspace.mkdir(parents=True, exist_ok=False)
    for name in ("config", "data", "logs", "run", "artifacts"):
        (workspace / name).mkdir()
    runtime_path = Path(str(requested.get("_runtime_manifest", ""))).resolve()
    if not runtime_path.is_file():
        shutil.rmtree(workspace, ignore_errors=True)
        fail("runtime manifest is unavailable")
    runtime = json.loads(runtime_path.read_text())
    ports = reserve_ports(17)
    names = (
        "rpc",
        "admin",
        "debug",
        "metrics",
        "proxy",
        "agent",
        "sync",
        "auth",
        "onboard",
        "kms",
        "gateway",
        "verifier",
        "vmm",
        "aux1",
        "aux2",
        "aux3",
        "aux4",
    )
    port_map = dict(zip(names, ports, strict=True))
    values = {
        "component_substrate": {
            "workspace": str(workspace),
            "config_dir": str(workspace / "config"),
            "data_dir": str(workspace / "data"),
            "log_dir": str(workspace / "logs"),
            "run_dir": str(workspace / "run"),
            "ports": port_map,
            "loopback": "127.0.0.1",
            "case_owned": True,
            "destructive_actions_allowed": True,
        },
        "prepared_binaries": runtime.get("prepared_binaries", {}),
        "repository": runtime.get("repository"),
        "cargo_target_dir": runtime.get("cargo_target_dir"),
        # Populate this map only with listeners that this provider actually
        # starts. Reserved ports remain available through component_substrate
        # but must never be mistaken for ready services.
        "services": {},
    }
    pids: list[int] = []
    loopback_alias = ""
    prepare_complete = False

    def rollback_failed_prepare() -> None:
        if prepare_complete:
            return
        terminate_pids(set(pids))
        if loopback_alias:
            subprocess.run(
                [
                    "sudo",
                    "-n",
                    "ip",
                    "address",
                    "delete",
                    f"{loopback_alias}/32",
                    "dev",
                    "lo",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        plan_root = Path(str(requested.get("_plan_root", ""))).resolve()
        stop_helper = plan_root / "automation/stop-simulator.sh"
        for fixture in Path("/tmp").glob(
            f"dstack-test-case-*-{lease_id}/simulator-fixture.json"
        ):
            if stop_helper.is_file():
                subprocess.run(
                    [str(stop_helper), str(fixture)],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
        shutil.rmtree(workspace, ignore_errors=True)

    atexit.register(rollback_failed_prepare)
    if requested.get("profile") == "vmm-empty-control-plane":
        binaries = runtime.get("prepared_binaries", {})
        binary = Path(str(binaries.get("dstack_vmm", {}).get("path", ""))).resolve()
        supervisor = Path(
            str(binaries.get("dstack_supervisor", {}).get("path", ""))
        ).resolve()
        repository = Path(str(runtime.get("repository", ""))).resolve()
        source_config = repository / "dstack/vmm/vmm.toml"
        vmm_cli = repository / "dstack/vmm/src/vmm-cli.py"
        image_store_text = os.environ.get("DSTACK_TEST_IMAGE_STORE", "").strip()
        if (
            not binary.is_file()
            or not supervisor.is_file()
            or not source_config.is_file()
            or not vmm_cli.is_file()
        ):
            shutil.rmtree(workspace, ignore_errors=True)
            fail("prepared VMM, supervisor, or candidate VMM config is unavailable")
        if not image_store_text:
            shutil.rmtree(workspace, ignore_errors=True)
            fail("DSTACK_TEST_IMAGE_STORE is required for the case-owned VMM")
        vm_run_path_target = workspace / "data/vm"
        vm_run_path_target.mkdir()
        runtime_base = Path(
            os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        )
        supervisor_runtime_dir = runtime_base / "dtsv" / lease_id[-12:]
        if supervisor_runtime_dir.exists():
            shutil.rmtree(workspace, ignore_errors=True)
            fail(f"short supervisor runtime already exists: {supervisor_runtime_dir}")
        supervisor_runtime_dir.mkdir(parents=True, mode=0o700)
        supervisor_runtime_dir.chmod(0o700)
        supervisor_socket = supervisor_runtime_dir / "s.sock"
        vm_run_path = Path("/tmp") / f"dv-{lease_id[-12:]}"
        if vm_run_path.exists() or vm_run_path.is_symlink():
            shutil.rmtree(workspace, ignore_errors=True)
            fail(f"short VMM run-path link already exists: {vm_run_path}")
        vm_run_path.symlink_to(vm_run_path_target, target_is_directory=True)
        source_image_store = Path(image_store_text).resolve()
        case_image_store = workspace / "data/images"
        case_image_store.mkdir()
        link_image_store(source_image_store, case_image_store)
        actions = set(requested.get("actions_under_test", []))
        auto_restart_case = "Auto-restart policy and backoff" in actions
        supervisor_client = Path(
            str(binaries.get("supervisor_client", {}).get("path", ""))
        ).resolve()
        if auto_restart_case and not supervisor_client.is_file():
            fail(
                "prepared Supervisor client is required for auto-restart fault injection"
            )
        host_sealing = bool(
            {"HostApi.GetSealingKey", "Host sealing-key provider integration"} & actions
        )
        plan_root = Path(str(requested.get("_plan_root", ""))).resolve()
        test_image = os.environ.get(
            "DSTACK_TEST_NO_TEE_GUEST_IMAGE", "dstack-dev-0.6.0"
        )
        try:
            image_provenance = require_image_backend(source_image_store, test_image)
        except RuntimeError as error:
            fail(str(error))
        values["guest_image"] = image_provenance
        deletable_images: list[str] = []
        if "Vmm.DeleteImage" in actions:
            metadata_sources = sorted(source_image_store.glob("*/metadata.json"))
            if not metadata_sources:
                fail("candidate image store has no metadata for DeleteImage fixture")
            # JSON and protobuf are independent state-transition rows: deleting
            # one image must not turn the second representation into an
            # expected not-found error.
            for encoding in ("json", "protobuf"):
                image_name = f"dstack-test-deletable-{encoding}-{lease_id[-12:]}"
                deletable_dir = case_image_store / image_name
                deletable_dir.mkdir()
                source_dir = metadata_sources[0].parent
                for source_file in source_dir.iterdir():
                    target = deletable_dir / source_file.name
                    if source_file.name == "metadata.json":
                        shutil.copy2(source_file, target)
                    elif source_file.is_file():
                        target.symlink_to(source_file)
                deletable_images.append(image_name)
        discovery_images: dict[str, str] = {}
        if "Local image discovery metadata and deletion" in actions:
            source = source_image_store / test_image
            if not source.is_dir():
                fail(
                    f"prepared image is unavailable for discovery fixture: {test_image}"
                )
            unused_image = f"dstack-test-unused-{lease_id[-12:]}"
            unused_dir = case_image_store / unused_image
            unused_dir.mkdir()
            for source_file in source.iterdir():
                target = unused_dir / source_file.name
                if source_file.name == "metadata.json":
                    shutil.copy2(source_file, target)
                elif source_file.is_file():
                    target.symlink_to(source_file)
            invalid_image = f"dstack-test-invalid-{lease_id[-12:]}"
            invalid_dir = case_image_store / invalid_image
            invalid_dir.mkdir()
            (invalid_dir / "metadata.json").write_text(
                '{"version":123,"is_dev":"invalid"}\n', encoding="utf-8"
            )
            discovery_images = {
                "unused_image": unused_image,
                "invalid_image": invalid_image,
                "in_use_image": test_image,
                "image_root": str(case_image_store),
            }
        volume_matrix: dict[str, Any] = {}
        volumes_dir = ""
        if "Measured verity volume extraction resolution and path safety" in actions:
            volume_root = workspace / "data/verity-volumes"
            volume_root.mkdir()
            (volume_root / "volume-a.img").write_bytes(b"dstack-test-volume-a\n")
            (volume_root / "volume-b.img").write_bytes(b"dstack-test-volume-b\n")
            escape_target = workspace / "data/volume-escape.img"
            escape_target.write_bytes(b"dstack-test-volume-escape\n")
            (volume_root / "escape.img").symlink_to(escape_target)
            (volume_root / "comma,name.img").write_bytes(b"invalid-qemu-name\n")
            volumes_dir = str(volume_root)
            volume_matrix = {
                "volumes_dir": volumes_dir,
                "valid_sources": ["volume-a.img", "volume-b.img"],
                "escape_source": "escape.img",
                "qemu_metachar_source": "comma,name.img",
                "root_a": "11" * 32,
                "root_b": "22" * 32,
                "wrong_root": "33" * 32,
            }
        if "NUMA pinning hugepages and resource isolation" in actions:
            hugepages_total = 0
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("HugePages_Total:"):
                    hugepages_total = int(line.split()[1])
                    break
            values["host_capabilities"] = {
                "hugepages_2m_total": hugepages_total,
                "numa_nodes": len(
                    list(Path("/sys/devices/system/node").glob("node[0-9]*"))
                ),
            }
        registry_actions = {
            "Vmm.PullRegistryImage",
            "Registry authentication pull and extraction",
        }
        image_registry = ""
        registry_tag = "fixture"
        registry_ca = ""
        if registry_actions & actions:
            registry_helper = plan_root / "fixtures/providers/mock-oci-registry.py"
            if not registry_helper.is_file():
                fail("mock OCI registry helper is unavailable")
            registry_dir = workspace / "data/oci-registry"
            registry_dir.mkdir()
            metadata_layer = registry_dir / "metadata-layer.tar.gz"
            payload_layer = registry_dir / "payload-layer.tar.gz"
            traversal_layer = registry_dir / "traversal-layer.tar.gz"
            control = registry_dir / "control.json"
            metadata = source_image_store / test_image / "metadata.json"
            if not metadata.is_file():
                fail("prepared image metadata is unavailable for OCI fixture")
            fixture_metadata = json.loads(metadata.read_text(encoding="utf-8"))
            fixture_metadata.update(
                {
                    "kernel": "fixture.bin",
                    "initrd": "fixture.bin",
                    "hda": None,
                    "rootfs": None,
                    "bios": None,
                    "bios-sev": None,
                }
            )
            registry_metadata = registry_dir / "metadata.json"
            registry_metadata.write_text(
                json.dumps(fixture_metadata, separators=(",", ":")),
                encoding="utf-8",
            )
            fixture_blob = registry_dir / "fixture.bin"
            fixture_blob.write_bytes(b"dstack-test-registry-image" + bytes([10]))
            with tarfile.open(metadata_layer, "w:gz") as archive:
                archive.add(registry_metadata, arcname="metadata.json")
            with tarfile.open(payload_layer, "w:gz") as archive:
                archive.add(fixture_blob, arcname="fixture.bin")
            traversal_info = tarfile.TarInfo("../registry-escape")
            traversal_data = b"must-not-escape" + bytes([10])
            traversal_info.size = len(traversal_data)
            with tarfile.open(traversal_layer, "w:gz") as archive:
                archive.addfile(traversal_info, io.BytesIO(traversal_data))

            def descriptor(path: Path) -> dict[str, object]:
                return {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size": path.stat().st_size,
                }

            metadata_descriptor = descriptor(metadata_layer)
            payload_descriptor = descriptor(payload_layer)
            traversal_descriptor = descriptor(traversal_layer)
            manifest_base = {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:" + "0" * 64,
                    "size": 2,
                },
            }
            normal_manifest = {
                **manifest_base,
                "layers": [metadata_descriptor, payload_descriptor],
            }
            traversal_manifest = {
                **manifest_base,
                "layers": [metadata_descriptor, traversal_descriptor],
            }
            control.write_text(
                json.dumps(
                    {"variant": "normal", "auth_required": True, "fault": "none"}
                ),
                encoding="utf-8",
            )
            registry_tag = f"dstack-fixture-{lease_id[-12:]}"
            registry_config = registry_dir / "registry.json"
            registry_config.write_text(
                json.dumps(
                    {
                        "repo": "dstack/guest-image",
                        "tag": registry_tag,
                        "control": str(control),
                        "variants": {
                            "normal": {
                                "manifest": normal_manifest,
                                "blobs": {
                                    metadata_descriptor["digest"]: str(metadata_layer),
                                    payload_descriptor["digest"]: str(payload_layer),
                                },
                            },
                            "traversal": {
                                "manifest": traversal_manifest,
                                "blobs": {
                                    metadata_descriptor["digest"]: str(metadata_layer),
                                    traversal_descriptor["digest"]: str(
                                        traversal_layer
                                    ),
                                },
                            },
                        },
                    },
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            ca_cert = registry_dir / "ca.crt"
            ca_key = registry_dir / "ca.key"
            cert = registry_dir / "server.crt"
            key = registry_dir / "server.key"
            csr = registry_dir / "server.csr"
            extensions = registry_dir / "server.ext"
            extensions.write_text(
                "subjectAltName=IP:127.0.0.1\n"
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n",
                encoding="utf-8",
            )
            generated_ca = subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=dstack-test-oci-ca",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE,pathlen:0",
                    "-keyout",
                    str(ca_key),
                    "-out",
                    str(ca_cert),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            generated_server = subprocess.run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    "/CN=127.0.0.1",
                    "-keyout",
                    str(key),
                    "-out",
                    str(csr),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            signed = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-days",
                    "1",
                    "-in",
                    str(csr),
                    "-CA",
                    str(ca_cert),
                    "-CAkey",
                    str(ca_key),
                    "-CAcreateserial",
                    "-extfile",
                    str(extensions),
                    "-out",
                    str(cert),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            if (
                generated_ca.returncode
                or generated_server.returncode
                or signed.returncode
            ):
                detail = generated_ca.stderr + generated_server.stderr + signed.stderr
                fail(f"failed to generate OCI registry certificate: {detail[-500:]}")
            ca_key.chmod(0o600)
            key.chmod(0o600)
            registry = start_component(
                [
                    sys.executable,
                    str(registry_helper),
                    "--port",
                    str(port_map["aux2"]),
                    "--cert",
                    str(cert),
                    "--key",
                    str(key),
                    "--config",
                    str(registry_config),
                ],
                workspace / "logs/oci-registry.log",
                port_map["aux2"],
            )
            pids.append(registry.pid)
            image_registry = f"127.0.0.1:{port_map['aux2']}/dstack/guest-image"
            registry_ca = str(ca_cert)
        auth_token = (
            secrets.token_hex(32)
            if "External API authentication and listener separation" in actions
            else ""
        )
        auth_token_path = workspace / "data/vmm-auth-token"
        if auth_token:
            auth_token_path.write_text(auth_token, encoding="utf-8")
            auth_token_path.chmod(0o600)
        kms_url = ""
        if "Vmm.GetAppEnvEncryptPubKey" in actions:
            kms_binary = Path(
                str(
                    runtime.get("prepared_binaries", {})
                    .get("dstack_kms", {})
                    .get("path", "")
                )
            ).resolve()
            start_simulator = plan_root / "automation/start-simulator.sh"
            stop_simulator = plan_root / "automation/stop-simulator.sh"
            if not kms_binary.is_file() or not start_simulator.is_file():
                fail("prepared KMS binary or simulator helper is unavailable")
            simulator_runtime = Path("/tmp") / f"dstack-test-case-kms-{lease_id}"
            simulator_fixture = simulator_runtime / "simulator-fixture.json"
            simulator = subprocess.run(
                [
                    str(start_simulator),
                    str(runtime_path),
                    str(simulator_runtime),
                    str(simulator_fixture),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=180,
                check=False,
            )
            if simulator.returncode:
                fail(f"VMM KMS simulator failed to start: {simulator.stderr[-1000:]}")
            simulator_values = json.loads(simulator_fixture.read_text(encoding="utf-8"))
            agent_url = f"unix:{simulator_values['services']['DstackGuest']['socket']}"
            kms_certs = workspace / "data/vmm-kms-certs"
            kms_certs.mkdir()
            kms_config = workspace / "config/vmm-kms.toml"
            kms_admin_token = secrets.token_hex(32)
            kms_admin_token_path = workspace / "data/vmm-kms-admin-token"
            kms_admin_token_path.write_text(kms_admin_token, encoding="utf-8")
            kms_admin_token_path.chmod(0o600)
            write_kms_config(
                kms_config,
                kms_certs,
                port_map["kms"],
                port_map["onboard"],
                port_map["admin"],
                kms_admin_token,
                True,
            )
            kms = start_kms(
                kms_binary,
                kms_config,
                workspace / "logs/vmm-kms.log",
                port_map["kms"],
                agent_url,
            )
            pids.append(kms.pid)
            kms_url = f"https://127.0.0.1:{port_map['kms']}"
            values["vmm_kms"] = {
                "rpc_url": kms_url,
                "config": str(kms_config),
                "log": str(workspace / "logs/vmm-kms.log"),
                "pid": kms.pid,
                "tls_verify": False,
                "development_auth": True,
            }
        image_server, image_server_url = start_guest_image_server(workspace)
        pids.append(image_server.pid)
        config = workspace / "config/vmm.toml"
        compose = workspace / "config/test-app-compose.json"
        created_vms = workspace / "run/created-vms.json"
        created_vms.write_text("[]\n", encoding="utf-8")
        compose.write_text(
            json.dumps(
                {
                    "manifest_version": 2,
                    "name": "dstack-test-vmm-fixture",
                    "runner": "docker-compose",
                    "docker_compose_file": (
                        "services:\n  fixture:\n    image: ubuntu:latest\n"
                        '    command: ["sleep", "infinity"]\n'
                    ),
                    "pre_launch_script": (
                        "curl --fail --silent --show-error --retry 3 "
                        f"{image_server_url}/fixture-image.tar "
                        "--output /run/dstack-test-fixture-image.tar\n"
                        "docker load --input /run/dstack-test-fixture-image.tar\n"
                    ),
                    "gateway_enabled": False,
                    "public_logs": True,
                    "public_sysinfo": True,
                    "public_tcbinfo": True,
                    "key_provider_id": "",
                    "allowed_envs": [],
                    "no_instance_id": False,
                    "secure_time": False,
                    "key_provider": "local" if host_sealing else "tpm",
                    "kms_enabled": False,
                    "storage_fs": "ext4",
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        # Stride by the CID pool width, not by four: with a 1000-wide pool
        # a stride of four gave two leases whose rpc ports differ by less
        # than 250 overlapping guest CID ranges, and ephemeral ports are
        # normally allocated within a few of each other.
        cid_start = 100_000 + port_map["rpc"] * 1000
        simulator_seed = secrets.token_hex(32)
        write_vmm_config(
            source_config,
            config,
            workspace,
            vm_run_path,
            case_image_store,
            supervisor,
            port_map["rpc"],
            port_map["aux1"],
            cid_start,
            image_registry,
            auth_token,
            kms_url,
            bool(
                {"Vmm.SvStop", "Vmm.SvRemove", "Supervisor passthrough operations"}
                & actions
            ),
            simulator_seed,
            host_sealing,
            "Port mapping protocols and conflicts" in actions,
            volumes_dir,
            4096
            if "Serial log separator rotation history and follow continuity" in actions
            else 0,
            supervisor_socket=supervisor_socket,
            auto_restart_policy=(
                {
                    "interval": 1,
                    "max_retries": 3,
                    "initial_backoff": 1,
                    "max_backoff": 2,
                    "reset_window": 2,
                }
                if auto_restart_case
                else None
            ),
        )
        try:
            vmm = start_component(
                [str(binary), "--config", str(config)],
                workspace / "logs/vmm.log",
                port_map["rpc"],
                env={"SSL_CERT_FILE": registry_ca} if registry_ca else None,
                cwd=workspace,
            )
        except BaseException:
            terminate_pids(set(pids))
            if vm_run_path.is_symlink():
                vm_run_path.unlink()
            shutil.rmtree(supervisor_runtime_dir, ignore_errors=True)
            shutil.rmtree(workspace, ignore_errors=True)
            raise
        pids.append(vmm.pid)
        vmm_pid_file = workspace / "run/vmm.pid"
        vmm_pid_file.write_text(f"{vmm.pid}\n", encoding="utf-8")
        rpc_url = f"http://127.0.0.1:{port_map['rpc']}"
        cli_argv = [sys.executable, str(vmm_cli), "--url", rpc_url]
        test_name = f"dtest-{lease_id[-12:]}"
        create_helper = plan_root / "automation/vmm-create-stopped.py"
        crash_qemu = plan_root / "automation/vmm-crash-qemu.py"
        console_log_control = plan_root / "automation/vmm-console-log-control.py"
        web_ui_workflow = plan_root / "automation/vmm-web-ui-workflow.cjs"
        vsock_http = plan_root / "automation/vsock-http.py"
        if (
            not create_helper.is_file()
            or not vsock_http.is_file()
            or (auto_restart_case and not crash_qemu.is_file())
            or (
                "Console log channels follow and ANSI handling" in actions
                and not console_log_control.is_file()
            )
            or (
                "Web UI deployment workflows" in actions
                and (not web_ui_workflow.is_file() or shutil.which("npx") is None)
            )
        ):
            fail(
                "prepared VMM create, crash, console-log, or vsock HTTP helper is unavailable"
            )
        rpc_methods = (
            "CreateVm",
            "StartVm",
            "StopVm",
            "RemoveVm",
            "UpgradeApp",
            "UpdateVm",
            "ShutdownVm",
            "ResizeVm",
            "GetComposeHash",
            "Status",
            "ListImages",
            "GetAppEnvEncryptPubKey",
            "GetInfo",
            "Version",
            "GetMeta",
            "ListGpus",
            "ReloadVms",
            "SvList",
            "SvStop",
            "SvRemove",
            "ListRegistryImages",
            "PullRegistryImage",
            "DeleteImage",
        )
        values["vmm"] = {
            "rpc_url": rpc_url,
            "cli_argv": cli_argv,
            "json_prpc_route_template": "/prpc/<Method>?json",
            "json_prpc_routes": {
                method: f"/prpc/{method}?json" for method in rpc_methods
            },
            "commands": {
                "list_vms": [*cli_argv, "lsvm", "--json"],
                "list_images": [*cli_argv, "lsimage", "--json"],
                "supervisor": [
                    str(supervisor_client),
                    "--base-url",
                    f"unix:{supervisor_socket}",
                ]
                if auto_restart_case
                else [],
                "crash_qemu": [
                    sys.executable,
                    str(crash_qemu),
                    "--supervisor-client",
                    str(supervisor_client),
                    "--base-url",
                    f"unix:{supervisor_socket}",
                    "--run-path",
                    str(vm_run_path),
                ]
                if auto_restart_case
                else [],
            },
            "config": str(config),
            "log": str(workspace / "logs/vmm.log"),
            "pid": vmm.pid,
            "process_control": {
                "binary": str(binary),
                "config": str(config),
                "cwd": str(workspace),
                "log": str(workspace / "logs/vmm.log"),
                "pid_file": str(vmm_pid_file),
                "rpc_port": port_map["rpc"],
            },
            "case_owned": True,
            "run_path": str(vm_run_path),
            "cid_range": {"start": cid_start, "count": 1000},
            "auth": {
                "enabled": bool(auth_token),
                "token_file": str(auth_token_path) if auth_token else "",
            },
            "test_input": {
                "compose": str(compose),
                "image": test_image,
                "name_prefix": test_name,
                "create_stopped_args": (
                    ["--stopped"]
                    if host_sealing
                    else [
                        "--stopped",
                        "--no-tee",
                        "--simulated-tee",
                        "dstack-tdx",
                    ]
                ),
                "create_stopped_argv": [
                    *cli_argv,
                    "deploy",
                    "--name",
                    test_name,
                    "--image",
                    test_image,
                    "--compose",
                    str(compose),
                    "--stopped",
                    *(
                        []
                        if host_sealing
                        else ["--no-tee", "--simulated-tee", "dstack-tdx"]
                    ),
                ],
                "create_stopped_helper_argv": [sys.executable, str(create_helper)],
                "created_vms_registry": str(created_vms),
                "deletable_image": deletable_images[0] if deletable_images else "",
                "deletable_images": deletable_images,
                "registry": image_registry,
                "registry_tag": registry_tag,
                "registry_control": str(control) if "control" in locals() else "",
                "registry_workspace": (
                    str(registry_dir) if "registry_dir" in locals() else ""
                ),
                "registry_image_store": (
                    str(case_image_store) if "case_image_store" in locals() else ""
                ),
                "port_mapping": (
                    {"protocols": ["tcp", "udp"], "min": 20000, "max": 65535}
                    if "Port mapping protocols and conflicts" in actions
                    else {}
                ),
                "discovery_images": discovery_images,
                "verity_volume_matrix": volume_matrix,
                "auto_restart_policy": (
                    {
                        "interval": 1,
                        "max_retries": 3,
                        "initial_backoff": 1,
                        "max_backoff": 2,
                        "reset_window": 2,
                    }
                    if auto_restart_case
                    else {}
                ),
                "serial_history_max_bytes": (
                    4096
                    if "Serial log separator rotation history and follow continuity"
                    in actions
                    else 0
                ),
                "vm_configuration": {
                    "name": test_name,
                    "image": test_image,
                    "compose_file": compose.read_text(encoding="utf-8"),
                    "vcpu": 1,
                    "memory": 1024,
                    "disk_size": 20,
                    "ports": [],
                    "encrypted_env": "",
                    "app_id": "",
                    "user_config": "",
                    "hugepages": False,
                    "pin_numa": False,
                    "gpus": {"attach_mode": "listed", "gpus": []},
                    "kms_urls": [],
                    "gateway_urls": [],
                    "stopped": True,
                    "no_tee": not host_sealing,
                    "simulated_tee": None if host_sealing else "dstack-tdx",
                    "networks": [],
                },
            },
        }
        if "Console log channels follow and ANSI handling" in actions:
            log_control = [
                sys.executable,
                str(console_log_control),
                "--run-path",
                str(vm_run_path),
                "--registry",
                str(created_vms),
            ]
            values["vmm_console_follow"] = {
                "destructive_actions_allowed": True,
                "console_endpoint": f"{rpc_url}/logs",
                "history_seed_argv": [*log_control, "--truncate"],
                "live_append_argv": log_control,
                "follow_argv": ["curl", "--fail", "--silent", "--no-buffer"],
                "tail_observer_argv": ["curl", "--fail", "--silent"],
                "ansi_policy_selector": ["ansi=false", "ansi=true"],
                "ansi_observer_argv": ["curl", "--fail", "--silent"],
                "gap_duplicate_observer_argv": [
                    "curl",
                    "--fail",
                    "--silent",
                    "--no-buffer",
                ],
                "cross_vm_probe_argv": ["curl", "--fail", "--silent"],
                "path_escape_probe_argv": [
                    "curl",
                    "--silent",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                ],
                "invalid_input_argv": [
                    "curl",
                    "--silent",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                ],
                "availability_probe_argv": [*cli_argv, "lsvm", "--json"],
                "cleanup_argv": [sys.executable, str(create_helper), "--cleanup-only"],
            }

        if "Web UI deployment workflows" in actions:
            browser_command = [
                "npx",
                "--yes",
                "--package",
                "playwright@1.58.2",
                "-c",
                'NODE_PATH=$(dirname $(dirname $(command -v playwright))) node "$DSTACK_BROWSER_WORKFLOW"',
            ]
            values["vmm_web_ui_deployment"] = {
                "destructive_actions_allowed": True,
                "browser_session_argv": browser_command,
                "browser_workflow": str(web_ui_workflow),
                "ui_url": f"{rpc_url}/",
                "health_probe_argv": [*cli_argv, "status"],
                "semantic_form_rows": [
                    "defaults",
                    "image",
                    "compose",
                    "simulated-tee",
                    "network",
                    "gpu-empty-state",
                    "keyboard-submit",
                ],
                "ui_submit_argv": browser_command,
                "created_vm_observer_argv": [*cli_argv, "lsvm", "--json"],
                "lifecycle_argv": cli_argv,
                "server_error_row_argv": browser_command,
                "unset_default_observer_argv": browser_command,
                "keyboard_accessibility_argv": browser_command,
                "cross_session_probe_argv": browser_command,
                "cleanup_argv": cli_argv,
            }

        if "Serial log separator rotation history and follow continuity" in actions:
            serial_limit = 4096
            values["vmm_serial_continuity"] = {
                "destructive_actions_allowed": True,
                "serial_limit": serial_limit,
                "create_vm_argv": [sys.executable, str(create_helper)],
                "boot_cycle_argv": cli_argv,
                "serial_file_observer_argv": ["python3", "-c"],
                "history_file_observer_argv": ["python3", "-c"],
                "tail_request_argv": ["curl", "--fail", "--silent"],
                "follow_reader_argv": ["curl", "--fail", "--silent", "--no-buffer"],
                "ansi_rows": ["preserve", "strip"],
                "gap_duplicate_observer_argv": ["python3", "-c"],
                "path_probe_argv": [
                    "curl",
                    "--silent",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                ],
                "reload_argv": [
                    "curl",
                    "--fail",
                    "--silent",
                    "--request",
                    "POST",
                    "--header",
                    "content-type: application/json",
                    "--data",
                    "{}",
                    f"{rpc_url}/prpc/ReloadVms",
                ],
                "historical_version_rows": [
                    "v0.5.4-omitted-default",
                    "v0.5.8-omitted-default",
                    "v0.5.11-omitted-default",
                    "candidate-explicit-limit",
                ],
                "cleanup_argv": cli_argv,
                "run_path": str(vm_run_path),
                "console_endpoint": f"{rpc_url}/logs",
            }

        if "Proxied GuestApi transport and VM targeting" in actions:
            guest_routes = {
                method: f"{rpc_url}/guest/{method}?json"
                for method in (
                    "Info",
                    "SysInfo",
                    "NetworkInfo",
                    "ListContainers",
                    "Shutdown",
                )
            }
            values["vmm_proxied_guestapi"] = {
                "destructive_actions_allowed": True,
                "target_rows": ["running", "stopped", "unknown", "concurrent-remove"],
                "create_target_argv": [sys.executable, str(create_helper)],
                "proxy_request_argv": [
                    "curl",
                    "--fail",
                    "--silent",
                    "--request",
                    "POST",
                    "--header",
                    "content-type: application/json",
                ],
                "proxy_routes": guest_routes,
                "target_observer_argv": [*cli_argv, "lsvm", "--json"],
                "deadline_rows": {"request_seconds": 15, "recovery_seconds": 90},
                "concurrent_remove_argv": cli_argv,
                "closed_error_observer_argv": [
                    "curl",
                    "--silent",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                ],
                "dependency_stop_argv": cli_argv,
                "dependency_restart_argv": cli_argv,
                "recovery_request_argv": [
                    "curl",
                    "--fail",
                    "--silent",
                    "--request",
                    "POST",
                    "--header",
                    "content-type: application/json",
                ],
                "adjacent_identity_observer_argv": [*cli_argv, "lsvm", "--json"],
                "redaction_audit_argv": ["python3", "-c"],
                "cleanup_argv": cli_argv,
            }

        host_api_port = port_map["aux1"]
        host_api_prefix = [
            sys.executable,
            str(vsock_http),
            "--cid",
            "2",
            "--port",
            str(host_api_port),
        ]
        values["host_api"] = {
            "transport": "vsock",
            "cid": 2,
            "port": host_api_port,
            "route_template": "/api/<Method>?json",
            "json_prpc_routes": {
                method: f"/api/{method}?json"
                for method in ("Info", "Notify", "GetSealingKey")
            },
            "probe_argv": host_api_prefix,
            "commands": {
                "info": [
                    *host_api_prefix,
                    "--path",
                    "/api/Info?json",
                    "--public-json",
                ]
            },
            "case_owned": True,
            "key_provider_dependency": (
                {"address": "127.0.0.1", "port": 3443, "hardware": "sgx"}
                if host_sealing
                else None
            ),
        }
        values["services"]["rpc"] = {"url": values["vmm"]["rpc_url"]}
    if requested.get("profile") in {
        "kms-ready",
        "kms-onboard",
        "redaction-audit-stack",
    }:
        binary_info = runtime.get("prepared_binaries", {}).get("dstack_kms", {})
        binary = Path(str(binary_info.get("path", ""))).resolve()
        if not binary.is_file():
            shutil.rmtree(workspace, ignore_errors=True)
            fail("prepared dstack-kms binary is unavailable")
        plan_root = Path(str(requested.get("_plan_root", ""))).resolve()
        simulator_runtime = Path("/tmp") / f"dstack-test-case-kms-{lease_id}"
        simulator_fixture = simulator_runtime / "simulator-fixture.json"
        start_simulator = plan_root / "automation/start-simulator.sh"
        stop_simulator = plan_root / "automation/stop-simulator.sh"
        mock_seed = secrets.token_hex(32)
        process = subprocess.run(
            [
                str(start_simulator),
                str(runtime_path),
                str(simulator_runtime),
                str(simulator_fixture),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
            env={
                **os.environ,
                "DSTACK_TEST_MOCK_ATTESTATION_SEED": mock_seed,
            },
        )
        if process.returncode:
            shutil.rmtree(workspace, ignore_errors=True)
            fail(f"KMS guest simulator failed to start: {process.stderr[-1000:]}")
        simulator_values = json.loads(simulator_fixture.read_text(encoding="utf-8"))
        pids.append(int(simulator_values["pid"]))
        mock_binary = Path(
            str(
                runtime.get("prepared_binaries", {})
                .get("dstack_mock_attestation", {})
                .get("path", "")
            )
        ).resolve()
        if not mock_binary.is_file():
            fail("prepared dstack-mock-attestation binary is unavailable")
        collateral_url = f"http://127.0.0.1:{port_map['aux3']}"
        mock_config = workspace / "config/mock-attestation.json"
        mock_roots = workspace / "data/mock-attestation-roots"
        mock_roots.mkdir()
        mock_config.write_text(
            json.dumps(
                {
                    "platform": "dstack-tdx",
                    "mock_attestation_seed": mock_seed,
                    "collateral_base_url": collateral_url,
                }
            ),
            encoding="utf-8",
        )
        mock_config.chmod(0o600)
        collateral = start_component(
            [
                str(mock_binary),
                "serve",
                "--listen",
                f"127.0.0.1:{port_map['aux3']}",
                "--config",
                str(mock_config),
                "--output",
                str(mock_roots),
            ],
            workspace / "logs/mock-attestation.log",
            port_map["aux3"],
        )
        pids.append(collateral.pid)
        attestation_root = mock_roots / "tdx-root-ca.pem"
        if not attestation_root.is_file():
            fail("mock attestation fixture did not publish the TDX root")
        kms_client_identity = generate_simulator_client_identity(
            simulator_values,
            workspace / "data/kms-client",
            usage_ra_tls=True,
        )
        agent_socket = simulator_values["services"]["DstackGuest"]["socket"]
        agent_url = f"unix:{agent_socket}"
        csr_helper = Path(
            str(
                runtime.get("prepared_binaries", {})
                .get("dstack_kms_sign_cert_fixture", {})
                .get("path", "")
            )
        ).resolve()
        if not csr_helper.is_file():
            fail("prepared dstack-kms-sign-cert-fixture binary is unavailable")
        values["kms_guest_simulator"] = simulator_values
        source_certs = workspace / "data/source-certs"
        source_certs.mkdir()
        source_config = workspace / "config/source-kms.toml"
        historical_keys: list[tuple[Path, Path]] = []
        if case_id == "tc-kms-keys-certs-003":
            curve_order = int(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                16,
            )
            for index in range(2):
                history_dir = workspace / f"data/history-{index}"
                history_dir.mkdir()
                ca_key = history_dir / "root-ca.key"
                k256_key = history_dir / "root-k256.key"
                completed = subprocess.run(
                    [
                        "openssl",
                        "genpkey",
                        "-algorithm",
                        "EC",
                        "-pkeyopt",
                        "ec_paramgen_curve:P-256",
                        "-out",
                        str(ca_key),
                    ],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                if completed.returncode:
                    fail("failed to generate historical CA key")
                ca_key.chmod(0o600)
                scalar = secrets.randbelow(curve_order - 1) + 1
                k256_key.write_bytes(scalar.to_bytes(32, "big"))
                k256_key.chmod(0o600)
                historical_keys.append((ca_key, k256_key))
        source_admin_token = secrets.token_hex(32)
        source_admin_token_path = workspace / "data/source-kms-admin-token"
        source_admin_token_path.write_text(source_admin_token, encoding="utf-8")
        source_admin_token_path.chmod(0o600)
        write_kms_config(
            source_config,
            source_certs,
            port_map["rpc"],
            port_map["metrics"],
            port_map["admin"],
            source_admin_token,
            True,
            (
                None
                if requested.get("profile") == "kms-onboard"
                else Path(kms_client_identity["ca_cert"])
            ),
            attestation_root,
            collateral_url,
            historical_keys,
        )
        source = start_kms(
            binary,
            source_config,
            workspace / "logs/source-kms.log",
            port_map["rpc"],
            agent_url,
        )
        pids.append(source.pid)
        values["kms"] = {
            "rpc_url": f"https://127.0.0.1:{port_map['rpc']}",
            "rpc_prpc_url": f"https://127.0.0.1:{port_map['rpc']}/prpc",
            "metrics_url": f"https://127.0.0.1:{port_map['rpc']}/metrics",
            "config": str(source_config),
            "cert_dir": str(source_certs),
            "log": str(workspace / "logs/source-kms.log"),
            "pid": source.pid,
            "tls_verify": False,
            "development_auth": True,
            "admin_url": f"http://127.0.0.1:{port_map['admin']}/prpc",
            "admin_auth_token_file": str(source_admin_token_path),
            "registration_client": kms_client_identity,
        }
        simulator_fixture_dir = Path(str(runtime.get("simulator_fixtures", "")))
        simulator_sys_config = json.loads(
            (simulator_fixture_dir / "sys-config.json").read_text(encoding="utf-8")
        )
        client_vm_config = str(simulator_sys_config.get("vm_config", ""))
        if not client_vm_config or not json.loads(client_vm_config).get(
            "os_image_hash"
        ):
            fail("simulator fixture vm_config lacks os_image_hash")
        values["kms_attested_client"] = {
            "cert": kms_client_identity["cert"],
            "key": kms_client_identity["key"],
            "ca_cert": kms_client_identity["ca_cert"],
            "attestation_mode": "mock-dstack-tdx",
            "trust_root": str(attestation_root),
            "collateral_url": collateral_url,
            "vm_config": client_vm_config,
        }
        values["kms_attested_csr"] = {
            "generator": str(csr_helper),
            "agent_url": agent_url,
            "vm_config": client_vm_config,
            "api_version": 2,
            "subject": "kms-sign-cert.test",
        }
        values["services"].update(
            {
                "rpc": {
                    "url": f"https://127.0.0.1:{port_map['rpc']}/prpc",
                    "tls_verify": False,
                },
                "metrics": {
                    "url": f"https://127.0.0.1:{port_map['rpc']}/metrics",
                    "tls_verify": False,
                },
                "admin": {
                    "url": f"http://127.0.0.1:{port_map['admin']}/prpc",
                    "auth_token_file": str(source_admin_token_path),
                },
            }
        )
        if requested.get("profile") == "kms-onboard":
            target_certs = workspace / "data/target-certs"
            target_certs.mkdir()
            target_config = workspace / "config/target-kms.toml"
            write_kms_config(
                target_config,
                target_certs,
                port_map["kms"],
                port_map["onboard"],
                port_map["debug"],
                secrets.token_hex(32),
                False,
                Path(kms_client_identity["ca_cert"]),
                attestation_root,
                collateral_url,
            )
            target = start_kms(
                binary,
                target_config,
                workspace / "logs/target-kms.log",
                port_map["onboard"],
                agent_url,
            )
            pids.append(target.pid)
            protobuf_certs = workspace / "data/target-protobuf-certs"
            protobuf_certs.mkdir()
            protobuf_config = workspace / "config/target-protobuf-kms.toml"
            write_kms_config(
                protobuf_config,
                protobuf_certs,
                port_map["aux1"],
                port_map["aux2"],
                port_map["gateway"],
                secrets.token_hex(32),
                False,
                Path(kms_client_identity["ca_cert"]),
                attestation_root,
                collateral_url,
            )
            protobuf_target = start_kms(
                binary,
                protobuf_config,
                workspace / "logs/target-protobuf-kms.log",
                port_map["aux2"],
                agent_url,
            )
            pids.append(protobuf_target.pid)
            values["kms_onboard_source"] = {
                "available": True,
                "rpc_url": f"https://127.0.0.1:{port_map['rpc']}",
                "attestation_mode": "mock-dstack-tdx",
                "case_owned": True,
            }
            values["kms_onboard"] = {
                "url": f"http://127.0.0.1:{port_map['onboard']}",
                "prpc_url": f"http://127.0.0.1:{port_map['onboard']}/prpc",
                "target_rpc_url": f"https://127.0.0.1:{port_map['kms']}",
                "source_rpc_url": f"https://127.0.0.1:{port_map['rpc']}",
                "config": str(target_config),
                "cert_dir": str(target_certs),
                "log": str(workspace / "logs/target-kms.log"),
                "pid": target.pid,
                "representation_targets": [
                    {
                        "name": "json",
                        "prpc_url": f"http://127.0.0.1:{port_map['onboard']}/prpc",
                        "cert_dir": str(target_certs),
                        "log": str(workspace / "logs/target-kms.log"),
                        "pid": target.pid,
                    },
                    {
                        "name": "protobuf",
                        "prpc_url": f"http://127.0.0.1:{port_map['aux2']}/prpc",
                        "cert_dir": str(protobuf_certs),
                        "log": str(workspace / "logs/target-protobuf-kms.log"),
                        "pid": protobuf_target.pid,
                    },
                ],
            }
            values["services"]["onboard"] = {
                "url": f"http://127.0.0.1:{port_map['onboard']}/prpc"
            }
    if requested.get("profile") in {
        "gateway-ready",
        "gateway-cluster",
        "gateway-exit-cluster",
        "redaction-audit-stack",
    }:
        binaries = runtime.get("prepared_binaries", {})
        binary = Path(str(binaries.get("dstack_gateway", {}).get("path", ""))).resolve()
        repository = Path(str(runtime.get("repository", ""))).resolve()
        source_config = repository / "dstack/gateway/gateway.toml"
        if not binary.is_file() or not source_config.is_file():
            shutil.rmtree(workspace, ignore_errors=True)
            fail("prepared Gateway binary or candidate Gateway config is unavailable")
        plan_root = Path(str(requested.get("_plan_root", ""))).resolve()
        simulator_runtime = Path("/tmp") / f"dstack-test-case-gateway-{lease_id}"
        simulator_fixture = simulator_runtime / "simulator-fixture.json"
        start_simulator = plan_root / "automation/start-simulator.sh"
        stop_simulator = plan_root / "automation/stop-simulator.sh"
        simulator = subprocess.run(
            [
                str(start_simulator),
                str(runtime_path),
                str(simulator_runtime),
                str(simulator_fixture),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        if simulator.returncode:
            shutil.rmtree(workspace, ignore_errors=True)
            fail(f"Gateway guest simulator failed to start: {simulator.stderr[-1000:]}")
        simulator_values = json.loads(simulator_fixture.read_text(encoding="utf-8"))
        values["gateway_guest_simulator"] = simulator_values
        registration_client = generate_simulator_client_identity(
            simulator_values,
            workspace / "data/registration-client",
            usage_ra_tls=case_id == "tc-gw-cluster-ad-002",
        )
        node_count = {"gateway-cluster": 3, "gateway-exit-cluster": 4}.get(
            str(requested.get("profile")), 1
        )
        allocated = reserve_ports(node_count * 4)
        node_ports = [
            dict(
                zip(
                    ("rpc", "admin", "debug", "proxy"),
                    allocated[index : index + 4],
                    strict=True,
                )
            )
            for index in range(0, len(allocated), 4)
        ]
        admin_token = secrets.token_hex(32)
        admin_token_path = workspace / "data/gateway-admin-token"
        admin_token_path.write_text(admin_token, encoding="utf-8")
        admin_token_path.chmod(0o600)
        nodes: list[dict[str, Any]] = []
        fixture_client_public_key = (
            base64.b64encode(secrets.token_bytes(32)).decode()
            if case_id
            in {
                "tc-gw-proxy-prot-003",
                "tc-gw-proxy-prot-004",
                "tc-gw-proxy-prot-005",
                "tc-gw-proxy-prot-006",
                "tc-gw-select-007",
            }
            else None
        )
        bootnode = ""
        for node_id, ports_for_node in enumerate(node_ports, start=1):
            node_workspace = workspace / f"gateway-node-{node_id}"
            for name in ("config", "data", "logs", "run"):
                (node_workspace / name).mkdir(parents=True)
            handshake_fixture = node_workspace / "run/latest-handshakes"
            gateway_env = {
                "DSTACK_AGENT_ADDRESS": f"unix:{simulator_values['services']['DstackGuest']['socket']}"
            }
            if case_id in {
                "tc-gw-cluster-ad-004",
                "tc-gw-proxy-prot-003",
                "tc-gw-proxy-prot-004",
                "tc-gw-proxy-prot-005",
                "tc-gw-proxy-prot-006",
                "tc-gw-select-007",
            }:
                handshake_fixture.write_text(
                    (
                        f"{fixture_client_public_key} {int(time.time())}\n"
                        if case_id
                        in {
                            "tc-gw-proxy-prot-003",
                            "tc-gw-proxy-prot-004",
                            "tc-gw-proxy-prot-005",
                            "tc-gw-proxy-prot-006",
                            "tc-gw-select-007",
                        }
                        else ""
                    ),
                    encoding="utf-8",
                )
                mock_bin = node_workspace / "run/mock-bin"
                mock_bin.mkdir()
                wg = mock_bin / "wg"
                wg.write_text(
                    "#!/bin/sh\n"
                    'test "$1" = show && test "$3" = latest-handshakes || exit 2\n'
                    'cat "$DSTACK_TEST_HANDSHAKES_FILE"\n',
                    encoding="utf-8",
                )
                wg.chmod(0o755)
                gateway_env["DSTACK_TEST_HANDSHAKES_FILE"] = str(handshake_fixture)
                gateway_env["PATH"] = f"{mock_bin}:{os.environ.get('PATH', '')}"
            config = node_workspace / "config/gateway.toml"
            write_gateway_config(
                source_config,
                config,
                node_workspace,
                ports_for_node,
                admin_token,
                sync_node_id=node_id if node_count > 1 else None,
                sync_bootnode=bootnode,
                tls_identity=registration_client,
                app_address_dns_servers=(
                    [
                        f"127.0.0.1:{port_map['aux3']}",
                        f"127.0.0.1:{port_map['aux4']}",
                    ]
                    if case_id == "tc-gw-proxy-prot-005"
                    else None
                ),
                proxy_stress=case_id == "tc-gw-proxy-prot-006",
                fast_recycle=case_id
                in {
                    "tc-gw-registrati-002",
                    "tc-gw-cluster-ad-001",
                },
                enable_debug=not (
                    case_id == "tc-gw-internal-001"
                    or (
                        case_id in {"tc-gw-cluster-ad-002", "tc-gw-cluster-ad-006"}
                        and node_id == node_count
                    )
                ),
                exercise_startup=case_id == "tc-gw-internal-001",
            )
            gateway = start_component(
                [str(binary), "--config", str(config)],
                node_workspace / "logs/gateway.log",
                ports_for_node["rpc"],
                env=gateway_env,
            )
            pids.append(gateway.pid)
            node = {
                "node_id": node_id,
                "rpc_url": f"https://127.0.0.1:{ports_for_node['rpc']}/prpc",
                "health_url": f"https://127.0.0.1:{ports_for_node['rpc']}/health",
                "dashboard_url": f"http://127.0.0.1:{ports_for_node['admin']}/",
                "admin_url": f"http://127.0.0.1:{ports_for_node['admin']}/prpc",
                "debug_url": f"http://127.0.0.1:{ports_for_node['debug']}/prpc",
                "proxy_address": f"127.0.0.1:{ports_for_node['proxy']}",
                "admin_auth_token_file": str(admin_token_path),
                "config": str(config),
                "log": str(node_workspace / "logs/gateway.log"),
                "pid": gateway.pid,
                "tls_verify": False,
            }
            if case_id in {
                "tc-gw-cluster-ad-004",
                "tc-gw-proxy-prot-003",
                "tc-gw-proxy-prot-004",
                "tc-gw-proxy-prot-005",
                "tc-gw-proxy-prot-006",
                "tc-gw-select-007",
            }:
                node["handshake_fixture"] = str(handshake_fixture)
            nodes.append(node)
            if node_id == 1:
                bootnode = (
                    node["rpc_url"]
                    .removesuffix("/prpc")
                    .replace("127.0.0.1", "localhost", 1)
                )
        values["gateway"] = nodes[0]
        values["gateway"]["registration_client"] = registration_client
        if case_id in {
            "tc-gw-admin-002",
            "tc-gw-registrati-001",
            "tc-gw-registrati-002",
            "tc-gw-admin-031",
            "tc-gw-admin-032",
            "tc-gw-admin-033",
            "tc-gw-proxy-prot-003",
            "tc-gw-proxy-prot-004",
            "tc-gw-proxy-prot-005",
            "tc-gw-proxy-prot-006",
            "tc-gw-select-007",
        }:
            fixture_port_policy = None
            if case_id in {
                "tc-gw-proxy-prot-003",
                "tc-gw-proxy-prot-004",
                "tc-gw-proxy-prot-005",
                "tc-gw-proxy-prot-006",
                "tc-gw-select-007",
            }:
                fixture_port_policy = {
                    "ports": [
                        {"port": port_map["aux1"], "pp": False},
                        {"port": port_map["aux2"], "pp": False},
                    ],
                    "restrict_mode": False,
                }
            identity = register_gateway_fixture(
                values["gateway"]["rpc_url"],
                registration_client,
                simulator_values,
                fixture_port_policy,
                fixture_client_public_key,
            )
            values["gateway"]["registered_app_id"] = identity["app_id"]
            values["gateway"]["registered_instance_id"] = identity["instance_id"]
            if case_id in {
                "tc-gw-proxy-prot-003",
                "tc-gw-proxy-prot-004",
                "tc-gw-proxy-prot-005",
                "tc-gw-proxy-prot-006",
                "tc-gw-select-007",
            }:
                assigned_ip = identity["client_ip"]
                try:
                    socket.inet_aton(assigned_ip)
                except OSError:
                    fail("Gateway assigned a non-IPv4 fixture address")
                current = subprocess.run(
                    ["ip", "-j", "address", "show"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                if current.returncode:
                    fail("failed to inspect host addresses before fixture allocation")
                existing = {
                    row.get("local")
                    for link in json.loads(current.stdout)
                    for row in link.get("addr_info", [])
                }
                if assigned_ip in existing:
                    fail("refusing to claim a pre-existing Gateway fixture address")
                allocated_alias = subprocess.run(
                    [
                        "sudo",
                        "-n",
                        "ip",
                        "address",
                        "add",
                        f"{assigned_ip}/32",
                        "dev",
                        "lo",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                if allocated_alias.returncode:
                    fail("failed to allocate the case-owned Gateway fixture address")
                loopback_alias = assigned_ip
                fixture_key = (
                    "gateway_select_007"
                    if case_id == "tc-gw-select-007"
                    else f"gateway_proxy_protocol_{case_id.rsplit('-', 1)[-1]}"
                )
                values[fixture_key] = {
                    "case_owned": True,
                    "registered_app_id": identity["app_id"],
                    "registered_instance_id": identity["instance_id"],
                    "backend_address": identity["client_ip"],
                    "backend_port": port_map["aux1"],
                    "failure_port": port_map["aux2"],
                    "proxy_address": values["gateway"]["proxy_address"],
                    "base_domain": "localhost",
                    "dns_addresses": (
                        [
                            f"127.0.0.1:{port_map['aux3']}",
                            f"127.0.0.1:{port_map['aux4']}",
                        ]
                        if case_id == "tc-gw-proxy-prot-005"
                        else None
                    ),
                    "max_connections_per_app": (
                        2 if case_id == "tc-gw-proxy-prot-006" else None
                    ),
                }
        if case_id in {"tc-gw-cluster-ad-002", "tc-gw-cluster-ad-006"}:
            values["gateway_production_node"] = nodes[-1]
        if node_count > 1:
            values["gateway_cluster"] = {
                "nodes": nodes,
                "bootnode": bootnode,
                "admin_auth_token_file": str(admin_token_path),
            }
        values["services"].update(
            {
                "rpc": {"url": values["gateway"]["rpc_url"], "tls_verify": False},
                "admin": {"url": values["gateway"]["admin_url"]},
                "debug": {"url": values["gateway"]["debug_url"]},
                "proxy": {"address": values["gateway"]["proxy_address"]},
            }
        )
    if requested.get("profile") == "verifier-ready":
        binary = Path(
            str(
                runtime.get("prepared_binaries", {})
                .get("dstack_verifier", {})
                .get("path", "")
            )
        ).resolve()
        if not binary.is_file():
            shutil.rmtree(workspace, ignore_errors=True)
            fail("prepared dstack-verifier binary is unavailable")
        config = workspace / "config/verifier.toml"
        config.write_text(
            f'''address = "127.0.0.1"\nport = {port_map["verifier"]}\nimage_cache_dir = "{workspace / "data/image-cache"}"\nimage_download_url = "http://127.0.0.1:1/mr_{{OS_IMAGE_HASH}}.tar.gz"\nimage_download_timeout_secs = 2\n[attestation]\ninsecure_allow_external_trust_anchors = false\n''',
            encoding="utf-8",
        )
        verifier = start_component(
            [str(binary), "--config", str(config)],
            workspace / "logs/verifier.log",
            port_map["verifier"],
        )
        pids.append(verifier.pid)
        values["verifier"] = {
            "url": f"http://127.0.0.1:{port_map['verifier']}",
            "verify_url": f"http://127.0.0.1:{port_map['verifier']}/verify",
            "health_url": f"http://127.0.0.1:{port_map['verifier']}/health",
            "config": str(config),
            "log": str(workspace / "logs/verifier.log"),
            "pid": verifier.pid,
        }
        values["services"]["rpc"] = {"url": values["verifier"]["verify_url"]}
    if requested.get("profile") == "image-assembly":
        image_store_text = os.environ.get("DSTACK_TEST_IMAGE_STORE", "").strip()
        if not image_store_text:
            shutil.rmtree(workspace, ignore_errors=True)
            fail(
                "DSTACK_TEST_IMAGE_STORE must name the protected candidate image store"
            )
        image_store = Path(image_store_text).resolve()
        image_name = os.environ.get("DSTACK_TEST_GUEST_IMAGE", "dstack-0.6.0")
        try:
            image_provenance = require_image_backend(image_store, image_name)
        except RuntimeError as error:
            fail(str(error))
        image_dir = image_store / image_name
        required = [image_dir / "digest.txt", image_dir / "sha256sum.txt"]
        if not image_dir.is_dir() or not all(path.is_file() for path in required):
            shutil.rmtree(workspace, ignore_errors=True)
            fail(f"candidate image assembly inputs are incomplete: {image_dir}")
        values["image_assembly"] = {
            "candidate_image": image_name,
            "image_provenance": image_provenance,
            "input_dir": str(image_dir),
            "workspace": str(workspace / "artifacts"),
            "source_dir": str(Path(str(runtime["repository"])) / "os/image"),
            "required_manifests": [str(path) for path in required],
            "case_owned_output": True,
        }
    prepare_complete = True
    return {
        "values": values,
        "cleanup_handle": {
            "workspace": str(workspace),
            "state_root": str(STATE_ROOT.resolve()),
            "run_path_link": str(vm_run_path) if "vm_run_path" in locals() else "",
            "supervisor_runtime_dir": (
                str(supervisor_runtime_dir)
                if "supervisor_runtime_dir" in locals()
                else ""
            ),
            "pids": pids,
            "loopback_alias": loopback_alias,
            "simulator_fixture": str(simulator_fixture)
            if "simulator_fixture" in locals()
            else "",
            "stop_simulator": str(stop_simulator)
            if "stop_simulator" in locals()
            else "",
        },
    }


def verify(value: dict[str, Any]) -> dict[str, Any]:
    values = value.get("prepared", {}).get("values", {})
    substrate = values.get("component_substrate", {})
    workspace = Path(str(substrate.get("workspace", "")))
    ok = (
        substrate.get("case_owned") is True
        and workspace.is_dir()
        and isinstance(substrate.get("ports"), dict)
        and len(substrate.get("ports", {})) >= 12
    )
    kms = values.get("kms")
    if isinstance(kms, dict):
        try:
            port = int(str(kms["rpc_url"]).rsplit(":", 1)[1])
            ok = ok and endpoint_ready("127.0.0.1", port)
        except (KeyError, ValueError):
            ok = False
    gateway_nodes = values.get("gateway_cluster", {}).get("nodes")
    if gateway_nodes is None and isinstance(values.get("gateway"), dict):
        gateway_nodes = [values["gateway"]]
    if isinstance(gateway_nodes, list):
        for node in gateway_nodes:
            try:
                port = int(str(node["rpc_url"]).split(":")[-1].split("/")[0])
                ok = ok and endpoint_ready("127.0.0.1", port)
            except (KeyError, TypeError, ValueError):
                ok = False
    return {
        "ok": ok,
        "expected": {"case_owned": True, "workspace": "allocated"},
        "observed": {
            "case_owned": substrate.get("case_owned"),
            "workspace_exists": workspace.is_dir(),
            "port_count": len(substrate.get("ports", {})),
        },
        "error": None if ok else "isolated component substrate is incomplete",
    }


def destroy(value: dict[str, Any]) -> dict[str, Any]:
    for resource in value.get("resources", []):
        handle = resource.get("cleanup", {}).get("handle", {})
        workspace_text = str(handle.get("workspace", ""))
        if not workspace_text:
            continue
        workspace = Path(workspace_text).resolve()
        recorded_state_root = str(handle.get("state_root", "")).strip()
        expected_root = (
            Path(recorded_state_root).resolve() / "component-fixtures"
            if recorded_state_root
            else ROOT.resolve()
        )
        if workspace.parent != expected_root or not workspace.name.startswith("lease-"):
            fail(f"refusing unsafe component workspace cleanup: {workspace}")
        pids = {
            pid for pid in handle.get("pids", []) if isinstance(pid, int) and pid > 1
        }
        supervisor_pid_file = workspace / "run/supervisor.pid"
        if supervisor_pid_file.is_file():
            try:
                supervisor_pid = int(supervisor_pid_file.read_text().strip())
                if supervisor_pid > 1:
                    pids.add(supervisor_pid)
            except ValueError:
                pass
        vmm_pid_file = workspace / "run/vmm.pid"
        if vmm_pid_file.is_file():
            try:
                vmm_pid = int(vmm_pid_file.read_text().strip())
                if vmm_pid > 1:
                    pids.add(vmm_pid)
            except ValueError:
                pass
        terminate_pids(pids)
        loopback_alias = str(handle.get("loopback_alias", ""))
        if loopback_alias:
            try:
                socket.inet_aton(loopback_alias)
            except OSError:
                fail("refusing unsafe loopback alias cleanup")
            removed = subprocess.run(
                [
                    "sudo",
                    "-n",
                    "ip",
                    "address",
                    "delete",
                    f"{loopback_alias}/32",
                    "dev",
                    "lo",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if removed.returncode:
                fail("failed to release the case-owned Gateway fixture address")
        run_path_link_text = str(handle.get("run_path_link", ""))
        if run_path_link_text:
            run_path_link = Path(run_path_link_text)
            if (
                run_path_link.parent == Path("/tmp")
                and run_path_link.name.startswith("dv-")
                and run_path_link.is_symlink()
            ):
                run_path_link.unlink()
        supervisor_runtime_text = str(handle.get("supervisor_runtime_dir", ""))
        if supervisor_runtime_text:
            supervisor_runtime = Path(supervisor_runtime_text)
            runtime_base = Path(
                os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
            )
            expected_parent = runtime_base / "dtsv"
            if (
                supervisor_runtime.parent != expected_parent
                or len(supervisor_runtime.name) != 12
            ):
                fail(
                    f"refusing unsafe supervisor runtime cleanup: {supervisor_runtime}"
                )
            shutil.rmtree(supervisor_runtime, ignore_errors=True)
        simulator_fixture = str(handle.get("simulator_fixture", ""))
        stop_simulator = str(handle.get("stop_simulator", ""))
        if simulator_fixture and stop_simulator:
            subprocess.run(
                [stop_simulator, simulator_fixture],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        time.sleep(0.2)
        shutil.rmtree(workspace, ignore_errors=True)
    return {"released": True}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "verify", "destroy"}:
        fail("usage: isolated-component.py prepare|verify|destroy")
    value = request()
    result = {"prepare": prepare, "verify": verify, "destroy": destroy}[sys.argv[1]](
        value
    )
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
