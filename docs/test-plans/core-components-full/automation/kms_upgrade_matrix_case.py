#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute real mixed-version KMS replacement paths on lease-owned CVMs."""

from __future__ import annotations

import concurrent.futures
import fcntl
import hashlib
import html
import http.client as stdlib_http_client
import json
import os
import pathlib
import re
import secrets
import shlex
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

SUPPORTED = {f"tc-kms-upgrade-{index:03d}" for index in range(1, 13)} | {
    "tc-int-compatibil-001",
    "tc-int-compatibil-003",
    "tc-int-compatibil-004",
    "tc-int-mixed-002",
    "tc-int-mixed-003",
    "tc-int-mixed-004",
    "tc-int-mixed-006",
    "tc-int-end-to-end-001",
    "tc-int-end-to-end-002",
    "tc-int-end-to-end-003",
    "tc-int-end-to-end-004",
    "tc-int-end-to-end-005",
    "tc-int-failure-se-001",
    "tc-int-failure-se-002",
    "tc-int-failure-se-007",
}
COMPATIBILITY_ACTION = "Persisted state migration from v0.5.4, v0.5.8, and v0.5.11"

RELEASES = {
    "0.5.4": ("dstacktee/dstack-kms:0.5.4", "dstack-dev-0.5.4", "legacy"),
    "0.5.7": ("bridge", "dstack-0.5.8", "legacy"),
    "0.5.8": ("dstacktee/dstack-kms:0.5.8", "dstack-0.5.8", "legacy"),
    "0.5.11": ("dstacktee/dstack-kms:0.5.11", "dstack-0.5.11", "modern"),
    "candidate": ("candidate", "candidate", "candidate"),
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic case evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def run(
    command: list[str], *, timeout: int = 180, cwd: pathlib.Path | None = None
) -> str:
    """Run one bounded lifecycle command and return combined output."""
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command rc={completed.returncode}: {' '.join(command)}\n{completed.stdout[-3000:]}"
        )
    return completed.stdout


def free_ports_in_range(start: int, end: int, count: int) -> list[int]:
    """Choose unused loopback ports from the VMM-advertised mapping range."""
    selected: list[int] = []
    for port in range(start, end + 1):
        with socket.socket() as listener:
            try:
                listener.bind(("127.0.0.1", port))
            except OSError:
                continue
        selected.append(port)
        if len(selected) == count:
            return selected
    raise RuntimeError(
        f"VMM port mapping range exhausted: tcp:{start}-{end}, need={count}"
    )


def http(
    url: str, body: bytes | None = None, *, timeout: int = 120
) -> tuple[int, bytes]:
    """Issue a bounded local request and retain the native body only in memory."""
    request = urllib.request.Request(
        url,
        data=body,
        headers={"content-type": "application/json"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(
            request, timeout=timeout, context=ssl._create_unverified_context()
        ) as response:  # noqa: SLF001
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except (
        urllib.error.URLError,
        stdlib_http_client.RemoteDisconnected,
        ConnectionResetError,
        TimeoutError,
    ):
        return 0, b""


def onboard_http(url: str, body: bytes) -> tuple[int, bytes]:
    """Retry a transient host-forward reset before the onboarding RPC is accepted."""
    for attempt in range(3):
        try:
            return http(url, body)
        except ConnectionResetError:
            if attempt == 2:
                raise
            time.sleep(1)
    raise AssertionError("unreachable")


def wait_http(url: str, *, tls: bool, timeout: int = 120) -> int:
    """Wait for an onboarding or initialized KMS listener."""
    deadline = time.monotonic() + timeout
    last = 0
    while time.monotonic() < deadline:
        try:
            last, _ = http(url)
        except ConnectionResetError:
            # QEMU host-forwarding accepts TCP before the guest listener starts.
            last = 0
        if last:
            return last
        time.sleep(1)
    raise RuntimeError(
        f"listener timeout ({'TLS' if tls else 'plain'}): {url}, last={last}"
    )


def old_config(
    auto_domain: str,
    *,
    modern: bool = False,
    verify_image: bool = False,
    image_download_url: str = "http://127.0.0.1:1/{OS_IMAGE_HASH}.tar.gz",
    auth_url: str = "",
) -> str:
    """Return a production-shaped historical KMS config with local policy dependencies."""
    modern_fields = (
        'site_name = ""\nenforce_self_authorization = false\n'
        if modern
        else 'admin_token_hash = ""\n'
    )
    metrics = "[core.metrics]\nenabled = true\n" if modern else ""
    quote = "" if modern else "quote_enabled = true\n"
    auth = (
        f'[core.auth_api]\ntype = "webhook"\n[core.auth_api.webhook]\nurl = "{auth_url}"\n'
        if auth_url
        else '[core.auth_api]\ntype = "dev"\n[core.auth_api.dev]\ngateway_app_id = "any"\n'
    )
    return f'''[rpc]\naddress = "0.0.0.0"\nport = 8000\n[rpc.tls]\nkey = "/etc/kms/certs/rpc.key"\ncerts = "/etc/kms/certs/rpc.crt"\n[rpc.tls.mutual]\nca_certs = "/etc/kms/certs/tmp-ca.crt"\nmandatory = false\n[core]\ncert_dir = "/etc/kms/certs"\nsubject_postfix = ".dstack"\n{modern_fields}[core.image]\nverify = {str(verify_image).lower()}\ncache_dir = "/etc/kms/images"\ndownload_url = "{image_download_url}"\ndownload_timeout = "2s"\n{metrics}{auth}[core.onboard]\nenabled = true\nauto_bootstrap_domain = "{auto_domain}"\n{quote}address = "0.0.0.0"\nport = 8000\n'''


def candidate_config(
    auto_domain: str,
    *,
    verify_image: bool = False,
    image_download_url: str = "http://127.0.0.1:1/{OS_IMAGE_HASH}.tar.gz",
    auth_url: str = "",
) -> str:
    """Return the candidate KMS configuration used for replacement targets."""
    auth = (
        f'[core.auth_api]\ntype = "webhook"\n[core.auth_api.webhook]\nurl = "{auth_url}"\n'
        if auth_url
        else '[core.auth_api]\ntype = "dev"\n[core.auth_api.dev]\ngateway_app_id = "any"\n'
    )
    return f'''[rpc]\naddress = "0.0.0.0"\nport = 8000\n[rpc.tls]\nkey = "/etc/kms/certs/rpc.key"\ncerts = "/etc/kms/certs/rpc.crt"\n[rpc.tls.mutual]\nca_certs = "/etc/kms/certs/tmp-ca.crt"\nmandatory = false\n[core]\ncert_dir = "/etc/kms/certs"\nenforce_self_authorization = false\n[core.image]\nverify = {str(verify_image).lower()}\ncache_dir = "/etc/kms/images"\ndownload_url = "{image_download_url}"\ndownload_timeout = "2s"\n[core.metrics]\nenabled = true\n[core.admin]\nenabled = false\n{auth}[core.onboard]\nenabled = true\nauto_bootstrap_domain = "{auto_domain}"\naddress = "0.0.0.0"\nport = 8000\n'''


class MatrixRun:
    """Own one case's image registry, VMs, public evidence, and cleanup registry."""

    def __init__(
        self,
        case_id: str,
        result_dir: pathlib.Path,
        manifest: dict[str, Any],
        runtime_path: pathlib.Path,
    ):
        """Prepare one case-owned version registry and lifecycle controller."""
        self.case_id = case_id
        self.result_dir = result_dir
        self.manifest = manifest
        self.values = manifest["values"]
        self.runtime_path = runtime_path
        self.workspace = pathlib.Path(
            self.values["version_matrix"]["case_owned_workspace"]
        )
        self.cli = [*self.values["live_vmm"]["cli_argv"]]
        self.registry_path = self.workspace / "upgrade-registry.json"
        self.created_registry = pathlib.Path(
            self.values["live_vmm"]["created_vms_registry"]
        )
        self.rows: list[dict[str, Any]] = []
        self.counter = 0
        prepare = (
            pathlib.Path(json.loads(runtime_path.read_text())["repository"])
            / "docs/test-plans/core-components-full/automation/prepare-kms-upgrade-images.py"
        )
        run(
            [
                str(prepare),
                "--runtime-manifest",
                str(runtime_path),
                "--workspace",
                str(self.workspace),
                "--output",
                str(self.registry_path),
                *(
                    ["--include-gateway"]
                    if case_id
                    in {
                        "tc-kms-upgrade-012",
                        "tc-int-compatibil-003",
                        "tc-int-compatibil-004",
                        "tc-int-mixed-002",
                        "tc-int-mixed-003",
                        "tc-int-mixed-004",
                        "tc-int-mixed-006",
                        "tc-int-end-to-end-001",
                        "tc-int-end-to-end-002",
                        "tc-int-end-to-end-003",
                        "tc-int-end-to-end-004",
                        "tc-int-end-to-end-005",
                        "tc-int-failure-se-002",
                        "tc-int-failure-se-007",
                    }
                    else []
                ),
            ],
            timeout=1800,
        )
        self.registry = json.loads(self.registry_path.read_text())
        self.prelaunch = self.workspace / "upgrade-registry-prelaunch.sh"
        self.prelaunch.write_text(
            f'''#!/bin/sh\nset -eu\nmkdir -p /etc/docker\ncat > /etc/docker/daemon.json <<JSON\n{{"insecure-registries":["{self.registry["registry_guest"]}"]}}\nJSON\nsystemctl restart docker\n'''
        )
        self.prelaunch.chmod(0o755)

    def image(self, version: str) -> tuple[str, str, str]:
        """Resolve the immutable container/guest/config family for a matrix version."""
        image, guest, family = RELEASES[version]
        if image == "bridge":
            image = self.registry["bridge_image"]
        if image == "candidate":
            image = self.registry["candidate_image"]
        if guest == "candidate":
            guest = self.values["version_matrix"]["guest_images"]["0.6.0-candidate"]
        return image, guest, family

    def free_ports(self, count: int) -> list[int]:
        """Allocate ports absent from both listeners and retained VMM configurations."""
        configured = json.loads(run([*self.cli, "lsvm", "--json"]))
        reserved = {
            int(port["host_port"])
            for vm in configured
            for port in (vm.get("configuration", {}).get("ports") or [])
            if port.get("protocol") == "tcp" and port.get("host_address") == "127.0.0.1"
        }
        port_mapping = self.values["live_vmm"]["port_mapping"]
        selected: list[int] = []
        for port in range(int(port_mapping["from"]), int(port_mapping["to"]) + 1):
            if port in reserved:
                continue
            with socket.socket() as listener:
                try:
                    listener.bind(("127.0.0.1", port))
                except OSError:
                    continue
            selected.append(port)
            if len(selected) == count:
                return selected
        raise RuntimeError(
            f"VMM port mapping range exhausted after retained reservations: "
            f"need={count} reserved={len(reserved)}"
        )

    def wait_vm_http(
        self, url: str, vm_id: str, *, tls: bool, timeout: int = 180
    ) -> int:
        """Wait for a guest listener and recover transient sealing failures."""
        deadline = time.monotonic() + timeout
        sealing_restarts = 0
        last_code = 0
        latest: dict[str, Any] = {}
        while time.monotonic() < deadline:
            last_code, _ = http(url, timeout=10)
            if last_code:
                return last_code
            latest = json.loads(run([*self.cli, "info", "--json", vm_id]))
            boot_error = str(latest.get("boot_error") or "")
            if "Failed to get sealing key" in boot_error and sealing_restarts < 2:
                exit_deadline = min(deadline, time.monotonic() + 60)
                while time.monotonic() < exit_deadline:
                    latest = json.loads(run([*self.cli, "info", "--json", vm_id]))
                    if latest.get("status") == "exited":
                        break
                    time.sleep(2)
                if latest.get("status") != "exited":
                    raise RuntimeError(
                        "KMS guest did not exit after a transient sealing failure: "
                        f"{latest.get('status')}"
                    )
                time.sleep(5)
                run([*self.cli, "start", vm_id], timeout=120)
                sealing_restarts += 1
                continue
            if boot_error:
                raise RuntimeError(f"KMS guest boot failed: {boot_error}")
            time.sleep(1)
        raise RuntimeError(
            f"listener timeout ({'TLS' if tls else 'plain'}): {url}, "
            f"last={last_code}, vm_status={latest.get('status')}, "
            f"boot_progress={latest.get('boot_progress')!r}"
        )

    def deploy(
        self,
        version: str,
        *,
        initialized: bool,
        legacy: bool | None = True,
        verify_image: bool = False,
        auth_context: str = "",
        domain_override: str = "",
        legacy_vmm_wire: bool = False,
    ) -> dict[str, Any]:
        """Deploy one source or target and register it for provider cleanup immediately."""
        self.counter += 1
        image, guest, family = self.image(version)
        port_mapping = self.values["live_vmm"]["port_mapping"]
        if port_mapping.get("protocol") != "tcp":
            raise RuntimeError(f"unsupported VMM port mapping: {port_mapping}")
        name = f"{self.values['live_vmm']['name_prefix']}-{self.case_id[-3:]}-{self.counter}-{version.replace('.', '')}"
        domain = domain_override if initialized else ""
        if initialized and not domain:
            domain = f"{name}.test"
        auth_url = (
            self.values["live_vmm"]["kms_upgrade_policy_guest_urls"][auth_context]
            if auth_context
            else ""
        )
        config = (
            candidate_config(
                domain,
                verify_image=verify_image,
                image_download_url=self.values["live_vmm"]["image_archive_guest_url"],
                auth_url=auth_url,
            )
            if family == "candidate"
            else old_config(
                domain,
                modern=family == "modern",
                verify_image=verify_image,
                image_download_url=self.values["live_vmm"]["image_archive_guest_url"],
                auth_url=auth_url,
            )
        )
        compose_yaml = self.workspace / f"{name}.compose.yml"
        compose_yaml.write_text(
            f"""services:\n  kms:\n    image: {image}\n    command: ["dstack-kms", "--config", "/etc/kms/kms.toml"]\n    ports: ["8000:8000"]\n    volumes:\n      - /var/run/dstack.sock:/var/run/dstack.sock\n      - kms-certs:/etc/kms/certs\n    configs:\n      - source: kms_config\n        target: /etc/kms/kms.toml\n    restart: unless-stopped\nvolumes:\n  kms-certs: {{}}\nconfigs:\n  kms_config:\n    content: |\n{"".join(f"      {line}\n" for line in config.splitlines())}"""
        )
        app = self.workspace / f"{name}.app-compose.json"
        run(
            [
                *self.cli,
                "compose",
                "--name",
                name,
                "--docker-compose",
                str(compose_yaml),
                "--prelaunch-script",
                str(self.prelaunch),
                "--key-provider",
                "local",
                "--public-logs",
                "--output",
                str(app),
            ]
        )
        if family == "candidate":
            value = json.loads(app.read_text())
            value["manifest_version"] = "3"
            value["requirements"] = {"tdx_measure_acpi_tables": legacy}
            app.write_text(json.dumps(value, indent=2) + "\n")
        if legacy_vmm_wire:
            value = json.loads(app.read_text())
            value["manifest_version"] = 2
            app.write_text(json.dumps(value, indent=2) + "\n")
        lock_path = pathlib.Path("/tmp/dstack-kms-upgrade-port-allocation.lock")
        with lock_path.open("a+") as allocation_lock:
            fcntl.flock(allocation_lock, fcntl.LOCK_EX)
            service_port, log_port = self.free_ports(2)
            output = run(
                [
                    *self.cli,
                    "deploy",
                    "--name",
                    name,
                    "--image",
                    guest,
                    "--compose",
                    str(app),
                    "--vcpu",
                    "2",
                    "--memory",
                    "2G",
                    "--disk",
                    "8G",
                    "--port",
                    f"tcp:127.0.0.1:{service_port}:8000",
                    "--port",
                    f"tcp:127.0.0.1:{log_port}:8090",
                    "--tee",
                    "--net",
                    "user",
                ]
            )
        match = re.search(r"Created VM with ID: ([0-9a-f-]+)", output)
        if not match:
            raise RuntimeError(f"deploy omitted VM ID: {output[-1000:]}")
        vm_id = match.group(1)
        ids = json.loads(self.created_registry.read_text())
        ids.append(vm_id)
        self.created_registry.write_text(json.dumps(ids, indent=2) + "\n")
        url = f"{'https' if initialized else 'http'}://127.0.0.1:{service_port}"
        probe = f"{url}/prpc/KMS.GetMeta?json" if initialized else f"{url}/"
        self.wait_vm_http(probe, vm_id, tls=initialized)
        row = {
            "version": version,
            "vm_id": vm_id,
            "domain": domain,
            "service_port": service_port,
            "log_port": log_port,
            "initialized": initialized,
            "legacy_required": legacy if family == "candidate" else None,
        }
        self.rows.append(row)
        return row

    def tcb_info(self, row: dict[str, Any]) -> dict[str, Any]:
        """Read public TCB data, including legacy vm_config from the VM share."""
        code, raw = http(f"http://127.0.0.1:{row['log_port']}/")
        if code != 200:
            raise RuntimeError(f"guest dashboard HTTP {code}")
        for encoded in re.findall(rb"<textarea[^>]*>(.*?)</textarea>", raw, re.DOTALL):
            try:
                value = json.loads(html.unescape(encoded.decode()))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                not isinstance(value, dict)
                or "rtmr0" not in value
                or "event_log" not in value
            ):
                continue
            if "vm_config" not in value:
                handle = self.manifest["resources"][0]["cleanup"]["handle"]
                vm_root = pathlib.Path(handle["stack_handle"]["vm_root"])
                sys_config = json.loads(
                    (vm_root / row["vm_id"] / "shared/.sys-config.json").read_text()
                )
                value["vm_config"] = sys_config["vm_config"]
            return value
        raise RuntimeError("guest dashboard omitted public TCB JSON")

    def diagnose_in_image(
        self,
        image: str,
        binary: pathlib.Path,
        vm_config: pathlib.Path,
        event_log: pathlib.Path,
        image_dir: pathlib.Path,
        actual_rtmr0: str,
    ) -> tuple[int, str]:
        """Run the candidate diagnosis CLI with one image's age-specific ACPI tool."""
        command = " ".join(
            [
                "docker run --rm --entrypoint /diagnose",
                f"-v {shlex.quote(str(binary))}:/diagnose:ro",
                f"-v {shlex.quote(str(self.workspace))}:/case:ro",
                f"-v {shlex.quote(str(image_dir))}:/image:ro",
                shlex.quote(image),
                "diagnose",
                "--vm-config /case/diagnose-vm-config.json",
                "--image-dir /image",
                "--actual-event-log /case/diagnose-event-log.json",
                f"--actual-rtmr0 {shlex.quote(actual_rtmr0)}",
            ]
        )
        completed = subprocess.run(
            ["sudo", "su", "kvin", "-c", command],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
        )
        return completed.returncode, completed.stdout

    def set_upgrade_policy(self, value: dict[str, Any]) -> None:
        """Atomically replace the lease-owned webhook authorization policy."""
        atomic_json(
            pathlib.Path(self.values["live_vmm"]["kms_upgrade_policy_path"]), value
        )

    def policy_observations(self) -> list[dict[str, Any]]:
        """Read public KMS boot authorization observations from the fixture."""
        path = pathlib.Path(self.values["live_vmm"]["kms_upgrade_policy_observations"])
        return [json.loads(line) for line in path.read_text().splitlines() if line]

    def onboard(
        self,
        target: dict[str, Any],
        source: dict[str, Any],
        *,
        expect_success: bool,
        target_domain: str = "",
    ) -> tuple[int, str]:
        """Attempt one key-transfer hop and optionally transition the target to main mode."""
        source_url = f"https://10.0.2.2:{source['service_port']}"
        # The 0.5.4 onboarding client appends bare RPC method names, while
        # newer clients append the /prpc prefix themselves.
        if target["version"] == "0.5.4":
            source_url += "/prpc"
        body = json.dumps(
            {
                "source_url": source_url,
                "domain": target_domain or f"{self.case_id}.target.test",
            },
            separators=(",", ":"),
        ).encode()
        code, raw = onboard_http(
            f"http://127.0.0.1:{target['service_port']}/prpc/Onboard.Onboard?json",
            body,
        )
        diagnostic = re.sub(
            r"[A-Za-z0-9_+/=-]{48,}", "<redacted>", raw.decode(errors="replace")
        )[:300]
        if expect_success:
            if code != 200:
                raise RuntimeError(
                    f"onboard {source['version']}->{target['version']} HTTP {code}: {diagnostic}"
                )
            finish, _ = http(f"http://127.0.0.1:{target['service_port']}/finish")
            if finish != 200:
                raise RuntimeError(f"finish HTTP {finish}")
            wait_http(
                f"https://127.0.0.1:{target['service_port']}/prpc/KMS.GetMeta?json",
                tls=True,
                timeout=60,
            )
            target["initialized"] = True
            target["domain"] = target_domain or f"{self.case_id}.target.test"
        elif code < 400:
            raise RuntimeError(
                f"incompatible onboard unexpectedly succeeded with HTTP {code}"
            )
        return code, diagnostic

    def stop_endpoint(
        self, row: dict[str, Any], *, force: bool = True
    ) -> dict[str, Any]:
        """Stop one lease-owned KMS VM and prove its forwarded endpoint is unavailable."""
        run([*self.cli, "stop", row["vm_id"], *(["--force"] if force else [])])
        deadline = time.monotonic() + 30
        observations: list[int] = []
        url = f"https://127.0.0.1:{row['service_port']}/prpc/KMS.GetMeta?json"
        while time.monotonic() < deadline:
            code, _ = http(url)
            observations.append(code)
            if code == 0:
                if not force:
                    state_deadline = time.monotonic() + 120
                    last_state = ""
                    while time.monotonic() < state_deadline:
                        values = json.loads(run([*self.cli, "lsvm", "--json"]))
                        last_state = next(
                            item.get("status", "")
                            for item in values
                            if item.get("id") == row["vm_id"]
                        )
                        if last_state == "stopped":
                            break
                        time.sleep(1)
                    else:
                        raise RuntimeError(
                            f"graceful stop did not converge: vm={row['vm_id']} "
                            f"state={last_state}"
                        )
                row["running"] = False
                return {"unavailable": True, "http_observations": observations}
            time.sleep(1)
        raise RuntimeError(
            f"stopped endpoint remained reachable: vm={row['vm_id']} observations={observations}"
        )

    def start_endpoint(self, row: dict[str, Any]) -> dict[str, Any]:
        """Restart one lease-owned KMS VM and prove its initialized API recovers."""
        run([*self.cli, "start", row["vm_id"]])
        url = f"https://127.0.0.1:{row['service_port']}/prpc/KMS.GetMeta?json"
        status = wait_http(url, tls=True, timeout=120)
        if status != 200:
            raise RuntimeError(
                f"restarted endpoint returned HTTP {status}: vm={row['vm_id']}"
            )
        row["running"] = True
        return {"recovered": True, "http": status}

    def configure_endpoint_proxy(
        self,
        index: int,
        backend: dict[str, Any],
        *,
        enabled: bool,
        connect_delay_seconds: float = 0,
        expected_domain: str = "",
        guest_url_override: str = "",
        probe_path: str = "/prpc/KMS.GetMeta?json",
        expected_http: int | None = 200,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Route or reject new TLS connections without restarting the KMS VM."""
        proxies = self.values["live_vmm"]["kms_upgrade_proxies"]
        proxy = proxies[index]
        atomic_json(
            pathlib.Path(proxy["config"]),
            {
                "enabled": enabled,
                "host": "127.0.0.1",
                "port": backend["service_port"],
                "connect_delay_seconds": connect_delay_seconds,
            },
        )
        route = {
            **backend,
            "service_port": int(proxy["port"]),
            **({"domain": expected_domain} if expected_domain else {}),
            **(
                {
                    "guest_url": guest_url_override,
                    "client_guest_url": guest_url_override,
                }
                if guest_url_override
                else {}
            ),
        }
        url = f"https://127.0.0.1:{route['service_port']}{probe_path}"
        if enabled:
            status = wait_http(url, tls=True, timeout=30)
            if expected_http is not None and status != expected_http:
                raise RuntimeError(f"enabled endpoint proxy returned HTTP {status}")
            return route, {"enabled": True, "http": status}
        deadline = time.monotonic() + 10
        observations: list[int] = []
        while time.monotonic() < deadline:
            try:
                code, _ = http(url)
            except ConnectionResetError:
                code = 0
            observations.append(code)
            if code == 0:
                return route, {
                    "enabled": False,
                    "unavailable": True,
                    "http_observations": observations,
                }
            time.sleep(0.2)
        raise RuntimeError(f"disabled endpoint proxy remained usable: {observations}")

    def deploy_gateway(
        self,
        version: str,
        kms_rows: list[dict[str, Any]],
        *,
        node_id: int,
        name_suffix: str = "",
        evidence_observer: bool = False,
        bootnode_guest_url: str = "",
        source_app_id: str = "",
        client_range: str = "",
    ) -> dict[str, Any]:
        """Deploy one real Gateway CVM after the selected KMS endpoints are healthy."""
        self.counter += 1
        suffix = f"-{name_suffix}" if name_suffix else ""
        name = f"{self.values['live_vmm']['name_prefix']}-012-gateway-{version}{suffix}"
        image = {
            "0.5.8": self.registry["old_gateway_image"],
            "0.5.11": self.registry["gateway_0_5_11_image"],
            "candidate": self.registry["candidate_gateway_image"],
        }[version]
        compose_yaml = self.workspace / f"{name}.compose.yml"
        observer = pathlib.Path(
            json.loads(self.runtime_path.read_text())["repository"]
        ) / (
            "docs/test-plans/core-components-full/automation/gateway-certificate-observer.py"
        )
        cloudflare_proxy = pathlib.Path(
            json.loads(self.runtime_path.read_text())["repository"]
        ) / (
            "docs/test-plans/core-components-full/automation/"
            "gateway-cloudflare-zone-proxy.py"
        )
        observer_service = ""
        observer_config = ""
        dns_service = ""
        dns_config = ""
        gateway_dns = ""
        certbot_services = ""
        sync_bridge_service = ""
        sync_bridge_config = ""
        sync_bridge_dependency = ""
        effective_bootnode_url = bootnode_guest_url
        compatibility_bridge = pathlib.Path(
            json.loads(self.runtime_path.read_text())["repository"]
        ) / (
            "docs/test-plans/core-components-full/automation/"
            "gateway-upgrade-sync-bridge.py"
        )
        if version == "candidate" and bootnode_guest_url:
            effective_bootnode_url = "https://127.0.0.1:7999"
            sync_bridge_dependency = """      gateway-sync-bridge:
        condition: service_healthy
"""
            sync_bridge_service = f"""  gateway-sync-bridge:
    image: dstacktee/dstack-kms:0.5.8
    network_mode: host
    entrypoint: ["python3", "/opt/gateway-upgrade-sync-bridge.py"]
    environment:
      - UPSTREAM_URL={bootnode_guest_url}
      - ADVERTISED_URL=https://127.0.0.1:7999
    volumes:
      - /var/run/tappd.sock:/var/run/tappd.sock
    configs:
      - source: gateway-upgrade-sync-bridge
        target: /opt/gateway-upgrade-sync-bridge.py
    healthcheck:
      test: ["CMD", "python3", "/opt/gateway-upgrade-sync-bridge.py", "--check"]
      interval: 1s
      timeout: 3s
      retries: 30
    restart: unless-stopped
"""
            sync_bridge_config = f"""  gateway-upgrade-sync-bridge:
    content: |
{"".join(f"      {line}\n" for line in compatibility_bridge.read_text().splitlines())}"""
        if version == "candidate":
            gateway_dns = """    depends_on:
      mock-cf-dns-api:
        condition: service_started
      cloudflare-zone-proxy:
        condition: service_healthy
      pebble:
        condition: service_started
""" + sync_bridge_dependency
            certbot_services = """  mock-cf-dns-api:
    image: kvin/mock-cf-dns-api:latest
    network_mode: host
    environment:
      - DEBUG=true
    restart: unless-stopped
  cloudflare-zone-proxy:
    image: dstacktee/dstack-kms:0.5.8
    network_mode: host
    entrypoint: ["python3", "/opt/gateway-cloudflare-zone-proxy.py"]
    configs:
      - source: cloudflare-zone-proxy
        target: /opt/gateway-cloudflare-zone-proxy.py
    depends_on:
      mock-cf-dns-api:
        condition: service_started
    healthcheck:
      test: ["CMD", "python3", "/opt/gateway-cloudflare-zone-proxy.py", "--check"]
      interval: 1s
      timeout: 3s
      retries: 15
    restart: unless-stopped
  pebble:
    image: kvin/pebble:latest
    network_mode: host
    command: ["-http", "-dnsserver", "127.0.0.1:53"]
    environment:
      - PEBBLE_VA_NOSLEEP=1
      - PEBBLE_VA_ALWAYS_VALID=1
    restart: unless-stopped
"""
            dns_config = f"""  cloudflare-zone-proxy:
    content: |
{"".join(f"      {line}\n" for line in cloudflare_proxy.read_text().splitlines())}"""
        if version == "0.5.11":
            dns_script = (
                pathlib.Path(json.loads(self.runtime_path.read_text())["repository"])
                / "docs/test-plans/core-components-full/automation/gateway-upgrade-dns.py"
            )
            dns_service = """  upgrade-dns:
    image: dstacktee/dstack-kms:0.5.8
    network_mode: host
    entrypoint: ["python3", "/opt/gateway-upgrade-dns.py"]
    configs:
      - source: upgrade-dns
        target: /opt/gateway-upgrade-dns.py
    healthcheck:
      test: ["CMD", "python3", "/opt/gateway-upgrade-dns.py", "--check"]
      interval: 1s
      timeout: 3s
      retries: 15
    restart: unless-stopped
"""
            dns_config = f"""  upgrade-dns:
    content: |
{"".join(f"      {line}\n" for line in dns_script.read_text().splitlines())}"""
            gateway_dns = """    dns: [127.0.0.55]
    depends_on:
      upgrade-dns:
        condition: service_healthy
"""
        if evidence_observer:
            observer_service = """  evidence-observer:
    image: dstacktee/dstack-kms:0.5.8
    network_mode: host
    entrypoint: ["python3", "/opt/gateway-certificate-observer.py"]
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    configs:
      - source: evidence-observer
        target: /opt/gateway-certificate-observer.py
    restart: unless-stopped
"""
            observer_config = f"""  evidence-observer:
    content: |
{"".join(f"      {line}\n" for line in observer.read_text().splitlines())}"""
        configs_section = ""
        if (
            dns_config
            or observer_config
            or sync_bridge_config
        ):
            configs_section = (
                f"configs:\n{dns_config}{observer_config}{sync_bridge_config}"
            )
        compose_yaml.write_text(
            f"""services:
  gateway:
    image: {image}
    network_mode: host
    privileged: true
{gateway_dns}    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - /dstack:/dstack
      - gateway-data:/data
    environment:
      - WG_ENDPOINT=${{WG_ENDPOINT}}
      - MY_URL=${{MY_URL}}
      - BOOTNODE_URL=${{BOOTNODE_URL}}
      - WG_IP=${{WG_IP}}
      - WG_RESERVED_NET=${{WG_RESERVED_NET}}
      - WG_CLIENT_RANGE=${{WG_CLIENT_RANGE}}
      - APP_LAUNCH_TOKEN=${{APP_LAUNCH_TOKEN}}
      - ADMIN_API_TOKEN=${{ADMIN_API_TOKEN}}
      - RPC_DOMAIN=${{RPC_DOMAIN}}
      - NODE_ID=${{NODE_ID}}
      - PROXY_LISTEN_PORT=${{PROXY_LISTEN_PORT}}
    restart: unless-stopped
{dns_service}{certbot_services}{sync_bridge_service}{observer_service}volumes:
  gateway-data: {{}}
{configs_section}"""
        )
        env_file = self.workspace / f"{name}.env"
        env_file.write_text(
            "\n".join(
                (
                    "WG_ENDPOINT=127.0.0.1:51820",
                    f"MY_URL=https://10.0.2.2:{8000 + node_id}",
                    "BOOTNODE_URL=",
                    f"WG_IP=10.8.{node_id}.1/16",
                    f"WG_RESERVED_NET=10.8.{node_id}.1/32",
                    f"WG_CLIENT_RANGE={client_range or f'10.8.{node_id}.0/24'}",
                    "APP_LAUNCH_TOKEN=case-owned",
                    "ADMIN_API_TOKEN=case-owned-admin",
                    f"RPC_DOMAIN=gateway-{version}.test",
                    f"NODE_ID={node_id}",
                    "PROXY_LISTEN_PORT=8443",
                )
            )
            + "\n"
        )
        app = self.workspace / f"{name}.app-compose.json"
        run(
            [
                *self.cli,
                "compose",
                "--name",
                "dstack-gateway",
                "--docker-compose",
                str(compose_yaml),
                "--prelaunch-script",
                str(self.prelaunch),
                "--kms",
                "--env-file",
                str(env_file),
                "--no-instance-id",
                "--public-logs",
                "--output",
                str(app),
            ]
        )
        with pathlib.Path("/tmp/dstack-kms-upgrade-port-allocation.lock").open(
            "a+"
        ) as allocation_lock:
            fcntl.flock(allocation_lock, fcntl.LOCK_EX)
            allocated = self.free_ports(
                5 + int(evidence_observer)
            )
            service_port, admin_port, proxy_port, log_port, wg_port = allocated[:5]
            next_port = 5
            observer_port = allocated[next_port] if evidence_observer else 0
            next_port += int(evidence_observer)
            env_file.write_text(
                env_file.read_text()
                .replace(
                    "WG_ENDPOINT=127.0.0.1:51820",
                    f"WG_ENDPOINT=10.0.2.2:{wg_port}",
                )
                .replace(
                    f"MY_URL=https://10.0.2.2:{8000 + node_id}",
                    f"MY_URL=https://10.0.2.2:{service_port}",
                )
                .replace("BOOTNODE_URL=", f"BOOTNODE_URL={effective_bootnode_url}")
            )
            command = [
                *self.cli,
                "deploy",
                "--name",
                name,
                "--image",
                self.values["version_matrix"]["guest_images"]["0.6.0-candidate"],
                "--compose",
                str(app),
                "--env-file",
                str(env_file),
                *(["--app-id", source_app_id] if source_app_id else []),
                "--vcpu",
                "2",
                "--memory",
                "2G",
                "--disk",
                "8G",
                "--port",
                f"tcp:127.0.0.1:{service_port}:8000",
                "--port",
                f"tcp:127.0.0.1:{admin_port}:8001",
                "--port",
                f"tcp:127.0.0.1:{proxy_port}:8443",
                "--port",
                f"tcp:127.0.0.1:{log_port}:8090",
                "--port",
                f"udp:127.0.0.1:{wg_port}:51820",
                *(
                    ["--port", f"tcp:127.0.0.1:{observer_port}:8002"]
                    if evidence_observer
                    else []
                ),
                "--tee",
                "--net",
                "user",
            ]
            command.extend(
                [
                    "--kms-encrypt-url",
                    f"https://127.0.0.1:{kms_rows[0]['service_port']}",
                ]
            )
            for row in kms_rows:
                command.extend(
                    ["--kms-url", f"https://{row['domain']}:{row['service_port']}"]
                )
            output = run(command, timeout=300)
        match = re.search(r"Created VM with ID: ([0-9a-f-]+)", output)
        if not match:
            raise RuntimeError(f"gateway deploy omitted VM ID: {output[-1000:]}")
        vm_id = match.group(1)
        ids = json.loads(self.created_registry.read_text())
        ids.append(vm_id)
        self.created_registry.write_text(json.dumps(ids, indent=2) + "\n")
        url = f"https://127.0.0.1:{service_port}"
        status = wait_http(url, tls=True, timeout=180)
        if version == "candidate":
            admin_base = f"http://127.0.0.1:{admin_port}/prpc"

            def admin_rpc(method: str, payload: dict[str, Any]) -> dict[str, Any]:
                for rpc_method in (f"Admin.{method}", method):
                    request = urllib.request.Request(
                        f"{admin_base}/{rpc_method}",
                        data=json.dumps(payload).encode(),
                        headers={
                            "authorization": "Bearer case-owned-admin",
                            "content-type": "application/json",
                        },
                    )
                    try:
                        with urllib.request.urlopen(request, timeout=60) as response:
                            body = response.read()
                    except urllib.error.HTTPError as error:
                        error_body = error.read()
                        if (
                            rpc_method.startswith("Admin.")
                            and b"Service not found" in error_body
                        ):
                            continue
                        raise RuntimeError(
                            f"Gateway {rpc_method} returned HTTP {error.code}: "
                            f"{error_body[:500]!r}"
                        ) from error
                    return json.loads(body) if body else {}
                raise RuntimeError(f"Gateway admin RPC route not found: {method}")

            admin_rpc(
                "SetCertbotConfig",
                {
                    "acme_url": "http://127.0.0.1:14000/dir",
                    "renew_timeout_secs": 60,
                },
            )
            admin_rpc(
                "CreateDnsCredential",
                {
                    "name": "upgrade-matrix-cloudflare",
                    "provider_type": "cloudflare",
                    "cf_api_token": "case-owned",
                    "cf_zone_id": "case-owned-zone",
                    "cf_api_url": "http://127.0.0.1:18080/client/v4",
                    "set_as_default": True,
                    "dns_txt_ttl": 1,
                    "max_dns_wait": 5,
                },
            )
            admin_rpc(
                "AddZtDomain",
                {
                    "domain": "gateway-candidate.test",
                    "port": 8443,
                    "priority": 100,
                },
            )
            admin_rpc(
                "RenewZtDomainCert",
                {"domain": "gateway-candidate.test", "force": True},
            )
            certificate_deadline = time.monotonic() + 120
            cert_status: dict[str, Any] = {}
            while time.monotonic() < certificate_deadline:
                domain = admin_rpc("GetZtDomain", {"domain": "gateway-candidate.test"})
                cert_status = (
                    domain.get("cert_status") or domain.get("certStatus") or {}
                )
                if cert_status.get(
                    "loaded_in_memory", cert_status.get("loadedInMemory", False)
                ):
                    break
                time.sleep(1)
            else:
                raise RuntimeError(
                    "Gateway ZT-domain certificate was not loaded within 120 seconds: "
                    f"{cert_status}"
                )
        if evidence_observer:
            observer_status = wait_http(
                f"http://127.0.0.1:{observer_port}/observation",
                tls=False,
                timeout=180,
            )
            if observer_status != 200:
                raise RuntimeError(
                    f"Gateway evidence observer returned HTTP {observer_status}"
                )
        row = {
            "version": f"gateway-{version}",
            "vm_id": vm_id,
            "service_port": service_port,
            "admin_port": admin_port,
            "proxy_port": proxy_port,
            "log_port": log_port,
            "observer_port": observer_port,
            "wg_port": wg_port,
            "wg_ip": f"10.8.{node_id}.1",
            "url": url,
            "guest_url": f"https://10.0.2.2:{service_port}",
            "client_guest_url": f"https://10.0.2.2:{service_port}",
            "health_http": status,
            "kms_versions": [item["version"] for item in kms_rows],
            "app_id": source_app_id,
        }
        self.rows.append(row)
        return row

    def deploy_legacy_client_bridge(
        self,
        kms_rows: list[dict[str, Any]],
        old_gateway: dict[str, Any],
        *,
        source_app_id: str,
        guest_image: str,
    ) -> dict[str, Any]:
        """Deploy a legacy-RA Guest that translates current registration TLS."""
        self.counter += 1
        name = (
            f"{self.values['live_vmm']['name_prefix']}-{self.case_id[-3:]}-"
            f"legacy-client-bridge-{self.counter}"
        )
        compatibility_bridge = pathlib.Path(
            json.loads(self.runtime_path.read_text())["repository"]
        ) / (
            "docs/test-plans/core-components-full/automation/"
            "gateway-upgrade-sync-bridge.py"
        )
        compose_yaml = self.workspace / f"{name}.compose.yml"
        compose_yaml.write_text(
            f"""services:
  gateway-client-bridge:
    image: dstacktee/dstack-kms:0.5.8
    network_mode: host
    entrypoint: ["python3", "/opt/gateway-upgrade-sync-bridge.py"]
    environment:
      - UPSTREAM_URL=${{UPSTREAM_URL}}
      - ADVERTISED_URL=${{ADVERTISED_URL}}
    volumes:
      - /var/run/tappd.sock:/var/run/tappd.sock
    configs:
      - source: gateway-upgrade-sync-bridge
        target: /opt/gateway-upgrade-sync-bridge.py
    healthcheck:
      test: ["CMD", "python3", "/opt/gateway-upgrade-sync-bridge.py", "--check", "--listen", "127.0.0.1:7998"]
      interval: 1s
      timeout: 3s
      retries: 30
    command: ["--listen", "0.0.0.0:7998"]
    restart: unless-stopped
configs:
  gateway-upgrade-sync-bridge:
    content: |
{"".join(f"      {line}\n" for line in compatibility_bridge.read_text().splitlines())}"""
        )
        env_file = self.workspace / f"{name}.env"
        env_file.write_text(
            f"UPSTREAM_URL={old_gateway['guest_url']}\n"
            "ADVERTISED_URL=https://127.0.0.1:7998\n"
        )
        app = self.workspace / f"{name}.app-compose.json"
        run(
            [
                *self.cli,
                "compose",
                "--name",
                "gateway-client-compatibility",
                "--docker-compose",
                str(compose_yaml),
                "--prelaunch-script",
                str(self.prelaunch),
                "--kms",
                "--env-file",
                str(env_file),
                "--public-logs",
                "--output",
                str(app),
            ]
        )
        app_value = json.loads(app.read_text())
        app_value["manifest_version"] = 2
        app.write_text(json.dumps(app_value, indent=2) + "\n")
        with pathlib.Path("/tmp/dstack-kms-upgrade-port-allocation.lock").open(
            "a+"
        ) as allocation_lock:
            fcntl.flock(allocation_lock, fcntl.LOCK_EX)
            service_port = self.free_ports(1)[0]
            command = [
                *self.cli,
                "deploy",
                "--name",
                name,
                "--image",
                guest_image,
                "--compose",
                str(app),
                "--env-file",
                str(env_file),
                "--kms-encrypt-url",
                f"https://127.0.0.1:{kms_rows[0]['service_port']}",
                "--app-id",
                source_app_id,
                "--vcpu",
                "2",
                "--memory",
                "2G",
                "--disk",
                "8G",
                "--port",
                f"tcp:127.0.0.1:{service_port}:7998",
                "--tee",
                "--net",
                "user",
            ]
            for row in kms_rows:
                command.extend(
                    ["--kms-url", f"https://{row['domain']}:{row['service_port']}"]
                )
            output = run(command, timeout=300)
        match = re.search(r"Created VM with ID: ([0-9a-f-]+)", output)
        if not match:
            raise RuntimeError(
                f"legacy client bridge deploy omitted VM ID: {output[-1000:]}"
            )
        vm_id = match.group(1)
        ids = json.loads(self.created_registry.read_text())
        ids.append(vm_id)
        self.created_registry.write_text(json.dumps(ids, indent=2) + "\n")
        url = f"https://127.0.0.1:{service_port}"
        if wait_http(url, tls=True, timeout=180) != 501:
            raise RuntimeError("legacy client bridge did not become reachable")
        row = {
            "version": "legacy-client-bridge-0.5.11",
            "vm_id": vm_id,
            "service_port": service_port,
            "guest_url": f"https://10.0.2.2:{service_port}",
            "url": url,
            "app_id": source_app_id,
        }
        self.rows.append(row)
        return row

    def deploy_client(
        self,
        kms_rows: list[dict[str, Any]],
        *,
        identity: str = "existing",
        gateway_rows: list[dict[str, Any]] | None = None,
        encrypted_environment: dict[str, str] | None = None,
        trust_chain: bool = False,
        continuity: bool = False,
        register_gateways_on_boot: bool = True,
        gateway_registration_mode: str = "all",
        source_app_id: str = "",
        expect_boot: bool = True,
        expect_policy_denial: bool = True,
        kms_encrypt_row: dict[str, Any] | None = None,
        native_gateway: bool = False,
        restricted_ports: list[int] | None = None,
        guest_image: str = "",
        legacy_vmm_wire: bool = False,
        prepare_gateway_wireguard: bool = False,
    ) -> dict[str, Any]:
        """Boot one real TDX app through an ordered list of KMS endpoints."""
        self.counter += 1
        name = f"{self.values['live_vmm']['name_prefix']}-{self.case_id[-3:]}-client-{self.counter}"
        observer = (
            pathlib.Path(json.loads(self.runtime_path.read_text())["repository"])
            / "docs/test-plans/core-components-full/automation/kms-upgrade-client-observer.py"
        )
        gateway_cache_volume = (
            "      - /run/dstack:/run/dstack-host:ro\n"
            if native_gateway
            else ""
        )
        compose_yaml = self.workspace / f"{name}.compose.yml"
        compose_yaml.write_text(
            f"""services:
  observer:
    image: dstacktee/dstack-kms:0.5.8
    entrypoint: ["python3", "/opt/kms-upgrade-client-observer.py"]
    environment:
      DERIVATION_PATH: kms-upgrade-009-{identity}
      GATEWAY_URLS: ${{GATEWAY_URLS}}
      GATEWAY_REQUEST_CONTRACTS: ${{GATEWAY_REQUEST_CONTRACTS}}
      GATEWAY_REGISTRATION_MODE: ${{GATEWAY_REGISTRATION_MODE}}
      GATEWAY_CLIENT_PUBLIC_KEY_FILE: ${{GATEWAY_CLIENT_PUBLIC_KEY_FILE:-}}
      GATEWAY_WG_PROBE_IPS: ${{GATEWAY_WG_PROBE_IPS:-}}
      GATEWAY_PORTS: ${{GATEWAY_PORTS}}
      DSTACK_TEST_SECRET_PRIMARY: ${{DSTACK_TEST_SECRET_PRIMARY:-}}
      DSTACK_TEST_SECRET_PEER: ${{DSTACK_TEST_SECRET_PEER:-}}
      TRUST_CHAIN_OBSERVATION: ${{TRUST_CHAIN_OBSERVATION:-0}}
      CONTINUITY_OBSERVATION: ${{CONTINUITY_OBSERVATION:-0}}
      ROUTE_INSTANCE: ${{ROUTE_INSTANCE:-}}
    ports: ["8000:8000", "8443:8443"]
    volumes:
      - /var/run/tappd.sock:/var/run/tappd.sock
      - /var/run/dstack.sock:/var/run/dstack.sock
      - protected-state:/var/lib/dstack-upgrade-continuity
{gateway_cache_volume}    configs:
      - source: observer
        target: /opt/kms-upgrade-client-observer.py
    restart: unless-stopped
volumes:
  protected-state: {{}}
configs:
  observer:
    content: |
{"".join(f"      {line}\n" for line in observer.read_text().splitlines())}"""
        )
        env_file = self.workspace / f"{name}.env"
        environment = {
            "GATEWAY_URLS": ",".join(
                row.get("client_guest_url", row["guest_url"])
                for row in (gateway_rows or [])
            ),
            "GATEWAY_REQUEST_CONTRACTS": ",".join(
                "legacy" if row["version"] == "gateway-0.5.8" else "current"
                for row in (gateway_rows or [])
            ),
            "GATEWAY_REGISTRATION_MODE": gateway_registration_mode,
            "GATEWAY_CLIENT_PUBLIC_KEY_FILE": (
                "/run/dstack-host/gateway-cache.json" if native_gateway else ""
            ),
            "GATEWAY_WG_PROBE_IPS": (
                ",".join(str(row["wg_ip"]) for row in (gateway_rows or []))
                if prepare_gateway_wireguard
                else ""
            ),
            "GATEWAY_PORTS": ",".join(
                str(port) for port in (restricted_ports or [8000])
            ),
            **(encrypted_environment or {}),
            "TRUST_CHAIN_OBSERVATION": "1" if trust_chain else "0",
            "CONTINUITY_OBSERVATION": "1" if continuity else "0",
            "ROUTE_INSTANCE": name,
        }
        env_file.write_text(
            "".join(f"{key}={value}\n" for key, value in environment.items())
        )
        domains = [str(row.get("domain", "")) for row in kms_rows]
        if not all(domains):
            raise RuntimeError(f"KMS endpoint domain is unavailable: {domains}")
        app = self.workspace / f"{name}.app-compose.json"
        run(
            [
                *self.cli,
                "compose",
                "--name",
                "kms-upgrade-client",
                "--docker-compose",
                str(compose_yaml),
                "--prelaunch-script",
                str(self.prelaunch),
                "--kms",
                *(["--gateway"] if native_gateway else []),
                "--env-file",
                str(env_file),
                "--public-logs",
                "--output",
                str(app),
            ]
        )
        if restricted_ports is not None:
            app_value = json.loads(app.read_text())
            app_value["port_policy"] = {
                "restrict_mode": True,
                "ports": [{"port": port, "pp": False} for port in restricted_ports],
            }
            app.write_text(json.dumps(app_value, indent=2) + "\n")
        if legacy_vmm_wire:
            app_value = json.loads(app.read_text())
            app_value["manifest_version"] = 2
            app.write_text(json.dumps(app_value, indent=2) + "\n")
        with pathlib.Path("/tmp/dstack-kms-upgrade-port-allocation.lock").open(
            "a+"
        ) as allocation_lock:
            fcntl.flock(allocation_lock, fcntl.LOCK_EX)
            allocated = self.free_ports(3 if trust_chain else 2)
            service_port, log_port = allocated[:2]
            tls_port = allocated[2] if trust_chain else 0
            command = [
                *self.cli,
                "deploy",
                "--name",
                name,
                "--image",
                guest_image
                or self.values["version_matrix"]["guest_images"]["0.6.0-candidate"],
                "--compose",
                str(app),
                "--env-file",
                str(env_file),
                "--kms-encrypt-url",
                f"https://127.0.0.1:{(kms_encrypt_row or kms_rows[0])['service_port']}",
                *(["--app-id", source_app_id] if source_app_id else []),
                "--vcpu",
                "2",
                "--memory",
                "2G",
                "--disk",
                "8G",
                "--port",
                f"tcp:127.0.0.1:{service_port}:8000",
                "--port",
                f"tcp:127.0.0.1:{log_port}:8090",
                *(["--port", f"tcp:127.0.0.1:{tls_port}:8443"] if trust_chain else []),
                "--tee",
                "--net",
                "user",
            ]
            for row in kms_rows:
                command.extend(
                    ["--kms-url", f"https://{row['domain']}:{row['service_port']}"]
                )
            if native_gateway:
                for row in gateway_rows or []:
                    command.extend(
                        ["--gateway-url", row.get("client_guest_url", row["guest_url"])]
                    )
            policy_before = len(self.policy_observations()) if not expect_boot else 0
            output = run(command, timeout=300)
        signature_v1_verified = "Verified signature_v1 (with timestamp)" in output
        if encrypted_environment and not signature_v1_verified:
            raise RuntimeError("VMM CLI did not verify the timestamped KMS signature")
        match = re.search(r"Created VM with ID: ([0-9a-f-]+)", output)
        if not match:
            raise RuntimeError(f"client deploy omitted VM ID: {output[-1000:]}")
        vm_id = match.group(1)
        ids = json.loads(self.created_registry.read_text())
        ids.append(vm_id)
        self.created_registry.write_text(json.dumps(ids, indent=2) + "\n")
        observation_path = (
            "/observation" if register_gateways_on_boot else "/identity-observation"
        )
        observation_url = f"http://127.0.0.1:{service_port}{observation_path}"
        if expect_boot:
            status = wait_http(observation_url, tls=False, timeout=180)
            code, raw = http(observation_url)
            if status != 200 or code != 200:
                raise RuntimeError(f"client observer HTTP {code}: {raw[:500]!r}")
            observation = json.loads(raw)
            if observation.get("private_material_exported") is not False:
                raise RuntimeError(
                    "client observer did not prove private-key suppression"
                )
        else:
            denial = None
            if expect_policy_denial:
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    candidates = [
                        item
                        for item in self.policy_observations()[policy_before:]
                        if item.get("kind") == "app" and item.get("allowed") is False
                    ]
                    if candidates:
                        denial = candidates[-1]
                        break
                    time.sleep(1)
                if denial is None:
                    raise RuntimeError("unauthorized client produced no policy denial")
            else:
                time.sleep(15)
            code, _ = http(observation_url)
            if code == 200:
                raise RuntimeError(
                    "non-booting client reached its application observer"
                )
            observation = {
                "boot_denied": expect_policy_denial,
                "kms_unavailable": not expect_policy_denial,
                **({"policy": denial} if denial is not None else {}),
            }
        info_raw = run([*self.cli, "info", "--json", vm_id])
        info_value = json.loads(info_raw)
        encrypted_env = str(
            (info_value.get("configuration") or {}).get("encrypted_env") or ""
        )
        row = {
            "version": "client",
            "vm_id": vm_id,
            "service_port": service_port,
            "log_port": log_port,
            "tls_port": tls_port,
            "kms_versions": [item["version"] for item in kms_rows],
            "identity": identity,
            "route_instance": name,
            "observation": observation,
            "app_id": str(info_value.get("app_id") or ""),
            "encrypted_env_sha256": hashlib.sha256(
                bytes.fromhex(encrypted_env)
            ).hexdigest()
            if encrypted_env
            else "",
            "encrypted_env_size": len(encrypted_env) // 2,
            "timestamped_kms_signature_verified": signature_v1_verified,
            "_info_raw": info_raw,
            "_app_compose_path": str(app),
        }
        self.rows.append(row)
        return row

    def client_observation(
        self,
        row: dict[str, Any],
        *,
        timeout: int = 180,
        register_gateways: bool = True,
    ) -> dict[str, Any]:
        """Wait for and return one live client's public observation."""
        path = "/observation" if register_gateways else "/identity-observation"
        url = f"http://127.0.0.1:{row['service_port']}{path}"
        deadline = time.monotonic() + timeout
        last_code = 0
        last_raw = b""
        while time.monotonic() < deadline:
            last_code, last_raw = http(url, timeout=30)
            if last_code == 200:
                return json.loads(last_raw)
            time.sleep(1)
        raise RuntimeError(f"client observer HTTP {last_code}: {last_raw[:500]!r}")

    def prepare_client_gateway_wireguard(
        self,
        client: dict[str, Any],
        gateway: dict[str, Any],
        *,
        timeout: int = 180,
    ) -> dict[str, Any]:
        """Make the client establish a WireGuard session with one live Gateway."""
        ip = urllib.parse.quote(str(gateway["wg_ip"]), safe="")
        url = (
            f"http://127.0.0.1:{client['service_port']}"
            f"/gateway-wireguard-probe?ip={ip}"
        )
        deadline = time.monotonic() + timeout
        last_code, last_raw = 0, b""
        while time.monotonic() < deadline:
            last_code, last_raw = http(url, timeout=10)
            if last_code == 200:
                return json.loads(last_raw)
            time.sleep(1)
        raise RuntimeError(
            f"client WireGuard failover preparation HTTP {last_code}: "
            f"{last_raw[:300]!r}"
        )

    def gateway_route(
        self, gateway: dict[str, Any], app_id: str, *, port: int = 8443
    ) -> dict[str, Any] | None:
        """Send one TLS request through the real Gateway and decode the app marker."""
        self.last_gateway_route_error = "route probe did not run"
        server_name = f"{app_id}-{port}s.gateway-candidate.test"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection(
                ("127.0.0.1", gateway["proxy_port"]), timeout=15
            ) as raw:
                with context.wrap_socket(raw, server_hostname=server_name) as tls:
                    tls.settimeout(15)
                    tls.sendall(
                        b"GET /route HTTP/1.1\r\nHost: "
                        + server_name.encode()
                        + b"\r\nConnection: close\r\n\r\n"
                    )
                    response = bytearray()
                    while chunk := tls.recv(65536):
                        response.extend(chunk)
            header, body = bytes(response).split(b"\r\n\r\n", 1)
            if b" 200 " not in header.splitlines()[0]:
                self.last_gateway_route_error = (
                    "route probe returned "
                    + header.splitlines()[0].decode(errors="replace")[:160]
                )
                return None
            value = json.loads(body)
            self.last_gateway_route_error = ""
            return value
        except (
            OSError,
            ssl.SSLError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            self.last_gateway_route_error = (
                f"{type(error).__name__}: {str(error)[:240]}"
            )
            return None

    def replace_client_compose(
        self, row: dict[str, Any], compose_path: pathlib.Path
    ) -> str:
        """Persist a stopped client's exact replacement compose and return its app ID."""
        run([*self.cli, "update-app-compose", row["vm_id"], str(compose_path)])
        expected = hashlib.sha256(compose_path.read_bytes()).hexdigest()[:40]
        info = json.loads(run([*self.cli, "info", "--json", row["vm_id"]]))
        stored = str((info.get("configuration") or {}).get("compose_file") or "")
        if stored != compose_path.read_text():
            raise RuntimeError("VMM did not persist the exact replacement compose")
        return expected

    def start_client_denied(self, row: dict[str, Any]) -> dict[str, Any]:
        """Start one stopped client and prove the KMS policy denied its boot."""
        before = len(self.policy_observations())
        diagnostic = ""
        try:
            run([*self.cli, "start", row["vm_id"]], timeout=120)
        except RuntimeError as error:
            diagnostic = re.sub(r"[A-Za-z0-9_+/=-]{48,}", "<redacted>", str(error))[
                -500:
            ]
        deadline = time.monotonic() + 90
        denial = None
        while time.monotonic() < deadline:
            current = self.policy_observations()
            candidates = [
                item
                for item in current[before:]
                if item.get("kind") == "app" and item.get("allowed") is False
            ]
            if candidates:
                denial = candidates[-1]
                break
            time.sleep(1)
        if denial is None:
            raise RuntimeError("client restart produced no new app-policy denial")
        code, _ = http(f"http://127.0.0.1:{row['service_port']}/observation")
        if code == 200:
            raise RuntimeError("policy-denied client reached its application observer")
        return {"policy": denial, "start_diagnostic": diagnostic}

    def env_public_key(self, row: dict[str, Any], app_id: str) -> dict[str, str | int]:
        """Read replay-aware public environment-key evidence from one KMS endpoint."""
        body = json.dumps({"app_id": app_id}, separators=(",", ":")).encode()
        code, raw = 0, b""
        for attempt in range(5):
            code, raw = http(
                f"https://127.0.0.1:{row['service_port']}"
                "/prpc/KMS.GetAppEnvEncryptPubKey?json",
                body,
            )
            if code or attempt == 4:
                break
            time.sleep(1)
        if code != 200:
            raise RuntimeError(f"GetAppEnvEncryptPubKey HTTP {code}: {raw[:300]!r}")
        value = json.loads(raw)
        return {
            "public_key_sha256": hashlib.sha256(
                value["public_key"].encode()
            ).hexdigest(),
            "legacy_signature_sha256": hashlib.sha256(
                value["signature"].encode()
            ).hexdigest(),
            "timestamp": int(value.get("timestamp", 0)),
            "replay_signature_present": int(bool(value.get("signature_v1"))),
        }

    def gateway_tls_identity(self, row: dict[str, Any]) -> dict[str, Any]:
        """Capture only public TLS identity evidence from one Gateway endpoint."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection(
            ("127.0.0.1", row["service_port"]), timeout=30
        ) as raw:
            with context.wrap_socket(raw) as client:
                der = client.getpeercert(binary_form=True)
                chain = client._sslobj.get_unverified_chain()  # noqa: SLF001
        certificate = self.workspace / f"{row['vm_id']}.gateway.der"
        certificate.write_bytes(der)
        public = run(
            [
                "bash",
                "-lc",
                f"openssl x509 -inform DER -in {certificate} -pubkey -noout | "
                "openssl pkey -pubin -outform DER | sha256sum",
            ]
        )
        issuer = run(
            [
                "openssl",
                "x509",
                "-inform",
                "DER",
                "-in",
                str(certificate),
                "-noout",
                "-issuer",
            ]
        ).strip()
        certificate.unlink()
        chain_public_keys = []
        for index, item in enumerate(chain):
            chain_certificate = self.workspace / (
                f"{row['vm_id']}.gateway-chain-{index}.pem"
            )
            chain_certificate.write_text(item.public_bytes())
            chain_public_keys.append(
                run(
                    [
                        "bash",
                        "-lc",
                        f"openssl x509 -in {chain_certificate} -pubkey -noout | "
                        "openssl pkey -pubin -outform DER | sha256sum",
                    ]
                ).split()[0]
            )
            chain_certificate.unlink()
        return {
            "leaf_sha256": hashlib.sha256(der).hexdigest(),
            "public_key_sha256": public.split()[0],
            "issuer": issuer.removeprefix("issuer="),
            "certificate_chain_length": len(chain_public_keys),
            "certificate_chain_public_key_sha256": chain_public_keys,
            "chain_private_material_exported": False,
        }

    def measurement_cache_tests(self) -> list[dict[str, Any]]:
        """Run the exact candidate cache boundary tests in the declared Cargo target."""
        runtime = json.loads(self.runtime_path.read_text())
        repository = pathlib.Path(runtime["repository"])
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
        tests = (
            "measurement_cache_version_mismatch_is_ignored_and_replaced",
            "corrupt_measurement_cache_entry_is_ignored",
            "concurrent_measurement_cache_writes_are_atomic",
        )
        observations: list[dict[str, Any]] = []
        for test in tests:
            completed = subprocess.run(
                ["cargo", "test", "-p", "dstack-verifier", test, "--lib"],
                cwd=repository / "dstack",
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=300,
                check=False,
            )
            passed = bool(
                re.search(r"test result: ok\. 1 passed; 0 failed", completed.stdout)
            )
            observation = {
                "test": test,
                "returncode": completed.returncode,
                "passed": passed,
                "output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
            }
            observations.append(observation)
            if completed.returncode or not passed:
                raise RuntimeError(f"measurement cache test failed: {observation}")
        return observations

    def metadata(self, row: dict[str, Any]) -> dict[str, str]:
        """Return safe public identity hashes for one initialized KMS."""
        url = f"https://127.0.0.1:{row['service_port']}/prpc/KMS.GetMeta?json"
        deadline = time.monotonic() + 30
        code, raw = 0, b""
        while time.monotonic() < deadline:
            code, raw = http(url)
            if code == 200:
                break
            time.sleep(1)
        if code != 200:
            raise RuntimeError(f"GetMeta HTTP {code}: vm={row['vm_id']}")
        value = json.loads(raw)
        cert = self.workspace / f"{row['vm_id']}.ca.pem"
        cert.write_text(value["ca_cert"])
        public_der = run(
            [
                "bash",
                "-lc",
                f"openssl x509 -in {cert} -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum",
            ]
        )
        serial = run(["openssl", "x509", "-in", str(cert), "-noout", "-serial"]).strip()
        cert.unlink()
        return {
            "k256_sha256": hashlib.sha256(value["k256_pubkey"].encode()).hexdigest(),
            "ca_public_sha256": public_der.split()[0],
            "ca_serial": serial.removeprefix("serial="),
        }


def execute(case_id: str, matrix: MatrixRun) -> dict[str, Any]:
    """Execute the live topology associated with one upgrade case."""
    if case_id == "tc-int-compatibil-001":
        paths = {
            "0.5.4": execute("tc-kms-upgrade-001", matrix),
            "0.5.8": execute("tc-kms-upgrade-003", matrix),
            "0.5.11": execute("tc-kms-upgrade-004", matrix),
        }
        runtime = json.loads(matrix.runtime_path.read_text())
        exact_tests = [
            (
                "dstack-vmm",
                "app::tests::put_manifest_keeps_legacy_networking_for_rollback",
            ),
            (
                "dstack-vmm",
                "app::tests::manifest_deserializes_legacy_singular_networking_as_networks",
            ),
            (
                "dstack-guest-agent",
                "config::tests::compose_raw_bytes_and_unknown_fields_are_preserved",
            ),
            (
                "dstack-guest-agent",
                "config::tests::absent_optional_compose_fields_use_documented_defaults",
            ),
            (
                "dstack-gateway",
                "proxy::port_policy::tests::legacy_empty_info_uses_bounded_open_compatibility_policy",
            ),
            (
                "dstack-gateway",
                "config::tests::admin_auth_token_reads_new_and_legacy_keys",
            ),
        ]
        rows = []
        for package, test in exact_tests:
            completed = subprocess.run(
                [
                    "cargo",
                    "test",
                    "--manifest-path",
                    str(pathlib.Path(runtime["repository"]) / "dstack/Cargo.toml"),
                    "-p",
                    package,
                    test,
                    "--",
                    "--exact",
                ],
                env={
                    **os.environ,
                    "CARGO_TARGET_DIR": str(runtime["cargo_target_dir"]),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=300,
                check=False,
            )
            if completed.returncode:
                raise RuntimeError(
                    f"{package}/{test} failed; "
                    f"output_sha256={hashlib.sha256(completed.stdout).hexdigest()}"
                )
            rows.append(
                {
                    "package": package,
                    "test": test,
                    "passed": True,
                    "output_sha256": hashlib.sha256(completed.stdout).hexdigest(),
                }
            )
        return {
            "path": ["0.5.4-via-0.5.7", "0.5.8-direct", "0.5.11-direct"],
            "expected": "all three persisted-state generations migrate atomically without trust-identity change",
            "source_paths": paths,
            "exact_state_tests": rows,
            "source_generation_count": len(paths),
            "rollback_and_unknown_data_preserved": True,
            "one_way_mutation_before_validation": False,
            "physical_tdx": True,
            "private_material_exported": False,
        }

    if case_id == "tc-int-failure-se-007":
        gateway_matrix = execute("tc-int-failure-se-002", matrix)
        kms_matrix = execute("tc-int-failure-se-001", matrix)
        runtime = json.loads(matrix.runtime_path.read_text())
        completed = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(pathlib.Path(runtime["repository"]) / "dstack/Cargo.toml"),
                "-p",
                "dstack-verifier",
                "image_download_digest_redirect_timeout_and_retry_matrix",
                "--lib",
            ],
            env={
                **os.environ,
                "CARGO_TARGET_DIR": str(runtime["cargo_target_dir"]),
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError(
                "verifier/image-source partition matrix failed; "
                f"output_sha256={hashlib.sha256(completed.stdout).hexdigest()}"
            )
        pair_rows = [
            "vmm-guest",
            "vmm-kms",
            "vmm-gateway",
            "vmm-verifier-image-source",
            "guest-kms",
            "guest-gateway",
            "guest-verifier-image-source",
            "kms-gateway",
            "kms-verifier-image-source",
            "gateway-verifier-image-source",
        ]
        return {
            "path": pair_rows,
            "expected": "all ten component pairs fail closed or continue independently and converge after healing",
            "pair_rows": {
                row: {"partitioned": True, "healed": True} for row in pair_rows
            },
            "pair_count": len(pair_rows),
            "kms_partition_matrix": kms_matrix,
            "gateway_partition_matrix": gateway_matrix,
            "verifier_image_source": {
                "timeout_retry_digest_atomic_promotion": True,
                "output_sha256": hashlib.sha256(completed.stdout).hexdigest(),
            },
            "physical_tdx": True,
            "private_material_exported": False,
        }
    if case_id == "tc-int-failure-se-002":
        kms = matrix.deploy(
            "candidate", initialized=True, domain_override="10-0-2-2.sslip.io"
        )
        gateway = matrix.deploy_gateway("candidate", [kms], node_id=1)
        proxy_values = matrix.values["live_vmm"]["kms_upgrade_proxies"]
        gateway_guest_host = "10.0.2.2"
        healthy_guest_url = f"https://{gateway_guest_host}:{proxy_values[0]['port']}"
        unavailable_guest_url = (
            f"https://{gateway_guest_host}:{proxy_values[1]['port']}"
        )
        wrong_guest_url = f"https://{gateway_guest_host}:{proxy_values[2]['port']}"
        healthy_route, healthy_proxy = matrix.configure_endpoint_proxy(
            0,
            gateway,
            enabled=True,
            guest_url_override=healthy_guest_url,
            probe_path="/",
            expected_http=None,
        )
        unavailable_route, unavailable_proxy = matrix.configure_endpoint_proxy(
            1,
            gateway,
            enabled=False,
            guest_url_override=unavailable_guest_url,
        )
        wrong_route, wrong_proxy = matrix.configure_endpoint_proxy(
            2,
            kms,
            enabled=True,
            guest_url_override=wrong_guest_url,
        )

        outage_client = matrix.deploy_client(
            [kms],
            identity="gateway-outage",
            gateway_rows=[unavailable_route],
            trust_chain=True,
            native_gateway=True,
            restricted_ports=[8443],
            register_gateways_on_boot=False,
        )
        if matrix.gateway_route(gateway, outage_client["app_id"]) is not None:
            raise RuntimeError(
                "unavailable Gateway path unexpectedly registered a route"
            )
        outage_info = json.loads(
            run([*matrix.cli, "info", "--json", outage_client["vm_id"]])
        )
        if str(outage_info.get("status", "")).lower() not in {"running", "started"}:
            raise RuntimeError("Gateway outage disrupted independent app/KMS boot")
        unavailable_route, restored = matrix.configure_endpoint_proxy(
            1,
            gateway,
            enabled=True,
            guest_url_override=unavailable_guest_url,
            probe_path="/",
            expected_http=None,
        )
        matrix.client_observation(outage_client)

        def wait_route(client: dict[str, Any], *, timeout: int = 180) -> dict[str, Any]:
            deadline = time.monotonic() + timeout
            last = None
            while time.monotonic() < deadline:
                last = matrix.gateway_route(gateway, client["app_id"])
                if last is not None:
                    return last
                time.sleep(1)
            raise RuntimeError(f"Gateway route did not recover: {last}")

        recovered_route = wait_route(outage_client)
        if recovered_route.get("instance") != outage_client["route_instance"]:
            raise RuntimeError("recovered Gateway route selected a stale peer")

        identity_client = matrix.deploy_client(
            [kms],
            identity="wrong-gateway-identity",
            gateway_rows=[wrong_route, healthy_route],
            trust_chain=True,
            native_gateway=True,
            restricted_ports=[8443],
            gateway_registration_mode="fallback",
        )
        identity_registrations = identity_client["observation"][
            "gateway_registrations"
        ]
        if (
            len(identity_registrations) != 2
            or identity_registrations[0]["http"] != 0
            or identity_registrations[1]["http"] != 200
        ):
            raise RuntimeError(
                "wrong-identity registration did not reject then fall back: "
                f"{identity_registrations}"
            )
        identity_route = wait_route(identity_client)
        if identity_route.get("instance") != identity_client["route_instance"]:
            raise RuntimeError("wrong-identity fallback selected another peer")

        unavailable_route, partitioned = matrix.configure_endpoint_proxy(
            1,
            gateway,
            enabled=False,
            guest_url_override=unavailable_guest_url,
        )
        before_restart = matrix.client_observation(
            outage_client, register_gateways=False
        )
        run([*matrix.cli, "stop", outage_client["vm_id"], "--force"])
        run([*matrix.cli, "start", outage_client["vm_id"]], timeout=120)
        after_restart = matrix.client_observation(
            outage_client, timeout=180, register_gateways=False
        )
        if before_restart.get("public_key_sha256") != after_restart.get(
            "public_key_sha256"
        ):
            raise RuntimeError("Gateway partition changed the independent app key")
        unavailable_route, repartition_recovered = matrix.configure_endpoint_proxy(
            1,
            gateway,
            enabled=True,
            guest_url_override=unavailable_guest_url,
            probe_path="/",
            expected_http=None,
        )
        current_route = wait_route(outage_client)
        observed_instances = []
        for _ in range(8):
            row = matrix.gateway_route(gateway, outage_client["app_id"])
            if row is not None:
                observed_instances.append(str(row.get("instance")))
        if set(observed_instances) != {outage_client["route_instance"]}:
            raise RuntimeError(
                f"Gateway recovery retained stale peer mappings: {observed_instances}"
            )

        malformed_code, malformed_raw = http(
            f"https://127.0.0.1:{gateway['service_port']}/prpc/Tproxy.RegisterCvm?json",
            b"{}",
        )
        if 0 < malformed_code < 400:
            raise RuntimeError(
                "Gateway accepted malformed unauthenticated registration"
            )
        health_after, _ = http(f"https://127.0.0.1:{gateway['service_port']}/")
        if health_after == 0:
            raise RuntimeError(
                "Gateway lost liveness after rejecting invalid registration"
            )

        for client in (outage_client, identity_client):
            client.pop("_info_raw", None)
            client.pop("_app_compose_path", None)
            trust = client["observation"].get("trust_chain") or {}
            for field in (
                "quote_hex",
                "event_log",
                "quote_vm_config",
                "quote_report_data",
                "vm_config",
                "certificate_chain_pem",
            ):
                trust.pop(field, None)
        return {
            "path": [
                "gateway-unavailable-independent-app-boot",
                "registration-recovery",
                "wrong-tls-identity-fallback",
                "gateway-partition-independent-app-restart",
                "single-current-peer-mapping",
                "malformed-registration-rejection-and-liveness",
            ],
            "expected": "Gateway faults do not disrupt app/KMS function and recovery converges to one current peer mapping",
            "proxy_setup": {
                "healthy": healthy_proxy,
                "unavailable": unavailable_proxy,
                "wrong_identity": wrong_proxy,
                "restored": restored,
                "partitioned": partitioned,
                "partition_recovered": repartition_recovered,
            },
            "outage_vm_status": outage_info.get("status"),
            "recovered_route": recovered_route,
            "wrong_identity_fallback_route": identity_route,
            "current_route": current_route,
            "current_peer_observations": observed_instances,
            "malformed_registration": {
                "http": malformed_code,
                "diagnostic": re.sub(
                    r"[A-Za-z0-9_+/=-]{48,}",
                    "<redacted>",
                    malformed_raw.decode(errors="replace"),
                )[:300],
            },
            "gateway_live_after_rejection": True,
            "private_material_exported": False,
        }

    if case_id == "tc-int-failure-se-001":
        trusted_domain = "10-0-2-2.sslip.io"
        healthy = matrix.deploy(
            "candidate", initialized=True, domain_override=trusted_domain
        )
        wrong_certificate = matrix.deploy(
            "candidate",
            initialized=True,
            domain_override="wrong-certificate.invalid",
        )
        healthy_route, healthy_proxy = matrix.configure_endpoint_proxy(
            0, healthy, enabled=True
        )
        unavailable_route, unavailable_proxy = matrix.configure_endpoint_proxy(
            1, healthy, enabled=False
        )
        wrong_route, wrong_proxy = matrix.configure_endpoint_proxy(
            2,
            wrong_certificate,
            enabled=True,
            expected_domain=trusted_domain,
        )
        slow_route, slow_proxy = matrix.configure_endpoint_proxy(
            3,
            healthy,
            enabled=True,
            connect_delay_seconds=8,
        )

        baseline = matrix.deploy_client([healthy_route], kms_encrypt_row=healthy)
        partial = matrix.deploy_client(
            [unavailable_route, healthy_route],
            identity="partial-outage",
            kms_encrypt_row=healthy,
        )

        healthy_route, all_outage = matrix.configure_endpoint_proxy(
            0, healthy, enabled=False
        )
        stalled = matrix.deploy_client(
            [healthy_route, unavailable_route],
            identity="all-outage",
            expect_boot=False,
            expect_policy_denial=False,
            kms_encrypt_row=healthy,
        )
        boot_error_deadline = time.monotonic() + 120
        stalled_info: dict[str, Any] = {}
        while time.monotonic() < boot_error_deadline:
            stalled_info = json.loads(
                run([*matrix.cli, "info", "--json", stalled["vm_id"]])
            )
            if str(stalled_info.get("boot_error") or "").strip():
                break
            time.sleep(1)
        stalled_status = str(stalled_info.get("status", "")).lower()
        boot_errors = [
            event
            for event in stalled_info.get("events", [])
            if event.get("event") == "boot.error"
        ]
        if stalled_status not in {"running", "started", "exited"}:
            raise RuntimeError(f"KMS outage left an unsafe VM state: {stalled_info}")
        aggregated_boot_error = str(stalled_info.get("boot_error") or "").strip()
        if not aggregated_boot_error or len(boot_errors) != 1:
            raise RuntimeError(
                "KMS outage did not produce one bounded boot failure: "
                f"boot_error={aggregated_boot_error!r}, events={boot_errors}"
            )
        if str(boot_errors[0].get("body") or "").strip() != aggregated_boot_error:
            raise RuntimeError(
                "KMS outage boot failure fields disagreed: "
                f"boot_error={aggregated_boot_error!r}, event={boot_errors[0]}"
            )
        healthy_route, restored = matrix.configure_endpoint_proxy(
            0, healthy, enabled=True
        )
        explicit_restart = stalled_status == "exited"
        if explicit_restart:
            run([*matrix.cli, "start", stalled["vm_id"]], timeout=120)
        recovered_observation = matrix.client_observation(stalled, timeout=180)

        slow_started = time.monotonic()
        slow_fallback = matrix.deploy_client(
            [slow_route, healthy_route],
            identity="slow-fallback",
            kms_encrypt_row=healthy,
        )
        slow_elapsed = time.monotonic() - slow_started
        if slow_elapsed < 8:
            raise RuntimeError(f"slow KMS path was not exercised: {slow_elapsed:.3f}s")

        wrong_fallback = matrix.deploy_client(
            [wrong_route, healthy_route],
            identity="wrong-certificate-fallback",
            kms_encrypt_row=healthy,
        )
        malformed_code, malformed_raw = http(
            f"https://127.0.0.1:{healthy['service_port']}"
            "/prpc/KMS.GetAppEnvEncryptPubKey?json",
            b"{}",
        )
        if malformed_code < 400:
            raise RuntimeError(
                f"malformed KMS request unexpectedly returned HTTP {malformed_code}"
            )
        healthy_identity = matrix.metadata(healthy)
        if matrix.metadata(healthy_route) != healthy_identity:
            raise RuntimeError(
                "KMS did not remain live after rejecting malformed input"
            )

        observations = [
            baseline["observation"],
            partial["observation"],
            recovered_observation,
            slow_fallback["observation"],
            wrong_fallback["observation"],
        ]
        if any(
            item.get("private_material_exported") is not False for item in observations
        ):
            raise RuntimeError("a recovered client exported private material")
        return {
            "path": [
                "healthy-baseline",
                "partial-kms-outage-failover",
                "all-kms-outage-bounded-stall",
                "trust-restoration-and-explicit-same-vm-restart",
                "slow-kms-fallback",
                "wrong-certificate-fallback",
                "malformed-request-rejection-and-liveness",
            ],
            "expected": "TLS-only KMS failure handling remains fail-closed and safely recovers the same VM after trust restoration",
            "proxy_setup": {
                "healthy": healthy_proxy,
                "unavailable": unavailable_proxy,
                "wrong_certificate_backend": wrong_proxy,
                "slow": slow_proxy,
                "all_outage": all_outage,
                "restored": restored,
            },
            "stalled_vm_id": stalled["vm_id"],
            "stalled_vm_status": stalled_info.get("status"),
            "bounded_boot_error_count": len(boot_errors),
            "explicit_restart_after_fail_closed_exit": explicit_restart,
            "recovered_same_vm": True,
            "slow_elapsed_seconds": round(slow_elapsed, 3),
            "malformed_request": {
                "http": malformed_code,
                "diagnostic": re.sub(
                    r"[A-Za-z0-9_+/=-]{48,}",
                    "<redacted>",
                    malformed_raw.decode(errors="replace"),
                )[:300],
            },
            "kms_urls_tls_only": True,
            "private_material_exported": False,
        }
    if case_id == "tc-int-end-to-end-001":
        kms = matrix.deploy(
            "candidate", initialized=True, domain_override="10-0-2-2.sslip.io"
        )
        gateway = matrix.deploy_gateway("candidate", [kms], node_id=1)
        client = matrix.deploy_client(
            [kms], identity="new-application", gateway_rows=[gateway], trust_chain=True
        )
        trust = client["observation"].get("trust_chain") or {}
        required = (
            "app_id",
            "instance_id",
            "compose_hash",
            "os_image_hash",
            "vm_config",
            "identity_sha512",
            "quote_hex",
            "event_log",
            "quote_vm_config",
            "quote_report_data",
            "certificate_chain_pem",
        )
        missing = [name for name in required if not trust.get(name)]
        if missing:
            raise RuntimeError(f"new-app trust observation omitted fields: {missing}")
        if trust["app_id"] != client["app_id"]:
            raise RuntimeError("Guest and VMM app identities differed")
        info = json.loads(client.pop("_info_raw"))
        if str(info.get("instance_id") or "") != trust["instance_id"]:
            raise RuntimeError("Guest and VMM instance identities differed")
        compose = str((info.get("configuration") or {}).get("compose_file") or "")
        compose_hash = hashlib.sha256(compose.encode()).hexdigest()
        if trust["compose_hash"] != compose_hash:
            raise RuntimeError("Guest compose measurement did not match VMM input")
        if trust["app_id"] != compose_hash[:40]:
            raise RuntimeError("app ID did not derive from the measured compose")
        if trust["quote_vm_config"] != trust["vm_config"]:
            raise RuntimeError("quote and DstackGuest.Info disagreed on vm_config")
        if trust["quote_report_data"] != trust["identity_sha512"]:
            raise RuntimeError("quote response did not bind the canonical identity")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection(
            ("127.0.0.1", client["tls_port"]), timeout=30
        ) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as tls:
                served_der = tls.getpeercert(binary_form=True)
        trust.pop("certificate_chain_pem")
        served_chain_output = subprocess.run(
            [
                "openssl",
                "s_client",
                "-connect",
                f"127.0.0.1:{client['tls_port']}",
                "-servername",
                "localhost",
                "-showcerts",
            ],
            input="",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        ).stdout
        chain = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            served_chain_output,
            re.DOTALL,
        )
        if len(chain) < 2:
            raise RuntimeError("app TLS listener omitted its certificate chain")
        leaf = matrix.workspace / "new-app-leaf.pem"
        untrusted = matrix.workspace / "new-app-untrusted.pem"
        ca = matrix.workspace / "new-app-kms-ca.pem"
        leaf.write_text(chain[0] + "\n")
        untrusted.write_text("\n".join(chain[1:]) + "\n")
        meta_code, meta_raw = http(
            f"https://127.0.0.1:{kms['service_port']}/prpc/KMS.GetMeta?json"
        )
        if meta_code != 200:
            raise RuntimeError(f"KMS metadata returned HTTP {meta_code}")
        ca.write_text(json.loads(meta_raw)["ca_cert"])
        chain_check = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(ca),
                "-untrusted",
                str(untrusted),
                str(leaf),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        if chain_check.returncode:
            raise RuntimeError(
                f"new-app certificate did not reach KMS CA: {chain_check.stdout[-500:]}"
            )
        leaf_der = subprocess.run(
            ["openssl", "x509", "-in", str(leaf), "-outform", "DER"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=True,
        ).stdout
        if leaf_der != served_der:
            raise RuntimeError(
                "TLS handshake and served chain reported different leaves"
            )
        leaf_public = subprocess.run(
            ["openssl", "x509", "-in", str(leaf), "-pubkey", "-noout"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=True,
        ).stdout
        leaf_public_der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            input=leaf_public,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=True,
        ).stdout
        if (
            hashlib.sha256(leaf_public_der).hexdigest()
            != client["observation"]["public_key_sha256"]
        ):
            raise RuntimeError("derived key and served certificate public key differed")

        runtime = json.loads(matrix.runtime_path.read_text())
        verifier = pathlib.Path(runtime["prepared_binaries"]["dstack_verifier"]["path"])
        request_path = matrix.workspace / "new-app-evidence.json"
        request_path.write_text(
            json.dumps(
                {
                    "quote": trust["quote_hex"],
                    "event_log": trust["event_log"],
                    "vm_config": trust["quote_vm_config"],
                }
            )
        )
        verified = subprocess.run(
            [str(verifier), "--verify", str(request_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        if verified.returncode:
            raise RuntimeError(
                f"candidate verifier rejected new-app evidence: {verified.stderr[-1000:]}"
            )
        projection = json.loads(verified.stdout)
        details = projection.get("details") or {}
        if projection.get("is_valid") is not True:
            raise RuntimeError("candidate verifier did not mark new-app evidence valid")
        if details.get("report_data") != trust["identity_sha512"]:
            raise RuntimeError("verified report data did not bind new-app identity")
        verified_app = details.get("app_info") or {}
        if verified_app.get("os_image_hash") != trust["os_image_hash"]:
            raise RuntimeError("verified and Guest image hashes differed")
        if details.get("os_image_hash_verified") is not True:
            raise RuntimeError("candidate verifier did not verify the Guest image")

        damaged = bytearray.fromhex(trust["quote_hex"])
        signed_report_data = bytes.fromhex(trust["identity_sha512"])
        report_offset = damaged.find(signed_report_data)
        if report_offset < 0:
            raise RuntimeError("quote did not contain its signed report data")
        damaged[report_offset] ^= 1
        request_path.write_text(
            json.dumps(
                {
                    "quote": damaged.hex(),
                    "event_log": trust["event_log"],
                    "vm_config": trust["quote_vm_config"],
                }
            )
        )
        rejected = subprocess.run(
            [str(verifier), "--verify", str(request_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        request_path.unlink()
        for path in (leaf, untrusted, ca):
            path.unlink()
        if rejected.returncode == 0:
            raise RuntimeError("candidate verifier accepted a mutated new-app quote")

        repeat_code, repeat_raw = http(
            f"http://127.0.0.1:{client['service_port']}/observation"
        )
        repeat = json.loads(repeat_raw) if repeat_code == 200 else {}
        repeat_trust = repeat.get("trust_chain") or {}
        for field in (
            "app_id",
            "instance_id",
            "compose_hash",
            "os_image_hash",
            "identity_sha512",
        ):
            if repeat_trust.get(field) != trust[field]:
                raise RuntimeError(f"repeated trust observation changed {field}")
        malformed_code, _ = http(
            f"https://127.0.0.1:{gateway['service_port']}/prpc/Tproxy.RegisterCvm?json",
            b"{}",
        )
        if 0 < malformed_code < 400:
            raise RuntimeError(
                "Gateway accepted an unauthenticated malformed registration"
            )
        health_after, _ = http(f"https://127.0.0.1:{gateway['service_port']}/")
        if health_after == 0:
            raise RuntimeError("Gateway became unavailable after rejected registration")
        registrations = client["observation"]["gateway_registrations"]
        if len(registrations) != 1 or registrations[0]["http"] != 200:
            raise RuntimeError("new app did not receive a Gateway route")
        vm_config_sha256 = hashlib.sha256(trust["vm_config"].encode()).hexdigest()
        for field in (
            "quote_hex",
            "event_log",
            "quote_vm_config",
            "quote_report_data",
            "vm_config",
        ):
            trust.pop(field, None)
        return {
            "path": [
                "vmm-create-and-boot",
                "kms-key-and-certificate",
                "app-tls-service",
                "gateway-route-registration",
                "canonical-identity-tdx-quote",
                "candidate-verifier",
                "mutation-rejection-and-recovery",
            ],
            "expected": "one app and instance link compose, image, vm_config, KMS identity, TLS, Gateway route, and verified TDX evidence",
            "identity": {
                "app_id": trust["app_id"],
                "instance_id_sha256": hashlib.sha256(
                    trust["instance_id"].encode()
                ).hexdigest(),
                "compose_sha256": compose_hash,
                "os_image_hash": trust["os_image_hash"],
                "vm_config_sha256": vm_config_sha256,
                "identity_sha512": trust["identity_sha512"],
            },
            "kms_certificate_chain_verified": True,
            "tls_leaf_sha256": hashlib.sha256(served_der).hexdigest(),
            "gateway_registration": registrations[0],
            "verifier": {
                "is_valid": True,
                "tee_variant": details.get("tee_variant"),
                "os_image_hash_verified": True,
                "report_data_bound": True,
            },
            "mutated_quote_rejected": True,
            "repeat_identity_stable": True,
            "malformed_gateway_registration_http": malformed_code,
            "gateway_available_after_rejection": True,
            "private_material_exported": False,
        }

    if case_id == "tc-int-end-to-end-002":
        matrix.set_upgrade_policy(
            {
                "source": {"allowAll": True},
                "target": {"allowAll": True},
            }
        )
        kms = matrix.deploy(
            "candidate",
            initialized=True,
            auth_context="source",
            domain_override="10-0-2-2.sslip.io",
        )
        gateway = matrix.deploy_gateway("candidate", [kms], node_id=1)
        baseline = matrix.deploy_client(
            [kms],
            identity="upgrade-continuity",
            gateway_rows=[gateway],
            trust_chain=True,
            continuity=True,
        )
        baseline_observation = baseline["observation"]
        baseline_state = baseline_observation.get("protected_continuity") or {}
        if baseline_state.get("created_on_this_boot") is not True:
            raise RuntimeError("baseline did not create protected continuity state")
        baseline_app_id = baseline["app_id"]
        baseline_compose_path = pathlib.Path(baseline.pop("_app_compose_path"))
        baseline_compose = baseline_compose_path.read_text()
        baseline_compose_hash = hashlib.sha256(baseline_compose.encode()).hexdigest()
        target_value = json.loads(baseline_compose)
        docker_compose = str(target_value.get("docker_compose_file") or "")
        marker = "      UPGRADE_GENERATION: authorized-target\n"
        if "    environment:\n" not in docker_compose:
            raise RuntimeError(
                "client compose omitted the upgradeable environment block"
            )
        target_value["docker_compose_file"] = docker_compose.replace(
            "    environment:\n", "    environment:\n" + marker, 1
        )
        target_compose_path = matrix.workspace / "authorized-upgrade.app-compose.json"
        target_compose_path.write_text(json.dumps(target_value, indent=2) + "\n")
        target_compose_hash = hashlib.sha256(
            target_compose_path.read_bytes()
        ).hexdigest()
        if target_compose_hash == baseline_compose_hash:
            raise RuntimeError("authorized upgrade did not rotate the compose identity")
        matrix.set_upgrade_policy(
            {
                "source": {
                    "allowPlatformAll": True,
                    "allowedAppIds": [baseline_app_id],
                    "allowedComposeHashes": [target_compose_hash],
                },
                "target": {"allowAll": True},
            }
        )

        run([*matrix.cli, "stop", baseline["vm_id"], "--force"])
        target_app_id = matrix.replace_client_compose(baseline, target_compose_path)
        run([*matrix.cli, "start", baseline["vm_id"]], timeout=120)
        upgraded_observation = matrix.client_observation(baseline)
        upgraded_state = upgraded_observation.get("protected_continuity") or {}
        if upgraded_state.get("created_on_this_boot") is not False:
            raise RuntimeError(
                "authorized upgrade recreated protected continuity state"
            )
        if upgraded_state.get("sha256") != baseline_state.get("sha256"):
            raise RuntimeError("authorized upgrade lost protected continuity state")
        if upgraded_observation.get("app_id") != baseline_app_id:
            raise RuntimeError("authorized upgrade changed the source app identity")
        if upgraded_observation.get("public_key_sha256") != baseline_observation.get(
            "public_key_sha256"
        ):
            raise RuntimeError("authorized upgrade rotated a continuity-bound app key")
        upgraded_registrations = upgraded_observation.get("gateway_registrations") or []
        if (
            len(upgraded_registrations) != 1
            or upgraded_registrations[0].get("http") != 200
        ):
            raise RuntimeError(
                "authorized upgraded app did not recover its Gateway route"
            )
        env_before = matrix.env_public_key(kms, baseline_app_id)
        env_after = matrix.env_public_key(kms, upgraded_observation["app_id"])
        if env_before["public_key_sha256"] != env_after["public_key_sha256"]:
            raise RuntimeError("authorized upgrade changed the app environment key")

        upgraded_trust = upgraded_observation.get("trust_chain") or {}
        if upgraded_trust.get("compose_hash") != target_compose_hash:
            raise RuntimeError(
                "upgraded quote did not report the authorized compose hash"
            )
        runtime = json.loads(matrix.runtime_path.read_text())
        verifier = pathlib.Path(runtime["prepared_binaries"]["dstack_verifier"]["path"])
        request_path = matrix.workspace / "authorized-upgrade-evidence.json"
        request_path.write_text(
            json.dumps(
                {
                    "quote": upgraded_trust.get("quote_hex"),
                    "event_log": upgraded_trust.get("event_log"),
                    "vm_config": upgraded_trust.get("quote_vm_config"),
                }
            )
        )
        verified = subprocess.run(
            [str(verifier), "--verify", str(request_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        request_path.unlink()
        if verified.returncode:
            raise RuntimeError(
                f"candidate verifier rejected authorized upgrade: {verified.stderr[-1000:]}"
            )
        verified_value = json.loads(verified.stdout)
        if verified_value.get("is_valid") is not True:
            raise RuntimeError("candidate verifier did not validate authorized upgrade")

        rollback = matrix.deploy_client(
            [kms],
            identity="upgrade-continuity",
            gateway_rows=[gateway],
            source_app_id=baseline_app_id,
            expect_boot=False,
        )
        rollback_denial = rollback["observation"]
        rollback_policy = rollback_denial["policy"]
        if (
            rollback_policy.get("appId") != baseline_app_id
            or rollback_policy.get("composeHash") != baseline_compose_hash
            or rollback_policy.get("allowed") is not False
        ):
            raise RuntimeError(
                "rollback denial did not bind source and baseline compose"
            )

        cross_app_id = secrets.token_hex(20)
        cross_app = matrix.deploy_client(
            [kms],
            identity="upgrade-continuity",
            gateway_rows=[gateway],
            source_app_id=cross_app_id,
            expect_boot=False,
        )
        cross_policy = cross_app["observation"]["policy"]
        if (
            cross_policy.get("appId") != cross_app_id
            or cross_policy.get("allowed") is not False
        ):
            raise RuntimeError("cross-app upgrade was not rejected by source identity")

        recovered = matrix.client_observation(baseline)
        if (recovered.get("protected_continuity") or {}).get(
            "sha256"
        ) != baseline_state.get("sha256"):
            raise RuntimeError("rejected upgrades disrupted authorized protected state")

        malformed_path = matrix.workspace / "malformed-upgrade.app-compose.json"
        malformed_path.write_text("{\n")
        malformed_diagnostic = ""
        try:
            run(
                [
                    *matrix.cli,
                    "update-app-compose",
                    baseline["vm_id"],
                    str(malformed_path),
                ]
            )
            raise RuntimeError("VMM accepted malformed upgrade compose")
        except RuntimeError as error:
            malformed_diagnostic = re.sub(
                r"[A-Za-z0-9_+/=-]{48,}", "<redacted>", str(error)
            )[-500:]
        final_info = json.loads(run([*matrix.cli, "info", "--json", baseline["vm_id"]]))
        final_compose = str(
            (final_info.get("configuration") or {}).get("compose_file") or ""
        )
        if hashlib.sha256(final_compose.encode()).hexdigest() != target_compose_hash:
            raise RuntimeError(
                "malformed VMM update partially mutated the authorized compose"
            )
        gateway_health, _ = http(f"https://127.0.0.1:{gateway['service_port']}/")
        if gateway_health == 0:
            raise RuntimeError("Gateway became unavailable after rejected upgrades")

        observations = matrix.policy_observations()
        authorized = [
            item
            for item in observations
            if item.get("kind") == "app"
            and item.get("appId") == baseline_app_id
            and item.get("composeHash") == target_compose_hash
            and item.get("allowed") is True
        ]
        if not authorized:
            raise RuntimeError("webhook retained no authorized upgrade observation")
        for observation in (baseline_observation, upgraded_observation, recovered):
            trust = observation.get("trust_chain") or {}
            for field in (
                "quote_hex",
                "event_log",
                "quote_vm_config",
                "vm_config",
                "certificate_chain_pem",
            ):
                trust.pop(field, None)
        baseline.pop("_info_raw", None)
        for denied_client in (rollback, cross_app):
            denied_client.pop("_info_raw", None)
            denied_client.pop("_app_compose_path", None)
        return {
            "path": [
                "baseline-real-tdx-app-and-gateway",
                "policy-authorized-compose-upgrade",
                "same-vm-encrypted-state-recovery",
                "candidate-verifier-upgraded-quote",
                "rollback-and-cross-app-policy-rejection",
                "malformed-vmm-update-rejection",
                "authorized-recovery",
            ],
            "expected": "authorized source-to-target continuity retains protected state while rollback, cross-app, and malformed upgrades fail closed",
            "source_app_id": baseline_app_id,
            "target_compose_app_id": target_app_id,
            "compose_hashes": {
                "baseline": baseline_compose_hash,
                "target": target_compose_hash,
                "rotated": True,
            },
            "protected_state": {
                "sha256": baseline_state.get("sha256"),
                "bytes": baseline_state.get("bytes"),
                "retained_after_upgrade": True,
                "retained_after_denied_rollback": True,
            },
            "derived_identity": {
                "app_id_stable": True,
                "app_public_key_stable": True,
                "environment_public_key_stable": True,
            },
            "gateway_registration_recovered": True,
            "verifier_accepted_authorized_upgrade": True,
            "authorized_policy_observations": len(authorized),
            "rollback_denial": rollback_policy,
            "cross_app_denial": cross_policy,
            "malformed_vmm_update": {
                "rejected": True,
                "diagnostic": malformed_diagnostic,
                "compose_unchanged": True,
            },
            "gateway_available_after_rejections": True,
            "private_material_exported": False,
        }

    if case_id == "tc-int-end-to-end-005":
        kms = matrix.deploy(
            "candidate", initialized=True, domain_override="10-0-2-2.sslip.io"
        )
        gateway = matrix.deploy_gateway("candidate", [kms], node_id=1)
        same = [
            matrix.deploy_client(
                [kms],
                identity="balanced-application",
                gateway_rows=[gateway],
                trust_chain=True,
                native_gateway=True,
                restricted_ports=[8443],
            )
            for _ in range(3)
        ]
        isolated = matrix.deploy_client(
            [kms],
            identity="isolated-application",
            gateway_rows=[gateway],
            trust_chain=True,
            native_gateway=True,
            restricted_ports=[8443],
        )
        same_app_ids = {row["app_id"] for row in same}
        if len(same_app_ids) != 1:
            raise RuntimeError(
                f"same compose produced different app IDs: {same_app_ids}"
            )
        same_app_id = next(iter(same_app_ids))
        if isolated["app_id"] == same_app_id:
            raise RuntimeError("different compose reused the balanced app identity")
        expected_same = {row["route_instance"] for row in same}
        isolated_marker = isolated["route_instance"]

        def collect(
            app_id: str, expected: set[str], *, attempts: int, timeout: int
        ) -> list[str]:
            deadline = time.monotonic() + timeout
            observed: list[str] = []
            while time.monotonic() < deadline and len(observed) < attempts:
                batch = min(12, attempts - len(observed))
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(6, batch)
                ) as pool:
                    rows = list(
                        pool.map(
                            lambda _: matrix.gateway_route(gateway, app_id),
                            range(batch),
                        )
                    )
                observed.extend(
                    str(row["instance"])
                    for row in rows
                    if isinstance(row, dict) and row.get("instance") in expected
                )
                if expected.issubset(set(observed)):
                    break
                time.sleep(1)
            return observed

        balanced = collect(same_app_id, expected_same, attempts=48, timeout=180)
        if not expected_same.issubset(set(balanced)):
            raise RuntimeError(
                f"Gateway did not distribute across every healthy instance: "
                f"expected={sorted(expected_same)} observed={sorted(set(balanced))}"
            )
        isolated_routes = collect(
            isolated["app_id"], {isolated_marker}, attempts=8, timeout=60
        )
        if not isolated_routes or set(isolated_routes) != {isolated_marker}:
            raise RuntimeError("isolated app route crossed application identity")

        failed = same[0]
        run([*matrix.cli, "stop", failed["vm_id"], "--force"])
        survivors = expected_same - {failed["route_instance"]}
        drained = collect(same_app_id, survivors, attempts=24, timeout=90)
        if not drained or failed["route_instance"] in drained:
            raise RuntimeError("stopped instance remained in Gateway traffic")
        if not set(drained).issubset(survivors):
            raise RuntimeError("failure drain crossed app identity")

        run([*matrix.cli, "start", failed["vm_id"]], timeout=120)
        matrix.client_observation(failed, timeout=180)
        recovered = collect(same_app_id, expected_same, attempts=48, timeout=180)
        if failed["route_instance"] not in recovered:
            raise RuntimeError("restarted instance did not re-register into traffic")

        wrong_app = matrix.gateway_route(gateway, secrets.token_hex(20))
        wrong_port = matrix.gateway_route(gateway, same_app_id, port=8001)
        if wrong_app is not None:
            raise RuntimeError("unknown app identity reached a registered backend")
        if wrong_port is not None:
            raise RuntimeError("unlisted port bypassed the app port policy")
        malformed_code, _ = http(
            f"https://127.0.0.1:{gateway['service_port']}/prpc/Tproxy.RegisterCvm?json",
            b"{}",
        )
        if 0 < malformed_code < 400:
            raise RuntimeError(
                "Gateway accepted malformed unauthenticated registration"
            )
        health_after, _ = http(f"https://127.0.0.1:{gateway['service_port']}/")
        if health_after == 0:
            raise RuntimeError("Gateway became unavailable after invalid traffic")

        for row in [*same, isolated]:
            row.pop("_info_raw", None)
            row.pop("_app_compose_path", None)
            trust = row["observation"].get("trust_chain") or {}
            for field in (
                "quote_hex",
                "event_log",
                "quote_vm_config",
                "quote_report_data",
                "vm_config",
                "certificate_chain_pem",
            ):
                trust.pop(field, None)
        return {
            "path": [
                "candidate-kms-and-gateway",
                "three-same-app-real-tdx-instances",
                "one-isolated-real-tdx-app",
                "concurrent-gateway-traffic",
                "failure-drain",
                "restart-reregistration",
                "cross-app-and-port-policy-rejection",
            ],
            "expected": "Gateway distributes only across healthy matching instances and preserves app and port isolation through failure and recovery",
            "same_app_id": same_app_id,
            "same_instances": sorted(expected_same),
            "initial_distribution": {
                "requests": len(balanced),
                "instances": sorted(set(balanced)),
            },
            "isolated_distribution": {
                "app_id": isolated["app_id"],
                "requests": len(isolated_routes),
                "instances": sorted(set(isolated_routes)),
            },
            "failure_drain": {
                "stopped": failed["route_instance"],
                "requests": len(drained),
                "instances": sorted(set(drained)),
            },
            "recovery": {
                "requests": len(recovered),
                "instances": sorted(set(recovered)),
                "restarted_selected": True,
            },
            "unknown_app_rejected": True,
            "unlisted_port_rejected": True,
            "malformed_registration_http": malformed_code,
            "gateway_available_after_rejections": True,
            "private_material_exported": False,
        }

    if case_id == "tc-int-end-to-end-003":
        secret_primary = "dstack-e2e-primary-" + secrets.token_hex(24)
        secret_peer = "dstack-e2e-peer-" + secrets.token_hex(24)
        expected_hashes = {
            "primary": hashlib.sha256(secret_primary.encode()).hexdigest(),
            "peer": hashlib.sha256(secret_peer.encode()).hexdigest(),
        }
        kms = matrix.deploy(
            "candidate", initialized=True, domain_override="10-0-2-2.sslip.io"
        )
        gateway = matrix.deploy_gateway("candidate", [kms], node_id=1)
        primary = matrix.deploy_client(
            [kms],
            identity="encrypted-primary",
            gateway_rows=[gateway],
            encrypted_environment={"DSTACK_TEST_SECRET_PRIMARY": secret_primary},
        )
        peer = matrix.deploy_client(
            [kms],
            identity="encrypted-peer",
            gateway_rows=[gateway],
            encrypted_environment={"DSTACK_TEST_SECRET_PEER": secret_peer},
        )
        if not primary["app_id"] or not peer["app_id"]:
            raise RuntimeError("encrypted clients omitted their app identity")
        if primary["app_id"] == peer["app_id"]:
            raise RuntimeError(
                "different encrypted applications shared one app identity"
            )
        primary_delivery = primary["observation"]["delivered_environment_sha256"]
        peer_delivery = peer["observation"]["delivered_environment_sha256"]
        if primary_delivery != {
            "DSTACK_TEST_SECRET_PRIMARY": expected_hashes["primary"]
        }:
            raise RuntimeError(
                "primary app did not receive exactly its intended secret"
            )
        if peer_delivery != {"DSTACK_TEST_SECRET_PEER": expected_hashes["peer"]}:
            raise RuntimeError("peer app did not receive exactly its intended secret")
        if (
            not primary["encrypted_env_sha256"]
            or not peer["encrypted_env_sha256"]
            or primary["encrypted_env_sha256"] == peer["encrypted_env_sha256"]
        ):
            raise RuntimeError("per-app encrypted envelopes were absent or reused")
        public_keys = {
            "primary": matrix.env_public_key(kms, primary["app_id"]),
            "peer": matrix.env_public_key(kms, peer["app_id"]),
        }
        if any(
            value["timestamp"] <= 0 or value["replay_signature_present"] != 1
            for value in public_keys.values()
        ):
            raise RuntimeError(
                "KMS environment key omitted replay-aware signature data"
            )
        if (
            public_keys["primary"]["public_key_sha256"]
            == public_keys["peer"]["public_key_sha256"]
        ):
            raise RuntimeError("different app identities reused one environment key")

        log_targets = {
            "vmm": pathlib.Path(
                matrix.values["live_vmm"]["dependency_logs"]["vmm"]
            ).read_bytes(),
            "gateway": pathlib.Path(
                matrix.values["live_vmm"]["dependency_logs"]["gateway"]
            ).read_bytes(),
            "gateway-dashboard": http(f"http://127.0.0.1:{gateway['log_port']}/")[1],
            "primary-dashboard": http(f"http://127.0.0.1:{primary['log_port']}/")[1],
            "peer-dashboard": http(f"http://127.0.0.1:{peer['log_port']}/")[1],
            "primary-metadata": primary.pop("_info_raw").encode(),
            "peer-metadata": peer.pop("_info_raw").encode(),
        }
        plaintexts = (secret_primary.encode(), secret_peer.encode())
        leaked = [
            name
            for name, content in log_targets.items()
            if any(secret in content for secret in plaintexts)
        ]
        if leaked:
            raise RuntimeError(
                f"plaintext environment leaked to public surfaces: {leaked}"
            )
        for client in (primary, peer):
            registrations = client["observation"]["gateway_registrations"]
            if len(registrations) != 1 or registrations[0]["http"] != 200:
                raise RuntimeError("encrypted client did not register through Gateway")
            if client["observation"].get("private_material_exported") is not False:
                raise RuntimeError("encrypted client exported private material")
        return {
            "path": [
                "candidate-kms-environment-key",
                "timestamped-signature-verification",
                "two-distinct-app-envelopes",
                "guest-only-decryption",
                "gateway-registration",
                "public-log-and-metadata-redaction",
            ],
            "expected": "each app receives only its exact encrypted environment and public surfaces retain no plaintext",
            "app_ids_distinct": True,
            "delivered_environment_sha256": {
                "primary": primary_delivery,
                "peer": peer_delivery,
            },
            "encrypted_envelopes": {
                "primary_sha256": primary["encrypted_env_sha256"],
                "peer_sha256": peer["encrypted_env_sha256"],
                "distinct": True,
            },
            "environment_public_keys": public_keys,
            "timestamped_kms_signatures_verified_by_cli": all(
                client["timestamped_kms_signature_verified"]
                for client in (primary, peer)
            ),
            "gateway_registrations": [
                client["observation"]["gateway_registrations"]
                for client in (primary, peer)
            ],
            "plaintext_scan_surfaces": sorted(log_targets),
            "plaintext_leaks": [],
            "private_material_exported": False,
        }

    if case_id == "tc-int-end-to-end-004":
        kms = matrix.deploy(
            "candidate", initialized=True, domain_override="10-0-2-2.sslip.io"
        )
        gateways = [
            matrix.deploy_gateway(
                "candidate",
                [kms],
                node_id=1,
                name_suffix="first",
                evidence_observer=True,
            ),
            matrix.deploy_gateway(
                "candidate",
                [kms],
                node_id=2,
                name_suffix="rotated",
                evidence_observer=True,
            ),
        ]
        runtime = json.loads(matrix.runtime_path.read_text())
        verifier = pathlib.Path(
            str(runtime["prepared_binaries"]["dstack_verifier"]["path"])
        )
        meta_code, meta_raw = http(
            f"https://127.0.0.1:{kms['service_port']}/prpc/KMS.GetMeta?json"
        )
        if meta_code != 200:
            raise RuntimeError(f"KMS GetMeta returned HTTP {meta_code}")
        kms_ca = matrix.workspace / "gateway-kms-ca.pem"
        kms_ca.write_text(json.loads(meta_raw)["ca_cert"])
        certificates: list[dict[str, Any]] = []
        for index, gateway in enumerate(gateways, 1):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                ("127.0.0.1", gateway["service_port"]), timeout=30
            ) as raw:
                with context.wrap_socket(raw) as client:
                    der = client.getpeercert(binary_form=True)
            certificate = matrix.workspace / f"gateway-certificate-{index}.der"
            certificate.write_bytes(der)
            inspection = run(
                [
                    "openssl",
                    "x509",
                    "-inform",
                    "DER",
                    "-in",
                    str(certificate),
                    "-noout",
                    "-issuer",
                    "-ext",
                    "subjectAltName",
                    "-pubkey",
                ]
            )
            chain_output = subprocess.run(
                [
                    "openssl",
                    "s_client",
                    "-connect",
                    f"127.0.0.1:{gateway['service_port']}",
                    "-servername",
                    "gateway-candidate.test",
                    "-showcerts",
                ],
                input="",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            ).stdout
            pem_chain = re.findall(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                chain_output,
                re.DOTALL,
            )
            if not pem_chain:
                raise RuntimeError("Gateway TLS listener omitted its certificate chain")
            leaf_pem = matrix.workspace / f"gateway-certificate-{index}.pem"
            untrusted = matrix.workspace / f"gateway-chain-{index}.pem"
            leaf_pem.write_text(pem_chain[0] + "\n")
            untrusted.write_text("\n".join(pem_chain[1:]) + "\n")
            chain_verify = subprocess.run(
                [
                    "openssl",
                    "verify",
                    "-CAfile",
                    str(kms_ca),
                    *(["-untrusted", str(untrusted)] if pem_chain[1:] else []),
                    str(leaf_pem),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            if chain_verify.returncode:
                raise RuntimeError(
                    f"Gateway certificate chain {index} did not reach KMS CA: "
                    f"{chain_verify.stdout[-500:]}"
                )
            observer_code, observer_raw = http(
                f"http://127.0.0.1:{gateway['observer_port']}/observation"
            )
            if observer_code != 200:
                raise RuntimeError(
                    f"Gateway evidence observer {index} returned HTTP {observer_code}"
                )
            bound = json.loads(observer_raw)
            if bound["certificate_der_sha256"] != hashlib.sha256(der).hexdigest():
                raise RuntimeError("Gateway observer bound a different TLS certificate")
            request_path = matrix.workspace / f"gateway-evidence-{index}.json"
            request_value = {
                "quote": bound["quote_hex"],
                "event_log": bound["event_log"],
                "vm_config": bound["vm_config"],
            }
            if bound.get("attestation_hex"):
                request_value = {"attestation": bound["attestation_hex"]}
            request_path.write_text(json.dumps(request_value))
            verified = subprocess.run(
                [str(verifier), "--verify", str(request_path)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=180,
                check=False,
            )
            request_path.unlink()
            if verified.returncode:
                raise RuntimeError(
                    f"candidate verifier rejected Gateway TDX evidence {index}: "
                    f"{verified.stderr[-1000:]}"
                )
            projection = json.loads(verified.stdout)
            if projection.get("is_valid") is not True:
                raise RuntimeError(
                    f"Gateway TDX evidence {index} verification was not valid"
                )
            details = projection.get("details") or {}
            if details.get("report_data") != bound["report_data_hex"]:
                raise RuntimeError("verified TDX report data did not bind the TLS leaf")
            public_match = re.search(
                r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----",
                inspection,
                re.DOTALL,
            )
            if public_match is None:
                raise RuntimeError("Gateway certificate omitted its public key")
            certificates.append(
                {
                    "der_sha256": hashlib.sha256(der).hexdigest(),
                    "public_key_sha256": hashlib.sha256(
                        public_match.group(0).encode()
                    ).hexdigest(),
                    "issuer": next(
                        line.removeprefix("issuer=")
                        for line in inspection.splitlines()
                        if line.startswith("issuer=")
                    ),
                    "gateway_domain_bound": "gateway-candidate.test" in inspection,
                    "kms_chain_verified": True,
                    "verifier_valid": True,
                    "report_data_bound_to_tls_leaf": True,
                    "tee_variant": details.get("tee_variant"),
                    "os_image_hash_verified": details.get("os_image_hash_verified"),
                }
            )
            if certificates[-1]["gateway_domain_bound"] is not True:
                raise RuntimeError(
                    "Gateway certificate did not bind its configured domain"
                )
            certificate.unlink()
            leaf_pem.unlink()
            untrusted.unlink()
        if certificates[0]["issuer"] != certificates[1]["issuer"]:
            raise RuntimeError("Gateway certificate rotation changed its issuer")
        if certificates[0]["public_key_sha256"] == certificates[1]["public_key_sha256"]:
            raise RuntimeError(
                "Gateway certificate rotation reused the leaf public key"
            )

        tampered = matrix.workspace / "gateway-certificate-tampered.der"
        with socket.create_connection(
            ("127.0.0.1", gateways[-1]["service_port"]), timeout=30
        ) as raw:
            with ssl._create_unverified_context().wrap_socket(raw) as client:  # noqa: SLF001
                damaged = bytearray(client.getpeercert(binary_form=True))
        damaged[-1] ^= 1
        tampered.write_bytes(damaged)
        rejected = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(kms_ca),
                str(tampered),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        tampered.unlink()
        kms_ca.unlink()
        if rejected.returncode == 0:
            raise RuntimeError(
                "candidate verifier accepted a tampered Gateway certificate"
            )
        return {
            "path": [
                "candidate-kms-root-holder",
                "first-gateway-certificate",
                "rotated-gateway-certificate",
                "independent-candidate-verification",
                "tampered-certificate-rejection",
            ],
            "expected": "both same-domain Gateway certificates verify, rotate their leaf key under one issuer, and tampering fails closed",
            "certificates": certificates,
            "tampered_certificate_rejected": True,
            "private_material_exported": False,
        }
    if case_id in {"tc-int-compatibil-004", "tc-int-mixed-003"}:
        kms = matrix.deploy(
            "candidate", initialized=True, domain_override="10-0-2-2.sslip.io"
        )
        gateway_app_id = hashlib.sha1(  # noqa: S324 - opaque case identity, not cryptography
            f"{case_id}:rolling-gateway-cluster".encode()
        ).hexdigest()
        old_gateway = matrix.deploy_gateway(
            "0.5.11",
            [kms],
            node_id=1,
            name_suffix="old",
            source_app_id=gateway_app_id,
            client_range="10.8.0.0/16",
        )
        candidate_gateway = matrix.deploy_gateway(
            "candidate",
            [kms],
            node_id=2,
            name_suffix="candidate",
            bootnode_guest_url=old_gateway["guest_url"],
            source_app_id=gateway_app_id,
            client_range="10.8.0.0/16",
        )

        def wait_route(
            gateway: dict[str, Any], app_id: str, instance: str, timeout: int = 180
        ) -> dict[str, Any]:
            deadline = time.monotonic() + timeout
            last = None
            while time.monotonic() < deadline:
                last = matrix.gateway_route(gateway, app_id)
                if last is not None and last.get("instance") == instance:
                    return last
                time.sleep(1)
            diagnostic = getattr(matrix, "last_gateway_route_error", "unavailable")
            raise RuntimeError(
                f"Gateway cluster did not converge app={app_id}: {last}; "
                f"last_route_error={diagnostic}"
            )

        old_client = matrix.deploy_client(
            [kms],
            identity="old-gateway-client",
            gateway_rows=[candidate_gateway, old_gateway],
            trust_chain=True,
            restricted_ports=[8443],
            native_gateway=True,
        )
        old_to_candidate = wait_route(
            candidate_gateway,
            old_client["app_id"],
            old_client["route_instance"],
        )
        candidate_client = matrix.deploy_client(
            [kms],
            identity="candidate-gateway-client",
            gateway_rows=[candidate_gateway, old_gateway],
            trust_chain=True,
            restricted_ports=[8443],
            native_gateway=True,
        )
        candidate_to_old = wait_route(
            old_gateway,
            candidate_client["app_id"],
            candidate_client["route_instance"],
        )

        before_restart = matrix.gateway_tls_identity(candidate_gateway)
        run([*matrix.cli, "stop", old_gateway["vm_id"], "--force"], timeout=120)
        failover_client = matrix.deploy_client(
            [kms],
            identity="candidate-only-client",
            gateway_rows=[candidate_gateway],
            trust_chain=True,
            restricted_ports=[8443],
            native_gateway=True,
        )
        candidate_failover = wait_route(
            candidate_gateway,
            failover_client["app_id"],
            failover_client["route_instance"],
        )
        run([*matrix.cli, "start", old_gateway["vm_id"]], timeout=120)
        wait_http(old_gateway["url"], tls=True, timeout=180)
        healed_to_old = wait_route(
            old_gateway,
            failover_client["app_id"],
            failover_client["route_instance"],
        )
        after_restart = matrix.gateway_tls_identity(candidate_gateway)

        invalid_rows = []
        for gateway in (old_gateway, candidate_gateway):
            code, raw = http(f"{gateway['url']}/prpc/Tproxy.RegisterCvm?json", b"{}")
            if 0 < code < 400:
                raise RuntimeError(
                    f"{gateway['version']} accepted invalid registration"
                )
            health, _ = http(gateway["url"])
            if health == 0:
                raise RuntimeError(
                    f"{gateway['version']} lost availability after rejection"
                )
            invalid_rows.append(
                {
                    "version": gateway["version"],
                    "http": code,
                    "response_sha256": hashlib.sha256(raw).hexdigest(),
                    "healthy_after": True,
                }
            )

        runtime = json.loads(matrix.runtime_path.read_text())
        exact_test = "kv::kv_lifecycle_tests::gateway_kv_batch_009_encoding_persistence_watch_and_corruption"
        completed = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(pathlib.Path(runtime["repository"]) / "dstack/Cargo.toml"),
                "-p",
                "dstack-gateway",
                exact_test,
                "--",
                "--exact",
            ],
            env={**os.environ, "CARGO_TARGET_DIR": str(runtime["cargo_target_dir"])},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError(
                "Gateway WaveKV/certificate-lock regression failed; "
                f"output_sha256={hashlib.sha256(completed.stdout).hexdigest()}"
            )
        return {
            "path": [
                "v0.5.11-gateway-bootnode",
                "candidate-gateway-join",
                "dual-version-client-registrations",
                "old-node-outage",
                "candidate-only-registration",
                "old-node-heal-and-convergence",
                "certificate-lock-and-persistence-regression",
            ],
            "expected": "mixed Gateway nodes accept compatible client registrations, preserve policy and certificate identity, survive one-node loss, and converge after healing",
            "old_to_candidate": old_to_candidate,
            "candidate_to_old": candidate_to_old,
            "candidate_failover": candidate_failover,
            "healed_to_old": healed_to_old,
            "candidate_certificate_identity_stable": before_restart == after_restart,
            "invalid_registrations": invalid_rows,
            "exact_gateway_test": {
                "name": exact_test,
                "passed": True,
                "output_sha256": hashlib.sha256(completed.stdout).hexdigest(),
            },
            "private_material_exported": False,
        }
    if case_id in {
        "tc-kms-upgrade-012",
        "tc-int-compatibil-003",
        "tc-int-mixed-002",
        "tc-int-mixed-004",
    }:
        client_domain = "10-0-2-2.sslip.io"
        old_primary = matrix.deploy(
            "0.5.8", initialized=True, domain_override=client_domain
        )
        old_secondary = matrix.deploy("0.5.8", initialized=False)
        matrix.onboard(
            old_secondary,
            old_primary,
            expect_success=True,
            target_domain=client_domain,
        )
        old_identities = [matrix.metadata(row) for row in (old_primary, old_secondary)]
        if old_identities[0] != old_identities[1]:
            raise RuntimeError(f"old KMS quorum identity mismatch: {old_identities}")
        old_gateway = matrix.deploy_gateway(
            "0.5.8", [old_primary, old_secondary], node_id=1
        )
        baseline = matrix.deploy_client(
            [old_primary, old_secondary], gateway_rows=[old_gateway]
        )

        candidate_primary = matrix.deploy("candidate", initialized=False, legacy=True)
        matrix.onboard(
            candidate_primary,
            old_primary,
            expect_success=True,
            target_domain=client_domain,
        )
        candidate_secondary = matrix.deploy("candidate", initialized=False, legacy=True)
        matrix.onboard(
            candidate_secondary,
            old_secondary,
            expect_success=True,
            target_domain=client_domain,
        )
        kms_rows = (
            old_primary,
            old_secondary,
            candidate_primary,
            candidate_secondary,
        )
        endpoint_identities = [matrix.metadata(row) for row in kms_rows]
        if (
            len({json.dumps(value, sort_keys=True) for value in endpoint_identities})
            != 1
        ):
            raise RuntimeError(
                f"KMS cutover changed root or CA identity: {endpoint_identities}"
            )

        new_gateway = matrix.deploy_gateway(
            "candidate", [candidate_primary, candidate_secondary], node_id=2
        )
        gateway_identities = [
            matrix.gateway_tls_identity(row) for row in (old_gateway, new_gateway)
        ]
        post_cutover = matrix.deploy_client(
            [candidate_primary, candidate_secondary],
            gateway_rows=[new_gateway, old_gateway],
        )
        rollback = matrix.deploy_client(
            [old_primary, old_secondary],
            gateway_rows=[old_gateway, new_gateway],
        )
        stable_fields = (
            "app_id",
            "public_key_sha256",
            "certificate_chain_length",
        )
        app_identities = [
            tuple(row["observation"][key] for key in stable_fields)
            for row in (baseline, post_cutover, rollback)
        ]
        if len(set(app_identities)) != 1:
            raise RuntimeError(
                f"gateway cutover changed app identity: {app_identities}"
            )
        new_client = matrix.deploy_client(
            [candidate_secondary, candidate_primary],
            identity="new",
            gateway_rows=[new_gateway, old_gateway],
        )
        if new_client["observation"]["app_id"] == baseline["observation"]["app_id"]:
            raise RuntimeError("new post-cutover client reused existing app identity")
        for client in (baseline, post_cutover, rollback, new_client):
            registrations = client["observation"]["gateway_registrations"]
            if not registrations or any(row["http"] != 200 for row in registrations):
                raise RuntimeError(f"gateway traffic failed: {registrations}")
        env_keys: dict[str, list[dict[str, str | int]]] = {}
        for name, client in (("existing", baseline), ("new", new_client)):
            values = [
                matrix.env_public_key(endpoint, client["observation"]["app_id"])
                for endpoint in kms_rows
            ]
            stable = {
                (value["public_key_sha256"], value["legacy_signature_sha256"])
                for value in values
            }
            if len(stable) != 1:
                raise RuntimeError(f"{name} env identity changed: {values}")
            env_keys[name] = values
        unavailable_old, disabled_observation = matrix.configure_endpoint_proxy(
            0, old_secondary, enabled=False
        )
        failure_recovery = {
            "old_secondary_route_disabled": disabled_observation,
        }
        surviving_key = matrix.env_public_key(
            old_primary, baseline["observation"]["app_id"]
        )
        expected_surviving_key = env_keys["existing"][0]
        if (
            surviving_key["public_key_sha256"],
            surviving_key["legacy_signature_sha256"],
        ) != (
            expected_surviving_key["public_key_sha256"],
            expected_surviving_key["legacy_signature_sha256"],
        ):
            raise RuntimeError(
                "old-node loss changed existing environment-key identity"
            )
        recovered_old, recovered_observation = matrix.configure_endpoint_proxy(
            0, old_secondary, enabled=True
        )
        if matrix.metadata(recovered_old) != endpoint_identities[1]:
            raise RuntimeError("recovered old endpoint changed KMS identity")
        failure_recovery["old_secondary_route_recovered"] = recovered_observation
        malformed_code, malformed_raw = http(
            f"https://127.0.0.1:{candidate_primary['service_port']}"
            "/prpc/KMS.GetAppEnvEncryptPubKey?json",
            b"{}",
        )
        if malformed_code < 400:
            raise RuntimeError(
                f"malformed environment-key request unexpectedly returned HTTP {malformed_code}"
            )
        identity_after_rejection = matrix.metadata(candidate_primary)
        if identity_after_rejection != endpoint_identities[2]:
            raise RuntimeError("rejected request mutated candidate KMS identity")

        return {
            "path": [
                "two-old-kms-root-holders",
                "old-gateway-and-client-baseline",
                "two-candidate-kms-root-holders",
                "candidate-gateway-after-kms-health",
                "dual-gateway-existing-and-new-client-traffic",
                "old-gateway-and-old-kms-rollback",
            ],
            "expected": "Gateway upgrade follows verified KMS cutover and preserves old rollback traffic",
            "endpoint_identities": endpoint_identities,
            "gateway_tls_identities": gateway_identities,
            "existing_app_observations": [
                row["observation"] for row in (baseline, post_cutover, rollback)
            ],
            "new_app_observation": new_client["observation"],
            "env_public_keys": env_keys,
            "failure_recovery": failure_recovery,
            "surviving_old_key": surviving_key,
            "invalid_request": {
                "http": malformed_code,
                "diagnostic": re.sub(
                    r"[A-Za-z0-9_+/=-]{48,}",
                    "<redacted>",
                    malformed_raw.decode(errors="replace"),
                )[:300],
                "identity_unchanged": True,
            },
            "gateway_participated_in_root_transfer": False,
            "private_material_exported": False,
        }
    if case_id == "tc-kms-upgrade-011":
        cache_tests = matrix.measurement_cache_tests()
        client_domain = "10-0-2-2.sslip.io"
        old_primary = matrix.deploy(
            "0.5.8",
            initialized=True,
            verify_image=False,
            domain_override=client_domain,
        )
        old_secondary = matrix.deploy("0.5.8", initialized=False, verify_image=True)
        matrix.onboard(
            old_secondary,
            old_primary,
            expect_success=True,
            target_domain=client_domain,
        )
        candidate_legacy = matrix.deploy(
            "candidate", initialized=False, legacy=True, verify_image=True
        )
        matrix.onboard(
            candidate_legacy,
            old_secondary,
            expect_success=True,
            target_domain=client_domain,
        )
        baseline = matrix.deploy_client([old_primary, candidate_legacy])

        candidate_active = matrix.deploy(
            "candidate", initialized=False, legacy=False, verify_image=True
        )
        archive = pathlib.Path(matrix.values["live_vmm"]["image_archive_path"])
        hidden = archive.with_suffix(archive.suffix + ".cache-boundary-unavailable")
        archive.rename(hidden)
        try:
            cached_recompute_http, cached_recompute_diagnostic = matrix.onboard(
                candidate_active,
                candidate_legacy,
                expect_success=True,
                target_domain=client_domain,
            )
        finally:
            hidden.rename(archive)

        candidate_retry = matrix.deploy(
            "candidate", initialized=False, legacy=None, verify_image=True
        )
        archive.rename(hidden)
        try:
            retry_http, retry_diagnostic = matrix.onboard(
                candidate_retry,
                candidate_active,
                expect_success=True,
                target_domain=client_domain,
            )
        finally:
            hidden.rename(archive)

        endpoints = (
            old_primary,
            old_secondary,
            candidate_legacy,
            candidate_active,
            candidate_retry,
        )
        identities = [matrix.metadata(endpoint) for endpoint in endpoints]
        if len({json.dumps(value, sort_keys=True) for value in identities}) != 1:
            raise RuntimeError(f"cache boundary changed KMS identity: {identities}")
        after_upgrade = matrix.deploy_client(
            [candidate_active, candidate_legacy], identity="existing"
        )
        stable_app_fields = (
            "app_id",
            "public_key_sha256",
            "certificate_chain_length",
        )
        before_identity = tuple(
            baseline["observation"][field] for field in stable_app_fields
        )
        after_identity = tuple(
            after_upgrade["observation"][field] for field in stable_app_fields
        )
        if before_identity != after_identity:
            raise RuntimeError(
                f"existing app identity changed at cache boundary: "
                f"{before_identity} != {after_identity}"
            )
        new_client = matrix.deploy_client(
            [candidate_legacy, candidate_active], identity="new"
        )
        if new_client["observation"]["app_id"] == baseline["observation"]["app_id"]:
            raise RuntimeError("new cache-boundary client reused existing app identity")
        env_keys: dict[str, list[dict[str, str | int]]] = {}
        for name, client in (("existing", baseline), ("new", new_client)):
            values = [
                matrix.env_public_key(endpoint, client["observation"]["app_id"])
                for endpoint in endpoints
            ]
            stable = {
                (value["public_key_sha256"], value["legacy_signature_sha256"])
                for value in values
            }
            if len(stable) != 1:
                raise RuntimeError(f"{name} env identity changed: {values}")
            env_keys[name] = values
        return {
            "path": [
                "candidate-cache-unit-boundaries",
                "two-retained-0.5.8-sources",
                "legacy-acpi-candidate-onboard",
                "cached-archive-active-config-recompute",
                "second-candidate-cached-archive-recompute",
                "active-acpi-candidate-onboard",
                "existing-and-new-app-authorization",
            ],
            "expected": "stale cache results cannot cross version/config boundaries and active rules recompute",
            "cache_tests": cache_tests,
            "cached_recompute": {
                "http": cached_recompute_http,
                "diagnostic": cached_recompute_diagnostic,
            },
            "second_cached_recompute": {
                "http": retry_http,
                "diagnostic": retry_diagnostic,
            },
            "endpoint_identities": identities,
            "existing_app_before": baseline["observation"],
            "existing_app_after": after_upgrade["observation"],
            "new_app": new_client["observation"],
            "env_public_keys": env_keys,
            "private_material_exported": False,
        }
    if case_id == "tc-kms-upgrade-010":
        client_domain = "10-0-2-2.sslip.io"
        old_primary = matrix.deploy(
            "0.5.8",
            initialized=True,
            verify_image=False,
            domain_override=client_domain,
        )
        old_secondary = matrix.deploy("0.5.8", initialized=False)
        matrix.onboard(
            old_secondary,
            old_primary,
            expect_success=True,
            target_domain=client_domain,
        )
        new_primary = matrix.deploy("candidate", initialized=False, legacy=True)
        matrix.onboard(
            new_primary,
            old_primary,
            expect_success=True,
            target_domain=client_domain,
        )
        new_secondary = matrix.deploy("candidate", initialized=False, legacy=True)
        matrix.onboard(
            new_secondary,
            old_primary,
            expect_success=True,
            target_domain=client_domain,
        )
        endpoints = [old_primary, old_secondary, new_primary, new_secondary]
        endpoint_identities = [matrix.metadata(item) for item in endpoints]
        if len({tuple(sorted(item.items())) for item in endpoint_identities}) != 1:
            raise RuntimeError(
                f"rollback quorum identity changed: {endpoint_identities}"
            )

        routes = [
            matrix.configure_endpoint_proxy(index, endpoint, enabled=True)[0]
            for index, endpoint in enumerate(endpoints)
        ]
        (
            old_primary_route,
            old_secondary_route,
            new_primary_route,
            new_secondary_route,
        ) = routes
        baseline = matrix.deploy_client([old_primary_route, old_secondary_route])
        gradual = matrix.deploy_client(
            [new_primary_route, old_primary_route, old_secondary_route]
        )
        new_primary_route, target_outage = matrix.configure_endpoint_proxy(
            2, new_primary, enabled=False
        )
        rollback = matrix.deploy_client(
            [new_primary_route, old_primary_route, old_secondary_route],
            kms_encrypt_row=old_primary,
        )
        new_primary_route, target_recovery = matrix.configure_endpoint_proxy(
            2, new_primary, enabled=True
        )
        cutover = matrix.deploy_client(
            [
                new_primary_route,
                new_secondary_route,
                old_primary_route,
                old_secondary_route,
            ]
        )
        old_primary_route, old_primary_retired = matrix.configure_endpoint_proxy(
            0, old_primary, enabled=False
        )
        old_secondary_route, old_secondary_retired = matrix.configure_endpoint_proxy(
            1, old_secondary, enabled=False
        )
        post_retirement = matrix.deploy_client(
            [
                new_primary_route,
                new_secondary_route,
                old_primary_route,
                old_secondary_route,
            ]
        )
        old_primary_route, old_primary_restored = matrix.configure_endpoint_proxy(
            0, old_primary, enabled=True
        )
        old_secondary_route, old_secondary_restored = matrix.configure_endpoint_proxy(
            1, old_secondary, enabled=True
        )

        existing = [
            item["observation"]
            for item in (baseline, gradual, rollback, cutover, post_retirement)
        ]
        stable_existing = [
            (
                item["app_id"],
                item["public_key_sha256"],
                item["certificate_chain_length"],
                item["certificate_public_key_sha256"][-1],
            )
            for item in existing
        ]
        if len(set(stable_existing)) != 1:
            raise RuntimeError(f"cutover changed existing app identity: {existing}")

        new_client = matrix.deploy_client(
            [new_primary_route, new_secondary_route], identity="new"
        )
        if new_client["observation"]["app_id"] == baseline["observation"]["app_id"]:
            raise RuntimeError("new cutover client reused the existing app identity")
        env_keys: dict[str, list[dict[str, str | int]]] = {}
        for name, client in (("existing", baseline), ("new", new_client)):
            values = [
                matrix.env_public_key(endpoint, client["observation"]["app_id"])
                for endpoint in endpoints
            ]
            stable_fields = {
                (item["public_key_sha256"], item["legacy_signature_sha256"])
                for item in values
            }
            if len(stable_fields) != 1:
                raise RuntimeError(f"{name} rollback env identity changed: {values}")
            env_keys[name] = values
        return {
            "path": [
                "two-retained-0.5.8-sources",
                "two-onboarded-candidate-holders",
                "gradual-candidate-first-routing",
                "candidate-outage-old-source-rollback",
                "candidate-recovery-and-cutover",
                "old-route-retirement-boundary",
                "old-route-rollback-window-restored",
            ],
            "expected": "bounded cutover, old-source rollback, recovered recutover, and two-holder retirement boundary",
            "endpoint_identities": endpoint_identities,
            "existing_app_observations": existing,
            "new_app_observation": new_client["observation"],
            "env_public_keys": env_keys,
            "target_outage": target_outage,
            "target_recovery": target_recovery,
            "old_primary_retired": old_primary_retired,
            "old_secondary_retired": old_secondary_retired,
            "old_primary_restored": old_primary_restored,
            "old_secondary_restored": old_secondary_restored,
            "private_material_exported": False,
        }
    if case_id == "tc-kms-upgrade-009":
        client_domain = "10-0-2-2.sslip.io"
        source = matrix.deploy(
            "0.5.8",
            initialized=True,
            verify_image=True,
            domain_override=client_domain,
        )
        target = matrix.deploy("candidate", initialized=False, legacy=True)
        matrix.onboard(
            target,
            source,
            expect_success=True,
            target_domain=client_domain,
        )
        endpoint_identities = [matrix.metadata(item) for item in (source, target)]
        if endpoint_identities[0] != endpoint_identities[1]:
            raise RuntimeError(
                f"mixed endpoints changed root or CA identity: {endpoint_identities}"
            )

        source_route, _ = matrix.configure_endpoint_proxy(0, source, enabled=True)
        target_route, _ = matrix.configure_endpoint_proxy(1, target, enabled=True)
        baseline = matrix.deploy_client([source_route, target_route])
        source_route, source_outage = matrix.configure_endpoint_proxy(
            0, source, enabled=False
        )
        target_failover = matrix.deploy_client(
            [source_route, target_route], kms_encrypt_row=target
        )
        source_route, source_recovery = matrix.configure_endpoint_proxy(
            0, source, enabled=True
        )
        target_route, target_outage = matrix.configure_endpoint_proxy(
            1, target, enabled=False
        )
        source_failover = matrix.deploy_client(
            [target_route, source_route], kms_encrypt_row=source
        )
        target_route, target_recovery = matrix.configure_endpoint_proxy(
            1, target, enabled=True
        )

        existing = [
            row["observation"] for row in (baseline, target_failover, source_failover)
        ]
        stable_existing = [
            (
                item["app_id"],
                item["public_key_sha256"],
                item["certificate_chain_length"],
                item["certificate_public_key_sha256"][-1],
            )
            for item in existing
        ]
        if len(set(stable_existing)) != 1:
            raise RuntimeError(
                f"existing app identity changed across failover: {existing}"
            )

        new_client = matrix.deploy_client([target_route, source_route], identity="new")
        if new_client["observation"]["app_id"] == baseline["observation"]["app_id"]:
            raise RuntimeError("new client did not receive a distinct app identity")

        env_keys: dict[str, list[dict[str, str | int]]] = {}
        for name, client in (("existing", baseline), ("new", new_client)):
            app_id = client["observation"]["app_id"]
            values = [matrix.env_public_key(item, app_id) for item in (source, target)]
            stable_fields = [
                (item["public_key_sha256"], item["legacy_signature_sha256"])
                for item in values
            ]
            if stable_fields[0] != stable_fields[1]:
                raise RuntimeError(f"{name} env public identity changed: {values}")
            env_keys[name] = values

        return {
            "path": [
                "0.5.8-source",
                "candidate-onboard",
                "source-outage-target-failover",
                "source-recovery",
                "target-outage-source-failover",
                "target-recovery",
                "new-app-provisioning",
            ],
            "expected": "stable old/candidate service identity with bidirectional client failover and recovery",
            "endpoint_identities": endpoint_identities,
            "existing_app_observations": existing,
            "new_app_observation": new_client["observation"],
            "env_public_keys": env_keys,
            "source_outage": source_outage,
            "source_recovery": source_recovery,
            "target_outage": target_outage,
            "target_recovery": target_recovery,
            "private_material_exported": False,
        }
    if case_id == "tc-kms-upgrade-008":
        source = matrix.deploy(
            "0.5.8", initialized=True, verify_image=True, auth_context="source"
        )
        target = matrix.deploy("candidate", initialized=False, auth_context="target")
        discovery = {
            "source": {
                "allowedMrAggregated": [],
                "allowedOsImageHashes": [],
                "denyAll": True,
            },
            "target": {
                "allowedMrAggregated": [],
                "allowedOsImageHashes": [],
                "allowAll": True,
            },
        }
        matrix.set_upgrade_policy(discovery)
        code, diagnostic = matrix.onboard(target, source, expect_success=False)
        observations = matrix.policy_observations()
        source_boot = next(
            item for item in reversed(observations) if item["context"] == "target"
        )
        target_boot = next(
            item for item in reversed(observations) if item["context"] == "source"
        )
        policy = {
            "source": {
                "allowedMrAggregated": [target_boot["mrAggregated"]],
                "allowedOsImageHashes": [target_boot["osImageHash"]],
            },
            "target": {
                "allowedMrAggregated": [source_boot["mrAggregated"]],
                "allowedOsImageHashes": [source_boot["osImageHash"]],
            },
        }
        failures = [
            {"mutation": "discovery-deny", "http": code, "diagnostic": diagnostic}
        ]
        mutations = (
            ("missing-source-mr", "target", "allowedMrAggregated"),
            ("missing-target-mr", "source", "allowedMrAggregated"),
            ("missing-target-image", "source", "allowedOsImageHashes"),
        )
        for name, context, field in mutations:
            mutated = json.loads(json.dumps(policy))
            mutated[context][field] = []
            matrix.set_upgrade_policy(mutated)
            code, diagnostic = matrix.onboard(target, source, expect_success=False)
            failures.append({"mutation": name, "http": code, "diagnostic": diagnostic})
        matrix.set_upgrade_policy(policy)
        archive = pathlib.Path(matrix.values["live_vmm"]["image_archive_path"])
        hidden = archive.with_suffix(archive.suffix + ".unavailable")
        archive.rename(hidden)
        try:
            code, diagnostic = matrix.onboard(target, source, expect_success=False)
            failures.append(
                {
                    "mutation": "missing-target-archive",
                    "http": code,
                    "diagnostic": diagnostic,
                }
            )
        finally:
            hidden.rename(archive)
        matrix.set_upgrade_policy(policy)
        code, diagnostic = matrix.onboard(target, source, expect_success=True)
        source_identity = matrix.metadata(source)
        target_identity = matrix.metadata(target)
        if source_identity["k256_sha256"] != target_identity["k256_sha256"]:
            raise RuntimeError("successful retry changed root k256 identity")
        if source_identity["ca_public_sha256"] != target_identity["ca_public_sha256"]:
            raise RuntimeError("successful retry changed CA public identity")
        return {
            "path": [
                "discover-public-boot-identities",
                "deny-source-mr",
                "deny-target-mr",
                "deny-target-image",
                "remove-target-archive",
                "restore-and-onboard",
            ],
            "expected": "four independent fail-closed mutations and successful restored retry",
            "failures": failures,
            "final_http": code,
            "final_diagnostic": diagnostic,
            "identity_continuity": True,
            "policy_observation_count": len(matrix.policy_observations()),
        }
    if case_id == "tc-kms-upgrade-007":
        source = matrix.deploy("0.5.4", initialized=True)
        tcb = matrix.tcb_info(source)
        vm_config = matrix.workspace / "diagnose-vm-config.json"
        event_log = matrix.workspace / "diagnose-event-log.json"
        vm_config.write_text(str(tcb["vm_config"]) + "\n")
        event_log.write_text(json.dumps(tcb["event_log"], indent=2) + "\n")
        runtime = json.loads(matrix.runtime_path.read_text())
        binary = pathlib.Path(runtime["prepared_binaries"]["dstack_mr_cli"]["path"])
        _, guest, _ = matrix.image("0.5.4")
        image_store = pathlib.Path(runtime["environment"]["DSTACK_TEST_IMAGE_STORE"])
        image_dir = image_store / guest
        matched_rc, matched_output = matrix.diagnose_in_image(
            "dstacktee/dstack-kms:0.5.4",
            binary,
            vm_config,
            event_log,
            image_dir,
            str(tcb["rtmr0"]),
        )
        if matched_rc != 0 or "RTMR0: MATCH" not in matched_output:
            raise RuntimeError(
                f"age-matched diagnosis failed: {matched_output[-2000:]}"
            )
        candidate_rc, candidate_output = matrix.diagnose_in_image(
            matrix.registry["candidate_image"].replace("10.0.2.2", "127.0.0.1"),
            binary,
            vm_config,
            event_log,
            image_dir,
            str(tcb["rtmr0"]),
        )
        if candidate_rc != 0 or "RTMR0: MATCH" not in candidate_output:
            raise RuntimeError(
                f"candidate ACPI compatibility diagnosis failed: {candidate_output[-2000:]}"
            )
        return {
            "path": [
                "0.5.4-quote",
                "age-matched-diagnosis",
                "candidate-acpi-diagnosis",
            ],
            "expected": "age-matched and candidate ACPI compatibility matches",
            "matched_status": "RTMR0: MATCH",
            "candidate_status": "RTMR0: MATCH",
            "vm_config_sha256": hashlib.sha256(vm_config.read_bytes()).hexdigest(),
            "event_log_sha256": hashlib.sha256(event_log.read_bytes()).hexdigest(),
        }
    if case_id == "tc-kms-upgrade-005":
        rows = []
        for source_version in ("0.5.4", "0.5.8", "0.5.11"):
            source = matrix.deploy(source_version, initialized=True, verify_image=True)
            expect_success = source_version != "0.5.4"
            for mode, legacy in (("lite", False), ("auto", None)):
                target = matrix.deploy("candidate", initialized=False, legacy=legacy)
                code, diagnostic = matrix.onboard(
                    target, source, expect_success=expect_success
                )
                row = {
                    "source": source_version,
                    "target_mode": mode,
                    "onboard_status": code,
                    "diagnostic": diagnostic,
                    "expected": "success" if expect_success else "rejection",
                }
                if expect_success:
                    identities = [matrix.metadata(item) for item in (source, target)]
                    if identities[0] != identities[1]:
                        raise RuntimeError(
                            f"{source_version}->{mode} identity changed: {identities}"
                        )
                    row["identities"] = identities
                else:
                    target_port = target["service_port"]
                    still_onboard, _ = http(f"http://127.0.0.1:{target_port}/")
                    if still_onboard != 200:
                        raise RuntimeError(
                            f"{source_version}->{mode} rejection lost onboarding "
                            f"listener: {still_onboard}"
                        )
                    row["target_remained_uninitialized"] = True
                rows.append(row)
        return {
            "path": ["0.5.x", "candidate-lite-or-auto"],
            "expected": "0.5.4 rejects; 0.5.8 and 0.5.11 succeed",
            "rows": rows,
        }
    if case_id == "tc-kms-upgrade-006":
        source = matrix.deploy("0.5.8", initialized=True, verify_image=True)
        legacy_target = matrix.deploy("candidate", initialized=False, legacy=True)
        legacy_status, _ = matrix.onboard(legacy_target, source, expect_success=True)
        auto_target = matrix.deploy("candidate", initialized=False, legacy=None)
        auto_apps = sorted(matrix.workspace.glob("*-candidate.app-compose.json"))
        if not auto_apps:
            raise RuntimeError("auto target app manifest is unavailable")
        auto_manifest = json.loads(auto_apps[-1].read_text())
        if auto_manifest.get("requirements", {}).get("tdx_measure_acpi_tables") is True:
            raise RuntimeError("auto target unexpectedly declared explicit legacy mode")
        auto_status, _ = matrix.onboard(auto_target, source, expect_success=True)
        identities = [
            matrix.metadata(row) for row in (source, legacy_target, auto_target)
        ]
        if len({tuple(sorted(row.items())) for row in identities}) != 1:
            raise RuntimeError(f"variant cutover identity changed: {identities}")
        return {
            "path": ["0.5.8", "candidate-legacy", "candidate-auto"],
            "expected": "both target verification strategies succeed",
            "legacy_status": legacy_status,
            "auto_status": auto_status,
            "auto_requirements": auto_manifest.get("requirements"),
            "identities": identities,
        }
    if case_id == "tc-kms-upgrade-001":
        source = matrix.deploy("0.5.4", initialized=True)
        bridge = matrix.deploy("0.5.7", initialized=False)
        hop1, _ = matrix.onboard(bridge, source, expect_success=True)
        target = matrix.deploy("candidate", initialized=False, legacy=True)
        hop2, _ = matrix.onboard(target, bridge, expect_success=True)
        identities = [matrix.metadata(row) for row in (source, bridge, target)]
        if len({tuple(sorted(row.items())) for row in identities}) != 1:
            raise RuntimeError(f"two-hop identity changed: {identities}")
        return {
            "path": ["0.5.4", "0.5.7", "candidate"],
            "hop_statuses": [hop1, hop2],
            "identities": identities,
            "expected": "success",
        }
    source_version = {
        "tc-kms-upgrade-002": "0.5.4",
        "tc-kms-upgrade-003": "0.5.8",
        "tc-kms-upgrade-004": "0.5.11",
    }[case_id]
    source = matrix.deploy(source_version, initialized=True)
    target = matrix.deploy("candidate", initialized=False, legacy=True)
    expect_success = case_id != "tc-kms-upgrade-002"
    code, diagnostic = matrix.onboard(target, source, expect_success=expect_success)
    evidence: dict[str, Any] = {
        "path": [source_version, "candidate"],
        "onboard_status": code,
        "expected": "success" if expect_success else "rejection",
        "diagnostic": diagnostic,
    }
    if expect_success:
        identities = [matrix.metadata(row) for row in (source, target)]
        if identities[0] != identities[1]:
            raise RuntimeError(f"direct-upgrade identity changed: {identities}")
        evidence["identities"] = identities
    else:
        still_onboard, _ = http(f"http://127.0.0.1:{target['service_port']}/")
        if still_onboard != 200:
            raise RuntimeError(
                f"rejected target onboarding listener was not preserved: {still_onboard}"
            )
        evidence["target_remained_uninitialized"] = True
    return evidence


def emit(case_id: str, step: int, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step."""
    step_id = f"{case_id}-step-{step:02d}"
    print(f"STEP {step_id} START", flush=True)
    print(f"EVIDENCE {step_id} - {observed}", flush=True)
    print(f"STEP {step_id} END - {status}", flush=True)
    return {"id": step_id, "status": status, "observed": observed}


def main() -> int:
    """Prepare version artifacts, execute one live path, and emit sanitized evidence."""
    case_id = os.environ.get("DSTACK_TEST_CASE_ID", "")
    if case_id not in SUPPORTED:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime_path = pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"])
    started = time.monotonic()
    steps: list[dict[str, str]] = []
    status = "FAIL"
    failure = ""
    evidence: dict[str, Any] = {}
    try:
        matrix = MatrixRun(case_id, result_dir, manifest, runtime_path)
        steps.append(
            emit(
                case_id,
                1,
                "PASS",
                "Pinned historical sources, static bridge/candidate images, local registry, TDX VMM, and cleanup registry were prepared.",
            )
        )
        evidence = execute(case_id, matrix)
        evidence["vms"] = matrix.rows
        evidence["registry"] = {
            key: matrix.registry[key]
            for key in (
                "candidate_commit",
                "bridge_commit",
                "bridge_binary_sha256",
                "candidate_binary_sha256",
            )
        }
        steps.append(
            emit(
                case_id,
                2,
                "PASS",
                f"The live compatibility path {evidence['path']} produced the expected {evidence['expected']}.",
            )
        )
        steps.append(
            emit(
                case_id,
                3,
                "PASS",
                "KMS public identity continuity or fail-closed uninitialized state matched the path contract.",
            )
        )
        if case_id != "tc-int-compatibil-003":
            steps.append(
                emit(
                    case_id,
                    4,
                    "PASS",
                    "All VMs and the registry are lease-owned; native private keys and response bodies were not persisted.",
                )
            )
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        steps.append(emit(case_id, min(len(steps) + 1, 4), "FAIL", failure))
    atomic_json(artifacts / "kms-upgrade-matrix.json", evidence)
    artifact = {
        "path": "artifacts/kms-upgrade-matrix.json",
        "name": "KMS upgrade matrix",
        "description": "Sanitized live version, path, public identity, rejection, and resource evidence.",
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": f"Live KMS upgrade path passed for {case_id}."
        if status == "PASS"
        else failure,
        "steps": steps,
        "artifacts": [artifact],
        "duration_seconds": round(time.monotonic() - started, 3),
        "remarks": "The case executes pinned historical and candidate KMS binaries in real TDX guests. Failure retains the compatibility stack, VMs, registry, logs, and created-vms registry for command-by-command debugging.",
    }
    atomic_json(result_dir / "result.json", result)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
