#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise multi-cluster registration and both Gateway proxy data paths."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-setup-009"


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        tmp = Path(out.name)
    tmp.replace(path)


def run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=False, **kw)


def free_ports(count: int) -> list[int]:
    sockets = []
    ports = []
    try:
        for _ in range(count):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            sockets.append(s)
            ports.append(s.getsockname()[1])
        return ports
    finally:
        for s in sockets:
            s.close()


def free_octets(count: int) -> list[int]:
    selected = []
    for octet in range(120, 250):
        route = run(["ip", "route", "show", f"10.{octet}.0.0/24"], timeout=10)
        if route.returncode == 0 and not route.stdout.strip():
            selected.append(octet)
        if len(selected) == count:
            return selected
    raise RuntimeError("no unused Gateway test subnets are available")


def ssh(
    ssh_argv: list[str], script: str, timeout: int = 60
) -> subprocess.CompletedProcess[str]:
    return run([*ssh_argv, script], timeout=timeout)


def gateway_config(
    source: Path,
    root: Path,
    name: str,
    ports: list[int],
    octet: int,
    interface: str,
    agent_url: str,
) -> tuple[Path, str]:
    rpc, admin, debug, proxy, wgport = ports
    private = run(["wg", "genkey"], timeout=10).stdout.strip()
    public = run(["wg", "pubkey"], input=private + "\n", timeout=10).stdout.strip()
    if not private or not public:
        raise RuntimeError("failed to generate Gateway WireGuard identity")
    node = root / name
    for sub in ("data", "run", "logs", "certs"):
        (node / sub).mkdir(parents=True, exist_ok=True)
    text = source.read_text()
    replacements = {
        'address = "127.0.0.1:8010"': f'address = "0.0.0.0:{rpc}"',
        "set_ulimit = true": "set_ulimit = false",
        'rpc_domain = ""': 'rpc_domain = "10.0.2.2"',
        '[core.admin]\nenabled = false\naddress = "127.0.0.1:8011"': f'[core.admin]\nenabled = true\naddress = "127.0.0.1:{admin}"',
        'auth_token = ""': f'auth_token = "{secrets.token_hex(32)}"',
        "insecure_enable_debug_rpc = false": "insecure_enable_debug_rpc = true",
        "insecure_skip_attestation = false": "insecure_skip_attestation = true",
        'address = "127.0.0.1:8012"': f'address = "127.0.0.1:{debug}"',
        'public_key = ""': f'public_key = "{public}"',
        'private_key = ""': f'private_key = "{private}"',
        "listen_port = 51820": f"listen_port = {wgport}",
        'ip = "10.0.0.1/24"': f'ip = "10.{octet}.0.1/24"',
        'reserved_net = ["10.0.0.1/32"]': f'reserved_net = ["10.{octet}.0.1/32"]',
        'client_ip_range = "10.0.0.0/25"': f'client_ip_range = "10.{octet}.0.0/25"',
        'config_path = "/etc/wireguard/wg0.conf"': f'config_path = "{node}/run/wireguard.conf"',
        'interface = "wg0"': f'interface = "{interface}"',
        'endpoint = "10.0.2.2:51820"': f'endpoint = "10.0.2.2:{wgport}"',
        "listen_port = 8443": f"listen_port = {proxy}",
        'data_dir = "/dstack-gateway/data"': f'data_dir = "{node}/data/sync"',
    }
    for old, new in replacements.items():
        if old not in text:
            raise RuntimeError(f"Gateway template missing {old}")
        text = text.replace(old, new, 1)
    text = text.replace(
        "[core.proxy]\n",
        f'[core.proxy]\nbase_domain = "localhost"\ncert_chain = "{node}/certs/server.crt"\ncert_key = "{node}/certs/server.key"\n',
        1,
    )
    text += f'\n[tls]\nkey = "{node}/certs/server.key"\ncerts = "{node}/certs/server.crt"\n[tls.mutual]\nca_certs = "{node}/certs/ca.crt"\n'
    config = node / "gateway.toml"
    config.write_text(text)
    config.chmod(0o600)
    return config, public


def main() -> int:
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    art = result_dir / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest["values"]
    ssh_argv = [str(x) for x in values["ssh_argv"]]
    guest_url = str(values["services"]["DstackGuest"]["url"]).replace("/{method}", "")
    repo = Path(runtime["repository"])
    binary = Path(runtime["prepared_binaries"]["dstack_gateway"]["path"])
    root = Path(tempfile.mkdtemp(prefix="dstack-multicluster-"))
    processes = []
    configs = []
    interfaces = ["dtmc-p", "dtmc-s"]
    observations = {}
    status = "FAIL"
    failure = ""
    try:
        native = run(
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "dstack-util",
                "gateway_registration_refresh_tests",
                "--",
                "--nocapture",
            ],
            cwd=repo / "dstack",
            env={**os.environ, "CARGO_TARGET_DIR": runtime["cargo_target_dir"]},
            timeout=600,
        )
        (art / "native-tests.log").write_text(native.stdout + native.stderr)
        if native.returncode:
            raise RuntimeError("candidate multi-cluster native tests failed")
        ports = free_ports(10)
        octets = free_octets(2)
        for row in (
            ("primary", ports[:5], octets[0], interfaces[0]),
            ("secondary", ports[5:], octets[1], interfaces[1]),
        ):
            config, _ = gateway_config(
                repo / "dstack/gateway/gateway.toml", root, *row, guest_url
            )
            configs.append(config)
            log = (config.parent / "logs/gateway.log").open("w")
            p = subprocess.Popen(
                [
                    "sudo",
                    "-n",
                    "-E",
                    "env",
                    f"DSTACK_AGENT_ADDRESS={guest_url}",
                    str(binary),
                    "--config",
                    str(config),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            processes.append(p)
            time.sleep(3)
            if p.poll() is not None:
                raise RuntimeError(f"{row[0]} Gateway exited during startup")
        time.sleep(5)
        primary_rpc, primary_proxy = ports[0], ports[3]
        secondary_rpc, secondary_proxy = ports[5], ports[8]
        sysconfig = json.dumps(
            [
                {"name": "primary", "urls": [f"https://10.0.2.2:{primary_rpc}"]},
                {"name": "secondary", "urls": [f"https://10.0.2.2:{secondary_rpc}"]},
            ],
            separators=(",", ":"),
        )
        setup = f"""set -eu
jq '.gateway_enabled=true | .port_policy={{"ports":[{{"port":80,"pp":false}}],"restrict_mode":true}}' /dstack/.host-shared/app-compose.json >/tmp/app-compose.json
mv /tmp/app-compose.json /dstack/.host-shared/app-compose.json
jq '.gateway_urls=[] | .gateway_clusters={sysconfig}' /dstack/.host-shared/.sys-config.json >/tmp/sys-config.json
mv /tmp/sys-config.json /dstack/.host-shared/.sys-config.json
systemctl restart dstack-gateway-checker.service
for i in $(seq 1 30); do ip link show dstack-wg0 >/dev/null 2>&1 && ip link show dstack-wg1 >/dev/null 2>&1 && break; sleep 1; done
systemctl is-active --quiet dstack-gateway-checker.service
mkdir -p /tmp/proxy-workload
echo same-cvm-via-two-gateway-clusters >/tmp/proxy-workload/identity
systemctl stop dstack-test-proxy-workload.service 2>/dev/null || true
systemd-run --unit=dstack-test-proxy-workload.service --property=Restart=no python3 -m http.server 80 --bind 0.0.0.0 --directory /tmp/proxy-workload
for i in $(seq 1 10); do test "$(curl -sf http://127.0.0.1/identity)" = same-cvm-via-two-gateway-clusters && break; sleep 1; done
test "$(curl -sf http://127.0.0.1/identity)" = same-cvm-via-two-gateway-clusters
"""
        ready = ssh(ssh_argv, setup, 120)
        if ready.returncode:
            raise RuntimeError(
                "CVM multi-cluster setup failed: " + ready.stderr[-1000:]
            )
        info = json.loads(urllib_request(guest_url + "/Info?json"))
        app_id = info["app_id"]
        responses = []
        for cluster, proxy in (
            ("primary", primary_proxy),
            ("secondary", secondary_proxy),
        ):
            for _ in range(30):
                probe = run(
                    [
                        "curl",
                        "--noproxy",
                        "*",
                        "-skf",
                        "--max-time",
                        "10",
                        "--resolve",
                        f"{app_id}.localhost:{proxy}:127.0.0.1",
                        f"https://{app_id}.localhost:{proxy}/identity",
                    ],
                    timeout=15,
                )
                if (
                    probe.returncode == 0
                    and probe.stdout.strip() == "same-cvm-via-two-gateway-clusters"
                ):
                    break
                time.sleep(1)
            if (
                probe.returncode
                or probe.stdout.strip() != "same-cvm-via-two-gateway-clusters"
            ):
                raise RuntimeError(
                    f"{cluster} Gateway proxy did not reach CVM (curl exit {probe.returncode}: {probe.stderr.strip()[-300:]})"
                )
            responses.append(
                {
                    "cluster": cluster,
                    "proxy_port": proxy,
                    "response_sha256": hashlib.sha256(
                        probe.stdout.encode()
                    ).hexdigest(),
                }
            )
        wg = ssh(
            ssh_argv,
            "wg show dstack-wg0 latest-handshakes; wg show dstack-wg1 latest-handshakes",
            30,
        )
        if wg.returncode or len([x for x in wg.stdout.splitlines() if x.strip()]) < 2:
            raise RuntimeError("both CVM WireGuard handshakes were not observed")
        observations = {
            "status": "PASS",
            "clusters": responses,
            "interfaces": ["dstack-wg0", "dstack-wg1"],
            "same_cvm_app_id_hash": hashlib.sha256(app_id.encode()).hexdigest(),
            "wireguard_handshakes_observed": True,
        }
        status = "PASS"
    except Exception as error:
        failure = str(error)
        observations = {"status": "FAIL", "failure": failure}
    finally:
        for config in configs:
            log = config.parent / "logs/gateway.log"
            if log.is_file():
                shutil.copy2(log, art / f"{config.parent.name}-gateway.log")
        ssh(
            ssh_argv,
            "systemctl stop dstack-test-proxy-workload.service 2>/dev/null || true",
            20,
        )
        for p in processes:
            run(["sudo", "-n", "kill", "--", f"-{p.pid}"], timeout=10)
        for interface in interfaces:
            run(["sudo", "-n", "ip", "link", "del", interface], timeout=10)
        run(["sudo", "-n", "rm", "-rf", "--", str(root)], timeout=10)
    observations["duration_seconds"] = round(time.monotonic() - started, 3)
    atomic_json(art / "gateway-multicluster-dataplane.json", observations)
    rows = [
        {
            "path": "artifacts/native-tests.log",
            "step_id": f"{CASE_ID}-step-01",
            "name": "Native multi-cluster tests",
            "description": "Candidate persistence, rollback, and selection tests.",
        },
        {
            "path": "artifacts/gateway-multicluster-dataplane.json",
            "step_id": f"{CASE_ID}-step-02",
            "name": "Multi-cluster Gateway proxy data plane",
            "description": "Redacted evidence that both independent Gateway proxies reached the same CVM workload.",
        },
    ]
    atomic_json(art / "manifest.json", {"artifacts": rows})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": "Multi-cluster Gateway proxy data plane passed"
            if status == "PASS"
            else failure,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": status,
                    "observed": "Candidate native multi-cluster tests passed."
                    if status == "PASS"
                    else failure,
                },
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "Primary and secondary Gateway proxies reached one CVM over separate WireGuard interfaces."
                    if status == "PASS"
                    else failure,
                },
            ],
            "artifacts": rows,
            "remarks": "Evidence contains hashes and public routing metadata only; private keys, certificates, and tokens are never persisted.",
        },
    )
    return 0 if status == "PASS" else 1


def urllib_request(url: str) -> str:
    import urllib.request

    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode()


if __name__ == "__main__":
    raise SystemExit(main())
