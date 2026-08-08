#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Start a seed-matched collateral service and KMS for a mkosi guest lease."""

from __future__ import annotations

# ruff: noqa: D103
import argparse
import json
import os
import pathlib
import secrets
import signal
import socket
import subprocess
import time
import urllib.request


def wait_port(port: int, process: subprocess.Popen[str], timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"process exited with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} did not become ready")


def start(
    argv: list[str], log: pathlib.Path, port: int, env: dict[str, str] | None = None
) -> subprocess.Popen[str]:
    stream = log.open("w")
    p = subprocess.Popen(
        argv,
        stdout=stream,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
        env={**os.environ, **(env or {})},
        umask=0o077,
    )
    try:
        wait_port(port, p)
    except Exception:
        p.terminate()
        raise
    return p


def stop(p: subprocess.Popen[str]) -> None:
    if p.poll() is not None:
        return
    os.killpg(p.pid, signal.SIGTERM)
    try:
        p.wait(5)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)


def verify_simulator_collateral(port: int, root: pathlib.Path) -> None:
    """Require the seed-owned PCCS endpoint and trust root before guest boot."""
    if not root.is_file() or root.stat().st_size == 0:
        raise RuntimeError("mock attestation fixture did not publish the TDX root")
    url = f"http://127.0.0.1:{port}/tdx/certification/v4/tcb?fmspc=000000000000"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            body = json.load(response)
    except Exception as error:
        raise RuntimeError(f"mock TDX collateral probe failed at {url}: {error}") from error
    if response.status != 200 or not isinstance(body, dict) or "tcbInfo" not in body:
        raise RuntimeError("mock TDX collateral probe returned an invalid response")


def verify_unattested_rpc_certificate(cert: pathlib.Path) -> None:
    """Fail preparation unless compatibility mode omitted RA-TLS attestation."""
    completed = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-text"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"failed to inspect KMS RPC certificate: {completed.stderr}")
    if "1.3.6.1.4.1.62397.1.8" in completed.stdout:
        raise RuntimeError(
            "KMS compatibility RPC certificate unexpectedly contains attestation"
        )


def write_kms(
    path: pathlib.Path,
    certs: pathlib.Path,
    rpc: int,
    onboard: int,
    admin: int,
    pccs: str = "",
    root: pathlib.Path | None = None,
    bootstrap: bool = True,
    rpc_attestation: str = "attested",
) -> None:
    attestation = ""
    if root:
        attestation = f'''\n[core.attestation]\ninsecure_allow_external_trust_anchors = true\n[core.attestation.urls]\npccs = "{pccs}"\n[core.attestation.root_ca]\ntdx = "{root}"\n'''
    attest_rpc_cert = rpc_attestation != "compatibility-unverified"
    path.write_text(
        f'''[rpc]\naddress = "0.0.0.0"\nport = {rpc}\n[rpc.tls]\nkey = "{certs / "rpc.key"}"\ncerts = "{certs / "rpc.crt"}"\n[rpc.tls.mutual]\nca_certs = "{certs / "tmp-ca.crt"}"\nmandatory = false\n[core]\ncert_dir = "{certs}"\nenforce_self_authorization = false\nattest_rpc_cert = {str(attest_rpc_cert).lower()}\n[core.image]\nverify = false\ncache_dir = "{certs.parent / "image-cache"}"\ndownload_url = "http://127.0.0.1:1/{{OS_IMAGE_HASH}}.tar.gz"\ndownload_timeout = "2s"\n[core.admin]\nenabled = true\naddress = "127.0.0.1"\nport = {admin}\nauth_token = "{secrets.token_hex(32)}"\n[core.auth_api]\ntype = "dev"\n[core.auth_api.dev]\ngateway_app_id = "any"\n[core.onboard]\nenabled = true\nauto_bootstrap_domain = "{"10.0.2.2" if bootstrap else ""}"\naddress = "127.0.0.1"\nport = {onboard}\n{attestation}'''
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime-manifest", type=pathlib.Path, required=True)
    ap.add_argument("--state", type=pathlib.Path, required=True)
    ap.add_argument("--seed", required=True)
    ap.add_argument("--collateral-port", type=int, required=True)
    ap.add_argument("--kms-port", type=int, required=True)
    ap.add_argument("--onboard-port", type=int, required=True)
    ap.add_argument("--admin-port", type=int, required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    ap.add_argument(
        "--guest-attestation",
        choices=("simulator", "hardware"),
        default="simulator",
    )
    ap.add_argument(
        "--rpc-attestation",
        choices=("attested", "compatibility-unverified"),
        default="attested",
        help="Use a test-only unquoted RPC certificate for legacy client matrices.",
    )
    a = ap.parse_args()
    runtime = json.loads(a.runtime_manifest.read_text())
    bins = runtime["prepared_binaries"]
    required_binaries = ["dstack_kms"]
    if a.guest_attestation == "simulator":
        required_binaries.append("dstack_mock_attestation")
    for name in required_binaries:
        binary = pathlib.Path(str(bins.get(name, {}).get("path", "")))
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError(f"prepared {name.replace('_', '-')} binary is unavailable")
    state = a.state.resolve()
    state.mkdir(parents=True, exist_ok=False)
    (state / "logs").mkdir()
    (state / "roots").mkdir()
    (state / "certs").mkdir()
    (state / "config").mkdir()
    simulator_fixture = state / "simulator.json"
    simulator_runtime = (
        pathlib.Path(
            os.environ.get(
                "DSTACK_TEST_STATE_ROOT",
                str(pathlib.Path.home() / ".cache/dstack-test/runtime-state"),
            )
        )
        / "s"
        / f"{state.parent.name}-{state.name}"
    )
    started = []
    try:
        helper = (
            pathlib.Path(runtime["repository"])
            / "docs/test-plans/core-components-full/automation/start-simulator.sh"
        )
        subprocess.run(
            [
                str(helper),
                str(a.runtime_manifest),
                str(simulator_runtime),
                str(simulator_fixture),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "DSTACK_TEST_MOCK_ATTESTATION_SEED": a.seed},
        )
        sim = json.loads(simulator_fixture.read_text())
        started.append(int(sim["pid"]))
        host_pccs = ""
        if a.guest_attestation == "simulator":
            mock_cfg = state / "config/mock.json"
            host_pccs = f"http://127.0.0.1:{a.collateral_port}"
            mock_cfg.write_text(
                json.dumps(
                    {
                        "platform": "dstack-tdx",
                        "mock_attestation_seed": a.seed,
                        "collateral_base_url": host_pccs,
                    }
                )
            )
            mock = start(
                [
                    bins["dstack_mock_attestation"]["path"],
                    "serve",
                    "--listen",
                    f"0.0.0.0:{a.collateral_port}",
                    "--output",
                    str(state / "roots"),
                    "--config",
                    str(mock_cfg),
                ],
                state / "logs/collateral.log",
                a.collateral_port,
            )
            started.append(mock.pid)
            verify_simulator_collateral(
                a.collateral_port, state / "roots/tdx-root-ca.pem"
            )
        kms_cfg = state / "config/kms.toml"
        agent = f"unix:{sim['services']['DstackGuest']['socket']}"
        env = {"DSTACK_AGENT_ADDRESS": agent}
        kms_bin = bins["dstack_kms"]["path"]
        write_kms(
            kms_cfg,
            state / "certs",
            a.kms_port,
            a.onboard_port,
            a.admin_port,
            rpc_attestation=a.rpc_attestation,
        )
        first = start(
            [kms_bin, "--config", str(kms_cfg)],
            state / "logs/kms-bootstrap.log",
            a.kms_port,
            env,
        )
        stop(first)
        write_kms(
            kms_cfg,
            state / "certs",
            a.kms_port,
            a.onboard_port,
            a.admin_port,
            host_pccs,
            (
                state / "roots/tdx-root-ca.pem"
                if a.guest_attestation == "simulator"
                else None
            ),
            False,
            a.rpc_attestation,
        )
        kms = start(
            [kms_bin, "--config", str(kms_cfg)], state / "logs/kms.log", a.kms_port, env
        )
        started.append(kms.pid)
        if a.rpc_attestation == "compatibility-unverified":
            verify_unattested_rpc_certificate(state / "certs/rpc.crt")
        value = {
            "pids": started,
            "simulator_fixture": str(simulator_fixture),
            "simulator_runtime": str(simulator_runtime),
            "controller_url": f"https://127.0.0.1:{a.kms_port}",
            "guest_url": f"https://10.0.2.2:{a.kms_port}",
            "guest_collateral_url": (
                f"http://10.0.2.2:{a.collateral_port}"
                if a.guest_attestation == "simulator"
                else ""
            ),
            "kms_log": str(state / "logs/kms.log"),
            "collateral_log": str(state / "logs/collateral.log"),
            "tdx_root_ca": (
                str(state / "roots/tdx-root-ca.pem")
                if a.guest_attestation == "simulator"
                else ""
            ),
            "kms_rpc_cert": str(state / "certs/rpc.crt"),
        }
        a.output.write_text(json.dumps(value, indent=2) + "\n")
        return 0
    except Exception:
        for pid in reversed(started):
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        raise


if __name__ == "__main__":
    raise SystemExit(main())
