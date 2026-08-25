#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate Certbot CLI once, hook, daemon, signal, outage, and recovery."""
# ruff: noqa: E701,E702,D103

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

CASE_ID = "tc-gw-certbot-006"


def load_support() -> Any:
    path = Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("certbot_cli_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load ACME support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def write_config(
    path: Path, workdir: Path, acme_url: str, api_url: str, domain: str, hook: str
) -> None:
    path.write_text(
        "\n".join(
            [
                f'workdir = "{workdir}"',
                f'acme_url = "{acme_url}"',
                f'cf_api_token = "{SUPPORT.SENTINEL_TOKEN}"',
                f'cf_api_url = "{api_url}"',
                "dns_txt_ttl = 60",
                "auto_set_caa = false",
                f'domains = ["{domain}"]',
                "renew_interval = 1",
                "renew_days_before = 0",
                "renew_timeout = 20",
                "max_dns_wait = 0",
                f'renewed_hook = "{hook}"',
                "",
            ]
        )
    )


def run_cli(binary: Path, config: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), "renew", "--config", str(config), *args],
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def main() -> int:
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    lease = os.environ.get("DSTACK_TEST_LEASE_ID", "lease")[-10:].replace("-", "")
    prefix = f"dstack-cli-{lease}"
    network = f"{prefix}-net"
    dns_name = f"{prefix}-dns"
    pebble_name = f"{prefix}-acme"
    domain = f"cli-{lease}.test"
    adjacent = f"adjacent-{lease}.test"
    state = SUPPORT.DnsState([domain, adjacent])
    server = SUPPORT.CloudflareServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    cleanup_errors = []
    checks = {}
    daemon = None
    status = "FAIL"
    summary = "Certbot CLI lifecycle did not complete"
    with tempfile.TemporaryDirectory(prefix="dstack-certbot-cli-") as temporary:
        root = Path(temporary)
        workdir = root / "workdir"
        config = root / "certbot.toml"
        malformed = root / "malformed.toml"
        hook_marker = root / "hook-marker"
        try:
            thread.start()
            SUPPORT.create_network(network)
            SUPPORT.docker(
                "run", "-d", "--name", dns_name, "--network", network, SUPPORT.CF_IMAGE
            )
            dns_ip = SUPPORT.docker(
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                dns_name,
            ).stdout.strip()
            SUPPORT.docker(
                "run",
                "-d",
                "--name",
                pebble_name,
                "--network",
                network,
                "-p",
                "127.0.0.1::14000",
                "-e",
                "PEBBLE_VA_NOSLEEP=1",
                "-e",
                "PEBBLE_VA_ALWAYS_VALID=1",
                SUPPORT.PEBBLE_IMAGE,
                "-http",
                "-dnsserver",
                f"{dns_ip}:53",
            )
            pebble_port = SUPPORT.published_port(pebble_name, "14000/tcp")
            acme_url = f"http://127.0.0.1:{pebble_port}/dir"
            SUPPORT.wait_http(acme_url)
            api_url = f"http://127.0.0.1:{server.server_port}/client/v4"
            env = os.environ.copy()
            env["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
            build = subprocess.run(
                ["cargo", "build", "--locked", "-p", "certbot-cli"],
                cwd=Path(str(runtime["repository"])) / "dstack",
                env=env,
                text=True,
                capture_output=True,
                timeout=300,
                check=False,
            )
            binary = Path(str(runtime["cargo_target_dir"])) / "debug/certbot"
            checks["candidate_cli_built"] = build.returncode == 0 and binary.is_file()
            if not checks["candidate_cli_built"]:
                raise AssertionError("candidate CLI build failed")
            write_config(
                config, workdir, acme_url, api_url, domain, f"printf x >> {hook_marker}"
            )
            first = run_cli(binary, config, "--once", "--force")
            cert_path = workdir / "live/cert.pem"
            key_path = workdir / "live/key.pem"
            first_target = cert_path.resolve() if cert_path.exists() else Path()
            checks["once_force_and_hook"] = (
                first.returncode == 0
                and cert_path.exists()
                and key_path.exists()
                and hook_marker.read_text() == "x"
            )
            write_config(config, workdir, acme_url, api_url, domain, "exit 7")
            failed_hook = run_cli(binary, config, "--once", "--force")
            second_target = cert_path.resolve() if cert_path.exists() else Path()
            checks["failing_hook_after_commit"] = (
                failed_hook.returncode == 0
                and second_target != first_target
                and cert_path.exists()
                and key_path.exists()
            )
            malformed.write_text("workdir = [\n")
            bad = run_cli(binary, malformed, "--once")
            checks["malformed_config_rejected"] = bad.returncode != 0
            write_config(
                config, workdir, acme_url, api_url, domain, f"printf x >> {hook_marker}"
            )
            before_daemon_ops = len(state.operations)
            daemon = subprocess.Popen(
                [str(binary), "renew", "--config", str(config)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )
            time.sleep(2.3)
            running_before_signal = daemon.poll() is None
            os.killpg(daemon.pid, signal.SIGTERM)
            daemon_rc = daemon.wait(timeout=10)
            daemon = None
            daemon_ops = len(state.operations) - before_daemon_ops
            checks["daemon_paced_and_sigterm_graceful"] = (
                running_before_signal
                and daemon_rc == 0
                and daemon_ops < 10
                and hook_marker.read_text() == "x"
            )
            restart = run_cli(binary, config, "--once")
            checks["restart_uses_persisted_workdir"] = (
                restart.returncode == 0 and hook_marker.read_text() == "x"
            )
            with state.lock:
                state.failure = True
            outage = run_cli(binary, config, "--once", "--force")
            with state.lock:
                state.failure = False
            recovery = run_cli(binary, config, "--once", "--force")
            snapshot = state.snapshot()
            checks["outage_rejected"] = outage.returncode != 0
            checks["recovery_and_hook"] = (
                recovery.returncode == 0 and hook_marker.read_text() == "xx"
            )
            checks["records_and_adjacent_clean"] = all(
                not records for records in snapshot.values()
            )
            status = "PASS" if all(checks.values()) else "FAIL"
            summary = (
                "Certbot CLI once, hook, daemon pacing, graceful SIGTERM, malformed config, persisted restart, outage, recovery, and cleanup passed."
                if status == "PASS"
                else f"Certbot CLI checks failed: {sorted(k for k, v in checks.items() if not v)}"
            )
        except Exception as error:
            summary = f"Certbot CLI lifecycle failed: {type(error).__name__}"
        finally:
            if daemon is not None:
                try:
                    os.killpg(daemon.pid, signal.SIGKILL)
                    daemon.wait(timeout=5)
                except Exception as error:
                    cleanup_errors.append(f"daemon:{type(error).__name__}")
            server.shutdown()
            server.server_close()
            thread.join(2)
            for name in (pebble_name, dns_name):
                try:
                    SUPPORT.docker("rm", "-f", name, check=False)
                except Exception as error:
                    cleanup_errors.append(f"container:{type(error).__name__}")
            try:
                SUPPORT.docker("network", "rm", network, check=False)
            except Exception as error:
                cleanup_errors.append(f"network:{type(error).__name__}")
            checks["api_server_reaped"] = not thread.is_alive()
    if cleanup_errors or not all(checks.values()):
        status = "FAIL"
    artifact = result_dir / "artifacts/certbot-cli-lifecycle.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(
        json.dumps(
            {
                "candidate_commit": runtime["candidate_commit"],
                "checks": checks,
                "cleanup_error_count": len(cleanup_errors),
                "retained_credentials_certificates_domains_paths_or_outputs": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/certbot-cli-lifecycle.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "Case-owned Pebble, DNS API, workdir, hook marker, daemon, containers, and network were removed; retained evidence contains booleans and counts only.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
