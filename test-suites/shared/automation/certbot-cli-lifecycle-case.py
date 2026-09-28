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
    path: Path,
    workdir: Path,
    acme_url: str,
    api_url: str,
    domain: str,
    hook: str,
    *,
    domains: list[str] | None = None,
    challenge: str | None = None,
    cf_api_token: str | None = None,
) -> None:
    names = domains if domains is not None else [domain]
    token = SUPPORT.SENTINEL_TOKEN if cf_api_token is None else cf_api_token
    path.write_text(
        "\n".join(
            [
                f'workdir = "{workdir}"',
                f'acme_url = "{acme_url}"',
                *([f'challenge = "{challenge}"'] if challenge else []),
                f'cf_api_token = "{token}"',
                f'cf_api_url = "{api_url}"',
                "dns_txt_ttl = 60",
                "auto_set_caa = false",
                "domains = [" + ", ".join(f'"{name}"' for name in names) + "]",
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


def run_subcommand(
    binary: Path, command: str, config: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), command, "--config", str(config)],
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def file_mode(path: Path) -> int:
    """Return the permission bits of a file, following symlinks."""
    return path.stat().st_mode & 0o777 if path.exists() else -1


def digest(path: Path) -> str:
    """Hash a file without retaining its content."""
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""


def certificate_names(path: Path) -> set[str]:
    """Return the DNS subject alternative names of a live certificate."""
    completed = subprocess.run(
        ["openssl", "x509", "-in", str(path), "-noout", "-ext", "subjectAltName"],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    if completed.returncode:
        return set()
    return {
        item.strip()[4:].lower()
        for line in completed.stdout.splitlines()[1:]
        for item in line.split(",")
        if item.strip().startswith("DNS:")
    }


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
            # PR #1241: the account key and every certificate key are
            # owner-only, and the live pair resolves through one `.current`
            # link that is swapped with a single rename.
            current = workdir / "live/.current"
            first_key_digest = digest(key_path)
            checks["account_and_key_owner_only"] = (
                file_mode(workdir / "credentials.json") == 0o600
                and file_mode(key_path) == 0o600
            )
            checks["live_pair_published_through_one_link"] = (
                current.is_symlink()
                and os.readlink(cert_path) == ".current/cert.pem"
                and os.readlink(key_path) == ".current/key.pem"
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
            checks["renewal_rotates_key"] = (
                bool(first_key_digest)
                and digest(key_path) not in {"", first_key_digest}
                and file_mode(key_path) == 0o600
                and current.is_symlink()
            )
            # A renewed hook that never exits is killed at `renew_timeout`
            # (20 s here) instead of holding the renewal loop.
            write_config(config, workdir, acme_url, api_url, domain, "exec sleep 600")
            hung_started = time.monotonic()
            try:
                hung_hook = run_cli(binary, config, "--once", "--force")
                hung_returncode: int | None = hung_hook.returncode
            except subprocess.TimeoutExpired:
                hung_returncode = None
            checks["hung_hook_bounded_by_renew_timeout"] = (
                hung_returncode == 0 and time.monotonic() - hung_started < 50
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

            # PR #1137: editing `domains` must reissue once a certificate
            # exists. PR #1136: a name and its wildcard share one
            # `_acme-challenge` name, whose TXT records must accumulate rather
            # than replace each other during one issuance. The pair is a name
            # the CA has never authorized, so neither authorization is reused
            # and both challenges are answered in this order.
            pair = f"pair.{domain}"
            added_names = [domain, pair, f"*.{pair}"]
            wildcard_names = [domain, f"*.{domain}"]
            before_change = cert_path.resolve() if cert_path.exists() else Path()
            write_config(
                config,
                workdir,
                acme_url,
                api_url,
                domain,
                "true",
                domains=added_names,
            )
            added = run_cli(binary, config, "--once")
            after_add = cert_path.resolve() if cert_path.exists() else Path()
            challenge_name = f"_acme-challenge.{pair}"
            with state.lock:
                challenge_peak = state.txt_peaks.get(challenge_name, 0)
            checks["domain_addition_reissued"] = (
                added.returncode == 0
                and after_add != before_change
                and certificate_names(cert_path) == set(added_names)
            )
            checks["name_and_wildcard_challenges_coexisted"] = challenge_peak >= 2
            write_config(config, workdir, acme_url, api_url, domain, "true")
            removed = run_cli(binary, config, "--once")
            after_remove = cert_path.resolve() if cert_path.exists() else Path()
            unchanged = run_cli(binary, config, "--once")
            checks["domain_removal_reissued_once"] = (
                removed.returncode == 0
                and after_remove != after_add
                and certificate_names(cert_path) == {domain}
                and unchanged.returncode == 0
                and (cert_path.resolve() if cert_path.exists() else Path())
                == after_remove
            )

            # PR #1198: a SIGTERM that arrives while the daemon is still building
            # the bot (here: blocked on the DNS provider's zone lookup) must be
            # handled gracefully instead of hitting the default disposition.
            with state.lock:
                state.blocked = True
                state.block_release.clear()
                startup_baseline = len(state.operations)
            startup_daemon = subprocess.Popen(
                [str(binary), "renew", "--config", str(config)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )
            daemon = startup_daemon
            startup_reached_provider = False
            startup_deadline = time.monotonic() + 15
            while time.monotonic() < startup_deadline:
                with state.lock:
                    startup_reached_provider = len(state.operations) > startup_baseline
                if startup_reached_provider or startup_daemon.poll() is not None:
                    break
                time.sleep(0.05)
            running_in_startup = startup_daemon.poll() is None
            os.killpg(startup_daemon.pid, signal.SIGTERM)
            try:
                startup_rc = startup_daemon.wait(timeout=10)
            finally:
                with state.lock:
                    state.blocked = False
                    state.block_release.set()
            daemon = None
            checks["sigterm_during_startup_graceful"] = (
                startup_reached_provider and running_in_startup and startup_rc == 0
            )

            # PR #1132: dns-persist-01 needs no provider credential and never
            # writes DNS; `dns-records` prints the one-time records instead.
            # A dns-01 configuration without a token is refused by name.
            persist_config = root / "certbot-persist.toml"
            write_config(
                persist_config,
                workdir,
                acme_url,
                api_url,
                domain,
                "true",
                domains=wildcard_names,
                challenge="dns-persist-01",
                cf_api_token="",
            )
            with state.lock:
                persist_baseline = len(state.operations)
            persist_records = run_subcommand(binary, "dns-records", persist_config)
            with state.lock:
                persist_operations = len(state.operations) - persist_baseline
            record_lines = persist_records.stdout.splitlines()
            checks["dns_persist_records_printed"] = (
                persist_records.returncode == 0
                and persist_operations == 0
                and any(
                    line.startswith(f"_validation-persist.{domain}. IN TXT ")
                    and "accounturi=" in line
                    and "policy=wildcard" in line
                    for line in record_lines
                )
                and sum(
                    line.startswith(f"{domain}. IN CAA ")
                    and "validationmethods=dns-persist-01" in line
                    for line in record_lines
                )
                == 2
            )
            tokenless_config = root / "certbot-tokenless.toml"
            write_config(
                tokenless_config,
                workdir,
                acme_url,
                api_url,
                domain,
                "true",
                cf_api_token="",
            )
            tokenless = run_subcommand(binary, "dns-records", tokenless_config)
            checks["dns01_without_token_rejected"] = (
                tokenless.returncode != 0
                and "cf_api_token is required" in tokenless.stderr
            )
            checks["records_and_adjacent_clean"] = checks[
                "records_and_adjacent_clean"
            ] and all(not records for records in state.snapshot().values())
            status = "PASS" if all(checks.values()) else "FAIL"
            summary = (
                "Certbot CLI once, owner-only keys, atomic live pair, key rotation, hook and hung-hook bound, daemon pacing, graceful SIGTERM (steady state and startup), malformed config, persisted restart, outage, recovery, domain-change reissue, name-plus-wildcard challenges, dns-persist-01 records, and cleanup passed."
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
