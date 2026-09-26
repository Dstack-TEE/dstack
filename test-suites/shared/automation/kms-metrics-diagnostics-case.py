#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify KMS metadata, counters, backend diagnostics, recovery, and redaction."""

from __future__ import annotations

import concurrent.futures
import http.server
import json
import os
import signal
import socket as socketlib
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import tomllib

SUPPORTED_CASES = {"tc-kms-keys-certs-008", "tc-kms-release-010", "tc-kms-apiver-011"}


def context(identity: dict[str, str] | None) -> ssl.SSLContext:
    """Build the case-owned client context."""
    value = ssl.create_default_context()
    value.check_hostname = False
    value.verify_mode = ssl.CERT_NONE
    if identity:
        value.load_cert_chain(identity["cert"], identity["key"])
    return value


def call(
    url: str, method: str, body: bytes, identity: dict[str, str] | None
) -> tuple[int, bytes]:
    """Call one KMS JSON pRPC and retain its body only in memory."""
    request = urllib.request.Request(
        f"{url}/{method}?json",
        data=body,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(
            request, context=context(identity), timeout=20
        ) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def metrics(url: str) -> tuple[int, int]:
    """Return total and failed attestation counters."""
    with urllib.request.urlopen(url, context=context(None), timeout=20) as response:
        text = response.read().decode()
    values: dict[str, int] = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            name, value = line.split()
            values[name] = int(value)
    return (
        values["dstack_kms_attestation_requests_total"],
        values["dstack_kms_attestation_failures_total"],
    )


def stop(pid: int) -> None:
    """Stop one lease-owned KMS process group."""
    if not Path(f"/proc/{pid}").exists():
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline and Path(f"/proc/{pid}").exists():
        time.sleep(0.1)
    if Path(f"/proc/{pid}").exists():
        os.kill(pid, signal.SIGKILL)


def start(binary: str, config: str, socket: str, log: Path) -> subprocess.Popen[bytes]:
    """Start a replacement KMS against the retained simulator and cert directory."""
    output = log.open("ab")
    return subprocess.Popen(
        [binary, "--config", config],
        env={**os.environ, "DSTACK_AGENT_ADDRESS": f"unix:{socket}"},
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


class AuthInfoHandler(http.server.BaseHTTPRequestHandler):
    """Answer the webhook info route slowly and count every request."""

    protocol_version = "HTTP/1.1"
    requests = 0
    lock = threading.Lock()

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        with AuthInfoHandler.lock:
            AuthInfoHandler.requests += 1
        time.sleep(0.3)
        body = json.dumps(
            {
                "status": "ok",
                "kmsContractAddr": "0x" + "11" * 20,
                "ethRpcUrl": "",
                "gatewayAppId": "0x" + "22" * 20,
                "chainId": 31337,
                "appImplementation": "0x" + "33" * 20,
            }
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def hold_connections(listener: socketlib.socket, held: list[socketlib.socket]) -> None:
    """Accept connections and never answer them."""
    while True:
        try:
            held.append(listener.accept()[0])
        except OSError:
            return


def webhook_config(original: str, url: str, timeout: str) -> str:
    """Point the lease-owned KMS at one webhook authorization backend."""
    return (
        original.replace('type = "dev"', 'type = "webhook"', 1)
        + f'\n[core.auth_api.webhook]\nurl = "{url}"\ntimeout = "{timeout}"\n'
    )


def wait_metrics(url: str) -> tuple[int, int]:
    """Wait until the replacement KMS metrics endpoint is ready."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            return metrics(url)
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("replacement KMS did not become ready")


def main() -> int:
    """Execute success, denial, backend outage, recovery, and redaction rows."""
    case_id = os.environ.get("DSTACK_TEST_CASE_ID", "")
    if case_id not in SUPPORTED_CASES:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    case = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    values = case["values"]
    kms = values["kms"]
    identity = values["kms_attested_client"]
    url = str(kms["rpc_prpc_url"])
    metrics_url = str(kms["metrics_url"])
    vm_config = str(identity["vm_config"])
    app_body = json.dumps({"api_version": 1, "vm_config": vm_config}).encode()
    config_path = Path(kms["config"])
    original_config = config_path.read_text()
    binary = str(runtime["prepared_binaries"]["dstack_kms"]["path"])
    socket = str(values["kms_guest_simulator"]["services"]["DstackGuest"]["socket"])
    replacement: subprocess.Popen[bytes] | None = None
    rows: list[dict[str, object]] = []
    status = "FAIL"
    failure = ""
    try:
        baseline = metrics(metrics_url)
        meta_code, meta_raw = call(url, "KMS.GetMeta", b"{}", identity)
        meta = json.loads(meta_raw) if meta_code == 200 else {}
        required_meta = ("ca_cert", "allow_any_upgrade", "k256_pubkey", "is_dev")
        if meta_code != 200 or any(name not in meta for name in required_meta):
            raise AssertionError("GetMeta omitted documented public fields")
        image_verify = tomllib.loads(original_config)["core"]["image"]["verify"]
        if meta.get("os_image_verification") is not image_verify:
            raise AssertionError(
                f"GetMeta os_image_verification {meta.get('os_image_verification')!r} "
                f"does not match [core.image] verify = {image_verify}"
            )
        disabled_warning = "os image verification is disabled" in Path(
            kms["log"]
        ).read_text(errors="replace")
        if disabled_warning is image_verify:
            raise AssertionError(
                "the startup warning for disabled os image verification does not match the config"
            )
        rows.append(
            {
                "name": "metadata",
                "status": "PASS",
                "field_count": len(meta),
                "os_image_verification": image_verify,
                "disabled_verification_warned": disabled_warning,
            }
        )

        first_code, first_raw = call(url, "KMS.GetAppKey", app_body, identity)
        second_code, second_raw = call(url, "KMS.GetAppKey", app_body, identity)
        if first_code != 200 or second_code != 200 or first_raw != second_raw:
            raise AssertionError("authorized repeated GetAppKey was not stable")
        after_success = metrics(metrics_url)
        if after_success != (baseline[0] + 2, baseline[1]):
            raise AssertionError(
                f"success counters mismatch: {baseline} -> {after_success}"
            )
        unauth_code, _ = call(url, "KMS.GetAppKey", app_body, None)
        malformed_code, _ = call(url, "KMS.GetAppKey", b"{", identity)
        after_denial = metrics(metrics_url)
        if (
            unauth_code < 400
            or malformed_code < 400
            or after_denial
            != (
                after_success[0] + 2,
                after_success[1] + 2,
            )
        ):
            raise AssertionError("denial counters did not track both failures")
        rows.append(
            {
                "name": "success_denial_counters",
                "status": "PASS",
                "baseline": baseline,
                "after_success": after_success,
                "after_denial": after_denial,
            }
        )

        stop(int(kms["pid"]))
        outage_config = original_config.replace('type = "dev"', 'type = "webhook"', 1)
        outage_config += '\n[core.auth_api.webhook]\nurl = "http://127.0.0.1:1"\n'
        config_path.write_text(outage_config)
        replacement = start(
            binary, str(config_path), socket, artifacts / "kms-backend-outage.log"
        )
        outage_baseline = wait_metrics(metrics_url)
        outage_code, _ = call(url, "KMS.GetAppKey", app_body, identity)
        outage_after = metrics(metrics_url)
        if outage_code < 400 or outage_after != (
            outage_baseline[0] + 1,
            outage_baseline[1] + 1,
        ):
            raise AssertionError(
                "backend outage did not fail closed and increment counters"
            )
        stop(replacement.pid)
        replacement.wait(timeout=5)
        replacement = None

        config_path.write_text(original_config)
        replacement = start(
            binary, str(config_path), socket, artifacts / "kms-backend-recovery.log"
        )
        wait_metrics(metrics_url)
        recovery_code, _ = call(url, "KMS.GetAppKey", app_body, identity)
        if recovery_code != 200:
            raise AssertionError("KMS did not recover after restoring auth backend")
        rows.append(
            {
                "name": "backend_outage_recovery",
                "status": "PASS",
                "outage_status": outage_code,
                "recovery_status": recovery_code,
            }
        )

        log_text = Path(kms["log"]).read_text(errors="replace")
        secrets = [
            Path(identity["key"]).read_text(),
            Path(kms["admin_auth_token_file"]).read_text().strip(),
        ]
        if any(secret and secret in log_text for secret in secrets):
            raise AssertionError("KMS log disclosed case-owned credential material")
        rows.append({"name": "redaction", "status": "PASS"})
        if case_id == "tc-kms-keys-certs-008":
            stop(replacement.pid)
            replacement.wait(timeout=5)
            replacement = None
            silent = socketlib.socket()
            silent.bind(("127.0.0.1", 0))
            silent.listen(16)
            held: list[socketlib.socket] = []
            threading.Thread(
                target=hold_connections, args=(silent, held), daemon=True
            ).start()
            config_path.write_text(
                webhook_config(
                    original_config,
                    f"http://127.0.0.1:{silent.getsockname()[1]}",
                    "2s",
                )
            )
            replacement = start(
                binary, str(config_path), socket, artifacts / "kms-silent-backend.log"
            )
            wait_metrics(metrics_url)
            started_at = time.monotonic()
            try:
                silent_code, _ = call(url, "KMS.GetMeta", b"{}", None)
            except OSError as error:
                raise AssertionError(
                    f"GetMeta was held open by a silent auth API: {error}"
                ) from error
            silent_seconds = round(time.monotonic() - started_at, 3)
            silent.close()
            for connection in held:
                connection.close()
            if silent_code < 400 or silent_seconds > 10:
                raise AssertionError(
                    f"silent auth API: GetMeta returned {silent_code} after {silent_seconds}s"
                )
            stop(replacement.pid)
            replacement.wait(timeout=5)
            replacement = None

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), AuthInfoHandler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            config_path.write_text(
                webhook_config(
                    original_config,
                    f"http://127.0.0.1:{server.server_address[1]}",
                    "10s",
                )
            )
            replacement = start(
                binary, str(config_path), socket, artifacts / "kms-shared-info.log"
            )
            wait_metrics(metrics_url)
            AuthInfoHandler.requests = 0
            burst = 16
            with concurrent.futures.ThreadPoolExecutor(max_workers=burst) as pool:
                codes = list(
                    pool.map(
                        lambda _n: call(url, "KMS.GetMeta", b"{}", None)[0],
                        range(burst),
                    )
                )
            burst_requests = AuthInfoHandler.requests
            time.sleep(1.5)
            after_code, _ = call(url, "KMS.GetMeta", b"{}", None)
            refreshed_requests = AuthInfoHandler.requests - burst_requests
            server.shutdown()
            server.server_close()
            if (
                any(code != 200 for code in codes)
                or after_code != 200
                or burst_requests > 2
                or refreshed_requests != 1
            ):
                raise AssertionError(
                    f"auth API info sharing: codes={codes}, burst upstream={burst_requests}, "
                    f"after expiry status={after_code} upstream={refreshed_requests}"
                )
            rows.append(
                {
                    "name": "auth_api_bounds",
                    "status": "PASS",
                    "silent_backend_status": silent_code,
                    "silent_backend_seconds": silent_seconds,
                    "burst_calls": burst,
                    "burst_upstream_requests": burst_requests,
                    "upstream_requests_after_expiry": refreshed_requests,
                }
            )
        if case_id == "tc-kms-release-010":
            gate_tests = subprocess.run(
                [
                    "cargo",
                    "test",
                    "--manifest-path",
                    "dstack/Cargo.toml",
                    "-p",
                    "dstack-kms",
                    "key_release_",
                    "--",
                    "--nocapture",
                ],
                cwd=runtime["repository"],
                env={**os.environ, "CARGO_TARGET_DIR": runtime["cargo_target_dir"]},
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            if gate_tests.returncode or "test result: ok" not in gate_tests.stdout:
                raise AssertionError(
                    f"platform release gate matrix failed: {gate_tests.stdout[-500:]} {gate_tests.stderr[-500:]}"
                )
            missing_gates = [
                name
                for name in (
                    "nitro_enclave_key_release_requires_explicit_enablement",
                    "key_release_gates_do_not_leak_across_platforms",
                )
                if f"{name} ... ok" not in gate_tests.stdout
            ]
            if missing_gates:
                raise AssertionError(
                    f"platform release gate matrix omitted {', '.join(missing_gates)}"
                )
            rows.append(
                {
                    "name": "platform_release_gates",
                    "status": "PASS",
                    "filter": "key_release_",
                    "nitro_enclave_gate_rows": 2,
                    "physical_origin_claimed": False,
                }
            )
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        rows.append({"name": "failure", "status": "FAIL", "diagnostic": failure})
    finally:
        config_path.write_text(original_config)
        if replacement is not None:
            stop(replacement.pid)
            try:
                replacement.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(replacement.pid, signal.SIGKILL)
                replacement.wait(timeout=5)

    evidence_path = artifacts / "kms-metrics-diagnostics.json"
    evidence_path.write_text(json.dumps({"rows": rows}, indent=2) + "\n")
    artifact = {
        "path": "artifacts/kms-metrics-diagnostics.json",
        "step_id": f"{case_id}-step-02",
        "name": "KMS metrics and diagnostics matrix",
        "description": "Sanitized metadata, exact counters, outage/recovery, and redaction evidence.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = (
        "4/4 KMS metrics and diagnostics groups passed" if status == "PASS" else failure
    )
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{case_id}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 4)
        ],
        "artifacts": [artifact],
        "remarks": "Native key responses and credentials were never persisted.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
