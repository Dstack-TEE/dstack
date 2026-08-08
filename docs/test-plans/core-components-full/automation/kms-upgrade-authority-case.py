#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise KMS upgrade authority routing and allow-any-upgrade semantics."""

from __future__ import annotations

import json
import os
import signal
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

CASE_ID = "tc-kms-attestatio-004"


def tls_context(identity: dict[str, str] | None) -> ssl.SSLContext:
    """Build the case-owned attested client context."""
    value = ssl.create_default_context()
    value.check_hostname = False
    value.verify_mode = ssl.CERT_NONE
    if identity:
        value.load_cert_chain(identity["cert"], identity["key"])
    return value


def call(
    url: str, method: str, body: dict[str, Any], identity: dict[str, str]
) -> tuple[int, bytes]:
    """Call one KMS JSON pRPC method."""
    request = urllib.request.Request(
        f"{url}/{method}?json",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(
            request, context=tls_context(identity), timeout=20
        ) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def stop(pid: int) -> None:
    """Stop one lease-owned KMS process."""
    if not Path(f"/proc/{pid}").exists():
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline and Path(f"/proc/{pid}").exists():
        time.sleep(0.1)
    if Path(f"/proc/{pid}").exists():
        os.kill(pid, signal.SIGKILL)


def start(
    binary: str, config: Path, socket_path: str, log: Path
) -> subprocess.Popen[bytes]:
    """Start a replacement KMS using the retained simulator and certificates."""
    output = log.open("ab")
    return subprocess.Popen(
        [binary, "--config", str(config)],
        env={**os.environ, "DSTACK_AGENT_ADDRESS": f"unix:{socket_path}"},
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def wait_rpc(url: str) -> dict[str, Any]:
    """Wait for KMS GetMeta and return its payload."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            code, raw = call(url, "KMS.GetMeta", {}, None)
            if code == 200:
                return json.loads(raw)
        except OSError:
            pass
        time.sleep(0.2)
    raise TimeoutError("replacement KMS did not become ready")


class Authority:
    """Mutable deterministic webhook state and captured requests."""

    def __init__(self) -> None:
        """Initialize an allowing authority with an empty request log."""
        self.allowed = True
        self.requests: list[dict[str, Any]] = []


def start_authority(state: Authority) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Start a local authorization webhook on an ephemeral port."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def send_json(self, value: dict[str, Any], status: int = 200) -> None:
            raw = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            self.send_json(
                {
                    "status": "ok",
                    "kmsContractAddr": "0x" + "11" * 20,
                    "ethRpcUrl": "http://127.0.0.1:18545",
                    "gatewayAppId": "gateway-authority-test",
                    "chainId": 31337,
                    "appImplementation": "0x" + "22" * 20,
                }
            )

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length", "0"))
            request = json.loads(self.rfile.read(length))
            state.requests.append(request)
            self.send_json(
                {
                    "isAllowed": state.allowed,
                    "reason": "" if state.allowed else "authority policy denied",
                    "gatewayAppId": "gateway-authority-test",
                }
            )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def main() -> int:
    """Verify dev/webhook selection, decision changes, hashes, recovery, and cleanup."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    case = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    values = case["values"]
    kms = values["kms"]
    identity = values["kms_attested_client"]
    config = Path(kms["config"])
    original_config = config.read_text()
    url = str(kms["rpc_prpc_url"])
    app_body = {"api_version": 1, "vm_config": str(identity["vm_config"])}
    binary = str(runtime["prepared_binaries"]["dstack_kms"]["path"])
    socket_path = str(
        values["kms_guest_simulator"]["services"]["DstackGuest"]["socket"]
    )
    authority = Authority()
    server, thread = start_authority(authority)
    replacement: subprocess.Popen[bytes] | None = None
    rows: list[dict[str, Any]] = []
    status = "FAIL"
    failure = ""
    try:
        dev = wait_rpc(url)
        if dev.get("allow_any_upgrade") is not True or dev.get("is_dev") is not True:
            raise AssertionError(
                "development mode did not explicitly advertise unrestricted upgrade"
            )
        rows.append({"name": "dev_selector", "status": "PASS"})

        stop(int(kms["pid"]))
        webhook = original_config.replace('type = "dev"', 'type = "webhook"', 1)
        webhook += f'\n[core.auth_api.webhook]\nurl = "http://127.0.0.1:{server.server_port}"\n'
        config.write_text(webhook)
        replacement = start(
            binary, config, socket_path, artifacts / "kms-upgrade-authority.log"
        )
        production = wait_rpc(url)
        expected_meta = {
            "allow_any_upgrade": False,
            "is_dev": False,
            "kms_contract_address": "0x" + "11" * 20,
            "chain_id": 31337,
            "gateway_app_id": "gateway-authority-test",
            "app_auth_implementation": "0x" + "22" * 20,
        }
        if any(production.get(key) != value for key, value in expected_meta.items()):
            raise AssertionError(f"webhook metadata mismatch: {production}")
        rows.append({"name": "production_selector_metadata", "status": "PASS"})

        allow_code, allow_raw = call(url, "KMS.GetAppKey", app_body, identity)
        if allow_code != 200 or not allow_raw or not authority.requests:
            raise AssertionError(
                "authority allow decision did not authorize the attested request"
            )
        observed = authority.requests[-1]
        required_hashes = (
            "mrAggregated",
            "osImageHash",
            "appId",
            "composeHash",
            "deviceId",
        )
        if any(not observed.get(name) for name in required_hashes):
            raise AssertionError("authority request omitted measured identity fields")
        authority.allowed = False
        deny_code, _ = call(url, "KMS.GetAppKey", app_body, identity)
        if deny_code < 400:
            raise AssertionError("authority deny decision did not fail closed")
        authority.allowed = True
        recovery_code, recovery_raw = call(url, "KMS.GetAppKey", app_body, identity)
        if recovery_code != 200 or recovery_raw != allow_raw:
            raise AssertionError(
                "authority recovery changed stable application identity"
            )
        rows.append(
            {
                "name": "allow_deny_recovery",
                "status": "PASS",
                "allow_status": allow_code,
                "deny_status": deny_code,
                "recovery_status": recovery_code,
                "captured_fields": sorted(observed),
            }
        )
        log = (artifacts / "kms-upgrade-authority.log").read_text(errors="replace")
        key_text = Path(identity["key"]).read_text()
        if key_text in log or "AUTHORITY_SECRET_SENTINEL" in log:
            raise AssertionError("authority lifecycle log disclosed private material")
        rows.append({"name": "redaction_cleanup", "status": "PASS"})
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        rows.append({"name": "failure", "status": "FAIL", "diagnostic": failure})
    finally:
        config.write_text(original_config)
        if replacement is not None:
            stop(replacement.pid)
            try:
                replacement.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(replacement.pid, signal.SIGKILL)
                replacement.wait(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    evidence = artifacts / "kms-upgrade-authority.json"
    evidence.write_text(json.dumps({"rows": rows}, indent=2) + "\n")
    artifact = {
        "path": "artifacts/kms-upgrade-authority.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "KMS upgrade authority matrix",
        "description": "Dev/webhook selector, measured request routing, allow/deny recovery, metadata, and redaction evidence.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = "4/4 upgrade-authority groups passed" if status == "PASS" else failure
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
        "artifacts": [artifact],
        "remarks": "Mock-TDX evidence exercises functional authority routing without claiming physical quote origin.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
