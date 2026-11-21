#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Exercise the gateway listener config, PROXY protocol and audit/access lines.

Covers #1582 (PROXY protocol on the gateway's own listeners), #1587 (listener
settings under [listeners.*], old locations refused), #1588 (admin audit) and
#1589 (access log).
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import signal
import socket
import ssl
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-gw-internal-009"
SOURCE = "203.0.113.9"
STALE = (
    (
        "top_level_address",
        'address = "127.0.0.1:1"\n',
        None,
        "address -> listeners.guest.address",
    ),
    ("tls", None, '\n[tls]\nkey = "k"\n', "tls -> listeners.guest.tls"),
    (
        "core_admin",
        None,
        "\n[core.admin]\nenabled = true\n",
        "core.admin -> listeners.admin",
    ),
    (
        "core_debug_localhost_backend",
        None,
        "\n[core.debug]\ninsecure_localhost_backend = true\n",
        "-> core.proxy.insecure_localhost_backend",
    ),
    (
        "top_level_proxy_protocol",
        "proxy_protocol = true\n",
        None,
        "proxy_protocol -> listeners.default.proxy_protocol",
    ),
)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def port_of(url: str) -> int:
    """Return the TCP port of an http(s) URL or host:port address."""
    return int(url.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[1])


def request(
    port: int,
    path: str,
    *,
    tls: bool,
    body: dict[str, Any] | None = None,
    header: bytes = b"",
    token: str = "",
) -> int:
    """Send one HTTP(S) request, optionally after a PROXY header. 0 if not served."""
    payload = b"" if body is None else json.dumps(body).encode()
    lines = [
        f"{'GET' if body is None else 'POST'} {path} HTTP/1.1",
        "Host: localhost",
        "Connection: close",
        f"Content-Length: {len(payload)}",
    ]
    if body is not None:
        lines.append("Content-Type: application/json")
    if token:
        lines.append(f"X-Admin-Token: {token}")
    raw = b""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as plain:
            if header:
                plain.sendall(header)
            stream: socket.socket = plain
            if tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                stream = context.wrap_socket(plain, server_hostname="localhost")
            stream.sendall("\r\n".join(lines).encode() + b"\r\n\r\n" + payload)
            while chunk := stream.recv(65536):
                raw += chunk
    except (OSError, ssl.SSLError):
        pass
    status = re.match(rb"HTTP/1\.[01] (\d{3})", raw)
    return int(status.group(1)) if status else 0


def tls_handshake(address: str, server_name: str) -> bool:
    """Complete one TLS handshake with the proxy listener."""
    host, port = address.rsplit(":", 1)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, int(port)), timeout=5) as plain:
            with context.wrap_socket(plain, server_hostname=server_name) as stream:
                stream.sendall(
                    b"GET / HTTP/1.1\r\nHost: gateway.localhost\r\nConnection: close\r\n\r\n"
                )
                stream.recv(1024)
                return True
    except (OSError, ssl.SSLError):
        return False


def stop_pid(pid: int) -> None:
    """Stop the fixture gateway process."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(100):
        if not pathlib.Path(f"/proc/{pid}").exists():
            return
        time.sleep(0.1)
    os.kill(pid, signal.SIGKILL)


def stop(process: subprocess.Popen[bytes] | None) -> None:
    """Stop a run-owned process group if it is still alive."""
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)


def emit(step: str, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step."""
    print(f"STEP {step} START", flush=True)
    print(f"EVIDENCE {step} - {observed}", flush=True)
    print(f"STEP {step} END - {status}", flush=True)
    return {"id": step, "status": status, "observed": observed}


def main() -> int:
    """Run the gateway listener matrix."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    gateway = values["gateway"]
    binary = str(values["prepared_binaries"]["dstack_gateway"]["path"])
    socket_path = values["gateway_guest_simulator"]["services"]["DstackGuest"]["socket"]
    environment = {
        **os.environ,
        "DSTACK_AGENT_ADDRESS": f"unix:{socket_path}",
        "RUST_LOG": "info",
    }
    workspace = pathlib.Path(values["component_substrate"]["workspace"])
    config_path = pathlib.Path(gateway["config"])
    text = config_path.read_text()
    token = pathlib.Path(gateway["admin_auth_token_file"]).read_text().strip()
    admin = port_of(gateway["admin_url"])
    guest = port_of(gateway["health_url"])
    log = artifacts / "gateway.log"
    rows: dict[str, dict[str, Any]] = {}
    steps: list[dict[str, str]] = []
    restarted: subprocess.Popen[bytes] | None = None

    def row(name: str, ok: bool, **observed: Any) -> None:
        rows[name] = {"passed": bool(ok), **observed}

    def step(number: int, names: list[str], observed: str) -> None:
        failed = [name for name in names if not rows[name]["passed"]]
        steps.append(
            emit(
                f"{CASE_ID}-step-{number:02d}",
                "FAIL" if failed else "PASS",
                f"failing rows: {', '.join(failed)}" if failed else observed,
            )
        )

    try:
        for name, prefix, suffix, expected in STALE:
            stale = workspace / f"config/{CASE_ID}-{name}.toml"
            stale.write_text((prefix or "") + text + (suffix or ""))
            completed = subprocess.run(
                [binary, "--config", str(stale)],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            output = completed.stdout.decode(errors="replace")
            row(
                f"refuses_{name}",
                completed.returncode != 0 and expected in output,
                output=output[-300:],
            )
            stale.unlink()
        step(
            1,
            [f"refuses_{name}" for name, *_ in STALE],
            "Configs using the old listener locations were refused, naming their new locations.",
        )

        if text.count("[listeners.admin]\n") != 1:
            raise RuntimeError("fixture config has no single [listeners.admin] section")
        proxied = workspace / f"config/{CASE_ID}-proxied.toml"
        proxied.write_text(
            text.replace(
                "[listeners.admin]\n", "[listeners.admin]\nproxy_protocol = true\n"
            )
        )
        proxied.chmod(0o600)
        stop_pid(int(gateway["pid"]))
        with log.open("ab") as output:
            restarted = subprocess.Popen(
                [binary, "--config", str(proxied)],
                env=environment,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        deadline = time.monotonic() + 60
        while (
            request(guest, "/health", tls=True) != 200 and time.monotonic() < deadline
        ):
            if restarted.poll() is not None:
                raise RuntimeError(
                    f"restarted gateway exited with {restarted.returncode}"
                )
            time.sleep(0.2)
        row("guest_serves_without_header", request(guest, "/health", tls=True) == 200)
        step(
            2,
            ["guest_serves_without_header"],
            "The gateway restarted with proxy_protocol on its admin listener only; the guest listener served /health without a header.",
        )

        header = f"PROXY TCP4 {SOURCE} 127.0.0.1 40000 {admin}\r\n".encode()
        code = request(
            admin, "/prpc/Admin.Status?json", tls=False, body={}, token=token
        )
        row("admin_without_header_dropped", code == 0, status=code)
        code = request(
            admin,
            "/prpc/Admin.Status?json",
            tls=False,
            body={},
            token=token,
            header=header,
        )
        row("admin_with_header", code == 200, status=code)
        code = request(
            admin,
            "/prpc/Admin.ImportCert?json",
            tls=False,
            body={
                "domain": "localhost",
                "cert_pem": "not a certificate",
                "key_pem": "not a key",
            },
            token=token,
            header=header,
        )
        row("admin_import_refused", code >= 400, status=code)
        step(
            3,
            [
                "admin_without_header_dropped",
                "admin_with_header",
                "admin_import_refused",
            ],
            "The admin listener dropped a connection without a PROXY header, served Admin.Status after one, and refused an unparsable ImportCert.",
        )

        row(
            "proxy_handshake",
            tls_handshake(gateway["proxy_address"], "gateway.localhost"),
        )
        time.sleep(1)
        logged = log.read_text(errors="replace").splitlines()
        audit = [
            line
            for line in logged
            if "dstack_gateway::audit" in line and "import_cert" in line
        ]
        access = [line for line in logged if "dstack_gateway::access" in line]
        row("request_remote", any(f"remote={SOURCE}" in line for line in logged))
        row(
            "admin_audit_remote",
            any(SOURCE in line and "admin refused" in line for line in audit),
            audit_lines=len(audit),
        )
        step(
            4,
            ["request_remote", "admin_audit_remote"],
            "Admin request lines and the import_cert audit line carried the PROXY source address as remote.",
        )
        row(
            "access_line",
            rows["proxy_handshake"]["passed"] and len(access) >= 1,
            access_lines=len(access),
        )
        step(
            5,
            ["proxy_handshake", "access_line"],
            "A TLS connection to the proxy listener wrote a dstack_gateway::access line.",
        )
    except Exception as error:  # noqa: BLE001 - every failure is reported as the case result.
        steps.append(
            emit(f"{CASE_ID}-step-error", "FAIL", f"{type(error).__name__}: {error}")
        )
    finally:
        stop(restarted)

    status = (
        "PASS"
        if len(steps) == 5 and all(s["status"] == "PASS" for s in steps)
        else "FAIL"
    )
    atomic_json(artifacts / "listener-matrix.json", {"status": status, "rows": rows})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": f"{sum(r['passed'] for r in rows.values())}/{len(rows)} gateway listener rows passed",
            "steps": steps,
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
