#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Exercise the KMS listeners, the public listener and the PROXY protocol.

A second candidate KMS runs from a copy of the fixture KMS's config and keys,
with `[listeners.default] proxy_protocol = true`, the admin listener overriding
it, and the public listener enabled (#1580, #1582, #1583, #1585).
"""

from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-kms-kms-007"
APP_ID = "11" * 20
GUEST_SOURCE = "203.0.113.7"
PUBLIC_SOURCE = "198.51.100.4"
NOT_PUBLIC = (
    "/prpc/GetAppKey",
    "/prpc/SignCert",
    "/prpc/GetTempCaCert",
    "/prpc/GetKmsKey",
    "/prpc/ClearImageCache",
    "/prpc/KMS.GetMeta",
)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def proxy_v1(source: str, port: int) -> bytes:
    """Build a PROXY protocol v1 header from `source`."""
    return f"PROXY TCP4 {source} 127.0.0.1 40000 {port}\r\n".encode()


def proxy_v2(source: str, port: int) -> bytes:
    """Build a PROXY protocol v2 PROXY/TCP4 header from `source`."""
    addresses = (
        ipaddress.IPv4Address(source).packed
        + ipaddress.IPv4Address("127.0.0.1").packed
        + struct.pack("!HH", 40000, port)
    )
    return (
        b"\r\n\r\n\x00\r\nQUIT\n\x21\x11"
        + struct.pack("!H", len(addresses))
        + addresses
    )


def request(
    port: int,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    header: bytes = b"",
    token: str = "",
) -> tuple[int, dict[str, str], bytes]:
    """Send one HTTPS request, optionally after a PROXY header. 0 if not served."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
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
        lines.append(f"Authorization: Bearer {token}")
    raw = b""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as plain:
            if header:
                plain.sendall(header)
            with context.wrap_socket(plain, server_hostname="localhost") as tls:
                tls.sendall("\r\n".join(lines).encode() + b"\r\n\r\n" + payload)
                while chunk := tls.recv(65536):
                    raw += chunk
    except (OSError, ssl.SSLError):
        pass
    head, _, content = raw.partition(b"\r\n\r\n")
    status = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    if not status:
        return 0, {}, b""
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.decode(errors="replace").partition(":")
        headers[name.strip().lower()] = value.strip()
    if headers.get("transfer-encoding") == "chunked":
        content = dechunk(content)
    return int(status.group(1)), headers, content


def dechunk(data: bytes) -> bytes:
    """Decode a chunked HTTP body."""
    out = b""
    while data:
        size, _, rest = data.partition(b"\r\n")
        length = int(size.split(b";")[0], 16)
        if not length:
            break
        out += rest[:length]
        data = rest[length + 2 :]
    return out


def rpc(port: int, method: str, body: dict[str, Any], **kwargs: Any) -> tuple[int, Any]:
    """Call one JSON pRPC method."""
    code, _, raw = request(port, f"/prpc/{method}?json", body=body, **kwargs)
    try:
        return code, json.loads(raw) if code == 200 else raw.decode(errors="replace")
    except json.JSONDecodeError:
        return code, raw.decode(errors="replace")


def wait_port(port: int, process: subprocess.Popen[bytes]) -> None:
    """Wait until a lease-owned listener accepts TCP connections."""
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"KMS exited early with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"KMS listener {port} did not become ready")


def start(
    binary: str, config: pathlib.Path, agent: str, log: pathlib.Path
) -> subprocess.Popen[bytes]:
    """Start a lease-owned KMS against the fixture's guest simulator."""
    with log.open("ab") as output:
        return subprocess.Popen(
            [binary, "--config", str(config)],
            env={
                **os.environ,
                "DSTACK_AGENT_ADDRESS": f"unix:{agent}",
                "RUST_LOG": "info",
            },
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )


def stop(process: subprocess.Popen[bytes]) -> None:
    """Stop a lease-owned KMS."""
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def refused(binary: str, config: pathlib.Path, agent: str) -> str:
    """Run a KMS that must refuse its config; return its output if it did."""
    completed = subprocess.run(
        [binary, "--config", str(config)],
        env={**os.environ, "DSTACK_AGENT_ADDRESS": f"unix:{agent}"},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    return completed.stdout.decode(errors="replace") if completed.returncode else ""


def emit(step: str, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step."""
    print(f"STEP {step} START", flush=True)
    print(f"EVIDENCE {step} - {observed}", flush=True)
    print(f"STEP {step} END - {status}", flush=True)
    return {"id": step, "status": status, "observed": observed}


def main() -> int:
    """Run the KMS listener matrix."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    kms = values["kms"]
    ports = values["component_substrate"]["ports"]
    workspace = pathlib.Path(values["component_substrate"]["workspace"])
    binary = str(runtime["prepared_binaries"]["dstack_kms"]["path"])
    agent = str(values["kms_guest_simulator"]["services"]["DstackGuest"]["socket"])
    token = pathlib.Path(kms["admin_auth_token_file"]).read_text().strip()
    source_text = pathlib.Path(kms["config"]).read_text()
    source_certs = re.search(r'(?m)^cert_dir = "([^"]+)"$', source_text).group(1)
    guest, admin, public, onboard = (
        ports["kms"],
        ports["onboard"],
        ports["debug"],
        ports["vmm"],
    )
    certs = workspace / "data/tc-kms-kms-007-certs"
    config = workspace / "config/tc-kms-kms-007.toml"
    log = artifacts / "listener-kms.log"
    rows: dict[str, dict[str, Any]] = {}
    steps: list[dict[str, str]] = []
    process: subprocess.Popen[bytes] | None = None

    def row(name: str, ok: bool, **observed: Any) -> bool:
        rows[name] = {"passed": bool(ok), **observed}
        return bool(ok)

    def step(number: int, names: list[str], observed: str) -> None:
        ok = all(rows[name]["passed"] for name in names)
        failed = [name for name in names if not rows[name]["passed"]]
        steps.append(
            emit(
                f"{CASE_ID}-step-{number:02d}",
                "PASS" if ok else "FAIL",
                observed if ok else f"failing rows: {', '.join(failed)}",
            )
        )

    try:
        shutil.copytree(source_certs, certs)
        source_ports = [
            int(port) for port in re.findall(r"(?m)^port = (\d+)$", source_text)
        ]
        mapping = dict(zip(source_ports, (guest, admin, onboard), strict=True))
        text = re.sub(
            r"(?m)^port = (\d+)$",
            lambda m: f"port = {mapping[int(m.group(1))]}",
            source_text,
        ).replace(source_certs, str(certs))
        if text.count("[listeners.admin]\n") != 1:
            raise RuntimeError("fixture config has no single [listeners.admin] section")
        text = text.replace(
            "[listeners.admin]\n", "[listeners.admin]\nproxy_protocol = false\n"
        )
        text += (
            "\n[listeners.default]\nproxy_protocol = true\n"
            f'[listeners.public]\nenabled = true\naddress = "127.0.0.1"\nport = {public}\n'
        )
        config.write_text(text)
        config.chmod(0o600)
        process = start(binary, config, agent, log)
        for port in (guest, admin, public):
            wait_port(port, process)

        code, _, _ = request(guest, "/prpc/KMS.GetMeta?json", body={})
        row("guest_without_header_dropped", code == 0, status=code)
        code, headers, raw = request(
            guest,
            "/prpc/KMS.GetMeta?json",
            body={},
            header=proxy_v1(GUEST_SOURCE, guest),
        )
        guest_meta = json.loads(raw) if code == 200 else {}
        row(
            "guest_with_v1_header",
            code == 200 and guest_meta.get("ca_cert"),
            status=code,
        )
        row(
            "server_header",
            headers.get("server") == "DStack KMS",
            server=headers.get("server"),
        )
        step(
            2,
            ["guest_without_header_dropped", "guest_with_v1_header", "server_header"],
            "The guest listener dropped a connection without a PROXY header and served one with a v1 header, as DStack KMS.",
        )

        public_header = proxy_v2(PUBLIC_SOURCE, public)
        guest_header = proxy_v1(GUEST_SOURCE, guest)
        # Clients call the public listener at the same /prpc/<Method> paths.
        code, meta = rpc(public, "GetMeta", {}, header=public_header)
        row(
            "public_get_meta",
            code == 200
            and meta.get("ca_cert") == guest_meta.get("ca_cert")
            and meta.get("k256_pubkey") == guest_meta.get("k256_pubkey"),
            status=code,
        )
        for method, field in (
            ("GetAppEnvEncryptPubKey", "public_key"),
            ("GetSealedEnvPubKey", "public_key"),
        ):
            pcode, presult = rpc(
                public, method, {"app_id": APP_ID}, header=public_header
            )
            gcode, gresult = rpc(
                guest, f"KMS.{method}", {"app_id": APP_ID}, header=guest_header
            )
            row(
                f"public_{method}",
                pcode == 200
                and gcode == 200
                and presult.get(field)
                and presult.get(field) == gresult.get(field),
                public_status=pcode,
                guest_status=gcode,
            )
        code, _, raw = request(public, "/health", header=public_header)
        row("public_health", code == 200, status=code)
        for path in NOT_PUBLIC:
            code, _, raw = request(
                public, f"{path}?json", body={}, header=public_header
            )
            row(
                f"public_refuses_{path.rsplit('/', 1)[1].replace('.', '_')}",
                code == 404,
                status=code,
            )
        code, _, _ = request(public, "/metrics", header=public_header)
        row("public_has_no_metrics", code == 404, status=code)
        step3 = [name for name in rows if name.startswith("public_")]
        step(
            3,
            step3,
            "The public listener served only GetMeta, both env public keys and /health, with the guest listener's keys, and 404 for every other RPC and /metrics.",
        )

        code, _ = rpc(
            admin,
            "Admin.ClearImageCache",
            {"image_hash": "", "config_hash": ""},
            token=token,
        )
        row("admin_override_without_header", code == 200, status=code)
        code, _ = rpc(
            admin,
            "Admin.ClearImageCache",
            {"image_hash": "", "config_hash": ""},
            token=token,
            header=proxy_v1(GUEST_SOURCE, admin),
        )
        row("admin_override_rejects_header", code == 0, status=code)
        step(
            4,
            ["admin_override_without_header", "admin_override_rejects_header"],
            "The admin listener, overriding proxy_protocol = false, served without a header and failed a connection that sent one.",
        )

        time.sleep(1)
        logged = log.read_text(errors="replace")
        audit = [
            line
            for line in logged.splitlines()
            if "dstack_kms::audit" in line and "env public key served" in line
        ]
        row(
            "remote_from_v1_header",
            re.search(rf"remote={re.escape(GUEST_SOURCE)}:40000", logged) is not None,
        )
        row(
            "remote_from_v2_header",
            re.search(rf"remote={re.escape(PUBLIC_SOURCE)}:40000", logged) is not None,
        )
        row(
            "audit_env_pubkey_remote",
            sum(PUBLIC_SOURCE in line for line in audit) >= 2
            and sum(GUEST_SOURCE in line for line in audit) >= 2,
            audit_lines=len(audit),
        )
        step(
            5,
            [
                "remote_from_v1_header",
                "remote_from_v2_header",
                "audit_env_pubkey_remote",
            ],
            "Request logs and the env public key audit lines carried the PROXY source address as remote.",
        )
        stop(process)
        process = None

        for name, extra, expected in (
            ("refuses_rpc", "\n[rpc]\nport = 1\n", "rpc -> listeners.guest"),
            (
                "refuses_core_admin",
                "\n[core.admin]\nenabled = true\n",
                "core.admin -> listeners.admin",
            ),
            (
                "refuses_top_level_rocket_setting",
                None,
                "log_level -> listeners.default.log_level",
            ),
        ):
            stale = workspace / f"config/tc-kms-kms-007-{name}.toml"
            stale.write_text(
                f'log_level = "debug"\n{text}' if extra is None else text + extra
            )
            output = refused(binary, stale, agent)
            row(name, expected in output, output=output[-300:])
            stale.unlink()
        step(
            6,
            ["refuses_rpc", "refuses_core_admin", "refuses_top_level_rocket_setting"],
            "Configs using [rpc], [core.admin] and a top-level log_level were refused, naming their new locations.",
        )
    except Exception as error:  # noqa: BLE001 - every failure is reported as the case result.
        steps.append(
            emit(f"{CASE_ID}-step-error", "FAIL", f"{type(error).__name__}: {error}")
        )
    finally:
        if process is not None:
            stop(process)
        shutil.rmtree(certs, ignore_errors=True)
        config.unlink(missing_ok=True)

    status = (
        "PASS"
        if steps and all(s["status"] == "PASS" for s in steps) and len(steps) == 5
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
            "summary": f"{sum(r['passed'] for r in rows.values())}/{len(rows)} KMS listener rows passed",
            "steps": steps,
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
