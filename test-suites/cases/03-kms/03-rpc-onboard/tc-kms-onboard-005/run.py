#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Exercise KMS root-key handover on the admin listener (PR #1307).

The source KMS is restarted with `[core.admin.tls]` and
`core.onboard.public_key_handover = false`. `Admin.GetKmsKey` must then need
both the admin bearer token and an attested RA-TLS client certificate, the
public `KMS.GetKmsKey` must refuse, and a fresh target must onboard through the
admin listener with `source_token`.
"""

from __future__ import annotations

import hashlib
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
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-kms-onboard-005"
PUBLIC_DISABLED = "public KMS key handover is disabled; use the admin listener"
ROOT_FILES = ("root-ca.key", "root-k256.key")


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def tls_context(identity: dict[str, Any] | None) -> ssl.SSLContext:
    """Create a test TLS context, optionally presenting the attested client."""
    value = ssl.create_default_context()
    value.check_hostname = False
    value.verify_mode = ssl.CERT_NONE
    if identity:
        value.load_cert_chain(str(identity["cert"]), str(identity["key"]))
    return value


def call(
    url: str,
    method: str,
    body: dict[str, Any],
    *,
    identity: dict[str, Any] | None = None,
    token: str = "",
) -> tuple[int, bytes]:
    """Invoke one JSON pRPC method and keep the native body in memory."""
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{url}/{method}?json",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers=headers,
        method="POST",
    )
    context = tls_context(identity) if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(request, context=context, timeout=90) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()
    except (urllib.error.URLError, OSError) as error:
        return 0, str(error).encode()


def diagnostic(raw: bytes) -> str:
    """Return a bounded diagnostic with token-like material removed."""
    text = raw.decode("utf-8", errors="replace")
    return re.sub(r"[A-Za-z0-9_+/=-]{48,}", "<redacted>", text)[:400]


def key_fingerprint(raw: bytes) -> str:
    """Hash the returned root key set without persisting it."""
    keys = json.loads(raw).get("keys")
    if not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict):
        raise AssertionError("GetKmsKey did not return exactly one key entry")
    entry = keys[0]
    if not entry.get("ca_key") or not entry.get("k256_key"):
        raise AssertionError("GetKmsKey key entry omitted private fields")
    return hashlib.sha256(f"{entry['ca_key']}:{entry['k256_key']}".encode()).hexdigest()


def port_of(url: str) -> int:
    """Return the TCP port of an http(s) URL."""
    return int(url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[1])


def wait_port(port: int, process: subprocess.Popen[bytes]) -> None:
    """Wait until a lease-owned KMS listener accepts connections."""
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


def stop(pid: int) -> None:
    """Stop one lease-owned KMS process."""
    if not pathlib.Path(f"/proc/{pid}").exists():
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline and pathlib.Path(f"/proc/{pid}").exists():
        time.sleep(0.1)
    if pathlib.Path(f"/proc/{pid}").exists():
        os.kill(pid, signal.SIGKILL)


def start(
    binary: str, config: pathlib.Path, agent_socket: str, log: pathlib.Path
) -> subprocess.Popen[bytes]:
    """Start a lease-owned KMS against the retained guest simulator."""
    output = log.open("ab")
    return subprocess.Popen(
        [binary, "--config", str(config)],
        env={**os.environ, "DSTACK_AGENT_ADDRESS": f"unix:{agent_socket}"},
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def root_keys(directory: pathlib.Path) -> list[str]:
    """List the root key files present, without reading them."""
    return [name for name in ROOT_FILES if (directory / name).is_file()]


def emit(step: str, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step."""
    print(f"STEP {step} START", flush=True)
    print(f"EVIDENCE {step} - {observed}", flush=True)
    print(f"STEP {step} END - {status}", flush=True)
    return {"id": step, "status": status, "observed": observed}


def main() -> int:
    """Run the admin-listener handover matrix."""
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
    identity = values["kms_attested_client"]
    onboard = values["kms_onboard"]
    ports = values["component_substrate"]["ports"]
    binary = str(runtime["prepared_binaries"]["dstack_kms"]["path"])
    agent_socket = str(
        values["kms_guest_simulator"]["services"]["DstackGuest"]["socket"]
    )
    source_config = pathlib.Path(kms["config"])
    source_cert_dir = pathlib.Path(kms["cert_dir"])
    public_url = str(kms["rpc_prpc_url"])
    admin_url = str(kms["admin_url"]).replace("http://", "https://", 1)
    token = pathlib.Path(kms["admin_auth_token_file"]).read_text().strip()
    request = {"vm_config": str(identity["vm_config"])}
    workspace = pathlib.Path(values["component_substrate"]["workspace"])
    original_config = source_config.read_text()
    processes: list[subprocess.Popen[bytes]] = []
    rows: dict[str, dict[str, Any]] = {}
    steps: list[dict[str, str]] = []
    failure = ""

    def row(name: str, ok: bool, **observed: Any) -> None:
        rows[name] = {"passed": bool(ok), **observed}

    try:
        code, raw = call(public_url, "KMS.GetKmsKey", request, identity=identity)
        if code != 200:
            raise AssertionError(f"baseline public GetKmsKey returned HTTP {code}")
        baseline = key_fingerprint(raw)
        meta_code, meta_raw = call(public_url, "KMS.GetMeta", {})
        source_pubkey = (
            json.loads(meta_raw).get("k256_pubkey") if meta_code == 200 else ""
        )
        if not source_pubkey:
            raise AssertionError("source GetMeta omitted k256_pubkey")
        row("public_handover_default_on", True, status=code)
        steps.append(
            emit(
                f"{CASE_ID}-step-01",
                "PASS",
                "With the default public_key_handover the attested client received the current root key on the public listener.",
            )
        )

        stop(int(kms["pid"]))
        hardened = original_config.replace(
            "[core.onboard]\n", "[core.onboard]\npublic_key_handover = false\n", 1
        )
        hardened += (
            f'\n[core.admin.tls]\nkey = "{source_cert_dir / "rpc.key"}"\n'
            f'certs = "{source_cert_dir / "rpc.crt"}"\n'
        )
        if "public_key_handover = false" not in hardened:
            raise RuntimeError("source config has no [core.onboard] section")
        source_config.write_text(hardened)
        source = start(
            binary, source_config, agent_socket, artifacts / "source-kms-hardened.log"
        )
        processes.append(source)
        wait_port(port_of(public_url), source)
        wait_port(port_of(admin_url), source)

        code, raw = call(public_url, "KMS.GetKmsKey", request, identity=identity)
        row(
            "public_handover_disabled",
            code >= 400 and PUBLIC_DISABLED in raw.decode(errors="replace"),
            status=code,
            error=diagnostic(raw),
        )
        code, raw = call(
            admin_url, "Admin.GetKmsKey", request, identity=identity, token=token
        )
        row(
            "admin_cert_and_token",
            code == 200 and key_fingerprint(raw) == baseline,
            status=code,
            same_root_key=code == 200 and key_fingerprint(raw) == baseline,
            error="" if code == 200 else diagnostic(raw),
        )
        code, raw = call(admin_url, "Admin.GetKmsKey", request, token=token)
        row("admin_token_without_cert", code >= 400, status=code, error=diagnostic(raw))
        code, raw = call(admin_url, "Admin.GetKmsKey", request, identity=identity)
        row("admin_cert_without_token", code == 401, status=code)
        code, raw = call(
            admin_url,
            "Admin.ClearImageCache",
            {"image_hash": "", "config_hash": ""},
            token=token,
        )
        row(
            "admin_other_rpc_without_cert",
            code == 200,
            status=code,
            error="" if code == 200 else diagnostic(raw),
        )
        step2 = all(
            rows[name]["passed"]
            for name in (
                "public_handover_disabled",
                "admin_cert_and_token",
                "admin_token_without_cert",
                "admin_cert_without_token",
                "admin_other_rpc_without_cert",
            )
        )
        steps.append(
            emit(
                f"{CASE_ID}-step-02",
                "PASS" if step2 else "FAIL",
                "Public GetKmsKey refused; Admin.GetKmsKey returned the same root key only with both the bearer token and an attested client certificate; ClearImageCache needed no client certificate."
                if step2
                else f"admin handover rows: { {k: v['passed'] for k, v in rows.items()} }",
            )
        )

        target_template = pathlib.Path(onboard["config"]).read_text()
        target_cert_dir = pathlib.Path(onboard["cert_dir"])
        cert_dir = workspace / "data/admin-handover-target-certs"
        cert_dir.mkdir()
        target_ports = {
            "rpc": port_of(onboard["target_rpc_url"]),
            "onboard": port_of(onboard["prpc_url"]),
        }
        target_text = target_template.replace(str(target_cert_dir), str(cert_dir))
        target_text = re.sub(
            r"(?m)^port = (\d+)$",
            lambda match: "port = "
            + str(
                {
                    target_ports["rpc"]: ports["verifier"],
                    target_ports["onboard"]: ports["aux4"],
                }.get(int(match.group(1)), ports["vmm"])
            ),
            target_text,
        )
        target_config = workspace / "config/admin-handover-target-kms.toml"
        target_config.write_text(target_text)
        target = start(
            binary, target_config, agent_socket, artifacts / "target-kms.log"
        )
        processes.append(target)
        wait_port(ports["aux4"], target)
        target_url = f"http://127.0.0.1:{ports['aux4']}/prpc"
        domain = f"{manifest['lease_id']}.admin-onboard.test"

        code, raw = call(
            target_url, "Onboard.Onboard", {"source_url": public_url, "domain": domain}
        )
        row(
            "onboard_via_public_refused",
            code >= 400
            and PUBLIC_DISABLED in raw.decode(errors="replace")
            and not root_keys(cert_dir),
            status=code,
            error=diagnostic(raw),
        )
        code, raw = call(
            target_url, "Onboard.Onboard", {"source_url": admin_url, "domain": domain}
        )
        row(
            "onboard_via_admin_without_token_refused",
            code >= 400 and not root_keys(cert_dir),
            status=code,
            error=diagnostic(raw),
        )
        code, raw = call(
            target_url,
            "Onboard.Onboard",
            {"source_url": admin_url, "domain": domain, "source_token": token},
        )
        inherited = json.loads(raw).get("k256_pubkey") if code == 200 else ""
        row(
            "onboard_via_admin_with_token",
            code == 200
            and inherited == source_pubkey
            and sorted(root_keys(cert_dir)) == sorted(ROOT_FILES),
            status=code,
            same_public_key=inherited == source_pubkey,
            error="" if code == 200 else diagnostic(raw),
        )
        step3 = all(
            rows[name]["passed"]
            for name in (
                "onboard_via_public_refused",
                "onboard_via_admin_without_token_refused",
                "onboard_via_admin_with_token",
            )
        )
        steps.append(
            emit(
                f"{CASE_ID}-step-03",
                "PASS" if step3 else "FAIL",
                "A fresh target could not onboard through the disabled public route or without the token, and onboarded through the admin listener with source_token, inheriting the source k256 key."
                if step3
                else "admin-listener onboarding rows: "
                + json.dumps(
                    {
                        name: {
                            "status": rows[name]["status"],
                            "error": rows[name]["error"],
                        }
                        for name in (
                            "onboard_via_public_refused",
                            "onboard_via_admin_without_token_refused",
                            "onboard_via_admin_with_token",
                        )
                        if not rows[name]["passed"]
                    }
                ),
            )
        )
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        steps.append(emit(f"{CASE_ID}-step-{len(steps) + 1:02d}", "FAIL", failure))
    finally:
        for process in processes:
            stop(process.pid)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        source_config.write_text(original_config)

    token_leaked = any(
        token in path.read_text(errors="replace") for path in artifacts.glob("*.log")
    )
    status = (
        "PASS"
        if not failure
        and not token_leaked
        and len(steps) == 3
        and all(step["status"] == "PASS" for step in steps)
        else "FAIL"
    )
    artifact = {
        "path": "artifacts/kms-admin-handover.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "KMS admin-listener key handover matrix",
        "description": "Status codes, bounded redacted errors, root-key fingerprint equality, and public-key equality; no key material or token.",
    }
    atomic_json(
        result_dir / artifact["path"],
        {"rows": rows, "token_in_logs": token_leaked, "native_keys_persisted": False},
    )
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": "Admin-listener KMS key handover and onboarding passed."
        if status == "PASS"
        else failure
        or "admin-listener handover failed: "
        + ", ".join(name for name, value in rows.items() if not value["passed"]),
        "steps": steps,
        "artifacts": [artifact],
        "remarks": "Simulated TDX attestation; the source KMS is restarted with admin TLS and public handover disabled, and a third lease-owned target is onboarded.",
    }
    if status != "PASS":
        result["failure"] = result["summary"]
    atomic_json(result_dir / "result.json", result)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
