#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise WaveKV bootstrap convergence and tombstone dominance."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
from typing import Any

CASE_ID = "tc-gw-cluster-ad-001"


def load_support() -> Any:
    """Load bounded Gateway HTTP and atomic artifact helpers."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_bootstrap_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def decoded(body: bytes) -> dict[str, Any]:
    """Decode JSON without retaining native bytes."""
    try:
        return json.loads(body) if body else {}
    except json.JSONDecodeError:
        return {}


def rpc(node: dict[str, Any], token: str | None, method: str, value: dict[str, Any], *, debug: bool = False) -> tuple[int, dict[str, Any]]:
    """Call one bounded Gateway pRPC method."""
    base = str(node["debug_url"] if debug else node["admin_url"]).rstrip("/")
    code, body = SUPPORT.http_call(
        f"{base}/{method}", json.dumps(value).encode(), "application/json", token
    )
    return code, decoded(body)


def domain_present(node: dict[str, Any], token: str, domain: str) -> bool:
    """Return whether a domain appears in the node list."""
    code, body = rpc(node, token, "Admin.ListZtDomains", {})
    if code != 200:
        return False
    return any(
        (row.get("config") or row).get("domain") == domain
        for row in body.get("domains", [])
    )


def instance_present(node: dict[str, Any], instance_id: str) -> bool:
    """Return whether an instance appears in synchronized state."""
    code, body = rpc(node, None, "Debug.GetSyncData", {}, debug=True)
    return code == 200 and any(
        row.get("instance_id") == instance_id for row in body.get("instances", [])
    )


def wait_until(predicate: Any, timeout: float = 15.0) -> bool:
    """Wait for one convergence predicate."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.25)
    return False


def wait_port(address: str) -> bool:
    """Wait for a restarted RPC listener."""
    host, port_text = address.rsplit(":", 1)
    return wait_until(
        lambda: _connectable(host, int(port_text)),
        timeout=10,
    )


def _connectable(host: str, port: int) -> bool:
    """Probe one TCP listener."""
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def stop_process(process: subprocess.Popen[bytes]) -> None:
    """Stop a harness-owned process group."""
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def main() -> int:
    """Run baseline, replication, offline deletion, restart, and tombstone checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest["values"]
    nodes = list(values["gateway_cluster"]["nodes"])
    token = pathlib.Path(values["gateway_cluster"]["admin_auth_token_file"]).read_text().strip()
    suffix = str(manifest["lease_id"])[-10:]
    domain = f"bootstrap-{suffix}.test"
    instance_id = f"bootstrap-{suffix}"
    app_id = f"bootstrap-app-{suffix}"
    restarted: subprocess.Popen[bytes] | None = None
    credential_id: str | None = None
    domain_added = False
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    status = "FAIL"
    summary = "WaveKV bootstrap lifecycle did not complete"
    try:
        statuses = [rpc(node, token, "Admin.Status", {})[1] for node in nodes]
        sync_views = [rpc(node, None, "Debug.GetSyncData", {}, debug=True)[1] for node in nodes]
        ids = [int(row.get("id", 0)) for row in statuses]
        peer_sets = [
            {int(row.get("id", 0)) for row in view.get("peer_addrs", [])}
            for view in sync_views
        ]
        checks["stable_cluster_baseline"] = (
            len(set(ids)) == len(nodes)
            and all(len(view.get("nodes", [])) >= len(nodes) for view in sync_views)
            and all(peers == peer_sets[0] for peers in peer_sets)
        )

        code, body = rpc(
            nodes[0],
            token,
            "Admin.CreateDnsCredential",
            {
                "name": f"bootstrap-{suffix}",
                "provider_type": "cloudflare",
                "cf_api_token": "case-owned-nonsecret-token",
                "set_as_default": False,
                "cf_api_url": "http://127.0.0.1:1/client/v4",
            },
        )
        if code != 200:
            raise AssertionError(f"CreateDnsCredential HTTP {code}")
        credential_id = str(body["id"])
        add_code, _ = rpc(
            nodes[0],
            token,
            "Admin.AddZtDomain",
            {"domain": domain, "dns_cred_id": credential_id, "port": 443, "priority": 1},
        )
        domain_added = add_code == 200
        domain_converged = domain_added and wait_until(
            lambda: all(domain_present(node, token, domain) for node in nodes)
        )

        register_code, _ = rpc(
            nodes[0],
            None,
            "Debug.RegisterCvm",
            {
                "app_id": app_id,
                "instance_id": instance_id,
                "client_public_key": base64.b64encode(os.urandom(32)).decode(),
            },
            debug=True,
        )
        instance_converged = register_code == 200 and wait_until(
            lambda: all(instance_present(node, instance_id) for node in nodes),
            timeout=3,
        )
        cert_views = [
            rpc(node, token, "Admin.ListCertAttestations", {"domain": domain})
            for node in nodes
        ]
        checks["state_converged"] = (
            domain_converged
            and instance_converged
            and all(code == 200 and not body.get("attestations", []) for code, body in cert_views)
        )

        stale_status = statuses[-1]
        os.killpg(int(nodes[-1]["pid"]), signal.SIGTERM)
        wait_until(lambda: not _connectable(*_host_port(nodes[-1]["rpc_url"])), timeout=5)

        delete_code, _ = rpc(
            nodes[0], token, "Admin.DeleteZtDomain", {"domain": domain}
        )
        domain_added = delete_code != 200
        online_deleted = delete_code == 200 and wait_until(
            lambda: all(not domain_present(node, token, domain) for node in nodes[:2])
            and all(not instance_present(node, instance_id) for node in nodes[:2]),
            timeout=10,
        )

        binary = str(values["prepared_binaries"]["dstack_gateway"]["path"])
        guest_socket = str(
            values["gateway_guest_simulator"]["services"]["DstackGuest"]["socket"]
        )
        environment = os.environ.copy()
        environment["DSTACK_AGENT_ADDRESS"] = f"unix:{guest_socket}"
        restarted = subprocess.Popen(
            [binary, "--config", str(nodes[-1]["config"])],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        )
        rpc_address = str(nodes[-1]["rpc_url"]).split("//", 1)[1].split("/", 1)[0]
        restart_ready = wait_port(rpc_address)
        tombstones_converged = restart_ready and wait_until(
            lambda: not domain_present(nodes[-1], token, domain)
            and not instance_present(nodes[-1], instance_id)
            and not domain_present(nodes[0], token, domain)
            and not instance_present(nodes[0], instance_id),
            timeout=15,
        )
        restarted_status = rpc(nodes[-1], token, "Admin.Status", {})[1]
        checks["tombstones_prevent_resurrection"] = online_deleted and tombstones_converged
        checks["self_identity_stable"] = (
            restarted_status.get("id") == stale_status.get("id")
            and restarted_status.get("uuid") == stale_status.get("uuid")
        )

        if credential_id is not None:
            delete_cred_code, _ = rpc(
                nodes[0],
                token,
                "Admin.DeleteDnsCredential",
                {"id": credential_id},
            )
            checks["credential_cleanup"] = delete_cred_code == 200
            credential_id = None

        if not all(checks.values()):
            raise AssertionError(
                f"bootstrap checks failed: {sorted(k for k, value in checks.items() if not value)}"
            )
        steps = [
            {"id": f"{CASE_ID}-step-01", "status": "PASS", "observed": "Three nodes exposed stable self identities and converged peer/node baselines."},
            {"id": f"{CASE_ID}-step-02", "status": "PASS", "observed": "Run-owned instance and domain state converged while empty certificate-attestation state remained consistent."},
            {"id": f"{CASE_ID}-step-03", "status": "PASS", "observed": "An offline stale node restarted with the same identity and accepted tombstones without resurrecting deleted domain or instance state."},
        ]
        observation = {
            "checks": checks,
            "node_count": len(nodes),
            "unique_node_count": len(set(ids)),
            "domain_add_http": add_code,
            "instance_register_http": register_code,
            "domain_delete_http": delete_code,
            "restart_ready": restart_ready,
            "certificate_view_count": len(cert_views),
        }
        path = result_dir / "artifacts/gateway-wavekv-bootstrap.json"
        SUPPORT.atomic_json(path, observation)
        artifacts.append({"path": "artifacts/gateway-wavekv-bootstrap.json", "step_id": f"{CASE_ID}-step-03", "name": "WaveKV bootstrap and tombstone lifecycle", "description": "Counts, HTTP statuses, and boolean convergence assertions only; no domain, key, instance, URL, UUID, credential, or response body is retained."})
        status = "PASS"
        summary = "WaveKV peer/node/instance/domain/certificate convergence, stable restart identity, and tombstone dominance passed."
    except Exception as error:  # noqa: BLE001
        failed = len(steps) + 1
        for index in range(failed, 4):
            steps.append({"id": f"{CASE_ID}-step-{index:02d}", "status": "FAIL" if index == failed else "NOT_RUN", "observed": str(error) if index == failed else "Not run after failure."})
        summary = f"WaveKV bootstrap lifecycle failed: {error}"
    finally:
        if restarted is not None:
            stop_process(restarted)
        if domain_added:
            try:
                rpc(nodes[0], token, "Admin.DeleteZtDomain", {"domain": domain})
            except Exception:  # noqa: BLE001
                pass
        if credential_id is not None:
            try:
                rpc(nodes[0], token, "Admin.DeleteDnsCredential", {"id": credential_id})
            except Exception:  # noqa: BLE001
                pass
    SUPPORT.atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    SUPPORT.atomic_json(result_dir / "result.json", {"schema_version": "1.0", "case_id": CASE_ID, "provisional": False, "status": status, "summary": summary, "steps": steps, "artifacts": artifacts, "remarks": "The restarted process was terminated; no domain, key, instance, URL, UUID, credential, certificate body, or native response body is retained."})
    return 0 if status == "PASS" else 1


def _host_port(url: str) -> tuple[str, int]:
    """Extract a host and port from a fixture URL."""
    value = __import__("urllib.parse").parse.urlsplit(str(url))
    return value.hostname or "127.0.0.1", int(value.port or 443)


if __name__ == "__main__":
    raise SystemExit(main())
