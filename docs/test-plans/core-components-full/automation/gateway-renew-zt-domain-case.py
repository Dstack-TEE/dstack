#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Admin.RenewZtDomainCert with case-owned ACME and DNS services."""

from __future__ import annotations

import concurrent.futures
import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-gw-admin-026"


def load_support() -> Any:
    """Load the committed Gateway ACME support without duplicating its control plane."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_acme_case_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway ACME support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def case_owned_public_rpc(url: str) -> tuple[int, bytes]:
    """Call the fixture's self-signed public TLS endpoint without host CA trust."""
    request = urllib.request.Request(
        url,
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def varint(value: int) -> bytes:
    """Encode an unsigned protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def protobuf_request(domain: str, force: bool) -> bytes:
    """Encode RenewZtDomainCertRequest from its checked-in inventory fields."""
    raw = domain.encode()
    return b"\x0a" + varint(len(raw)) + raw + b"\x10" + varint(int(force))


def decode_varints(data: bytes) -> dict[int, int]:
    """Decode the two scalar response fields."""
    output: dict[int, int] = {}
    offset = 0
    while offset < len(data):
        key = data[offset]
        offset += 1
        field, wire = key >> 3, key & 7
        if wire != 0:
            raise ValueError(f"unexpected wire type {wire}")
        value = 0
        shift = 0
        while True:
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if byte < 0x80:
                break
            shift += 7
        output[field] = value
    return output


def response_fields(body: bytes) -> tuple[bool, int]:
    """Parse the public JSON response fields."""
    value = json.loads(body)
    not_after = value.get("not_after", value.get("notAfter", 0))
    return bool(value.get("renewed")), int(not_after)


def main() -> int:
    """Run success, representation, boundary, concurrency, fault, and cleanup paths."""
    global CASE_ID  # noqa: PLW0603
    requested_case = os.environ["DSTACK_TEST_CASE_ID"]
    if requested_case not in {
        CASE_ID,
        "tc-gw-certificat-001",
        "tc-gw-certbot-001",
        "tc-gw-certbot-004",
        "tc-gw-certbot-002",
        "tc-gw-certificat-002",
        "tc-gw-certificat-007",
    }:
        raise ValueError("unsupported case")
    CASE_ID = requested_case
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    gateway = manifest["values"]["gateway"]
    base = str(gateway["admin_url"]).rstrip("/")
    token = pathlib.Path(gateway["admin_auth_token_file"]).read_text().strip()
    lease = str(manifest.get("lease_id", "lease"))[-10:].replace("-", "")
    prefix = f"dstack-renew-{lease}"
    network = f"{prefix}-net"
    dns_name = f"{prefix}-dns"
    pebble_name = f"{prefix}-acme"
    domain = f"renew-{lease}.test"
    adjacent = f"adjacent-{lease}.test"
    state = SUPPORT.DnsState([domain, adjacent])
    server = SUPPORT.CloudflareServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    created_credential: str | None = None
    configured = False
    original_config: dict[str, Any] | None = None
    cleanup_errors: list[str] = []
    restarted_gateway: subprocess.Popen[str] | None = None
    restarted_gateway_log: Any = None
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    public: dict[str, Any] = {}
    status = "FAIL"
    summary = "RenewZtDomainCert case did not complete"

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
        pebble_url = f"http://127.0.0.1:{pebble_port}/dir"
        SUPPORT.wait_http(pebble_url)
        cf_url = f"http://127.0.0.1:{server.server_port}/client/v4"

        code, body = SUPPORT.rpc(base, token, "Admin.GetCertbotConfig", {})
        if code != 200:
            raise AssertionError(f"GetCertbotConfig HTTP {code}")
        original_config = json.loads(body)
        configured_values = {
            "renew_interval_secs": original_config["renew_interval_secs"],
            # Keep the non-forced assertion away from the certificate-lifetime
            # boundary so scheduler delay cannot turn it into a renewal.
            "renew_before_expiration_secs": 3600,
            "renew_timeout_secs": original_config["renew_timeout_secs"],
            "acme_url": pebble_url,
        }
        if (
            SUPPORT.rpc(base, token, "Admin.SetCertbotConfig", configured_values)[0]
            != 200
        ):
            raise AssertionError("failed to install case ACME URL")
        code, body = SUPPORT.rpc(
            base,
            token,
            "Admin.CreateDnsCredential",
            {
                "name": prefix,
                "provider_type": "cloudflare",
                "cf_api_token": SUPPORT.SENTINEL_TOKEN,
                "cf_zone_id": "compatibility-input",
                "set_as_default": False,
                "cf_api_url": cf_url,
                "dns_txt_ttl": 60,
                "max_dns_wait": 5,
            },
        )
        if code != 200:
            raise AssertionError(f"CreateDnsCredential HTTP {code}")
        created_credential = json.loads(body)["id"]
        code, _ = SUPPORT.rpc(
            base,
            token,
            "Admin.AddZtDomain",
            {
                "domain": domain,
                "dns_cred_id": created_credential,
                "port": 443,
                "priority": 0,
            },
        )
        if code != 200:
            raise AssertionError(f"AddZtDomain HTTP {code}")
        configured = True
        baseline_code, baseline_body = SUPPORT.rpc(
            base, token, "Admin.GetZtDomain", {"domain": domain}
        )
        baseline = json.loads(baseline_body) if baseline_code == 200 else {}
        checks["prerequisites_healthy"] = (
            baseline_code == 200
            and (baseline.get("cert_status") or baseline.get("certStatus") or {}).get(
                "has_cert", False
            )
            is False
        )
        if not checks["prerequisites_healthy"]:
            raise AssertionError("run-scoped domain baseline was not empty")
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "Lease-owned Gateway, Pebble, DNS API, credential, and an empty run-scoped domain were healthy.",
            }
        )

        route = f"{base}/Admin.RenewZtDomainCert"
        first_code = 0
        first_body = b""
        first_renewed = False
        first_not_after = 0
        renewal_attempts = 0
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            renewal_attempts += 1
            first_code, first_body = SUPPORT.http_call(
                route,
                json.dumps({"domain": domain, "force": True}).encode(),
                "application/json",
                token,
            )
            first_renewed, first_not_after = (
                response_fields(first_body) if first_code == 200 else (False, 0)
            )
            if first_renewed and first_not_after > 0:
                break
            time.sleep(0.25)
        get_code, get_body = SUPPORT.rpc(
            base, token, "Admin.GetZtDomain", {"domain": domain}
        )
        info = json.loads(get_body) if get_code == 200 else {}
        cert_status = info.get("cert_status") or info.get("certStatus") or {}
        observed_not_after = int(
            cert_status.get("not_after", cert_status.get("notAfter", 0))
        )
        checks["forced_json_renewal"] = (
            first_code == 200
            and first_renewed
            and first_not_after > 0
            and bool(cert_status.get("has_cert", cert_status.get("hasCert", False)))
            and observed_not_after == first_not_after
        )

        pb_code, pb_body = SUPPORT.http_call(
            route,
            protobuf_request(domain, False),
            "application/octet-stream",
            token,
        )
        pb_fields = decode_varints(pb_body) if pb_code == 200 else {}
        checks["protobuf_nonforced_noop"] = (
            pb_code == 200 and pb_fields.get(1, 0) == 0 and pb_fields.get(2, 0) == 0
        )
        unknown_code, unknown_body = SUPPORT.http_call(
            route,
            json.dumps({"domain": domain, "force": False, "unknown": 1}).encode(),
            "application/json",
            token,
        )
        unknown_renewed, unknown_not_after = (
            response_fields(unknown_body) if unknown_code == 200 else (True, -1)
        )
        absent_code = SUPPORT.rpc(base, token, "Admin.RenewZtDomainCert", {})[0]
        invalid_code = SUPPORT.rpc(
            base,
            token,
            "Admin.RenewZtDomainCert",
            {"domain": "bad/domain", "force": True},
        )[0]
        missing_domain_code = SUPPORT.rpc(
            base,
            token,
            "Admin.RenewZtDomainCert",
            {"domain": adjacent, "force": True},
        )[0]
        unauthorized_code = SUPPORT.http_call(
            route,
            json.dumps({"domain": domain, "force": False}).encode(),
            "application/json",
            None,
        )[0]
        checks["schema_and_authorization"] = (
            unknown_code == 200
            and not unknown_renewed
            and unknown_not_after == 0
            and absent_code >= 400
            and invalid_code >= 400
            and missing_domain_code >= 400
            and unauthorized_code == 401
        )
        if not all(checks.values()):
            raise AssertionError(
                "representation matrix failed: "
                f"checks={sorted(k for k, v in checks.items() if not v)}, "
                f"first_http={first_code}, first_renewed={first_renewed}, "
                f"first_not_after_positive={first_not_after > 0}, get_http={get_code}, "
                f"state_has_cert={bool(cert_status.get('has_cert', cert_status.get('hasCert', False)))}, "
                f"state_not_after_positive={observed_not_after > 0}, "
                f"state_matches={observed_not_after == first_not_after}, "
                f"renewal_attempts={renewal_attempts}, pb_http={pb_code}, "
                f"pb_fields={pb_fields}, unknown_http={unknown_code}, "
                f"unknown_renewed={unknown_renewed}, unknown_not_after={unknown_not_after}, "
                f"absent_http={absent_code}, invalid_http={invalid_code}, "
                f"missing_domain_http={missing_domain_code}, unauthorized_http={unauthorized_code}"
            )
        steps.append(
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "Forced JSON renewal issued a certificate, protobuf and unknown-field non-forced requests were no-ops, and absent/invalid/missing-domain/unauthorized requests were rejected.",
            }
        )

        request_barrier = threading.Barrier(2)
        with state.lock:
            state.blocked = True
            state.block_release.clear()
            concurrent_operation_baseline = len(state.operations)

        def concurrent_renew(force: bool) -> tuple[int, bytes]:
            request_barrier.wait(timeout=10)
            return SUPPORT.http_call(
                route,
                json.dumps({"domain": domain, "force": force}).encode(),
                "application/json",
                token,
            )

        concurrent_dns_blocked = False
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                concurrent_futures = [
                    executor.submit(concurrent_renew, force)
                    for force in (True, False)
                ]
                concurrent_deadline = time.monotonic() + 10
                while time.monotonic() < concurrent_deadline:
                    with state.lock:
                        concurrent_dns_blocked = (
                            len(state.operations) > concurrent_operation_baseline
                        )
                    if concurrent_dns_blocked:
                        break
                    time.sleep(0.05)
                # Keep the forced issuance in the DNS fixture briefly so the
                # non-forced request reaches the Gateway's per-domain lock and
                # rechecks the freshly issued certificate after acquiring it.
                if concurrent_dns_blocked:
                    time.sleep(0.2)
                state.block_release.set()
                concurrent_responses = [
                    future.result() for future in concurrent_futures
                ]
        finally:
            with state.lock:
                state.blocked = False
                state.block_release.set()
        if not concurrent_dns_blocked:
            raise RuntimeError(
                "concurrent renewal did not reach the blocked DNS fixture"
            )
        concurrent_statuses = [code for code, _ in concurrent_responses]
        concurrent_renewed = [
            response_fields(body)[0] if code == 200 else False
            for code, body in concurrent_responses
        ]
        checks["concurrent_locking"] = (
            concurrent_statuses == [200, 200] and sum(concurrent_renewed) == 1
        )

        with state.lock:
            state.failure = True
        outage_code = SUPPORT.rpc(
            base,
            token,
            "Admin.RenewZtDomainCert",
            {"domain": domain, "force": True},
        )[0]
        with state.lock:
            state.failure = False
        recovery_code, recovery_body = SUPPORT.rpc(
            base,
            token,
            "Admin.RenewZtDomainCert",
            {"domain": domain, "force": True},
        )
        recovery_renewed, recovery_not_after = (
            response_fields(recovery_body) if recovery_code == 200 else (False, 0)
        )
        post_code, post_body = SUPPORT.rpc(
            base, token, "Admin.GetZtDomain", {"domain": domain}
        )
        post = json.loads(post_body) if post_code == 200 else {}
        post_cert = post.get("cert_status") or post.get("certStatus") or {}
        checks["dependency_outage_failed_closed"] = outage_code >= 400
        checks["recovery_converged"] = (
            recovery_code == 200
            and recovery_renewed
            and recovery_not_after > 0
            and post_code == 200
            and bool(post_cert.get("has_cert", post_cert.get("hasCert", False)))
        )
        checks["adjacent_unchanged"] = state.snapshot()["zone-1"] == []
        if CASE_ID == "tc-gw-certbot-002":
            operation_methods = [method for method, _ in state.operations]
            checks["dns_challenge_lifecycle"] = (
                operation_methods.count("POST") >= 1
                and operation_methods.count("DELETE") >= 1
                and all(not records for records in state.snapshot().values())
            )
        checks["gateway_remained_healthy"] = (
            SUPPORT.rpc(base, token, "Admin.GetCertbotConfig", {})[0] == 200
        )
        if CASE_ID == "tc-gw-certbot-004":
            checks["renewal_publication_hook"] = bool(
                cert_status.get(
                    "loaded_in_memory", cert_status.get("loadedInMemory", False)
                )
            ) and bool(
                post_cert.get(
                    "loaded_in_memory", post_cert.get("loadedInMemory", False)
                )
            )
        account_public: dict[str, Any] = {}
        if CASE_ID in {"tc-gw-certificat-001", "tc-gw-certbot-001"}:
            cluster_nodes = manifest["values"]["gateway_cluster"]["nodes"]
            account_values: list[dict[str, Any]] = []
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                account_values = []
                for node in cluster_nodes:
                    node_code, node_body = case_owned_public_rpc(
                        f"{str(node['rpc_url']).rstrip('/')}/AcmeInfo"
                    )
                    node_value = json.loads(node_body) if node_code == 200 else {}
                    account_values.append(
                        {
                            "code": node_code,
                            "uri": node_value.get(
                                "account_uri", node_value.get("accountUri", "")
                            ),
                            "quote": node_value.get(
                                "account_quote", node_value.get("accountQuote", "")
                            ),
                        }
                    )
                if all(row["code"] == 200 and row["uri"] for row in account_values):
                    break
                time.sleep(0.2)
            account_uris = [str(row["uri"]) for row in account_values]
            baseline_account_hash = (
                hashlib.sha256(account_uris[0].encode()).hexdigest()
                if account_uris and account_uris[0]
                else ""
            )
            rotate_route = f"{base}/Admin.RotateAcmeCredentials"
            unauthorized_rotate_code = SUPPORT.http_call(
                rotate_route,
                b"{}",
                "application/json",
                None,
            )[0]
            rotate_code, rotate_body = SUPPORT.rpc(
                base, token, "Admin.RotateAcmeCredentials", {}
            )
            rotate_value = json.loads(rotate_body) if rotate_code == 200 else {}
            rotated_uri = str(
                rotate_value.get("account_uri", rotate_value.get("accountUri", ""))
            )
            domains_updated = int(
                rotate_value.get(
                    "domains_updated", rotate_value.get("domainsUpdated", 0)
                )
            )
            rotated_values: list[dict[str, Any]] = []
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                rotated_values = []
                for node in cluster_nodes:
                    node_code, node_body = case_owned_public_rpc(
                        f"{str(node['rpc_url']).rstrip('/')}/AcmeInfo"
                    )
                    node_value = json.loads(node_body) if node_code == 200 else {}
                    rotated_values.append(
                        {
                            "code": node_code,
                            "uri": node_value.get(
                                "account_uri", node_value.get("accountUri", "")
                            ),
                        }
                    )
                if rotated_uri and all(
                    row["code"] == 200 and row["uri"] == rotated_uri
                    for row in rotated_values
                ):
                    break
                time.sleep(0.2)
            rotated_account_hash = (
                hashlib.sha256(rotated_uri.encode()).hexdigest() if rotated_uri else ""
            )
            caa_rows = [
                row
                for row in state.snapshot()["zone-0"]
                if row["type"] == "CAA" and row["name"].rstrip(".") == domain
            ]
            checks["acme_account_rotation"] = (
                unauthorized_rotate_code == 401
                and rotate_code == 200
                and domains_updated == 1
                and bool(rotated_uri)
                and rotated_account_hash != baseline_account_hash
                and len(rotated_values) >= 2
                and all(row["uri"] == rotated_uri for row in rotated_values)
                and any(rotated_uri in row["content"] for row in caa_rows)
                and any(" issuewild " in row["content"] for row in caa_rows)
                and all(
                    row["content"] not in ('0 issue ";"', '0 issuewild ";"')
                    for row in caa_rows
                )
            )
            invalid_config = {**configured_values, "acme_url": "http://127.0.0.1:1/dir"}
            invalid_config_code = SUPPORT.rpc(
                base, token, "Admin.SetCertbotConfig", invalid_config
            )[0]
            invalid_directory_code = SUPPORT.rpc(
                base,
                token,
                "Admin.RenewZtDomainCert",
                {"domain": domain, "force": True},
            )[0]
            restore_config_code = SUPPORT.rpc(
                base, token, "Admin.SetCertbotConfig", configured_values
            )[0]
            recovery_account_code, recovery_account_body = SUPPORT.rpc(
                base,
                token,
                "Admin.RenewZtDomainCert",
                {"domain": domain, "force": True},
            )
            recovery_account_renewed = (
                response_fields(recovery_account_body)[0]
                if recovery_account_code == 200
                else False
            )

            primary = cluster_nodes[0]
            os.killpg(int(primary["pid"]), signal.SIGTERM)
            stop_deadline = time.monotonic() + 10
            while time.monotonic() < stop_deadline:
                try:
                    os.kill(int(primary["pid"]), 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            runtime = json.loads(
                pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
            )
            binary = str(runtime["prepared_binaries"]["dstack_gateway"]["path"])
            restart_log_path = result_dir / "artifacts/gateway-restart.log"
            restart_log_path.parent.mkdir(parents=True, exist_ok=True)
            restarted_gateway_log = restart_log_path.open("w", encoding="utf-8")
            restart_env = os.environ.copy()
            guest_socket = manifest["values"]["gateway_guest_simulator"]["services"][
                "DstackGuest"
            ]["socket"]
            restart_env["DSTACK_AGENT_ADDRESS"] = f"unix:{guest_socket}"
            restarted_gateway = subprocess.Popen(
                [binary, "--config", str(primary["config"])],
                stdout=restarted_gateway_log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
                env=restart_env,
            )
            rpc_port = int(str(primary["rpc_url"]).split(":")[-1].split("/")[0])
            restart_deadline = time.monotonic() + 15
            while time.monotonic() < restart_deadline:
                if restarted_gateway.poll() is not None:
                    raise RuntimeError(
                        f"restarted Gateway exited rc={restarted_gateway.returncode}"
                    )
                try:
                    with socket.create_connection(("127.0.0.1", rpc_port), timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("restarted Gateway did not listen")
            restart_code, restart_body = case_owned_public_rpc(
                f"{str(primary['rpc_url']).rstrip('/')}/AcmeInfo"
            )
            restart_value = json.loads(restart_body) if restart_code == 200 else {}
            restart_uri = restart_value.get(
                "account_uri", restart_value.get("accountUri", "")
            )
            checks["acme_account_bootstrap_persistence"] = (
                len(account_values) >= 2
                and all(row["code"] == 200 and row["quote"] for row in account_values)
                and len(set(account_uris)) == 1
                and bool(baseline_account_hash)
                and invalid_config_code == 200
                and invalid_directory_code >= 400
                and restore_config_code == 200
                and recovery_account_code == 200
                and recovery_account_renewed
                and restart_code == 200
                and bool(restart_uri)
                and hashlib.sha256(str(restart_uri).encode()).hexdigest()
                == rotated_account_hash
            )
            account_public = {
                "cluster_node_count": len(account_values),
                "all_nodes_have_account": all(
                    bool(row["uri"]) for row in account_values
                ),
                "all_nodes_have_quote": all(
                    bool(row["quote"]) for row in account_values
                ),
                "cluster_account_agreement": len(set(account_uris)) == 1,
                "unauthorized_rotation_http": unauthorized_rotate_code,
                "rotation_http": rotate_code,
                "rotation_changed_account": bool(rotated_account_hash)
                and rotated_account_hash != baseline_account_hash,
                "rotation_domains_updated": domains_updated,
                "rotation_cluster_converged": bool(rotated_uri)
                and all(row["uri"] == rotated_uri for row in rotated_values),
                "rotation_caa_re_pinned": any(
                    rotated_uri in row["content"] for row in caa_rows
                ),
                "invalid_config_http": invalid_config_code,
                "invalid_directory_http": invalid_directory_code,
                "restore_config_http": restore_config_code,
                "recovery_http": recovery_account_code,
                "recovery_renewed": recovery_account_renewed,
                "restart_http": restart_code,
                "restart_account_matches": bool(restart_uri)
                and hashlib.sha256(str(restart_uri).encode()).hexdigest()
                == rotated_account_hash,
            }
        distributed_public: dict[str, Any] = {}
        if CASE_ID == "tc-gw-certificat-002":
            cluster_nodes = manifest["values"]["gateway_cluster"]["nodes"]
            node_admin_urls = [
                str(node["admin_url"]).rstrip("/") for node in cluster_nodes
            ]
            with state.lock:
                state.blocked = True
                state.block_release.clear()
                distributed_operation_baseline = len(state.operations)
            distributed_dns_blocked = False
            try:
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=len(cluster_nodes)
                ) as executor:
                    primary_future = executor.submit(
                        SUPPORT.rpc,
                        node_admin_urls[0],
                        token,
                        "Admin.RenewZtDomainCert",
                        {"domain": domain, "force": True},
                    )
                    distributed_deadline = time.monotonic() + 10
                    while time.monotonic() < distributed_deadline:
                        with state.lock:
                            distributed_dns_blocked = (
                                len(state.operations)
                                > distributed_operation_baseline
                            )
                        if distributed_dns_blocked:
                            break
                        time.sleep(0.05)
                    if not distributed_dns_blocked:
                        raise RuntimeError(
                            "distributed renewal did not reach the blocked DNS fixture"
                        )
                    competing_futures = [
                        executor.submit(
                            SUPPORT.rpc,
                            node_base,
                            token,
                            "Admin.RenewZtDomainCert",
                            {"domain": domain, "force": True},
                        )
                        for node_base in node_admin_urls[1:]
                    ]
                    time.sleep(0.2)
                    state.block_release.set()
                    distributed_responses = [primary_future.result()] + [
                        future.result() for future in competing_futures
                    ]
            finally:
                with state.lock:
                    state.blocked = False
                    state.block_release.set()
            distributed_statuses = [code for code, _ in distributed_responses]
            distributed_renewed = [
                response_fields(body)[0] if code == 200 else False
                for code, body in distributed_responses
            ]
            converged_rows: list[dict[str, Any]] = []
            converge_deadline = time.monotonic() + 10
            while time.monotonic() < converge_deadline:
                converged_rows = []
                for node_base in node_admin_urls:
                    node_code, node_body = SUPPORT.rpc(
                        node_base, token, "Admin.GetZtDomain", {"domain": domain}
                    )
                    node_value = json.loads(node_body) if node_code == 200 else {}
                    node_cert = node_value.get("cert_status") or node_value.get(
                        "certStatus", {}
                    )
                    converged_rows.append(
                        {
                            "code": node_code,
                            "not_after": int(
                                node_cert.get("not_after", node_cert.get("notAfter", 0))
                            ),
                            "loaded": bool(
                                node_cert.get(
                                    "loaded_in_memory",
                                    node_cert.get("loadedInMemory", False),
                                )
                            ),
                        }
                    )
                expiries = {row["not_after"] for row in converged_rows}
                if (
                    all(row["code"] == 200 and row["loaded"] for row in converged_rows)
                    and len(expiries) == 1
                    and 0 not in expiries
                ):
                    break
                time.sleep(0.2)

            with state.lock:
                state.blocked = True
                state.block_release.clear()
                operation_baseline = len(state.operations)
            crash_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            crash_future = crash_executor.submit(
                SUPPORT.rpc,
                node_admin_urls[0],
                token,
                "Admin.RenewZtDomainCert",
                {"domain": domain, "force": True},
            )
            block_deadline = time.monotonic() + 10
            while time.monotonic() < block_deadline:
                with state.lock:
                    request_blocked = len(state.operations) > operation_baseline
                if request_blocked:
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("renewal did not reach the blocked DNS provider")
            os.killpg(int(cluster_nodes[0]["pid"]), signal.SIGKILL)
            with state.lock:
                state.blocked = False
                state.block_release.set()
            try:
                crash_future.result(timeout=10)
            except Exception:  # noqa: BLE001
                pass
            crash_executor.shutdown(wait=True, cancel_futures=True)
            base = node_admin_urls[1]
            force_release_code = SUPPORT.rpc(
                base,
                token,
                "Admin.ForceReleaseCertLock",
                {"domain": domain},
            )[0]
            stale_recovery_code, stale_recovery_body = SUPPORT.rpc(
                base,
                token,
                "Admin.RenewZtDomainCert",
                {"domain": domain, "force": True},
            )
            stale_recovery_renewed = (
                response_fields(stale_recovery_body)[0]
                if stale_recovery_code == 200
                else False
            )
            survivor_rows = []
            survivor_deadline = time.monotonic() + 10
            while time.monotonic() < survivor_deadline:
                survivor_rows = []
                for node_base in node_admin_urls[1:]:
                    node_code, node_body = SUPPORT.rpc(
                        node_base, token, "Admin.GetZtDomain", {"domain": domain}
                    )
                    node_value = json.loads(node_body) if node_code == 200 else {}
                    node_cert = node_value.get("cert_status") or node_value.get(
                        "certStatus", {}
                    )
                    survivor_rows.append(
                        {
                            "code": node_code,
                            "not_after": int(
                                node_cert.get("not_after", node_cert.get("notAfter", 0))
                            ),
                            "loaded": bool(
                                node_cert.get(
                                    "loaded_in_memory",
                                    node_cert.get("loadedInMemory", False),
                                )
                            ),
                        }
                    )
                survivor_expiries = {row["not_after"] for row in survivor_rows}
                if (
                    all(row["code"] == 200 and row["loaded"] for row in survivor_rows)
                    and len(survivor_expiries) == 1
                    and 0 not in survivor_expiries
                ):
                    break
                time.sleep(0.2)
            checks["distributed_renewal_fencing"] = (
                distributed_statuses == [200] * len(cluster_nodes)
                and sum(distributed_renewed) == 1
                and all(row["code"] == 200 and row["loaded"] for row in converged_rows)
                and len({row["not_after"] for row in converged_rows}) == 1
                and force_release_code == 200
                and stale_recovery_code == 200
                and stale_recovery_renewed
                and all(row["code"] == 200 and row["loaded"] for row in survivor_rows)
                and len({row["not_after"] for row in survivor_rows}) == 1
            )
            distributed_public = {
                "node_count": len(cluster_nodes),
                "concurrent_statuses": distributed_statuses,
                "concurrent_renewed_count": sum(distributed_renewed),
                "initial_nodes_loaded": all(row["loaded"] for row in converged_rows),
                "initial_expiry_agreement": len(
                    {row["not_after"] for row in converged_rows}
                )
                == 1,
                "initial_request_blocked": distributed_dns_blocked,
                "blocked_request_observed": request_blocked,
                "force_release_http": force_release_code,
                "stale_recovery_http": stale_recovery_code,
                "stale_recovery_renewed": stale_recovery_renewed,
                "survivor_count": len(survivor_rows),
                "survivors_loaded": all(row["loaded"] for row in survivor_rows),
                "survivor_expiry_agreement": len(
                    {row["not_after"] for row in survivor_rows}
                )
                == 1,
            }
        attestation_public: dict[str, Any] = {}
        if CASE_ID == "tc-gw-certificat-007":
            history_code, history_body = SUPPORT.rpc(
                base,
                token,
                "Admin.ListCertAttestations",
                {"domain": domain, "limit": 0},
            )
            limited_code, limited_body = SUPPORT.rpc(
                base,
                token,
                "Admin.ListCertAttestations",
                {"domain": domain, "limit": 1},
            )
            missing_history_code = SUPPORT.rpc(
                base,
                token,
                "Admin.ListCertAttestations",
                {"domain": adjacent, "limit": 0},
            )[0]
            unauthorized_history_code = SUPPORT.http_call(
                f"{base}/Admin.ListCertAttestations",
                json.dumps({"domain": domain, "limit": 0}).encode(),
                "application/json",
                None,
            )[0]
            history_value = json.loads(history_body) if history_code == 200 else {}
            limited_value = json.loads(limited_body) if limited_code == 200 else {}
            history = history_value.get("history", [])
            latest = history_value.get("latest") or {}
            limited_history = limited_value.get("history", [])
            timestamps = [
                int(row.get("generated_at", row.get("generatedAt", 0)))
                for row in history
            ]
            public_keys = [
                row.get("public_key", row.get("publicKey", "")) for row in history
            ]
            quotes = [row.get("quote", "") for row in history]
            main_base = str(gateway["rpc_url"]).rstrip("/")
            acme_code, acme_body = case_owned_public_rpc(f"{main_base}/AcmeInfo")
            acme = json.loads(acme_body) if acme_code == 200 else {}
            quoted_keys = acme.get("quoted_hist_keys", acme.get("quotedHistKeys", []))
            account_uri = acme.get("account_uri", acme.get("accountUri", ""))
            account_quote = acme.get("account_quote", acme.get("accountQuote", ""))
            checks["attestation_history"] = (
                history_code == 200
                and len(history) >= 2
                and bool(latest)
                and timestamps == sorted(timestamps, reverse=True)
                and all(timestamps)
                and len(set(public_keys)) >= 2
                and all(public_keys)
                and all(quotes)
                and limited_code == 200
                and len(limited_history) == 1
                and missing_history_code == 200
                and unauthorized_history_code == 401
            )
            checks["public_acme_info"] = (
                acme_code == 200
                and bool(account_uri)
                and bool(account_quote)
                and len(quoted_keys) >= 2
                and all(
                    row.get("public_key", row.get("publicKey", ""))
                    and row.get("quote", "")
                    for row in quoted_keys
                )
            )
            attestation_public = {
                "history_http": history_code,
                "history_count": len(history),
                "latest_present": bool(latest),
                "timestamps_descending": timestamps == sorted(timestamps, reverse=True),
                "distinct_public_key_count": len(set(public_keys)),
                "quotes_present": bool(quotes) and all(bool(value) for value in quotes),
                "limited_history_count": len(limited_history),
                "missing_domain_http": missing_history_code,
                "unauthorized_http": unauthorized_history_code,
                "acme_info_http": acme_code,
                "account_uri_present": bool(account_uri),
                "account_quote_present": bool(account_quote),
                "quoted_key_count": len(quoted_keys),
            }
        if not all(checks.values()):
            raise AssertionError(
                "concurrency/fault/recovery matrix failed: "
                f"checks={sorted(k for k, v in checks.items() if not v)}, "
                f"concurrent_statuses={concurrent_statuses}, "
                f"concurrent_renewed={concurrent_renewed}, "
                f"account={account_public}, distributed={distributed_public}, "
                f"attestation={attestation_public}"
            )
        steps.append(
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Concurrent forced and non-forced requests admitted one renewal, DNS outage failed closed, retry renewed successfully, the adjacent zone stayed empty, and Gateway remained healthy.",
            }
        )
        public = {
            "checks": checks,
            "first": {
                "http": first_code,
                "renewed": first_renewed,
                "not_after_positive": first_not_after > 0,
                "state_matches": observed_not_after == first_not_after,
                "attempts": renewal_attempts,
            },
            "protobuf": {
                "http": pb_code,
                "field_numbers": sorted(pb_fields),
                "renewed": bool(pb_fields.get(1, 0)),
                "not_after": pb_fields.get(2, 0),
            },
            "invalid_statuses": {
                "absent": absent_code,
                "invalid": invalid_code,
                "missing_domain": missing_domain_code,
                "unauthorized": unauthorized_code,
            },
            "concurrent_statuses": concurrent_statuses,
            "concurrent_renewed_count": sum(concurrent_renewed),
            "outage_http": outage_code,
            "recovery_http": recovery_code,
            "recovery_not_after_positive": recovery_not_after > 0,
            "account": account_public,
            "distributed": distributed_public,
            "attestation": attestation_public,
            "dns_operation_count": len(state.operations),
            "dns_operation_hash": hashlib.sha256(
                json.dumps(state.operations, sort_keys=True).encode()
            ).hexdigest(),
        }
        artifact_path = result_dir / "artifacts/gateway-renew-domain-observation.json"
        atomic_json(artifact_path, public)
        artifacts.append(
            {
                "path": "artifacts/gateway-renew-domain-observation.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "RenewZtDomainCert assertions",
                "description": "Status codes, public booleans, certificate-expiry presence, counts, and hashes only; no certificate, account response, credential, or token is retained.",
            }
        )
        status = "PASS"
        summary = "Admin.RenewZtDomainCert passed representation, authorization, issuance, concurrency, outage, recovery, isolation, and cleanup coverage."
    except Exception as error:  # noqa: BLE001
        summary = f"Admin.RenewZtDomainCert matrix failed: {error}"
        failed_step = len(steps) + 1
        for index in range(failed_step, 4):
            steps.append(
                {
                    "id": f"{CASE_ID}-step-0{index}",
                    "status": "FAIL" if index == failed_step else "NOT_RUN",
                    "observed": str(error)
                    if index == failed_step
                    else "Not run after earlier failure.",
                }
            )
    finally:
        if configured:
            try:
                SUPPORT.rpc(base, token, "Admin.DeleteZtDomain", {"domain": domain})
            except Exception as error:  # noqa: BLE001
                cleanup_errors.append(f"domain:{type(error).__name__}")
        if created_credential:
            try:
                SUPPORT.rpc(
                    base, token, "Admin.DeleteDnsCredential", {"id": created_credential}
                )
            except Exception as error:  # noqa: BLE001
                cleanup_errors.append(f"credential:{type(error).__name__}")
        if original_config:
            try:
                SUPPORT.rpc(base, token, "Admin.SetCertbotConfig", original_config)
            except Exception as error:  # noqa: BLE001
                cleanup_errors.append(f"config:{type(error).__name__}")
        if restarted_gateway is not None:
            try:
                os.killpg(restarted_gateway.pid, signal.SIGTERM)
                restarted_gateway.wait(timeout=10)
            except Exception as error:  # noqa: BLE001
                cleanup_errors.append(f"restarted_gateway:{type(error).__name__}")
        if restarted_gateway_log is not None:
            restarted_gateway_log.close()
        server.shutdown()
        server.server_close()
        for name in (pebble_name, dns_name):
            try:
                SUPPORT.docker("rm", "-f", name, check=False)
            except Exception as error:  # noqa: BLE001
                cleanup_errors.append(f"container:{type(error).__name__}")
        try:
            SUPPORT.docker("network", "rm", network, check=False)
        except Exception as error:  # noqa: BLE001
            cleanup_errors.append(f"network:{type(error).__name__}")

    if cleanup_errors:
        status = "FAIL"
        summary = "Case behavior completed but cleanup reported bounded errors."
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "remarks": f"Case-owned resources were removed; cleanup_error_count={len(cleanup_errors)}. Certificate bodies, native ACME responses, credentials, and tokens were not retained.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
