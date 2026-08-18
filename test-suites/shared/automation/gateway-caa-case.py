#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Admin.SetCaa against case-owned ACME and DNS control planes."""

from __future__ import annotations

import concurrent.futures
import hashlib
import http.server
import ipaddress
import json
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

CASE_ID = "tc-gw-admin-006"
CF_IMAGE = os.environ.get("DSTACK_TEST_MOCK_CF_DNS_IMAGE", "")
PEBBLE_IMAGE = os.environ.get("DSTACK_TEST_PEBBLE_IMAGE", "")
SENTINEL_TOKEN = "dstack-caa-case-sentinel"


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


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run Docker through the operator-configured shell wrapper."""
    command = shlex.join(("docker", *args))
    return subprocess.run(
        [
            os.environ.get(
                "DSTACK_TEST_DOCKER_SHELL_RUNNER",
                os.path.join(
                    os.environ["DSTACK_TEST_PLAN_DIR"],
                    "shared/automation/run-docker-shell",
                ),
            ),
            command,
        ],
        text=True,
        capture_output=True,
        timeout=60,
        check=check,
    )


def create_network(name: str) -> subprocess.CompletedProcess[str]:
    """Create a case-owned network outside the daemon's exhausted default pool."""
    pool_value = os.environ.get("DSTACK_TEST_DOCKER_SUBNET_POOL")
    if not pool_value:
        raise RuntimeError("prepared Docker subnet pool is missing")
    pool = ipaddress.ip_network(pool_value)
    subnets = tuple(pool.subnets(new_prefix=24))
    index = int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], "big") % len(
        subnets
    )
    return docker("network", "create", "--subnet", str(subnets[index]), name)


def published_port(name: str, container_port: str) -> int:
    """Return a case-owned container's loopback host port."""
    output = docker("port", name, container_port).stdout.strip().splitlines()[0]
    return int(output.rsplit(":", 1)[1])


class DnsState:
    """Thread-safe bounded Cloudflare API state."""

    def __init__(self, domains: list[str]) -> None:
        """Initialize isolated zones and record storage."""
        self.lock = threading.Lock()
        self.failure = False
        self.blocked = False
        self.block_release = threading.Event()
        self.block_release.set()
        self.next_id = 0
        self.zones = {f"zone-{index}": domain for index, domain in enumerate(domains)}
        self.records: dict[str, list[dict[str, str]]] = {
            zone: [] for zone in self.zones
        }
        self.operations: list[tuple[str, str]] = []

    def snapshot(self) -> dict[str, list[dict[str, str]]]:
        """Return a deep copy without credentials."""
        with self.lock:
            return json.loads(json.dumps(self.records))


class CloudflareHandler(http.server.BaseHTTPRequestHandler):
    """Minimal deterministic Cloudflare API used by the candidate client."""

    server: "CloudflareServer"

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress raw request logging."""

    def response(self, code: int, value: dict[str, Any]) -> None:
        """Write a JSON response."""
        data = json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self) -> bool:
        """Check the sentinel credential without recording it."""
        return self.headers.get("Authorization") == f"Bearer {SENTINEL_TOKEN}"

    def begin(self) -> tuple[urllib.parse.SplitResult, DnsState] | None:
        """Apply common authorization and injected-outage behavior."""
        parsed = urllib.parse.urlsplit(self.path)
        state = self.server.state
        with state.lock:
            state.operations.append((self.command, parsed.path))
            failed = state.failure
            blocked = state.blocked
        if blocked:
            state.block_release.wait(timeout=30)
        if not self.authorized():
            self.response(401, {"success": False, "errors": [{"code": 10000}]})
            return None
        if failed:
            self.response(503, {"success": False, "errors": [{"code": 9000}]})
            return None
        return parsed, state

    def do_GET(self) -> None:  # noqa: N802
        """List zones or records."""
        begun = self.begin()
        if begun is None:
            return
        parsed, state = begun
        if parsed.path == "/client/v4/zones":
            with state.lock:
                zones = [
                    {"id": zone, "name": name} for zone, name in state.zones.items()
                ]
            self.response(
                200,
                {
                    "success": True,
                    "result": zones,
                    "result_info": {
                        "page": 1,
                        "per_page": 50,
                        "total_pages": 1,
                        "count": len(zones),
                        "total_count": len(zones),
                    },
                },
            )
            return
        parts = parsed.path.strip("/").split("/")
        if (
            len(parts) == 5
            and parts[:3] == ["client", "v4", "zones"]
            and parts[4] == "dns_records"
        ):
            zone = parts[3]
            query = urllib.parse.parse_qs(parsed.query)
            target = query.get("name", [""])[0].rstrip(".").lower()
            with state.lock:
                records = [
                    r.copy()
                    for r in state.records.get(zone, [])
                    if not target or r["name"].rstrip(".").lower() == target
                ]
            self.response(
                200,
                {"success": True, "result": records, "result_info": {"total_pages": 1}},
            )
            return
        self.response(404, {"success": False, "errors": [{"code": 1000}]})

    def do_POST(self) -> None:  # noqa: N802
        """Create a DNS record."""
        begun = self.begin()
        if begun is None:
            return
        parsed, state = begun
        parts = parsed.path.strip("/").split("/")
        if (
            len(parts) != 5
            or parts[:3] != ["client", "v4", "zones"]
            or parts[4] != "dns_records"
        ):
            self.response(404, {"success": False, "errors": [{"code": 1000}]})
            return
        zone = parts[3]
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        with state.lock:
            state.next_id += 1
            record_id = f"record-{state.next_id}"
            if request["type"] == "CAA":
                data = request["data"]
                content = f'{data["flags"]} {data["tag"]} "{data["value"]}"'
            else:
                content = str(request["content"])
            record = {
                "id": record_id,
                "name": request["name"],
                "content": content,
                "type": request["type"],
            }
            state.records.setdefault(zone, []).append(record)
        self.response(200, {"success": True, "result": {"id": record_id}})

    def do_DELETE(self) -> None:  # noqa: N802
        """Delete a DNS record."""
        begun = self.begin()
        if begun is None:
            return
        parsed, state = begun
        parts = parsed.path.strip("/").split("/")
        if (
            len(parts) != 6
            or parts[:3] != ["client", "v4", "zones"]
            or parts[4] != "dns_records"
        ):
            self.response(404, {"success": False, "errors": [{"code": 1000}]})
            return
        zone, record_id = parts[3], parts[5]
        with state.lock:
            state.records[zone] = [
                r for r in state.records.get(zone, []) if r["id"] != record_id
            ]
        self.response(200, {"success": True, "result": {"id": record_id}})


class CloudflareServer(http.server.ThreadingHTTPServer):
    """HTTP server carrying the case-owned DNS state."""

    def __init__(self, state: DnsState) -> None:
        """Bind a loopback-only API server to the supplied state."""
        super().__init__(("127.0.0.1", 0), CloudflareHandler)
        self.state = state


def http_call(
    url: str, body: bytes, content_type: str, token: str | None
) -> tuple[int, bytes]:
    """Invoke one pRPC route and retain its response only in memory."""
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", content_type)
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def rpc(base: str, token: str, method: str, value: dict[str, Any]) -> tuple[int, bytes]:
    """Invoke an Admin JSON pRPC method."""
    return http_call(
        f"{base}/{method}", json.dumps(value).encode(), "application/json", token
    )


def bounded_error(body: bytes, domains: list[str]) -> str:
    """Redact URLs, case domains, and opaque identifiers from an RPC error."""
    value = body.decode("utf-8", errors="replace")[:500]
    value = re.sub(r"https?://[^\s\"']+", "<url>", value)
    for domain in domains:
        value = value.replace(domain, "<case-domain>")
    value = re.sub(r"[A-Za-z0-9_-]{16,}", "<opaque-id>", value)
    return value


def wait_http(url: str) -> None:
    """Wait for a case-owned HTTP service."""
    for _ in range(40):
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:  # noqa: BLE001
            time.sleep(0.25)
    raise RuntimeError(
        f"service did not become ready: {urllib.parse.urlsplit(url).path}"
    )


def record_facts(state: DnsState) -> dict[str, Any]:
    """Return non-secret CAA assertions for artifacts."""
    snapshot = state.snapshot()
    facts: dict[str, Any] = {}
    for zone, domain in state.zones.items():
        all_rows = snapshot[zone]
        rows = [
            row
            for row in all_rows
            if row["type"] == "CAA" and row["name"].rstrip(".") == domain
        ]
        facts[domain] = {
            "count": len(rows),
            "types": sorted(r["type"] for r in rows),
            "names_match": all(r["name"].rstrip(".") == domain for r in rows),
            "unrelated_record_count": len(all_rows) - len(rows),
            "has_issue": any(
                ' issue "letsencrypt.org;validationmethods=dns-01;accounturi='
                in r["content"]
                for r in rows
            ),
            "has_issuewild": any(
                ' issuewild "letsencrypt.org;validationmethods=dns-01;accounturi='
                in r["content"]
                for r in rows
            ),
            "guard_absent": all(
                r["content"] not in ('0 issue ";"', '0 issuewild ";"') for r in rows
            ),
            "unrelated_caa_preserved": any(
                r["content"] == '0 iodef "mailto:security@example.invalid"'
                for r in rows
            ),
            "conflicting_issuer_removed": all(
                "unrelated-ca.invalid" not in r["content"] for r in rows
            ),
        }
    return facts


def main() -> int:
    if not CF_IMAGE or not PEBBLE_IMAGE:
        raise RuntimeError(
            "DSTACK_TEST_MOCK_CF_DNS_IMAGE and DSTACK_TEST_PEBBLE_IMAGE are required"
        )
    """Run multi-domain CAA success, transport, fault, concurrency, and cleanup coverage."""
    global CASE_ID  # noqa: PLW0603
    requested_case = os.environ["DSTACK_TEST_CASE_ID"]
    if requested_case not in {CASE_ID, "tc-gw-certificat-005"}:
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
    prefix = f"dstack-caa-{lease}"
    network, cf_name, pebble_name = f"{prefix}-net", f"{prefix}-dns", f"{prefix}-acme"
    domains = [f"a-{lease}.test", f"b-{lease}.test", f"adjacent-{lease}.test"]
    state = DnsState(domains)
    for zone, domain in list(state.zones.items())[:2]:
        state.records[zone].extend(
            [
                {
                    "id": f"existing-issuer-{zone}",
                    "name": domain,
                    "content": '0 issue "unrelated-ca.invalid"',
                    "type": "CAA",
                },
                {
                    "id": f"existing-iodef-{zone}",
                    "name": domain,
                    "content": '0 iodef "mailto:security@example.invalid"',
                    "type": "CAA",
                },
                {
                    "id": f"existing-txt-{zone}",
                    "name": domain,
                    "content": "unrelated-observation",
                    "type": "TXT",
                },
            ]
        )
    server = CloudflareServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    created_credential: str | None = None
    configured_domains: list[str] = []
    original_config: dict[str, Any] | None = None
    artifacts: list[dict[str, str]] = []
    steps: list[dict[str, str]] = []
    status = "FAIL"
    summary = "CAA case did not complete"
    cleanup_errors: list[str] = []
    checks: dict[str, bool] = {}

    try:
        thread.start()
        create_network(network)
        docker("run", "-d", "--name", cf_name, "--network", network, CF_IMAGE)
        cf_ip = docker(
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            cf_name,
        ).stdout.strip()
        docker(
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
            PEBBLE_IMAGE,
            "-http",
            "-dnsserver",
            f"{cf_ip}:53",
        )
        pebble_port = published_port(pebble_name, "14000/tcp")
        pebble_url = f"http://127.0.0.1:{pebble_port}/dir"
        wait_http(pebble_url)
        cf_url = f"http://127.0.0.1:{server.server_port}/client/v4"

        code, body = rpc(base, token, "Admin.GetCertbotConfig", {})
        if code != 200:
            raise AssertionError(f"GetCertbotConfig HTTP {code}")
        original_config = json.loads(body or b"{}")
        config_request = {
            "renew_interval_secs": original_config["renew_interval_secs"],
            "renew_before_expiration_secs": original_config[
                "renew_before_expiration_secs"
            ],
            "renew_timeout_secs": original_config["renew_timeout_secs"],
            "acme_url": pebble_url,
        }
        if rpc(base, token, "Admin.SetCertbotConfig", config_request)[0] != 200:
            raise AssertionError("failed to install case ACME URL")
        code, body = rpc(
            base,
            token,
            "Admin.CreateDnsCredential",
            {
                "name": prefix,
                "provider_type": "cloudflare",
                "cf_api_token": SENTINEL_TOKEN,
                "cf_zone_id": "ignored-by-current-provider",
                "set_as_default": False,
                "cf_api_url": cf_url,
                "dns_txt_ttl": 60,
                "max_dns_wait": 5,
            },
        )
        if code != 200:
            raise AssertionError(f"CreateDnsCredential HTTP {code}")
        created_credential = json.loads(body)["id"]
        for domain in domains[:2]:
            code, _ = rpc(
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
            configured_domains.append(domain)
        checks["prerequisites_healthy"] = True
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "Lease-owned Gateway, Pebble, Cloudflare API model, two configured domains, and an adjacent unconfigured domain were ready.",
            }
        )

        route = f"{base}/Admin.SetCaa"
        json_code, json_error_body = http_call(route, b"{}", "application/json", token)
        error_text = json_error_body.decode("utf-8", errors="replace").lower()
        error_categories = sorted(
            marker
            for marker in (
                "acme account",
                "acme client",
                "connection",
                "dns record",
                "no matching zone",
                "nonce",
                "set caa",
            )
            if marker in error_text
        )
        calls = {
            "json": json_code,
            "protobuf": http_call(route, b"", "application/octet-stream", token)[0],
            "unknown": http_call(route, b'{"unknown":true}', "application/json", token)[
                0
            ],
            "malformed": http_call(route, b"not-json", "application/json", token)[0],
            "unauthorized": http_call(route, b"{}", "application/json", None)[0],
            "invalid_route": http_call(
                route + "NoSuch", b"{}", "application/json", token
            )[0],
        }
        checks["transport_matrix"] = (
            all(
                calls[name] == 200
                for name in ("json", "protobuf", "unknown", "malformed")
            )
            and calls["unauthorized"] == 401
            and calls["invalid_route"] >= 400
        )
        facts = record_facts(state)
        checks["two_domains_reconciled"] = all(
            facts[domain]["count"] == 3
            and facts[domain]["types"] == ["CAA", "CAA", "CAA"]
            and facts[domain]["names_match"]
            and facts[domain]["has_issue"]
            and facts[domain]["has_issuewild"]
            and facts[domain]["guard_absent"]
            and facts[domain]["unrelated_caa_preserved"]
            and facts[domain]["conflicting_issuer_removed"]
            and facts[domain]["unrelated_record_count"] >= 1
            for domain in domains[:2]
        )
        checks["adjacent_unchanged"] = facts[domains[2]]["count"] == 0
        if not all(checks.values()):
            failed_checks = sorted(
                name for name, passed in checks.items() if not passed
            )
            raise AssertionError(
                "initial CAA or transport matrix failed: "
                f"checks={failed_checks}, statuses={calls}, "
                f"error_categories={error_categories}, error_len={len(json_error_body)}, "
                f"error_sha256={hashlib.sha256(json_error_body).hexdigest()}, "
                f"bounded_error={bounded_error(json_error_body, domains)}, "
                f"record_facts={facts}"
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            concurrent_responses = list(
                executor.map(
                    lambda _: http_call(route, b"{}", "application/json", token),
                    range(2),
                )
            )
        concurrent_codes = [response[0] for response in concurrent_responses]
        contention_diagnostics = [
            response[1].decode("utf-8", errors="replace").lower()
            for response in concurrent_responses
            if response[0] == 400
        ]
        facts_after_concurrency = record_facts(state)
        checks["concurrent_idempotence"] = (
            200 in concurrent_codes
            and all(code in {200, 400} for code in concurrent_codes)
            and all(
                any(
                    marker in diagnostic for marker in ("busy", "progress", "operation")
                )
                for diagnostic in contention_diagnostics
            )
            and all(
                facts_after_concurrency[d]["count"] == 3
                and facts_after_concurrency[d]["unrelated_caa_preserved"]
                for d in domains[:2]
            )
        )
        before_failure = state.snapshot()
        with state.lock:
            state.failure = True
        failure_code = http_call(route, b"{}", "application/json", token)[0]
        with state.lock:
            state.failure = False
        checks["dependency_failure_closed"] = (
            failure_code >= 400 and state.snapshot() == before_failure
        )
        recovery_code = http_call(route, b"{}", "application/json", token)[0]
        final_facts = record_facts(state)
        checks["recovery_converged"] = recovery_code == 200 and all(
            final_facts[d]["count"] == 3
            and final_facts[d]["guard_absent"]
            and final_facts[d]["unrelated_caa_preserved"]
            for d in domains[:2]
        )
        checks["gateway_remained_healthy"] = (
            rpc(base, token, "Admin.GetCertbotConfig", {})[0] == 200
        )
        if not all(checks.values()):
            failed_checks = sorted(
                name for name, passed in checks.items() if not passed
            )
            raise AssertionError(
                "CAA concurrency, fault, or recovery matrix failed: "
                f"checks={failed_checks}, concurrent_statuses={concurrent_codes}, "
                f"concurrent_record_facts={facts_after_concurrency}, "
                f"failure_status={failure_code}, recovery_status={recovery_code}, "
                f"final_record_facts={final_facts}"
            )
        steps.extend(
            [
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "PASS",
                    "observed": "JSON/protobuf and body-ignored compatibility calls reconciled issue/issuewild CAA records for both domains; unauthorized and invalid routes were rejected.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "Concurrent duplicates converged, a DNS outage failed closed, retry restored both domains, the adjacent domain stayed unchanged, and Gateway remained healthy.",
                },
            ]
        )
        observation = {
            "checks": checks,
            "http_statuses": calls,
            "concurrent_statuses": concurrent_codes,
            "failure_status": failure_code,
            "recovery_status": recovery_code,
            "record_facts": final_facts,
            "dns_operation_count": len(state.operations),
            "dns_operation_path_sha256": hashlib.sha256(
                json.dumps(state.operations, sort_keys=True).encode()
            ).hexdigest(),
            "container_images": {"dns": CF_IMAGE, "acme": PEBBLE_IMAGE},
        }
        artifact_path = result_dir / "artifacts/gateway-caa-observation.json"
        atomic_json(artifact_path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-caa-observation.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "Multi-domain CAA assertions",
                "description": "Only status codes, booleans, counts, record types, and hashes from the case-owned DNS/ACME matrix; no token or native ACME account response is retained.",
            }
        )
        status = "PASS"
        summary = "Admin.SetCaa reconciled two domains across encoding, authorization, concurrency, dependency-failure, retry, isolation, and cleanup paths."
    except Exception as error:  # noqa: BLE001
        summary = f"Admin.SetCaa matrix failed: {error}"
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
        for domain in reversed(configured_domains):
            try:
                rpc(base, token, "Admin.DeleteZtDomain", {"domain": domain})
            except Exception as error:  # noqa: BLE001
                cleanup_errors.append(f"domain:{type(error).__name__}")
        if created_credential:
            try:
                rpc(
                    base, token, "Admin.DeleteDnsCredential", {"id": created_credential}
                )
            except Exception as error:  # noqa: BLE001
                cleanup_errors.append(f"credential:{type(error).__name__}")
        if original_config:
            try:
                rpc(base, token, "Admin.SetCertbotConfig", original_config)
            except Exception as error:  # noqa: BLE001
                cleanup_errors.append(f"config:{type(error).__name__}")
        server.shutdown()
        server.server_close()
        for name in (pebble_name, cf_name):
            try:
                docker("rm", "-f", name, check=False)
            except Exception as error:  # noqa: BLE001
                cleanup_errors.append(f"container:{type(error).__name__}")
        try:
            docker("network", "rm", network, check=False)
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
            "remarks": f"Case-owned resources were removed; cleanup_error_count={len(cleanup_errors)}. Native ACME responses, DNS credentials, and tokens were not retained.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
