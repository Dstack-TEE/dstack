#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise normalized Gateway ZT-domain CRUD and certificate lifecycle."""

from __future__ import annotations

import concurrent.futures
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import threading
import time
from typing import Any

CASE_ID = "tc-gw-certificat-004"


def load_support() -> Any:
    """Load the shared Gateway ACME/DNS support."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_zt_domain_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway ACME support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


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


def decoded(body: bytes) -> dict[str, Any]:
    """Decode a JSON response in memory."""
    try:
        return json.loads(body) if body else {}
    except json.JSONDecodeError:
        return {}


def config_of(value: dict[str, Any]) -> dict[str, Any]:
    """Return a ZT-domain config across protobuf JSON naming modes."""
    return value.get("config") or {}


def cert_of(value: dict[str, Any]) -> dict[str, Any]:
    """Return a ZT-domain certificate status across JSON naming modes."""
    return value.get("cert_status") or value.get("certStatus") or {}


def field(value: dict[str, Any], snake: str, camel: str, default: Any = None) -> Any:
    """Read one field across protobuf JSON naming modes."""
    return value.get(snake, value.get(camel, default))


def main() -> int:
    """Run normalized CRUD, issuance, boundary, concurrency, and cleanup paths."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    gateway = manifest["values"]["gateway"]
    base = str(gateway["admin_url"]).rstrip("/")
    admin_token = pathlib.Path(gateway["admin_auth_token_file"]).read_text().strip()
    lease = str(manifest.get("lease_id", "lease"))[-10:].replace("-", "")
    prefix = f"dstack-domain-{lease}"
    network, dns_name, pebble_name = f"{prefix}-net", f"{prefix}-dns", f"{prefix}-acme"
    normalized = f"mixed-{lease}.test"
    presentation = f"*.MiXeD-{lease}.TEST."
    adjacent = f"adjacent-{lease}.test"
    state = SUPPORT.DnsState([normalized, adjacent])
    server = SUPPORT.CloudflareServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    credential_ids: list[str] = []
    domain_present = False
    original_config: dict[str, Any] | None = None
    cleanup_errors: list[str] = []
    checks: dict[str, bool] = {}
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    status = "FAIL"
    summary = "ZT-domain lifecycle did not complete"

    try:
        thread.start()
        SUPPORT.docker("network", "create", network)
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

        code, body = SUPPORT.rpc(base, admin_token, "Admin.GetCertbotConfig", {})
        if code != 200:
            raise AssertionError(f"GetCertbotConfig HTTP {code}")
        original_config = decoded(body)
        replacement = {
            "renew_interval_secs": original_config["renew_interval_secs"],
            "renew_before_expiration_secs": original_config[
                "renew_before_expiration_secs"
            ],
            "renew_timeout_secs": original_config["renew_timeout_secs"],
            "acme_url": pebble_url,
        }
        if (
            SUPPORT.rpc(base, admin_token, "Admin.SetCertbotConfig", replacement)[0]
            != 200
        ):
            raise AssertionError("failed to install case ACME URL")
        for index in range(2):
            code, body = SUPPORT.rpc(
                base,
                admin_token,
                "Admin.CreateDnsCredential",
                {
                    "name": f"{prefix}-credential-{index}",
                    "provider_type": "cloudflare",
                    "cf_api_token": SUPPORT.SENTINEL_TOKEN,
                    "set_as_default": False,
                    "cf_api_url": cf_url,
                    "dns_txt_ttl": 60,
                    "max_dns_wait": 5,
                },
            )
            if code != 200:
                raise AssertionError(f"CreateDnsCredential[{index}] HTTP {code}")
            credential_ids.append(str(decoded(body)["id"]))
        list_code, list_body = SUPPORT.rpc(base, admin_token, "Admin.ListZtDomains", {})
        baseline = decoded(list_body).get("domains", []) if list_code == 200 else []
        checks["baseline_healthy"] = list_code == 200 and all(
            config_of(row).get("domain") != normalized for row in baseline
        )
        if not checks["baseline_healthy"]:
            raise AssertionError("run-scoped domain existed at baseline")
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "Lease-owned Gateway, two DNS credentials, Pebble, and an empty run-scoped domain baseline were healthy.",
            }
        )

        add_request = {
            "domain": presentation,
            "dns_cred_id": credential_ids[0],
            "port": 443,
            "priority": 10,
        }
        add_code, add_body = SUPPORT.rpc(
            base, admin_token, "Admin.AddZtDomain", add_request
        )
        added = decoded(add_body)
        domain_present = add_code == 200
        added_config = config_of(added)
        checks["wildcard_normalized"] = (
            add_code == 200
            and added_config.get("domain") == normalized
            and field(added_config, "dns_cred_id", "dnsCredId") == credential_ids[0]
            and int(added_config.get("port", 0)) == 443
            and int(added_config.get("priority", 0)) == 10
        )
        duplicate_statuses = [
            SUPPORT.rpc(
                base,
                admin_token,
                "Admin.AddZtDomain",
                {**add_request, "domain": normalized},
            )[0],
            SUPPORT.rpc(
                base,
                admin_token,
                "Admin.AddZtDomain",
                {**add_request, "domain": normalized.upper() + "."},
            )[0],
            SUPPORT.rpc(base, admin_token, "Admin.AddZtDomain", add_request)[0],
        ]
        get_code, get_body = SUPPORT.rpc(
            base, admin_token, "Admin.GetZtDomain", {"domain": presentation}
        )
        listed_code, listed_body = SUPPORT.rpc(
            base, admin_token, "Admin.ListZtDomains", {}
        )
        listed = decoded(listed_body).get("domains", []) if listed_code == 200 else []
        checks["unique_get_list"] = (
            all(code >= 400 for code in duplicate_statuses)
            and get_code == 200
            and config_of(decoded(get_body)).get("domain") == normalized
            and sum(config_of(row).get("domain") == normalized for row in listed) == 1
        )

        update_code, update_body = SUPPORT.rpc(
            base,
            admin_token,
            "Admin.UpdateZtDomain",
            {
                "domain": presentation,
                "dns_cred_id": credential_ids[1],
                "port": 8443,
                "priority": -5,
            },
        )
        updated_config = config_of(decoded(update_body))
        checks["update_provider_policy"] = (
            update_code == 200
            and updated_config.get("domain") == normalized
            and field(updated_config, "dns_cred_id", "dnsCredId") == credential_ids[1]
            and int(updated_config.get("port", 0)) == 8443
            and int(updated_config.get("priority", 0)) == -5
        )

        invalid_inputs = {
            "empty": "",
            "root": ".",
            "slash": "bad/domain",
            "empty_label": "bad..test",
            "leading_hyphen": "-bad.test",
            "trailing_hyphen": "bad-.test",
            "unicode": "tést.example",
            "long_label": "a" * 64 + ".test",
        }
        invalid_statuses = {
            name: SUPPORT.rpc(
                base,
                admin_token,
                "Admin.AddZtDomain",
                {
                    "domain": value,
                    "dns_cred_id": credential_ids[0],
                    "port": 443,
                    "priority": 0,
                },
            )[0]
            for name, value in invalid_inputs.items()
        }
        missing_credential_code = SUPPORT.rpc(
            base,
            admin_token,
            "Admin.UpdateZtDomain",
            {
                "domain": normalized,
                "dns_cred_id": f"missing-{lease}",
                "port": 443,
                "priority": 0,
            },
        )[0]
        zero_port_code = SUPPORT.rpc(
            base,
            admin_token,
            "Admin.UpdateZtDomain",
            {
                "domain": normalized,
                "dns_cred_id": credential_ids[1],
                "port": 0,
                "priority": 0,
            },
        )[0]
        missing_domain_code = SUPPORT.rpc(
            base,
            admin_token,
            "Admin.UpdateZtDomain",
            {
                "domain": adjacent,
                "dns_cred_id": credential_ids[1],
                "port": 443,
                "priority": 0,
            },
        )[0]
        unauthorized_code = SUPPORT.http_call(
            f"{base}/Admin.ListZtDomains", b"{}", "application/json", None
        )[0]
        checks["invalid_inputs_atomic"] = (
            all(code >= 400 for code in invalid_statuses.values())
            and missing_credential_code >= 400
            and zero_port_code >= 400
            and missing_domain_code >= 400
            and unauthorized_code == 401
        )

        route = f"{base}/Admin.RenewZtDomainCert"
        renewal_attempts = 0
        renewed = False
        not_after = 0
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            renewal_attempts += 1
            code, body = SUPPORT.http_call(
                route,
                json.dumps({"domain": normalized, "force": True}).encode(),
                "application/json",
                admin_token,
            )
            if code == 200:
                value = decoded(body)
                renewed = bool(value.get("renewed"))
                not_after = int(field(value, "not_after", "notAfter", 0))
            if renewed and not_after > 0:
                break
            time.sleep(0.25)
        cert_get_code, cert_get_body = SUPPORT.rpc(
            base, admin_token, "Admin.GetZtDomain", {"domain": normalized}
        )
        cert_status = cert_of(decoded(cert_get_body))
        checks["certificate_lifecycle"] = (
            renewed
            and not_after > 0
            and cert_get_code == 200
            and bool(field(cert_status, "has_cert", "hasCert", False))
            and int(field(cert_status, "not_after", "notAfter", 0)) == not_after
            and bool(field(cert_status, "loaded_in_memory", "loadedInMemory", False))
        )

        concurrent_domain = f"concurrent-{lease}.test"
        concurrent_request = {
            "domain": concurrent_domain,
            "dns_cred_id": credential_ids[0],
            "port": 443,
            "priority": 0,
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            concurrent_codes = list(
                executor.map(
                    lambda _: SUPPORT.rpc(
                        base, admin_token, "Admin.AddZtDomain", concurrent_request
                    )[0],
                    range(2),
                )
            )
        concurrent_delete = SUPPORT.rpc(
            base, admin_token, "Admin.DeleteZtDomain", {"domain": concurrent_domain}
        )[0]
        checks["concurrent_add_once"] = (
            sorted(concurrent_codes) == [200, 400] and concurrent_delete == 200
        )
        if not all(checks.values()):
            certificate_flags = {
                "renewal_http": code,
                "renewed": renewed,
                "renewal_expiry_positive": not_after > 0,
                "get_http_ok": cert_get_code == 200,
                "stored_certificate_present": bool(
                    field(cert_status, "has_cert", "hasCert", False)
                ),
                "stored_expiry_matches": int(
                    field(cert_status, "not_after", "notAfter", 0)
                )
                == not_after,
                "resolver_loaded": bool(
                    field(
                        cert_status,
                        "loaded_in_memory",
                        "loadedInMemory",
                        False,
                    )
                ),
            }
            raise AssertionError(
                "ZT-domain matrix failed: "
                f"{sorted(name for name, passed in checks.items() if not passed)}; "
                f"certificate_flags={certificate_flags}"
            )
        steps.extend(
            [
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "PASS",
                    "observed": "Wildcard/case/root-dot inputs normalized once; duplicate and invalid inputs failed atomically; get/list/update and credential-policy changes matched the stored domain.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "Certificate issuance populated and loaded the domain state, concurrent duplicate add committed once, unauthorized access failed, and adjacent state remained isolated.",
                },
            ]
        )
        observation = {
            "checks": checks,
            "normalized_domain": normalized,
            "baseline_domain_count": len(baseline),
            "duplicate_statuses": duplicate_statuses,
            "invalid_statuses": invalid_statuses,
            "missing_credential_http": missing_credential_code,
            "zero_port_http": zero_port_code,
            "missing_domain_http": missing_domain_code,
            "unauthorized_http": unauthorized_code,
            "renewal_attempts": renewal_attempts,
            "renewed": renewed,
            "not_after_positive": not_after > 0,
            "concurrent_statuses": concurrent_codes,
        }
        artifact_path = result_dir / "artifacts/gateway-zt-domain-observation.json"
        atomic_json(artifact_path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-zt-domain-observation.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "ZT-domain lifecycle assertions",
                "description": "Public normalized names, status codes, booleans, counts, and expiry presence only; no certificate, ACME response, DNS credential, or token is retained.",
            }
        )
        status = "PASS"
        summary = "Gateway ZT-domain normalization, CRUD, certificate lifecycle, invalid-input atomicity, concurrency, authorization, and isolation passed."
    except Exception as error:  # noqa: BLE001
        summary = f"Gateway ZT-domain matrix failed: {error}"
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
        if domain_present:
            code = SUPPORT.rpc(
                base, admin_token, "Admin.DeleteZtDomain", {"domain": normalized}
            )[0]
            if code != 200:
                cleanup_errors.append(f"domain_http_{code}")
        for credential_id in reversed(credential_ids):
            code = SUPPORT.rpc(
                base, admin_token, "Admin.DeleteDnsCredential", {"id": credential_id}
            )[0]
            if code != 200:
                cleanup_errors.append(f"credential_http_{code}")
        if original_config:
            code = SUPPORT.rpc(
                base, admin_token, "Admin.SetCertbotConfig", original_config
            )[0]
            if code != 200:
                cleanup_errors.append(f"config_http_{code}")
        server.shutdown()
        server.server_close()
        for name in (pebble_name, dns_name):
            SUPPORT.docker("rm", "-f", name, check=False)
        SUPPORT.docker("network", "rm", network, check=False)

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
