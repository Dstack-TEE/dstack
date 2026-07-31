#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway DNS credential CRUD, redaction, defaults, and references."""

from __future__ import annotations

import concurrent.futures
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
from typing import Any

CASE_ID = "tc-gw-certificat-003"


def load_support() -> Any:
    """Load the shared Gateway HTTP helpers."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location(
        "gateway_dns_credential_support", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway support")
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


def json_rpc(
    base: str, token: str, method: str, value: dict[str, Any]
) -> tuple[int, dict[str, Any]]:
    """Invoke a JSON Admin RPC and decode only in memory."""
    code, body = SUPPORT.rpc(base, token, method, value)
    try:
        decoded = json.loads(body) if body else {}
    except json.JSONDecodeError:
        decoded = {}
    return code, decoded


def redacted(token: str) -> str:
    """Return the product's documented public token representation."""
    return f"{token[:4]}...{token[-4:]}" if len(token) > 8 else "*" * len(token)


def contains_bytes(root: pathlib.Path, values: list[bytes]) -> bool:
    """Check bounded lease-owned persistent files without retaining contents."""
    for path in root.rglob("*"):
        if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if any(value in data for value in values):
            return True
    return False


def main() -> int:
    """Run CRUD, boundary, authorization, concurrency, reference, and cleanup paths."""
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
    prefix = f"dns-{lease}"
    secret_one = f"sentinel-one-{lease}-alpha"
    secret_two = f"sentinel-two-{lease}-beta"
    updated_secret = f"sentinel-updated-{lease}-gamma"
    created_ids: list[str] = []
    configured_domain: str | None = None
    baseline_default = ""
    baseline_ids: set[str | None] = set()
    checks: dict[str, bool] = {}
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    cleanup_notes: list[str] = []
    status = "FAIL"
    summary = "DNS credential case did not complete"

    try:
        list_code, baseline = json_rpc(
            base, admin_token, "Admin.ListDnsCredentials", {}
        )
        baseline_credentials = baseline.get("credentials", [])
        baseline_ids = {item.get("id") for item in baseline_credentials}
        baseline_default = baseline.get("default_id", baseline.get("defaultId", ""))
        checks["baseline_healthy"] = list_code == 200 and all(
            not str(item.get("name", "")).startswith(prefix)
            for item in baseline_credentials
        )
        if not checks["baseline_healthy"]:
            raise AssertionError("credential baseline was not healthy or isolated")
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The lease-owned admin listener was healthy and no run-scoped credential existed.",
            }
        )

        create_common = {
            "provider_type": "cloudflare",
            "cf_zone_id": "compatibility-input",
            "set_as_default": False,
            "cf_api_url": "http://127.0.0.1:9/client/v4",
            "dns_txt_ttl": 60,
            "max_dns_wait": 5,
        }
        code_one, credential_one = json_rpc(
            base,
            admin_token,
            "Admin.CreateDnsCredential",
            {
                **create_common,
                "name": f"{prefix}-one",
                "cf_api_token": secret_one,
            },
        )
        code_two, credential_two = json_rpc(
            base,
            admin_token,
            "Admin.CreateDnsCredential",
            {
                **create_common,
                "name": f"{prefix}-two",
                "cf_api_token": secret_two,
            },
        )
        if code_one == 200:
            created_ids.append(str(credential_one["id"]))
        if code_two == 200:
            created_ids.append(str(credential_two["id"]))
        checks["create_and_redact"] = (
            code_one == 200
            and code_two == 200
            and credential_one.get("cf_api_token", credential_one.get("cfApiToken"))
            == redacted(secret_one)
            and credential_two.get("cf_api_token", credential_two.get("cfApiToken"))
            == redacted(secret_two)
            and secret_one not in json.dumps(credential_one)
            and secret_two not in json.dumps(credential_two)
        )
        first_id, second_id = created_ids[:2]
        update_code, updated = json_rpc(
            base,
            admin_token,
            "Admin.UpdateDnsCredential",
            {
                "id": first_id,
                "name": f"{prefix}-renamed",
                "cf_api_token": updated_secret,
                "cf_api_url": "https://127.0.0.1:9443/client/v4",
            },
        )
        get_code, fetched = json_rpc(
            base, admin_token, "Admin.GetDnsCredential", {"id": first_id}
        )
        checks["update_and_read_redacted"] = (
            update_code == 200
            and get_code == 200
            and fetched.get("name") == f"{prefix}-renamed"
            and fetched.get("cf_api_token", fetched.get("cfApiToken"))
            == redacted(updated_secret)
            and updated_secret not in json.dumps(updated)
            and int(fetched.get("updated_at", fetched.get("updatedAt", 0)))
            >= int(fetched.get("created_at", fetched.get("createdAt", 0)))
        )

        set_first = SUPPORT.rpc(
            base,
            admin_token,
            "Admin.SetDefaultDnsCredential",
            {"id": first_id},
        )[0]
        default_code, default_value = json_rpc(
            base, admin_token, "Admin.GetDefaultDnsCredential", {}
        )
        default_credential = default_value.get("credential") or {}
        checks["default_selection"] = (
            set_first == 200
            and default_code == 200
            and default_value.get("default_id", default_value.get("defaultId"))
            == first_id
            and default_credential.get(
                "cf_api_token", default_credential.get("cfApiToken")
            )
            == redacted(updated_secret)
        )
        delete_default_code = SUPPORT.rpc(
            base,
            admin_token,
            "Admin.DeleteDnsCredential",
            {"id": first_id},
        )[0]
        domain = f"{prefix}.test"
        add_domain_code = SUPPORT.rpc(
            base,
            admin_token,
            "Admin.AddZtDomain",
            {
                "domain": domain,
                "dns_cred_id": first_id,
                "port": 443,
                "priority": 0,
            },
        )[0]
        if add_domain_code == 200:
            configured_domain = domain
        set_second = SUPPORT.rpc(
            base,
            admin_token,
            "Admin.SetDefaultDnsCredential",
            {"id": second_id},
        )[0]
        delete_in_use_code = SUPPORT.rpc(
            base,
            admin_token,
            "Admin.DeleteDnsCredential",
            {"id": first_id},
        )[0]
        checks["referential_integrity"] = (
            delete_default_code >= 400
            and add_domain_code == 200
            and set_second == 200
            and delete_in_use_code >= 400
        )

        invalid_statuses = {
            "provider": SUPPORT.rpc(
                base,
                admin_token,
                "Admin.CreateDnsCredential",
                {
                    **create_common,
                    "name": f"{prefix}-bad-provider",
                    "provider_type": "invalid",
                    "cf_api_token": "sentinel",
                },
            )[0],
            "empty_secret": SUPPORT.rpc(
                base,
                admin_token,
                "Admin.CreateDnsCredential",
                {
                    **create_common,
                    "name": f"{prefix}-empty",
                    "cf_api_token": "",
                },
            )[0],
            "zero_ttl": SUPPORT.rpc(
                base,
                admin_token,
                "Admin.CreateDnsCredential",
                {
                    **create_common,
                    "name": f"{prefix}-zero-ttl",
                    "cf_api_token": "sentinel",
                    "dns_txt_ttl": 0,
                },
            )[0],
            "zero_wait": SUPPORT.rpc(
                base,
                admin_token,
                "Admin.CreateDnsCredential",
                {
                    **create_common,
                    "name": f"{prefix}-zero-wait",
                    "cf_api_token": "sentinel",
                    "max_dns_wait": 0,
                },
            )[0],
            "missing_get": SUPPORT.rpc(
                base,
                admin_token,
                "Admin.GetDnsCredential",
                {"id": f"missing-{lease}"},
            )[0],
            "missing_default": SUPPORT.rpc(
                base,
                admin_token,
                "Admin.SetDefaultDnsCredential",
                {"id": f"missing-{lease}"},
            )[0],
            "unauthorized": SUPPORT.http_call(
                f"{base}/Admin.ListDnsCredentials",
                b"{}",
                "application/json",
                None,
            )[0],
        }
        checks["invalid_inputs_rejected"] = (
            invalid_statuses["provider"] >= 400
            and invalid_statuses["empty_secret"] >= 400
            and invalid_statuses["zero_ttl"] >= 400
            and invalid_statuses["zero_wait"] >= 400
            and invalid_statuses["missing_get"] >= 400
            and invalid_statuses["missing_default"] >= 400
            and invalid_statuses["unauthorized"] == 401
        )

        concurrent_names = [f"{prefix}-concurrent-{index}" for index in range(4)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            concurrent_responses = list(
                executor.map(
                    lambda name: json_rpc(
                        base,
                        admin_token,
                        "Admin.CreateDnsCredential",
                        {
                            **create_common,
                            "name": name,
                            "cf_api_token": f"sentinel-{name}",
                        },
                    ),
                    concurrent_names,
                )
            )
        concurrent_ids = [
            str(value["id"]) for code, value in concurrent_responses if code == 200
        ]
        created_ids.extend(concurrent_ids)
        checks["concurrent_create_isolated"] = (
            len(concurrent_ids) == 4 and len(set(concurrent_ids)) == 4
        )

        persistence_root = pathlib.Path(gateway["config"]).parents[1] / "data"
        checks["persistent_secret_not_plaintext"] = not contains_bytes(
            persistence_root,
            [secret_one.encode(), secret_two.encode(), updated_secret.encode()],
        )
        list_after_code, after = json_rpc(
            base, admin_token, "Admin.ListDnsCredentials", {}
        )
        after_rows = after.get("credentials", [])
        checks["list_complete_and_redacted"] = (
            list_after_code == 200
            and set(created_ids).issubset({str(row.get("id")) for row in after_rows})
            and all(
                "..." in str(row.get("cf_api_token", row.get("cfApiToken", "")))
                for row in after_rows
                if str(row.get("id")) in set(created_ids)
            )
            and all(
                secret not in json.dumps(after)
                for secret in (secret_one, secret_two, updated_secret)
            )
        )
        if not all(checks.values()):
            raise AssertionError(
                "DNS credential matrix failed: "
                f"{sorted(name for name, passed in checks.items() if not passed)}"
            )
        steps.extend(
            [
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "PASS",
                    "observed": "Create/read/update/list/default operations redacted secrets; invalid inputs were rejected and default/in-use deletion preserved references.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "Concurrent creates remained isolated, persistent files contained no sentinel plaintext, repeated listing stayed redacted, and the admin listener remained healthy.",
                },
            ]
        )
        facts = {
            "checks": checks,
            "baseline_credential_count": len(baseline_credentials),
            "baseline_default_present": bool(baseline_default),
            "created_count": len(created_ids),
            "concurrent_created_count": len(concurrent_ids),
            "invalid_statuses": invalid_statuses,
            "redaction_shapes": {
                "create_one": credential_one.get(
                    "cf_api_token", credential_one.get("cfApiToken")
                ),
                "create_two": credential_two.get(
                    "cf_api_token", credential_two.get("cfApiToken")
                ),
                "updated": fetched.get("cf_api_token", fetched.get("cfApiToken")),
            },
            "default_switch_http": [set_first, set_second],
            "protected_delete_http": [
                delete_default_code,
                delete_in_use_code,
            ],
        }
        artifact_path = result_dir / "artifacts/gateway-dns-credential-observation.json"
        atomic_json(artifact_path, facts)
        artifacts.append(
            {
                "path": "artifacts/gateway-dns-credential-observation.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "DNS credential assertions",
                "description": "Status codes, counts, booleans, and intentionally redacted token shapes only; no native secret is retained.",
            }
        )
        status = "PASS"
        summary = "Gateway DNS credential CRUD, redaction, defaults, references, invalid inputs, concurrency, persistence, and isolation passed."
    except Exception as error:  # noqa: BLE001
        summary = f"Gateway DNS credential matrix failed: {error}"
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
        if configured_domain:
            code = SUPPORT.rpc(
                base,
                admin_token,
                "Admin.DeleteZtDomain",
                {"domain": configured_domain},
            )[0]
            if code != 200:
                cleanup_notes.append(f"domain_http_{code}")
        if baseline_default and str(baseline_default) in baseline_ids:
            SUPPORT.rpc(
                base,
                admin_token,
                "Admin.SetDefaultDnsCredential",
                {"id": baseline_default},
            )
        for credential_id in reversed(created_ids):
            code = SUPPORT.rpc(
                base,
                admin_token,
                "Admin.DeleteDnsCredential",
                {"id": credential_id},
            )[0]
            if code != 200:
                cleanup_notes.append(f"credential_http_{code}")

    # A newly selected default cannot be cleared by the current API when the
    # fixture began without one. The lease destroys its isolated WaveKV store.
    expected_default_teardown = not baseline_default and bool(created_ids)
    unexpected_cleanup = [
        item
        for item in cleanup_notes
        if not (expected_default_teardown and item.startswith("credential_http_"))
    ]
    if unexpected_cleanup:
        status = "FAIL"
        summary = (
            "Case behavior completed but cleanup reported unexpected bounded errors."
        )
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
            "remarks": f"External cleanup errors={len(unexpected_cleanup)}; lease-local default teardown={expected_default_teardown}. Native credential values were never retained.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
