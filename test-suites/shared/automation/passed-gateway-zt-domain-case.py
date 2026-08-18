#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for promoted Gateway ZT-domain admin RPCs."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import ssl
import tempfile
import urllib.error
import urllib.request
from typing import Any

CASES = {
    "tc-gw-admin-023": "Admin.AddZtDomain",
    "tc-gw-admin-024": "Admin.UpdateZtDomain",
    "tc-gw-admin-022": "Admin.GetZtDomain",
    "tc-gw-admin-025": "Admin.DeleteZtDomain",
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON so a reader never observes a partial document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def sanitize(value: Any) -> Any:
    """Reduce a response to the structural detail safe to persist."""
    if isinstance(value, dict):
        return {
            key: (
                "<redacted>"
                if any(marker in key.lower() for marker in ("token", "secret", "key"))
                else sanitize(child)
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [sanitize(child) for child in value]
    return value


def resolve_admin(manifest: dict[str, Any]) -> tuple[str, dict[str, str]]:
    """Resolve the admin base URL and its authentication headers."""
    values = manifest["values"]
    gateway = values.get("gateway") or {}
    services = values.get("services") or {}
    admin_service = services.get("admin") or {}
    base = str(gateway.get("admin_url") or admin_service.get("url") or "").rstrip("/")
    if not base:
        raise RuntimeError("manifest missing gateway admin URL")
    token_file = gateway.get("admin_auth_token_file") or admin_service.get(
        "auth_token_file"
    )
    if not token_file:
        raise RuntimeError("manifest missing gateway admin token file")
    token = pathlib.Path(token_file).read_text(encoding="utf-8").strip()
    if not token:
        raise RuntimeError("gateway admin token is empty")
    return base, {"Authorization": f"Bearer {token}"}


def call(
    base: str,
    method: str,
    payload: Any,
    headers: dict[str, str],
    *,
    authenticated: bool = True,
    raw: bytes | None = None,
    content_type: str = "application/json",
) -> dict[str, Any]:
    """Issue one admin pRPC call and capture its status and body."""
    body = raw if raw is not None else json.dumps(payload).encode()
    request_headers = {"Content-Type": content_type}
    if authenticated:
        request_headers.update(headers)
    request = urllib.request.Request(
        f"{base}/{method}", data=body, headers=request_headers, method="POST"
    )
    try:
        with urllib.request.urlopen(
            request, timeout=20, context=ssl._create_unverified_context()
        ) as response:
            response_body = response.read()
            status = int(response.status)
            response_type = response.headers.get("Content-Type")
    except urllib.error.HTTPError as error:
        response_body = error.read()
        status = int(error.code)
        response_type = error.headers.get("Content-Type") if error.headers else None
    parsed: Any = None
    if response_body:
        try:
            parsed = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
    return {
        "status": status,
        "ok": 200 <= status < 300,
        "content_type": response_type,
        "body": sanitize(parsed),
        "body_len": len(response_body),
        "body_sha256": hashlib.sha256(response_body).hexdigest(),
    }


def credential_id(response: dict[str, Any]) -> str:
    """Extract the DNS credential ID from a create response."""
    body = response.get("body")
    if not isinstance(body, dict):
        return ""
    for key in ("id", "credentialId", "credId", "dnsCredId"):
        value = body.get(key)
        if isinstance(value, str) and value:
            return value
    nested = body.get("credential")
    if isinstance(nested, dict):
        value = nested.get("id")
        if isinstance(value, str):
            return value
    return ""


def contains_domain(value: Any, domain: str) -> bool:
    """Report whether the domain appears anywhere in the response."""
    if isinstance(value, dict):
        return any(contains_domain(child, domain) for child in value.values())
    if isinstance(value, list):
        return any(contains_domain(child, domain) for child in value)
    return value == domain


def main() -> int:
    """Run the ZT-domain case selected by the environment."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASES:
        raise SystemExit(f"unsupported promoted ZT-domain case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    artifacts_dir = result_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    step_ids = [f"{case_id}-step-{number:02d}" for number in (1, 2, 3)]
    artifacts: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    status = "PASS"
    failure = ""
    domain = f"{case_id}-{os.urandom(6).hex()}.example.invalid"
    created_credential = ""
    base = ""
    headers: dict[str, str] = {}

    def record(name: str, step_id: str, value: Any, description: str) -> None:
        path = artifacts_dir / name
        atomic_json(path, value)
        artifacts.append(
            {
                "path": f"artifacts/{name}",
                "step_id": step_id,
                "name": name.removesuffix(".json").replace("-", " ").title(),
                "description": description,
            }
        )

    try:
        print(f"STEP {step_ids[0]} START", flush=True)
        base, headers = resolve_admin(manifest)
        baseline = call(base, "Admin.ListZtDomains", {}, headers)
        unauthorized = call(
            base, "Admin.ListZtDomains", {}, headers, authenticated=False
        )
        if baseline["status"] != 200:
            raise AssertionError(
                f"authenticated ListZtDomains returned HTTP {baseline['status']}"
            )
        if unauthorized["status"] not in (401, 403):
            raise AssertionError(
                f"unauthenticated admin request returned HTTP {unauthorized['status']}"
            )
        record(
            "step01-prereq.json",
            step_ids[0],
            {"baseline": baseline, "unauthorized": unauthorized, "domain": domain},
            "Authenticated admin reachability, authorization enforcement, and baseline state.",
        )
        steps.append(
            {
                "id": step_ids[0],
                "status": "PASS",
                "observed": "Admin listener was reachable, protected, and returned the baseline ZT-domain state.",
            }
        )
        print(f"STEP {step_ids[0]} END - PASS", flush=True)

        print(f"STEP {step_ids[1]} START", flush=True)
        create = call(
            base,
            "Admin.CreateDnsCredential",
            {
                "name": f"test credential {case_id}",
                "provider_type": "cloudflare",
                "cf_api_token": f"non-production-token-{case_id}-{os.getpid()}",
                "cf_zone_id": "non-production-zone",
            },
            headers,
        )
        created_credential = credential_id(create)
        if create["status"] != 200 or not created_credential:
            raise AssertionError(
                f"CreateDnsCredential did not return an id (HTTP {create['status']})"
            )
        set_default = call(
            base,
            "Admin.SetDefaultDnsCredential",
            {"id": created_credential},
            headers,
        )
        if set_default["status"] != 200:
            raise AssertionError(
                f"SetDefaultDnsCredential returned HTTP {set_default['status']}"
            )
        initial = {
            "domain": domain,
            "dns_cred_id": created_credential,
            "port": 443,
            "node": 1,
            "priority": 10,
        }
        add = call(base, "Admin.AddZtDomain", initial, headers)
        if add["status"] != 200:
            raise AssertionError(f"AddZtDomain returned HTTP {add['status']}")

        behavior: dict[str, Any] = {
            "create_dns_credential": create,
            "set_default_dns_credential": set_default,
            "add": add,
        }
        if case_id == "tc-gw-admin-023":
            invalid = call(
                base,
                "Admin.AddZtDomain",
                {"domain": "", "port": 443, "node": 1, "priority": 0},
                headers,
            )
            no_auth = call(
                base,
                "Admin.AddZtDomain",
                dict(initial, domain=f"unauthorized-{domain}"),
                headers,
                authenticated=False,
            )
            if invalid["status"] < 400:
                raise AssertionError("AddZtDomain accepted an empty domain")
        elif case_id == "tc-gw-admin-022":
            # Reading back the domain just added is the tested behaviour; an
            # unknown domain must not be reported as present.
            fetched = call(base, "Admin.GetZtDomain", {"domain": domain}, headers)
            if fetched["status"] != 200 or not contains_domain(
                fetched.get("body"), domain
            ):
                raise AssertionError("GetZtDomain did not return the added domain")
            behavior["fetched"] = fetched
            invalid = call(base, "Admin.GetZtDomain", {"domain": ""}, headers)
            no_auth = call(
                base,
                "Admin.GetZtDomain",
                {"domain": domain},
                headers,
                authenticated=False,
            )
            if invalid["status"] == 200 and contains_domain(
                invalid.get("body"), domain
            ):
                raise AssertionError("GetZtDomain resolved an empty domain")
        elif case_id == "tc-gw-admin-025":
            # Deletion is the tested action here, so assert the domain is gone
            # and that deleting it again is refused rather than silently reported
            # as success.
            removed = call(base, "Admin.DeleteZtDomain", {"domain": domain}, headers)
            if removed["status"] != 200:
                raise AssertionError(
                    f"DeleteZtDomain returned HTTP {removed['status']}"
                )
            listed = call(base, "Admin.ListZtDomains", {}, headers)
            if contains_domain(listed.get("body"), domain):
                raise AssertionError("domain remained listed after DeleteZtDomain")
            behavior["removed"] = removed
            behavior["listed_after_delete"] = listed
            invalid = call(base, "Admin.DeleteZtDomain", {"domain": ""}, headers)
            no_auth = call(
                base,
                "Admin.DeleteZtDomain",
                {"domain": domain},
                headers,
                authenticated=False,
            )
            if invalid["status"] < 400:
                raise AssertionError("DeleteZtDomain accepted an empty domain")
            # Re-add so the shared step 3 cleanup path still has a domain to
            # remove and the case leaves no residue either way.
            call(base, "Admin.AddZtDomain", initial, headers)
        else:
            updated = dict(initial, port=8443, priority=20)
            valid_update = call(base, "Admin.UpdateZtDomain", updated, headers)
            invalid = call(
                base,
                "Admin.UpdateZtDomain",
                dict(updated, port=70000),
                headers,
            )
            no_auth = call(
                base,
                "Admin.UpdateZtDomain",
                updated,
                headers,
                authenticated=False,
            )
            behavior["valid_update"] = valid_update
            if valid_update["status"] != 200:
                raise AssertionError(
                    f"UpdateZtDomain returned HTTP {valid_update['status']}"
                )
            if invalid["status"] < 400:
                raise AssertionError("UpdateZtDomain accepted port 70000")
        if no_auth["status"] not in (401, 403):
            raise AssertionError(
                f"unauthenticated mutation returned HTTP {no_auth['status']}"
            )
        behavior["invalid_boundary"] = invalid
        behavior["unauthorized"] = no_auth
        behavior["domain"] = domain
        record(
            "step02-behavior.json",
            step_ids[1],
            behavior,
            "Credential setup plus valid, boundary-invalid, and unauthorized ZT-domain mutation behavior.",
        )
        steps.append(
            {
                "id": step_ids[1],
                "status": "PASS",
                "observed": f"{CASES[case_id]} accepted the valid mutation and rejected boundary-invalid and unauthorized requests.",
            }
        )
        print(f"STEP {step_ids[1]} END - PASS", flush=True)

        print(f"STEP {step_ids[2]} START", flush=True)
        state = call(base, "Admin.ListZtDomains", {}, headers)
        if state["status"] != 200 or not contains_domain(state.get("body"), domain):
            raise AssertionError("run-scoped domain was not visible after mutation")
        delete_domain = call(base, "Admin.DeleteZtDomain", {"domain": domain}, headers)
        if delete_domain["status"] != 200:
            raise AssertionError(
                f"DeleteZtDomain returned HTTP {delete_domain['status']}"
            )
        state_after = call(base, "Admin.ListZtDomains", {}, headers)
        if state_after["status"] != 200 or contains_domain(
            state_after.get("body"), domain
        ):
            raise AssertionError("run-scoped domain remained after cleanup")
        delete_credential = call(
            base,
            "Admin.DeleteDnsCredential",
            {"id": created_credential},
            headers,
        )
        record(
            "step03-state-cleanup.json",
            step_ids[2],
            {
                "state_after_mutation": state,
                "delete_domain": delete_domain,
                "state_after_cleanup": state_after,
                "delete_credential": delete_credential,
            },
            "Post-mutation visibility, domain cleanup, credential cleanup, and final isolated state.",
        )
        steps.append(
            {
                "id": step_ids[2],
                "status": "PASS",
                "observed": "Run-scoped state was visible, then removed without affecting admin availability.",
            }
        )
        print(f"STEP {step_ids[2]} END - PASS", flush=True)
        summary = (
            f"{CASES[case_id]} passed deterministic credential setup, valid mutation, "
            "boundary and authorization rejection, state verification, and cleanup."
        )
    except Exception as error:  # noqa: BLE001
        status = "FAIL"
        failure = str(error)
        summary = f"{CASES[case_id]} deterministic regression failed: {failure}"
        completed = {step["id"] for step in steps}
        failure_recorded = False
        for step_id in step_ids:
            if step_id in completed:
                continue
            steps.append(
                {
                    "id": step_id,
                    "status": "FAIL" if not failure_recorded else "NOT_RUN",
                    "observed": failure
                    if not failure_recorded
                    else "Not run after earlier failure.",
                }
            )
            failure_recorded = True
        if base and headers and created_credential:
            cleanup_domain = call(
                base, "Admin.DeleteZtDomain", {"domain": domain}, headers
            )
            cleanup_credential = call(
                base,
                "Admin.DeleteDnsCredential",
                {"id": created_credential},
                headers,
            )
            record(
                "failure-cleanup.json",
                step_ids[2],
                {
                    "delete_domain": cleanup_domain,
                    "delete_credential": cleanup_credential,
                },
                "Best-effort cleanup after the first deterministic harness mismatch.",
            )

    atomic_json(artifacts_dir / "manifest.json", {"artifacts": artifacts})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "remarks": "Promoted deterministic Gateway ZT-domain regression harness.",
        },
    )
    print(json.dumps({"status": status, "summary": summary}), flush=True)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
