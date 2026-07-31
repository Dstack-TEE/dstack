#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regressions for promoted Gateway DNS credential admin RPCs."""

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
    "tc-gw-admin-015": "Admin.GetDnsCredential",
    "tc-gw-admin-016": "Admin.CreateDnsCredential",
    "tc-gw-admin-017": "Admin.UpdateDnsCredential",
    "tc-gw-admin-018": "Admin.DeleteDnsCredential",
    "tc-gw-admin-020": "Admin.SetDefaultDnsCredential",
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def sanitize(value: Any) -> Any:
    """Redact credential material from evidence."""
    if isinstance(value, dict):
        return {
            key: (
                "<redacted>"
                if any(mark in key.lower() for mark in ("token", "secret", "key"))
                else sanitize(child)
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [sanitize(child) for child in value]
    return value


def inventory_entry(root: pathlib.Path, service: str, method: str) -> dict[str, Any]:
    """Load the authoritative field matrix for one RPC method."""
    document = json.loads((root / "api-inventory.json").read_text(encoding="utf-8"))
    matches: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("service") == service and value.get("method") == method:
                matches.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    if len(matches) != 1:
        raise RuntimeError(f"expected one inventory entry for {service}.{method}")
    return matches[0]


def varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode_request(fields: list[dict[str, Any]], payload: dict[str, Any]) -> bytes:
    """Encode a request body from the inventory field matrix."""
    output = bytearray()
    for field in fields:
        name = field["name"]
        if name not in payload:
            continue
        number = int(field["number"])
        kind = str(field["type"])
        value = payload[name]
        if kind == "string":
            raw = str(value).encode()
            output.extend(varint((number << 3) | 2))
            output.extend(varint(len(raw)))
            output.extend(raw)
        elif kind == "bool" or kind.startswith(("uint", "int", "sint")):
            output.extend(varint((number << 3) | 0))
            output.extend(varint(int(value)))
        else:
            raise ValueError(f"unsupported request field type: {kind}")
    return bytes(output)


def wire_field_numbers(data: bytes) -> list[int]:
    """Return the field numbers present in a protobuf response body."""
    numbers: list[int] = []
    offset = 0
    while offset < len(data):
        key = 0
        shift = 0
        while True:
            byte = data[offset]
            offset += 1
            key |= (byte & 0x7F) << shift
            if byte < 0x80:
                break
            shift += 7
        number, wire = key >> 3, key & 7
        numbers.append(number)
        if wire == 0:
            while data[offset] >= 0x80:
                offset += 1
            offset += 1
        elif wire == 2:
            length = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                length |= (byte & 0x7F) << shift
                if byte < 0x80:
                    break
                shift += 7
            offset += length
        else:
            raise ValueError(f"unsupported response wire type {wire}")
    return sorted(set(numbers))


def call(
    base: str,
    method: str,
    payload: Any,
    token: str | None,
    raw: bytes | None = None,
    content_type: str = "application/json",
    secret: str | None = None,
) -> dict[str, Any]:
    """Call an admin method without persisting authorization material."""
    body = raw if raw is not None else json.dumps(payload).encode()
    headers = {"Content-Type": content_type}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{base}/{method}", data=body, headers=headers, method="POST"
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
    parsed = None
    if response_body:
        try:
            parsed = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    observation: dict[str, Any] = {
        "status": status,
        "body": sanitize(parsed),
        "body_len": len(response_body),
        "body_sha256": hashlib.sha256(response_body).hexdigest(),
        "content_type": response_type,
    }
    if content_type == "application/octet-stream":
        observation["field_numbers"] = wire_field_numbers(response_body)
    if secret is not None:
        # The response must never echo the credential material it was given.
        observation["secret_disclosed"] = secret.encode() in response_body
    return observation


def credential_id(response: dict[str, Any]) -> str:
    """Extract the documented DNS credential id."""
    body = response.get("body")
    if not isinstance(body, dict):
        return ""
    value = body.get("id")
    return value if isinstance(value, str) else ""


def contains_id(value: Any, target: str) -> bool:
    """Return whether a JSON value contains a credential id."""
    if isinstance(value, dict):
        return value.get("id") == target or any(
            contains_id(child, target) for child in value.values()
        )
    if isinstance(value, list):
        return any(contains_id(child, target) for child in value)
    return False


def documented_body(response: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    """Require every documented response field and return the body."""
    body = response.get("body")
    expected = {field["name"] for field in entry["response_fields"]}
    if response["status"] != 200 or not isinstance(body, dict):
        raise AssertionError(
            f"{entry['service']}.{entry['method']} returned HTTP {response['status']}"
        )
    missing = sorted(expected - set(body))
    if missing:
        raise AssertionError(
            f"{entry['service']}.{entry['method']} response omitted fields: {missing}"
        )
    return body


def main() -> int:
    """Execute one promoted DNS credential regression."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASES:
        raise SystemExit(f"unsupported promoted DNS credential case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    gateway = manifest["values"]["gateway"]
    base = str(gateway["admin_url"]).rstrip("/")
    auth = (
        pathlib.Path(gateway["admin_auth_token_file"])
        .read_text(encoding="utf-8")
        .strip()
    )
    if not auth:
        raise RuntimeError("gateway admin token file is empty")
    artifacts_dir = result_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    step_ids = [f"{case_id}-step-{number:02d}" for number in (1, 2, 3)]
    steps: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    created_ids: list[str] = []
    # Held outside the try so a mismatch still ships the observations that
    # explain it; a bare assertion text is not enough to diagnose a rerun.
    behavior: dict[str, Any] = {}
    status = "PASS"
    failure = ""
    tag = f"{case_id}-{os.urandom(6).hex()}"
    # Deliberately unusable placeholders: an .invalid API host and obviously
    # non-production secrets, so a leak or an accidental live call is inert.
    secret_token = f"non-production-token-{tag}"
    valid_create = {
        "name": f"non-production-{tag}",
        "provider_type": "cloudflare",
        "cf_api_token": secret_token,
        "cf_zone_id": f"non-production-zone-{tag}",
        "set_as_default": False,
        "cf_api_url": "https://api.cloudflare.invalid/client/v4",
        # Distinct from the server defaults (60/300) so the echo is meaningful.
        "dns_txt_ttl": 61,
        "max_dns_wait": 301,
    }

    def record(name: str, step_id: str, value: Any, description: str) -> None:
        atomic_json(artifacts_dir / name, value)
        artifacts.append(
            {
                "path": f"artifacts/{name}",
                "step_id": step_id,
                "name": name.removesuffix(".json").replace("-", " ").title(),
                "description": description,
            }
        )

    def track(response: dict[str, Any]) -> str:
        identifier = credential_id(response)
        if identifier:
            created_ids.append(identifier)
        return identifier

    try:
        print(f"STEP {step_ids[0]} START", flush=True)
        baseline = call(base, "Admin.ListDnsCredentials", {}, auth)
        unauthorized = call(base, "Admin.ListDnsCredentials", {}, None)
        if baseline["status"] != 200 or unauthorized["status"] not in (401, 403):
            raise AssertionError(
                "admin prerequisite or authorization enforcement failed"
            )
        record(
            "step01-prereq.json",
            step_ids[0],
            {"baseline": baseline, "unauthorized": unauthorized, "tag": tag},
            "Authenticated DNS credential baseline and authorization enforcement.",
        )
        steps.append(
            {
                "id": step_ids[0],
                "status": "PASS",
                "observed": "Admin listener was reachable, protected, and returned DNS credential state.",
            }
        )
        print(f"STEP {step_ids[0]} END - PASS", flush=True)

        print(f"STEP {step_ids[1]} START", flush=True)
        create = call(
            base,
            "Admin.CreateDnsCredential",
            valid_create,
            auth,
            secret=secret_token,
        )
        created_id = track(create)
        if create["status"] != 200 or not created_id:
            raise AssertionError("CreateDnsCredential did not return a credential id")
        behavior["create"] = create
        if case_id == "tc-gw-admin-015":
            entry = inventory_entry(plan_root, "Admin", "GetDnsCredential")
            fetched = call(
                base,
                "Admin.GetDnsCredential",
                {"id": created_id},
                auth,
                secret=secret_token,
            )
            body = documented_body(fetched, entry)
            expected = {
                "id": created_id,
                "name": valid_create["name"],
                "provider_type": valid_create["provider_type"],
                "cf_api_url": valid_create["cf_api_url"],
                "dns_txt_ttl": valid_create["dns_txt_ttl"],
                "max_dns_wait": valid_create["max_dns_wait"],
            }
            mismatched = {
                key: body.get(key)
                for key, value in expected.items()
                if body.get(key) != value
            }
            if mismatched:
                raise AssertionError(f"GetDnsCredential returned {mismatched}")
            if fetched["secret_disclosed"]:
                raise AssertionError("GetDnsCredential echoed the API token verbatim")
            # The stored record carries no per-call clock, so a repeated read is
            # byte-identical; assert that rather than assume it.
            repeated = call(base, "Admin.GetDnsCredential", {"id": created_id}, auth)
            if repeated["body_sha256"] != fetched["body_sha256"]:
                raise AssertionError("repeated GetDnsCredential was not deterministic")
            unknown_field = call(
                base,
                "Admin.GetDnsCredential",
                {"id": created_id, "unknown_field_probe": True},
                auth,
            )
            if unknown_field["body_sha256"] != fetched["body_sha256"]:
                raise AssertionError("GetDnsCredential did not ignore an unknown field")
            protobuf = call(
                base,
                "Admin.GetDnsCredential",
                None,
                auth,
                raw=encode_request(entry["request_fields"], {"id": created_id}),
                content_type="application/octet-stream",
            )
            documented_numbers = {
                int(field["number"]) for field in entry["response_fields"]
            }
            if protobuf["status"] != 200 or not documented_numbers.issubset(
                set(protobuf["field_numbers"])
            ):
                raise AssertionError(
                    "protobuf GetDnsCredential omitted documented response fields"
                )
            empty_id = call(base, "Admin.GetDnsCredential", {"id": ""}, auth)
            unknown_id = call(
                base, "Admin.GetDnsCredential", {"id": f"absent-{tag}"}, auth
            )
            malformed = call(base, "Admin.GetDnsCredential", {}, auth, raw=b'{"id":')
            no_auth = call(base, "Admin.GetDnsCredential", {"id": created_id}, None)
            for name, response in (
                ("empty_id", empty_id),
                ("unknown_id", unknown_id),
                ("malformed", malformed),
            ):
                if response["status"] < 400:
                    raise AssertionError(
                        f"GetDnsCredential accepted the {name} request "
                        f"(HTTP {response['status']})"
                    )
            if no_auth["status"] not in (401, 403):
                raise AssertionError(
                    f"unauthenticated GetDnsCredential returned HTTP {no_auth['status']}"
                )
            removed = call(base, "Admin.DeleteDnsCredential", {"id": created_id}, auth)
            created_ids.remove(created_id)
            after_delete = call(
                base, "Admin.GetDnsCredential", {"id": created_id}, auth
            )
            if removed["status"] != 200 or after_delete["status"] < 400:
                raise AssertionError(
                    "GetDnsCredential still resolved a removed credential"
                )
            behavior.update(
                {
                    "fetched": fetched,
                    "repeated": repeated,
                    "unknown_field": unknown_field,
                    "protobuf": protobuf,
                    "empty_id": empty_id,
                    "unknown_id": unknown_id,
                    "malformed": malformed,
                    "unauthorized": no_auth,
                    "after_delete": after_delete,
                }
            )
        elif case_id == "tc-gw-admin-016":
            entry = inventory_entry(plan_root, "Admin", "CreateDnsCredential")
            body = documented_body(create, entry)
            echoed = {
                "name": valid_create["name"],
                "provider_type": valid_create["provider_type"],
                "cf_api_url": valid_create["cf_api_url"],
                "dns_txt_ttl": valid_create["dns_txt_ttl"],
                "max_dns_wait": valid_create["max_dns_wait"],
            }
            mismatched = {
                key: body.get(key)
                for key, value in echoed.items()
                if body.get(key) != value
            }
            if mismatched:
                raise AssertionError(f"CreateDnsCredential returned {mismatched}")
            if create["secret_disclosed"]:
                raise AssertionError(
                    "CreateDnsCredential echoed the API token verbatim"
                )
            listed = call(base, "Admin.ListDnsCredentials", {}, auth)
            if listed["status"] != 200 or not contains_id(
                listed.get("body"), created_id
            ):
                raise AssertionError("created credential was not persisted")
            protobuf = call(
                base,
                "Admin.CreateDnsCredential",
                None,
                auth,
                raw=encode_request(entry["request_fields"], valid_create),
                content_type="application/octet-stream",
            )
            if protobuf["status"] != 200:
                raise AssertionError("protobuf CreateDnsCredential was rejected")
            documented_numbers = {
                int(field["number"]) for field in entry["response_fields"]
            }
            if not documented_numbers.issubset(set(protobuf["field_numbers"])):
                raise AssertionError(
                    "protobuf CreateDnsCredential omitted documented response fields"
                )
            unknown_field = call(
                base,
                "Admin.CreateDnsCredential",
                dict(valid_create, unknown_field_probe=True),
                auth,
            )
            track(unknown_field)
            if unknown_field["status"] != 200:
                raise AssertionError(
                    "CreateDnsCredential did not ignore an unknown field"
                )
            absent_provider = call(base, "Admin.CreateDnsCredential", {}, auth)
            unsupported_provider = call(
                base,
                "Admin.CreateDnsCredential",
                dict(valid_create, provider_type=f"unsupported-{tag}"),
                auth,
            )
            zero_ttl = call(
                base,
                "Admin.CreateDnsCredential",
                dict(valid_create, dns_txt_ttl=0),
                auth,
            )
            overflow_ttl = call(
                base,
                "Admin.CreateDnsCredential",
                dict(valid_create, dns_txt_ttl=4294967296),
                auth,
            )
            malformed = call(
                base, "Admin.CreateDnsCredential", {}, auth, raw=b'{"name":'
            )
            no_auth = call(base, "Admin.CreateDnsCredential", valid_create, None)
            for name, response in (
                ("absent_provider", absent_provider),
                ("unsupported_provider", unsupported_provider),
                ("zero_ttl", zero_ttl),
                ("overflow_ttl", overflow_ttl),
                ("malformed", malformed),
            ):
                track(response)
                if response["status"] < 400:
                    raise AssertionError(
                        f"CreateDnsCredential accepted the {name} request"
                    )
            track(no_auth)
            if no_auth["status"] not in (401, 403):
                raise AssertionError("unauthenticated CreateDnsCredential was accepted")
            behavior.update(
                {
                    "listed": listed,
                    "protobuf": protobuf,
                    "unknown_field": unknown_field,
                    "absent_provider": absent_provider,
                    "unsupported_provider": unsupported_provider,
                    "zero_ttl": zero_ttl,
                    "overflow_ttl": overflow_ttl,
                    "malformed": malformed,
                    "unauthorized": no_auth,
                }
            )
        elif case_id == "tc-gw-admin-017":
            entry = inventory_entry(plan_root, "Admin", "UpdateDnsCredential")
            update = {
                "id": created_id,
                "name": f"non-production-updated-{tag}",
                "cf_api_token": f"non-production-token-updated-{tag}",
                "cf_zone_id": f"non-production-zone-updated-{tag}",
                "cf_api_url": "https://api-updated.cloudflare.invalid/client/v4",
            }
            updated = call(
                base,
                "Admin.UpdateDnsCredential",
                update,
                auth,
                secret=str(update["cf_api_token"]),
            )
            body = documented_body(updated, entry)
            expected = {
                "id": created_id,
                "name": update["name"],
                "cf_api_url": update["cf_api_url"],
                # Fields the request cannot address must survive the update.
                "provider_type": valid_create["provider_type"],
                "dns_txt_ttl": valid_create["dns_txt_ttl"],
                "max_dns_wait": valid_create["max_dns_wait"],
            }
            mismatched = {
                key: body.get(key)
                for key, value in expected.items()
                if body.get(key) != value
            }
            if mismatched:
                raise AssertionError(f"UpdateDnsCredential returned {mismatched}")
            if updated["secret_disclosed"]:
                raise AssertionError("UpdateDnsCredential echoed the API token")
            readback = call(base, "Admin.GetDnsCredential", {"id": created_id}, auth)
            if readback["body_sha256"] != updated["body_sha256"]:
                raise AssertionError("UpdateDnsCredential did not persist its result")
            # Every field but the id is optional, so an id-only request is the
            # documented no-op and must not clear the stored values.
            id_only = call(base, "Admin.UpdateDnsCredential", {"id": created_id}, auth)
            if id_only["body_sha256"] != updated["body_sha256"]:
                raise AssertionError("id-only UpdateDnsCredential changed the record")
            protobuf = call(
                base,
                "Admin.UpdateDnsCredential",
                None,
                auth,
                raw=encode_request(entry["request_fields"], update),
                content_type="application/octet-stream",
            )
            documented_numbers = {
                int(field["number"]) for field in entry["response_fields"]
            }
            if protobuf["status"] != 200 or not documented_numbers.issubset(
                set(protobuf["field_numbers"])
            ):
                raise AssertionError(
                    "protobuf UpdateDnsCredential omitted documented response fields"
                )
            unknown_field = call(
                base,
                "Admin.UpdateDnsCredential",
                dict(update, unknown_field_probe=True),
                auth,
            )
            if unknown_field["status"] != 200:
                raise AssertionError(
                    "UpdateDnsCredential did not ignore an unknown field"
                )
            empty_id = call(base, "Admin.UpdateDnsCredential", {"id": ""}, auth)
            unknown_id = call(
                base,
                "Admin.UpdateDnsCredential",
                dict(update, id=f"absent-{tag}"),
                auth,
            )
            malformed = call(base, "Admin.UpdateDnsCredential", {}, auth, raw=b'{"id":')
            no_auth = call(base, "Admin.UpdateDnsCredential", update, None)
            behavior.update(
                {
                    "updated": updated,
                    "readback": readback,
                    "id_only": id_only,
                    "protobuf": protobuf,
                    "unknown_field": unknown_field,
                    "empty_id": empty_id,
                    "unknown_id": unknown_id,
                    "malformed": malformed,
                    "unauthorized": no_auth,
                }
            )
            for name, response in (
                ("empty_id", empty_id),
                ("unknown_id", unknown_id),
                ("malformed", malformed),
            ):
                if response["status"] < 400:
                    raise AssertionError(
                        f"UpdateDnsCredential accepted the {name} request "
                        f"(HTTP {response['status']})"
                    )
            if no_auth["status"] not in (401, 403):
                raise AssertionError(
                    f"unauthenticated UpdateDnsCredential returned HTTP {no_auth['status']}"
                )
            final = call(base, "Admin.ListDnsCredentials", {}, auth)
            behavior["listed_after"] = final
            if not contains_id(final.get("body"), created_id):
                raise AssertionError("a rejected update removed the credential")
        elif case_id == "tc-gw-admin-018":
            deleted = call(base, "Admin.DeleteDnsCredential", {"id": created_id}, auth)
            created_ids.remove(created_id)
            listed = call(base, "Admin.ListDnsCredentials", {}, auth)
            malformed = call(base, "Admin.DeleteDnsCredential", {}, auth, raw=b'{"id":')
            no_auth = call(
                base, "Admin.DeleteDnsCredential", {"id": "not-disclosed"}, None
            )
            if (
                deleted["status"] != 200
                or deleted["body_len"] != 0
                or listed["status"] != 200
                or contains_id(listed.get("body"), created_id)
                or malformed["status"] < 400
                or no_auth["status"] not in (401, 403)
            ):
                raise AssertionError("DeleteDnsCredential contract failed")
            behavior.update(
                {
                    "delete": deleted,
                    "listed_after": listed,
                    "malformed": malformed,
                    "unauthorized": no_auth,
                }
            )
        else:
            selected = call(
                base, "Admin.SetDefaultDnsCredential", {"id": created_id}, auth
            )
            current = call(base, "Admin.GetDefaultDnsCredential", {}, auth)
            invalid = call(
                base,
                "Admin.SetDefaultDnsCredential",
                {"id": f"absent-{tag}"},
                auth,
            )
            no_auth = call(
                base, "Admin.SetDefaultDnsCredential", {"id": created_id}, None
            )
            if (
                selected["status"] != 200
                or selected["body_len"] != 0
                or current["status"] != 200
                or not contains_id(current.get("body"), created_id)
                or invalid["status"] < 400
                or no_auth["status"] not in (401, 403)
            ):
                raise AssertionError("SetDefaultDnsCredential contract failed")
            behavior.update(
                {
                    "set_default": selected,
                    "get_default": current,
                    "invalid": invalid,
                    "unauthorized": no_auth,
                }
            )
        record(
            "step02-behavior.json",
            step_ids[1],
            behavior,
            "Run-scoped valid, invalid, unauthorized, and state-transition DNS credential behavior.",
        )
        steps.append(
            {
                "id": step_ids[1],
                "status": "PASS",
                "observed": f"{CASES[case_id]} satisfied its documented response, rejection, and state contract.",
            }
        )
        print(f"STEP {step_ids[1]} END - PASS", flush=True)

        print(f"STEP {step_ids[2]} START", flush=True)
        repeat = call(base, "Admin.ListDnsCredentials", {}, auth)
        repeat_unauthorized = call(base, "Admin.ListDnsCredentials", {}, None)
        if repeat["status"] != 200 or repeat_unauthorized["status"] not in (401, 403):
            raise AssertionError("post-call availability or authorization changed")
        record(
            "step03-diagnostics.json",
            step_ids[2],
            {"state": repeat, "unauthorized": repeat_unauthorized},
            "Post-call state, availability, and authorization isolation.",
        )
        steps.append(
            {
                "id": step_ids[2],
                "status": "PASS",
                "observed": "Gateway remained available and authorization remained enforced.",
            }
        )
        print(f"STEP {step_ids[2]} END - PASS", flush=True)
    except Exception as error:
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
        if behavior:
            record(
                "step02-behavior.json",
                step_ids[1],
                behavior,
                "Observations captured before the deterministic harness mismatch.",
            )
        if len(steps) < 3:
            steps.append(
                {"id": step_ids[len(steps)], "status": "FAIL", "observed": failure}
            )
    finally:
        for identifier in created_ids:
            try:
                call(base, "Admin.DeleteDnsCredential", {"id": identifier}, auth)
            except Exception:
                pass
    while len(steps) < 3:
        steps.append(
            {
                "id": step_ids[len(steps)],
                "status": "NOT_RUN",
                "observed": "Not run after an earlier failure.",
            }
        )
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": f"{CASES[case_id]} deterministic regression passed."
        if status == "PASS"
        else f"{CASES[case_id]} deterministic regression failed: {failure}",
        "steps": steps,
        "artifacts": artifacts,
        "remarks": "Uses only run-scoped non-production credentials, redacts provider material, and removes created state.",
    }
    atomic_json(result_dir / "result.json", result)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
