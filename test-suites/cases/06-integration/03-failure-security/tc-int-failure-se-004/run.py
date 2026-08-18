#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise certificate and time boundaries across the integrated trust path."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from cryptography import x509

CASE_ID = "tc-int-failure-se-004"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def rpc(url: str, method: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Call a JSON RPC and retain only bounded diagnostics on rejection."""
    request = urllib.request.Request(
        url.replace("{method}", method),
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        payload = error.read()
        return error.code, {
            "diagnostic_present": bool(payload),
            "diagnostic_sha256": hashlib.sha256(payload).hexdigest(),
        }


def cargo_test(
    repository: pathlib.Path, cargo: str, target: str, package: str, test: str
) -> dict[str, Any]:
    """Run one exact source-defined boundary test."""
    completed = subprocess.run(
        [cargo, "test", "-p", package, test, "--", "--exact"],
        cwd=repository / "dstack",
        env={**os.environ, "CARGO_TARGET_DIR": target},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=False,
    )
    passed = completed.returncode == 0 and bool(
        re.search(r"test result: ok\. 1 passed; 0 failed", completed.stdout)
    )
    if not passed:
        raise AssertionError(f"{package}:{test} failed with rc={completed.returncode}")
    return {
        "package": package,
        "test": test,
        "passed": True,
        "output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
    }


def main() -> int:
    """Execute the integrated certificate and clock boundary matrix."""
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    status = "PASS"
    summary = (
        "Certificate and clock boundaries rejected stale or future inputs and "
        "recovered without a trust reset."
    )
    evidence: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    stage = "fixture"
    try:
        guest = ((manifest.get("values") or {}).get("services") or {}).get(
            "DstackGuest"
        )
        if not isinstance(guest, dict) or not isinstance(guest.get("url"), str):
            raise AssertionError("lease-owned DstackGuest endpoint missing")
        url = guest["url"]
        _, info_before = rpc(url, "Info", {})
        now = int(datetime.now(timezone.utc).timestamp())
        token = hashlib.sha256(os.environ["DSTACK_TEST_RUN_ID"].encode()).hexdigest()
        subject = f"clock-{token[:12]}.example.test"
        base = {
            "subject": subject,
            "alt_names": [subject],
            "usage_server_auth": True,
        }

        stage = "guest-invalid-validity-order"
        invalid_status, invalid = rpc(
            url,
            "GetTlsKey",
            {**base, "not_before": now + 7200, "not_after": now + 3600},
        )
        if invalid_status < 400:
            raise AssertionError("Guest accepted not_before after not_after")

        stage = "guest-recovery"
        recovery_status, recovered = rpc(
            url,
            "GetTlsKey",
            {**base, "not_before": now - 60, "not_after": now + 3600},
        )
        chain = recovered.get("certificate_chain")
        if recovery_status != 200 or not isinstance(chain, list) or not chain:
            raise AssertionError(
                "Guest did not issue a certificate after time correction"
            )
        leaf = x509.load_pem_x509_certificate(str(chain[0]).encode())
        recovered.clear()
        _, info_after = rpc(url, "Info", {})
        if info_before.get("app_id") != info_after.get("app_id") or info_before.get(
            "instance_id"
        ) != info_after.get("instance_id"):
            raise AssertionError("Guest trust identity changed after rejection")
        evidence["guest"] = {
            "invalid_order_http_status": invalid_status,
            "invalid_order_diagnostic": invalid.get("diagnostic_present", False),
            "recovery_http_status": recovery_status,
            "recovery_valid_at_observation_time": (
                leaf.not_valid_before.replace(tzinfo=timezone.utc).timestamp()
                <= now
                <= leaf.not_valid_after.replace(tzinfo=timezone.utc).timestamp()
            ),
            "identity_stable": True,
        }

        stage = "component-boundary-matrices"
        rows = [
            (
                "dstack-kms",
                "crypto::tests::environment_public_key_signatures_bind_domain_app_key_and_timestamp",
            ),
            (
                "dstack-gateway",
                "cert_store::tests::expired_update_retains_previous_certificate",
            ),
            (
                "dstack-verifier",
                "certificate_profile_tests::certificate_profile_rejects_expired_and_future_certificates",
            ),
            (
                "mock-attestation",
                "server::tests::tdx_quote_collateral_and_tcb_matrix",
            ),
        ]
        search_path = os.pathsep.join(
            [*runtime.get("environment_path_prepend", []), os.environ.get("PATH", "")]
        )
        cargo = shutil.which("cargo", path=search_path)
        if cargo is None:
            raise OSError("cargo is absent from the runtime-declared PATH")
        evidence["component_rows"] = [
            cargo_test(repository, cargo, str(runtime["cargo_target_dir"]), *row)
            for row in rows
        ]
        evidence["coverage"] = {
            "guest_certificate_order_and_recovery": True,
            "kms_signature_timestamp_binding": True,
            "gateway_expired_certificate_atomic_rejection": True,
            "verifier_expired_and_future_certificate_rejection": True,
            "collateral_expiry_and_recovery": True,
        }
    except (
        AssertionError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        subprocess.TimeoutExpired,
        urllib.error.URLError,
    ) as error:
        status = "FAIL"
        summary = f"{stage}: {error}"
        evidence["failure_stage"] = stage
        evidence["failure"] = str(error)

    artifact = {
        "path": "artifacts/certificate-clock-boundaries.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Certificate and clock boundary matrix",
        "description": (
            "Guest RPC statuses plus exact component test identities and hashed outputs."
        ),
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": status,
                    "observed": "The lease-owned Guest identity and component inputs were checked.",
                },
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "Guest, KMS, Gateway, Verifier, and collateral time boundaries were exercised.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "Corrected issuance and stable identity proved recovery without trust reset.",
                },
            ],
            "artifacts": [artifact],
            "remarks": (
                "Explicit validity and timestamp evaluation points are used instead of "
                "mutating the host clock or other leases."
            ),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
