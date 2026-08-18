#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise every source-defined GetAppKey and SignCert API-version branch."""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

CASE_ID = "tc-kms-apiver-011"


def context(identity: dict[str, str] | None) -> ssl.SSLContext:
    """Build a test TLS context with optional attested identity."""
    value = ssl.create_default_context()
    value.check_hostname = False
    value.verify_mode = ssl.CERT_NONE
    if identity:
        value.load_cert_chain(identity["cert"], identity["key"])
    return value


def call(
    url: str, method: str, body: dict[str, object], identity: dict[str, str] | None
) -> tuple[int, bytes]:
    """Call one KMS JSON method without persisting native responses."""
    request = urllib.request.Request(
        f"{url}/{method}?json",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(
            request, context=context(identity), timeout=30
        ) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def generate(fixture: dict[str, str]) -> dict[str, str]:
    """Generate v1 and v2 signed CSRs bound to one fresh key and quote."""
    completed = subprocess.run(
        [fixture["generator"]],
        env={**os.environ, "DSTACK_AGENT_ADDRESS": fixture["agent_url"]},
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr[-500:])
    value = json.loads(completed.stdout)
    required = ("csr", "signature", "csr_v1", "signature_v1")
    if any(
        not isinstance(value.get(name), str) or not value[name] for name in required
    ):
        raise RuntimeError("CSR fixture omitted a versioned request")
    return value


def main() -> int:
    """Run accepted/rejected versions plus shared outage/recovery diagnostics."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    case = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = case["values"]
    identity = values["kms_attested_client"]
    fixture = values["kms_attested_csr"]
    url = str(values["kms"]["rpc_prpc_url"])
    vm_config = str(identity["vm_config"])
    rows: dict[str, object] = {}
    status = "FAIL"
    failure = ""
    try:
        for version, accepted in ((0, True), (1, True), (2, False), (2**32 - 1, False)):
            code, raw = call(
                url,
                "KMS.GetAppKey",
                {"api_version": version, "vm_config": vm_config},
                identity,
            )
            if accepted and (code != 200 or not raw):
                raise AssertionError(f"GetAppKey v{version} rejected")
            if not accepted and code < 400:
                raise AssertionError(f"GetAppKey v{version} accepted")
            rows[f"get_app_key_v{version}"] = {"status": code, "accepted": accepted}

        generated = generate(fixture)
        sign_rows = (
            (1, generated["csr_v1"], generated["signature_v1"], True),
            (2, generated["csr"], generated["signature"], True),
            (0, generated["csr_v1"], generated["signature_v1"], False),
            (3, generated["csr"], generated["signature"], False),
        )
        for version, csr, signature, accepted in sign_rows:
            code, raw = call(
                url,
                "KMS.SignCert",
                {
                    "api_version": version,
                    "csr": csr,
                    "signature": signature,
                    "vm_config": vm_config,
                },
                identity,
            )
            if accepted:
                payload = json.loads(raw) if code == 200 else {}
                if code != 200 or len(payload.get("certificate_chain", [])) != 3:
                    raise AssertionError(
                        f"SignCert v{version} rejected or returned bad chain"
                    )
            elif code < 400:
                raise AssertionError(f"SignCert v{version} accepted")
            rows[f"sign_cert_v{version}"] = {"status": code, "accepted": accepted}

        with tempfile.TemporaryDirectory(prefix="dstack-kms-api-outage-") as directory:
            nested = Path(directory)
            env = {
                **os.environ,
                "DSTACK_TEST_RESULT_DIR": str(nested),
                "DSTACK_TEST_CASE_ID": CASE_ID,
            }
            completed = subprocess.run(
                [
                    "python3",
                    str(Path(__file__).with_name("kms-metrics-diagnostics-case.py")),
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            nested_result = (
                json.loads((nested / "result.json").read_text())
                if (nested / "result.json").is_file()
                else {}
            )
            if completed.returncode or nested_result.get("status") != "PASS":
                raise AssertionError(
                    f"shared outage/recovery matrix failed: {nested_result.get('summary', completed.stderr[-300:])}"
                )
            rows["outage_restart_identity"] = {"status": "PASS"}
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        rows["failure"] = {"status": "FAIL", "diagnostic": failure}

    evidence_path = artifacts / "kms-api-version.json"
    evidence_path.write_text(
        json.dumps({"rows": rows, "native_material_persisted": False}, indent=2) + "\n"
    )
    artifact = {
        "path": "artifacts/kms-api-version.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "KMS API version matrix",
        "description": "Version acceptance, chain shape, outage/recovery, and identity-isolation observations.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = (
        "9/9 API-version and recovery groups passed" if status == "PASS" else failure
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 4)
        ],
        "artifacts": [artifact],
        "remarks": "Both CSR versions use the same fresh key-bound mock-TDX evidence; no physical-origin claim is made.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
