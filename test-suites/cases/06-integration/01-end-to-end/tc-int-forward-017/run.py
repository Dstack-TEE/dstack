#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Run focused product test rows for the forward interval 9b87d9f9a6..#1587."""

import json
import os
import pathlib
import re
import subprocess
import time

CASE = "tc-int-forward-017"
# (package, cargo target selector, test filter). An empty filter runs the target.
CARGO = [
    ("dstack-types", "--lib", "launch_ticket_hash_is_domain_separated"),
    ("dstack-kms", "--bins", "a_denial_for_a_missing_ticket_says_none_was_presented"),
    ("dstack-kms", "--bins", "launch_tickets_are_sent_as_hashes"),
    ("dstack-kms", "--bins", "onboarding_pins_the_registered_root_ca_keys"),
    ("dstack-auth", "--bins", "launch_tickets_are_required_only_when_configured"),
    ("ra-rpc", "--test=issuer_pinning", ""),
    ("dstack-vmm", "--bins", "put_manifest_restricts_the_workdir_to_its_owner"),
    ("dstack-mr", "--lib", "tdx_lite_"),
    ("dstack-verifier-wasm", "--lib", ""),
    ("sev-snp-attest", "--lib", "sealing::"),
    ("dstack-util", "--bins", "system_setup::snp::"),
    ("dstack-types", "--lib", "sev_snp_provider_"),
    ("dstack-types", "--lib", "snp_metadata_preserves_full_tcb_precision"),
    ("dstack-types", "--lib", "legacy_instance_metadata_encoding_is_unchanged"),
    ("dstack-vmm", "--bins", "snp_provider_requires_real_snp_hardware"),
    ("dstack-vmm", "--bins", "relaunch_preserves_snp_sealing_parameters"),
    (
        "dstack-cli",
        "--bins",
        "sev_snp_provider_is_explicit_and_conflicts_with_no_kms_alias",
    ),
    (
        "dstack-cli-core",
        "--lib",
        "typed_provider_matches_previous_cli_manifest_encoding",
    ),
    ("rocket-proxy-listener", "--lib", ""),
    ("load_config", "--lib", ""),
    ("dstack-kms", "--bins", "moved_listener_settings_are_refused"),
    ("dstack-kms", "--bins", "a_serving_kms_needs_a_key_handover_path"),
    ("dstack-gateway", "--bins", "moved_listener_settings_are_refused"),
]
PYTHON = [
    ("dstack/vmm/src/tests/test_vmm_cli.py", "test_launch_ticket_is_sent_and_removed"),
]
RESULT = re.compile(r"test result: \w+\. (\d+) passed; (\d+) failed")


def cargo_row(repo, env, package, target, filt):
    command = ["cargo", "test", "-p", package, target]
    if filt:
        command.append(filt)
    r = subprocess.run(
        command,
        cwd=repo / "dstack",
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=1200,
        check=False,
    )
    counts = [tuple(map(int, m)) for m in RESULT.findall(r.stdout)]
    return r.returncode, sum(p for p, _ in counts), sum(f for _, f in counts), r.stdout


def python_row(repo, env, path, test):
    r = subprocess.run(
        ["python3", "-m", "unittest", "-v", "-k", test, str(repo / path)],
        cwd=repo,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=False,
    )
    ran = re.search(r"Ran (\d+) test", r.stdout)
    return (
        r.returncode,
        int(ran.group(1)) if ran else 0,
        int(r.returncode != 0),
        r.stdout,
    )


def main():
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE:
        raise SystemExit("unsupported case")
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repo = pathlib.Path(runtime["repository"])
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = runtime["cargo_target_dir"]
    rd = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    (rd / "artifacts").mkdir(parents=True, exist_ok=True)
    rows = []
    for kind, spec in [("cargo", row) for row in CARGO] + [
        ("python", row) for row in PYTHON
    ]:
        start = time.monotonic()
        if kind == "cargo":
            code, passed, failed, output = cargo_row(repo, env, *spec)
        else:
            code, passed, failed, output = python_row(repo, env, *spec)
        ok = code == 0 and passed >= 1 and failed == 0
        rows.append(
            {
                "kind": kind,
                "row": " ".join(part for part in spec if part),
                "returncode": code,
                "passed": passed,
                "failed": failed,
                "ok": ok,
                "duration_seconds": round(time.monotonic() - start, 3),
            }
        )
        if not ok:
            (rd / "artifacts/failed-row.log").write_text(output[-20000:])
    good = sum(row["ok"] for row in rows)
    status = "PASS" if good == len(rows) else "FAIL"
    observed = f"{good}/{len(rows)} forward interval rows passed"
    if status == "FAIL":
        observed += ": failing " + ", ".join(
            row["row"] for row in rows if not row["ok"]
        )
    (rd / "artifacts/forward-interval-matrix.json").write_text(
        json.dumps({"status": status, "rows": rows}, indent=2) + "\n"
    )
    (rd / "result.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "case_id": CASE,
                "provisional": False,
                "status": status,
                "summary": observed,
                "steps": [
                    {"id": f"{CASE}-step-01", "status": status, "observed": observed}
                ],
            },
            indent=2,
        )
        + "\n"
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
