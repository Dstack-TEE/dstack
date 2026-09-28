#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa
"""Exercise dstack-util get-keys inside a lease-owned mkosi guest."""

import json
import os
import pathlib
import subprocess
import time

CASE_ID = "tc-gos-setup-024"


def run(a, data=None, timeout=60):
    return subprocess.run(
        a, input=data, capture_output=True, timeout=timeout, check=False
    )


def dump(p, v):
    p.write_text(json.dumps(v, indent=2, sort_keys=True) + "\n")


def main():
    r = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    art = r / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    m = json.loads(pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    v = m.get("values") or {}
    ssh = list(map(str, v.get("ssh_argv") or []))
    status = "FAIL"
    summary = "mkosi KMS get-keys suite did not execute"
    ev = {
        "candidate_commit": runtime.get("candidate_commit"),
        "guest_image": v.get("image"),
    }
    try:
        if not ssh or v.get("destructive_actions_allowed") is not True:
            raise RuntimeError("fixture omitted lease-owned guest SSH")
        kms = v.get("case_kms") or {}
        url = str(kms.get("guest_url", ""))
        cert = pathlib.Path(str(kms.get("kms_rpc_cert", "")))
        if not url or not cert.is_file():
            raise RuntimeError("fixture omitted case-scoped KMS public inputs")
        repo = pathlib.Path(runtime["repository"])
        payloads = [
            (
                pathlib.Path(
                    runtime["prepared_binaries"]["dstack_util"]["path"]
                ).read_bytes(),
                "/run/dstack-test-getkeys/dstack-util",
            ),
            (
                (repo / "dstack/cc-eventlog/samples/ccel.bin").read_bytes(),
                "/run/dstack-test-getkeys/ccel.bin",
            ),
            (cert.read_bytes(), "/run/dstack-test-getkeys/kms.crt"),
            (
                (
                    repo / "test-suites/shared/automation/kms-getkeys-mkosi.sh"
                ).read_bytes(),
                "/run/dstack-test-getkeys/run-case",
            ),
        ]
        for data, target in payloads:
            cp = run(
                [
                    *ssh,
                    f"mkdir -p /run/dstack-test-getkeys && install -m 0755 /dev/stdin {target}",
                ],
                data,
                180,
            )
            if cp.returncode:
                raise RuntimeError(f"guest install failed rc={cp.returncode}")
        cp = run([*ssh, "/run/dstack-test-getkeys/run-case", url], timeout=600)
        log = cp.stdout + cp.stderr
        (art / "mkosi-kms-getkeys.log").write_bytes(log)
        if cp.returncode:
            diag = run(
                [*ssh, "tail -80 /run/dstack-test-getkeys/*.err 2>/dev/null || true"],
                timeout=30,
            )
            log += diag.stdout + diag.stderr
            (art / "mkosi-kms-getkeys.log").write_bytes(log)
            raise RuntimeError(
                f"mkosi get-keys rc={cp.returncode}: {log.decode(errors='replace')[-1800:]}"
            )
        matrix = json.loads(
            [x for x in cp.stdout.decode().splitlines() if x.startswith("{")][-1]
        )
        ev["matrix"] = matrix
        if any(
            matrix.get(k) is not True
            for k in (
                "valid",
                "repeat_stable",
                "app_id_scope_preserved",
                "retry",
                "atomic",
                "restrictive",
            )
        ) or any(
            not isinstance(matrix.get(k), int) or matrix[k] <= 0
            for k in ("bad_app_rc", "wrong_ca_rc", "unreachable_rc", "output_rc")
        ):
            raise RuntimeError(f"unexpected matrix: {matrix}")
        status = "PASS"
        summary = "Case-scoped KMS get-keys authorization, TLS, identity, failure, retry, and atomic output checks passed inside mkosi."
    except Exception as e:
        summary = f"{type(e).__name__}: {e}"
    finally:
        if ssh:
            ev["cleanup_returncode"] = run(
                [*ssh, "rm -rf /run/dstack-test-getkeys"], timeout=30
            ).returncode
    ev["duration_seconds"] = round(time.monotonic() - started, 3)
    dump(art / "kms-getkeys-mkosi.json", ev)
    a = {
        "path": "artifacts/kms-getkeys-mkosi.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "mkosi KMS get-keys suite",
        "description": "Sanitized transport, identity, failure, retry, file-mode, and cleanup evidence.",
    }
    dump(art / "manifest.json", {"artifacts": [a]})
    dump(
        r / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
                for n in range(1, 4)
            ],
            "artifacts": [a],
            "remarks": "Case-scoped simulator-backed KMS proves functional authorization and transport behavior, not physical TDX isolation.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
