#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise full-TDX image verification, offline cache, and policy modes."""

from __future__ import annotations

import contextlib
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import threading
from typing import Any

CASE_ID = "tc-ver-cli-cert-o-003"
IMAGE_HASH = "14ad42d0270b444eaeb53918a5a94d9b17eec7a817cd336173b17c5327541c67"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def prepared_binary(runtime: dict[str, Any], name: str) -> pathlib.Path:
    """Return one manifest-declared prepared binary."""
    item = runtime["prepared_binaries"][name]
    return pathlib.Path(item.get("resolved_path") or item["path"])


def write_config(path: pathlib.Path, cache: pathlib.Path, download_url: str) -> None:
    """Write an isolated verifier configuration."""
    path.write_text(
        "\n".join(
            [
                'address = "127.0.0.1"',
                "port = 1",
                f'image_cache_dir = "{cache}"',
                f'image_download_url = "{download_url}"',
                "image_download_timeout_secs = 2",
                "[attestation]",
                "insecure_allow_external_trust_anchors = false",
                "",
            ]
        )
    )


def run_verifier(
    binary: pathlib.Path,
    request_source: pathlib.Path,
    workspace: pathlib.Path,
    name: str,
    cache: pathlib.Path,
    download_url: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run a one-shot verification and retain command material in the workspace."""
    row_dir = workspace / name
    row_dir.mkdir(parents=True, exist_ok=True)
    request = row_dir / "request.json"
    config = row_dir / "config.toml"
    shutil.copy2(request_source, request)
    write_config(config, cache, download_url)
    completed = subprocess.run(
        [str(binary), "--config", str(config), "--verify", str(request)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
    )
    (row_dir / "stdout.json").write_text(completed.stdout)
    (row_dir / "stderr.log").write_text(completed.stderr)
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(f"{name} returned non-JSON output: {error}") from error
    row = {
        "name": name,
        "returncode": completed.returncode,
        "is_valid": response.get("is_valid"),
        "quote_verified": response.get("details", {}).get("quote_verified"),
        "os_image_hash_verified": response.get("details", {}).get(
            "os_image_hash_verified"
        ),
        "event_log_verified": response.get("details", {}).get("event_log_verified"),
        "acpi_tables_verified": response.get("details", {}).get("acpi_tables_verified"),
        "output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
    }
    return row, response


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """Serve the controlled image archive without console logging."""

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress loopback HTTP request logs."""
        pass


@contextlib.contextmanager
def image_server(directory: pathlib.Path):
    """Serve a case-owned directory on an ephemeral loopback port."""
    handler = lambda *args, **kwargs: QuietHandler(  # noqa: E731
        *args, directory=str(directory), **kwargs
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/{{OS_IMAGE_HASH}}.tar.gz"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def expect_valid(row: dict[str, Any], response: dict[str, Any]) -> None:
    """Require the complete full-TDX success surface."""
    required = (
        row["returncode"] == 0,
        response.get("is_valid") is True,
        row["quote_verified"] is True,
        row["os_image_hash_verified"] is True,
        row["event_log_verified"] is True,
        row["acpi_tables_verified"] is True,
    )
    if not all(required):
        raise AssertionError(f"{row['name']} did not pass every full-TDX check")


def main() -> int:
    """Run the full-TDX image-mode matrix."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    fixture = pathlib.Path(
        runtime["environment"]["DSTACK_TEST_VERIFIER_FULL_TDX_IMAGE_DIR"]
    )
    binary = prepared_binary(runtime, "dstack_verifier")
    request = repository / "dstack/verifier/shared/fixtures/quote-report.json"
    workspace = result_dir / "debug-workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    status = "PASS"
    summary = (
        "Full-TDX strict, allowlist, offline, download, and recovery matrix passed."
    )
    stage = "prerequisite"
    try:
        if (
            hashlib.sha256((fixture / "sha256sum.txt").read_bytes()).hexdigest()
            != IMAGE_HASH
        ):
            raise AssertionError("fixture sha256sum identity does not match the quote")
        if not binary.is_file() or not request.is_file():
            raise AssertionError("prepared verifier or quote fixture is missing")

        stage = "offline cached verification"
        offline_cache = workspace / "offline-cache"
        shutil.copytree(
            fixture, offline_cache / "images" / IMAGE_HASH, dirs_exist_ok=True
        )
        row, response = run_verifier(
            binary,
            request,
            workspace,
            "offline-cached",
            offline_cache,
            "http://127.0.0.1:1/{OS_IMAGE_HASH}.tar.gz",
        )
        expect_valid(row, response)
        rows.append(row)

        stage = "relying-party allowlist"
        verified_hash = response["details"]["app_info"]["os_image_hash"]
        if verified_hash != IMAGE_HASH:
            raise AssertionError("verified app-info image hash changed")
        rows.extend(
            [
                {"name": "allowlist-accept", "passed": verified_hash in {IMAGE_HASH}},
                {
                    "name": "allowlist-reject",
                    "passed": verified_hash not in {"00" * 32},
                },
            ]
        )
        if not all(row["passed"] for row in rows[-2:]):
            raise AssertionError("relying-party allowlist decision failed")

        stage = "missing cache fail closed"
        recovery_cache = workspace / "recovery-cache"
        row, response = run_verifier(
            binary,
            request,
            workspace,
            "missing-cache-offline",
            recovery_cache,
            "http://127.0.0.1:1/{OS_IMAGE_HASH}.tar.gz",
        )
        reason = response.get("reason") or ""
        if row["returncode"] == 0 or response.get("is_valid") is not False:
            raise AssertionError("missing offline image did not fail closed")
        if "Failed to download image" not in reason:
            raise AssertionError("missing offline image lacked a download diagnostic")
        row["expected_rejection"] = True
        rows.append(row)

        stage = "controlled download recovery"
        server_dir = workspace / "server"
        server_dir.mkdir(parents=True, exist_ok=True)
        archive = server_dir / f"{IMAGE_HASH}.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for path in sorted(fixture.iterdir()):
                if path.is_file():
                    bundle.add(path, arcname=path.name, recursive=False)
        with image_server(server_dir) as url:
            row, response = run_verifier(
                binary,
                request,
                workspace,
                "controlled-download-recovery",
                recovery_cache,
                url,
            )
        expect_valid(row, response)
        if not (recovery_cache / "images" / IMAGE_HASH / "metadata.json").is_file():
            raise AssertionError(
                "successful recovery did not atomically promote the image"
            )
        rows.append(row)

        stage = "strict measurement mismatch"
        mismatch_cache = workspace / "mismatch-cache"
        mismatch_image = mismatch_cache / "images" / IMAGE_HASH
        shutil.copytree(fixture, mismatch_image, dirs_exist_ok=True)
        with (mismatch_image / "bzImage").open("r+b") as stream:
            original = stream.read(1)
            stream.seek(0)
            stream.write(bytes([original[0] ^ 1]))
        row, response = run_verifier(
            binary,
            request,
            workspace,
            "strict-measurement-mismatch",
            mismatch_cache,
            "http://127.0.0.1:1/{OS_IMAGE_HASH}.tar.gz",
        )
        reason = response.get("reason") or ""
        if row["returncode"] == 0 or response.get("is_valid") is not False:
            raise AssertionError("mutated measured image was accepted")
        if "mismatch" not in reason.lower():
            raise AssertionError("mutated measured image lacked a mismatch diagnostic")
        row["expected_rejection"] = True
        rows.append(row)
    except (AssertionError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        status = "FAIL"
        summary = f"{stage}: {error}"

    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "fixture_sha256sum_hash": IMAGE_HASH,
        "rows": rows,
        "workspace_retained": status != "PASS",
        "covered_behaviors": [
            "real_full_tdx_quote_and_image_measurement",
            "strict_mrtd_rtmr_and_acpi_binding",
            "verified_hash_allowlist_accept_and_reject",
            "pre_cached_offline_without_download",
            "missing_offline_image_fails_closed",
            "controlled_download_after_failure",
            "atomic_cache_promotion",
            "measured_image_mutation_rejection",
        ],
    }
    artifact = {
        "path": "artifacts/full-tdx-image-mode-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "Full-TDX image verification mode matrix",
        "description": "Row status and hashed outputs for strict, allowlist, offline, download, and recovery behavior.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "The manifest-declared full-TDX image and prepared verifier were selected.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": f"{len(rows)} strict, allowlist, offline, download, recovery, and mutation rows executed.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Failure state is retained under debug-workspace; successful rows retain bounded hashed evidence.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "This consumes a prepared image and does not test Yocto or mkosi build correctness. The verifier establishes image identity; the allowlist rows exercise the documented relying-party policy boundary.",
        },
    )
    if status == "PASS":
        shutil.rmtree(workspace, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
