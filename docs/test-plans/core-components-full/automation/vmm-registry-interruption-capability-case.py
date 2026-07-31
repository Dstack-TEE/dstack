#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise authenticated, public, interrupted, corrupt, and hostile OCI pulls."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-vmm-compute-ne-006"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write one JSON file atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write(chr(10))
        temporary = pathlib.Path(handle.name)
    temporary.replace(path)


def call(url: str, value: dict[str, Any]) -> tuple[int, bytes]:
    """Call one JSON pRPC endpoint."""
    request = urllib.request.Request(
        url,
        data=json.dumps(value).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def list_rows(base: str, route: str) -> list[dict[str, Any]]:
    """List registry rows from the case-owned VMM."""
    code, body = call(base + route, {})
    if code != 200:
        raise AssertionError(f"ListRegistryImages returned HTTP {code}")
    value = json.loads(body or b"{}")
    rows = value.get("images") if isinstance(value, dict) else None
    if not isinstance(rows, list):
        raise AssertionError("ListRegistryImages omitted images")
    return rows


def row_for(base: str, route: str, tag: str) -> dict[str, Any]:
    """Return the unique fixture tag row."""
    matches = [row for row in list_rows(base, route) if row.get("tag") == tag]
    if len(matches) != 1:
        raise AssertionError(f"fixture tag had {len(matches)} rows")
    return matches[0]


def await_state(
    base: str,
    route: str,
    tag: str,
    *,
    local: bool,
    failed: bool,
    timeout: float = 30,
) -> dict[str, Any]:
    """Wait for a completed success or failure state."""
    deadline = time.monotonic() + timeout
    observed: dict[str, Any] = {}
    while time.monotonic() < deadline:
        observed = row_for(base, route, tag)
        error = str(observed.get("error") or "")
        if not observed.get("pulling"):
            if failed and error and not observed.get("local"):
                return observed
            if not failed and not error and bool(observed.get("local")) is local:
                return observed
        time.sleep(0.2)
    raise AssertionError(f"registry state timed out: {observed}")


def main() -> int:
    """Run the complete registry interruption and integrity matrix."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise RuntimeError("wrong case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]["vmm"]
    inputs = values["test_input"]
    if values.get("case_owned") is not True:
        raise RuntimeError("VMM is not case-owned")
    base = str(values["rpc_url"]).rstrip("/")
    routes = values["json_prpc_routes"]
    list_route = str(routes["ListRegistryImages"]).split("?", 1)[0]
    pull_route = str(routes["PullRegistryImage"]).split("?", 1)[0]
    delete_route = str(routes["DeleteImage"]).split("?", 1)[0]
    tag = str(inputs["registry_tag"])
    control = pathlib.Path(inputs["registry_control"])
    image_store = pathlib.Path(inputs["registry_image_store"])
    registry_workspace = pathlib.Path(inputs["registry_workspace"])
    final_dir = image_store / tag
    tmp_dir = image_store / f".tmp-pull-{tag}"
    outside_candidates = [
        image_store / "registry-escape",
        image_store.parent / "registry-escape",
        registry_workspace / "registry-escape",
    ]
    rows: list[dict[str, Any]] = []
    failure: str | None = None

    def set_mode(
        *,
        variant: str = "normal",
        auth_required: bool = True,
        fault: str = "none",
    ) -> None:
        atomic_json(
            control,
            {
                "variant": variant,
                "auth_required": auth_required,
                "fault": fault,
            },
        )

    def pull(request_tag: str = tag) -> int:
        code, body = call(base + pull_route, {"tag": request_tag})
        if code != 200 or body not in (b"", b"null"):
            raise AssertionError(
                f"PullRegistryImage returned HTTP {code}, {len(body)} bytes"
            )
        return code

    def delete() -> int:
        code, body = call(base + delete_route, {"id": tag})
        if code != 200:
            raise AssertionError(f"DeleteImage returned HTTP {code}: {body[:200]!r}")
        await_state(base, list_route, tag, local=False, failed=False)
        return code

    def assert_failed_clean(state: dict[str, Any], expected: str) -> None:
        error = str(state.get("error") or "")
        if expected not in error:
            raise AssertionError(f"failure omitted {expected!r}: {error[:500]}")
        if final_dir.exists() or tmp_dir.exists():
            raise AssertionError("failed pull published final or temporary state")

    try:
        set_mode()
        baseline = row_for(base, list_route, tag)
        if baseline.get("local") or baseline.get("pulling") or baseline.get("error"):
            raise AssertionError(f"dirty registry baseline: {baseline}")

        for name, auth_required in (
            ("bearer-multilayer", True),
            ("public-multilayer", False),
        ):
            set_mode(auth_required=auth_required)
            pull()
            state = await_state(base, list_route, tag, local=True, failed=False)
            files = sorted(path.name for path in final_dir.iterdir())
            if not {"metadata.json", "fixture.bin"}.issubset(files):
                raise AssertionError(f"{name} extraction incomplete: {files}")
            rows.append(
                {
                    "name": name,
                    "status": "PASS",
                    "auth_required": auth_required,
                    "state": state,
                    "files": files,
                }
            )
            delete()

        set_mode(fault="interrupt")
        pull()
        interrupted = await_state(base, list_route, tag, local=False, failed=True)
        assert_failed_clean(interrupted, "failed to read blob body")
        set_mode()
        pull()
        resumed = await_state(base, list_route, tag, local=True, failed=False)
        rows.append(
            {
                "name": "interrupt-retry",
                "status": "PASS",
                "interrupted": interrupted,
                "resumed": resumed,
            }
        )
        delete()

        set_mode(fault="corrupt")
        pull()
        corrupt = await_state(base, list_route, tag, local=False, failed=True)
        assert_failed_clean(corrupt, "blob digest mismatch")
        rows.append({"name": "digest-mismatch", "status": "PASS", "state": corrupt})

        set_mode(variant="traversal")
        pull()
        traversal = await_state(base, list_route, tag, local=False, failed=True)
        assert_failed_clean(traversal, "failed to extract")
        if any(path.exists() for path in outside_candidates):
            raise AssertionError("traversal layer escaped the image store")
        rows.append({"name": "traversal", "status": "PASS", "state": traversal})

        set_mode(fault="deny_token")
        log = pathlib.Path(values["log"])
        log_offset = log.stat().st_size
        pull()
        during_auth_fault, _ = call(base + list_route, {})
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            recent_log = log.read_text(errors="replace")[log_offset:]
            if f"failed to pull registry image {tag}" in recent_log:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("invalid-auth pull failure was not logged")
        set_mode()
        denied = await_state(base, list_route, tag, local=False, failed=True)
        assert_failed_clean(denied, "HTTP 401")
        rows.append(
            {
                "name": "invalid-auth",
                "status": "PASS",
                "list_http_during_fault": during_auth_fault,
                "state_after_recovery": denied,
            }
        )

        invalid_tag = "dstack-../../registry-escape"
        set_mode()
        pull(invalid_tag)
        deadline = time.monotonic() + 10
        log = pathlib.Path(values["log"])
        while time.monotonic() < deadline:
            if "invalid registry tag" in log.read_text(errors="replace"):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("invalid tag rejection was not logged")
        if any(path.exists() for path in outside_candidates):
            raise AssertionError("invalid tag escaped the image store")
        healthy = row_for(base, list_route, tag)
        rows.append(
            {
                "name": "invalid-tag",
                "status": "PASS",
                "request_tag_sha256": hashlib.sha256(invalid_tag.encode()).hexdigest(),
                "healthy_after": healthy,
            }
        )
        if len(list_rows(base, list_route)) != 1:
            raise AssertionError("negative rows changed the registry inventory")
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
    finally:
        set_mode()
        try:
            state = row_for(base, list_route, tag)
            if state.get("local"):
                delete()
        except Exception as error:  # noqa: BLE001
            if failure is None:
                failure = f"cleanup {type(error).__name__}: {error}"
        for owned_path in (tmp_dir, final_dir):
            if owned_path.exists():
                shutil.rmtree(owned_path)

    cleanup = {
        "final_absent": not final_dir.exists(),
        "temporary_absent": not tmp_dir.exists(),
        "outside_absent": not any(path.exists() for path in outside_candidates),
    }
    passed = failure is None and len(rows) == 7 and all(cleanup.values())
    evidence = {
        "candidate_commit": json.loads(
            pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
        )["candidate_commit"],
        "baseline": baseline if "baseline" in locals() else {},
        "rows": rows,
        "cleanup": cleanup,
        "failure": failure,
        "registry_case_owned": True,
        "vm_started": False,
        "mkosi_build_tested": False,
    }
    artifact_path = result_dir / "artifacts/vmm-registry-interruption.json"
    atomic_json(artifact_path, evidence)
    artifact = {
        "path": "artifacts/vmm-registry-interruption.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Registry interruption and integrity matrix",
        "description": "Records authenticated/public multilayer pulls, interruption retry, digest and traversal rejection, invalid auth/tag handling, availability, and cleanup.",
    }
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if passed else "FAIL"
    observed = (
        f"{len(rows)}/7 registry rows passed; cleanup="
        f"{sum(cleanup.values())}/{len(cleanup)}"
    )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": observed if passed else failure,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-{number:02d}",
                    "status": status,
                    "observed": observed if passed else failure,
                }
                for number in range(1, 4)
            ],
            "artifacts": [artifact],
            "evidence": [
                {
                    "path": artifact["path"],
                    "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
                }
            ],
            "remarks": "The HTTPS registry, VMM, image store, fault control, and credentials were lease-owned; no VM or image build ran.",
        },
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
