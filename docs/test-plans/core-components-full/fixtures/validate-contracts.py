#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Audit full-plan fixture contracts without provisioning resources."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def fail(message: str) -> None:
    """Abort with a message."""
    raise SystemExit(message)


def main() -> None:
    """Run the case harness."""
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    index = json.loads((root / "index.json").read_text())
    registry = json.loads((root / "fixtures/profiles.json").read_text())["profiles"]
    cases = [
        case
        for chapter in index["chapters"]
        for section in chapter["sections"]
        for case in section["cases"]
    ]
    cases_by_id = {case["id"]: case for case in cases}
    errors: list[str] = []
    expected_versions = {"vmm", "guest", "kms", "gateway", "verifier"}
    for case in cases:
        fixture = case.get("fixture")
        actions = case.get("actions_under_test")
        if not isinstance(fixture, dict):
            errors.append(f"{case['id']}: missing fixture object")
            continue
        profile = fixture.get("profile")
        if profile not in registry:
            errors.append(f"{case['id']}: unknown profile {profile!r}")
        if fixture.get("destructive_scope") != "lease-only":
            errors.append(f"{case['id']}: destructive scope is not lease-only")
        versions = fixture.get("versions")
        if not isinstance(versions, dict) or set(versions) != expected_versions:
            errors.append(f"{case['id']}: incomplete component version request")
        elif any(
            not isinstance(value, str) or not value for value in versions.values()
        ):
            errors.append(f"{case['id']}: invalid component version selector")
        if not isinstance(fixture.get("hardware_required"), bool):
            errors.append(f"{case['id']}: hardware_required must be boolean")
        if not isinstance(fixture.get("simulation_allowed"), bool):
            errors.append(f"{case['id']}: simulation_allowed must be boolean")
        if (
            not isinstance(actions, list)
            or not actions
            or any(
                not isinstance(action, str) or not action.strip() for action in actions
            )
        ):
            errors.append(f"{case['id']}: missing actions_under_test")
    if errors:
        fail("fixture contract audit failed:\n" + "\n".join(errors))
    promoted_path = root / "automation/promoted-passing-cases.json"
    if promoted_path.is_file():
        promoted = json.loads(promoted_path.read_text()).get("cases", [])
        for item in promoted:
            case = cases_by_id.get(item.get("case_id"))
            if case is None:
                errors.append(f"promoted case is not indexed: {item.get('case_id')}")
                continue
            execution = case.get("execution", {})
            if execution.get("entrypoint") != item.get("entrypoint"):
                errors.append(f"{case['id']}: promoted entrypoint mismatch")
            entrypoint = root / str(item.get("entrypoint", ""))
            if not entrypoint.is_file() or not entrypoint.stat().st_mode & 0o111:
                errors.append(f"{case['id']}: promoted entrypoint is not executable")
        if len(promoted) != 46:
            errors.append(f"expected 46 promoted PASS cases, found {len(promoted)}")
    if errors:
        fail("fixture contract audit failed:\n" + "\n".join(errors))
    counts = Counter(case["fixture"]["profile"] for case in cases)
    print(
        json.dumps(
            {"cases": len(cases), "profiles": dict(sorted(counts.items()))}, indent=2
        )
    )


if __name__ == "__main__":
    main()
