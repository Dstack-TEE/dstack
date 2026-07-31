#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate NUMA and hugepage placement rows on prepared host capabilities."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

CASE_ID = "tc-vmm-compute-ne-003"


def main() -> int:
    """Record host placement capability and block safely when unavailable."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    host = manifest.get("values", {}).get("host_capabilities", {})
    total = int(host.get("hugepages_2m_total") or 0)
    nodes = int(host.get("numa_nodes") or 0)
    available = total > 0 and nodes > 0
    status = "FAIL" if available else "BLOCKED"
    evidence = {
        "case_id": CASE_ID,
        "status": status,
        "hugepages_2m_total": total,
        "numa_nodes": nodes,
        "placement_available": available,
        "unsafe_allocation_avoided": not available,
    }
    path = result_dir / "artifacts/numa-hugepage-capability.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact = {
        "path": "artifacts/numa-hugepage-capability.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "NUMA hugepage host capability",
        "description": "Prepared host inventory used to decide whether hardware placement rows can execute.",
    }
    (result_dir / "artifacts/manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    observed = (
        "Host placement resources exist; execution must be implemented instead of reporting a gap."
        if available
        else f"Prepared host inventory reports hugepages_2m_total={total} and numa_nodes={nodes}; the specification requires hardware rows to remain BLOCKED without launching or scanning unrelated VMs."
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": "NUMA/hugepage placement resources exist but execution is not implemented"
        if available
        else "missing capability: host NUMA hugepage placement resources",
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": observed}
            for n in range(1, 4)
        ],
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "No VM was created because a stopped definition cannot prove placement and the prepared host has no hugepages.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
