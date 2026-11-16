#!/usr/bin/env python3
"""Build a deterministic evidence matrix for non-passing full-plan results."""

import argparse
import json
from pathlib import Path

NONPASSING = {"FAIL", "BLOCKED", "INCOMPLETE"}


def load_json(path: Path):
    """Load a JSON document from path."""
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def main() -> int:
    """Generate the evidence matrix and return a validation status."""
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path, help="full-plan result directory")
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    classifications = {}
    if args.ledger and args.ledger.exists():
        for line in args.ledger.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("classification"):
                classifications[record.get("case_id")] = record

    rows = []
    for result_path in sorted((args.results / "cases").glob("**/result.json")):
        result = load_json(result_path)
        if result.get("status") not in NONPASSING:
            continue
        case_id = result.get("case_id")
        artifact_checks = []
        for artifact in result.get("artifacts", []):
            relative = artifact.get("path")
            artifact_path = result_path.parent / relative if relative else None
            artifact_checks.append(
                {
                    "name": artifact.get("name"),
                    "path": relative,
                    "exists": bool(artifact_path and artifact_path.is_file()),
                    "step_id": artifact.get("step_id"),
                }
            )
        steps = result.get("steps", [])
        classification = classifications.get(case_id, {})
        rows.append(
            {
                "case_id": case_id,
                "status": result.get("status"),
                "provisional": result.get("provisional"),
                "summary": result.get("summary"),
                "remarks": result.get("remarks"),
                "step_statuses": [step.get("status") for step in steps],
                "artifacts": artifact_checks,
                "all_declared_artifacts_exist": all(
                    a["exists"] for a in artifact_checks
                ),
                "classification": classification.get("classification"),
                "classification_reason": classification.get("reason"),
                "classification_timestamp": classification.get("ts"),
                "result_path": str(result_path.relative_to(args.results)),
            }
        )

    payload = {
        "schema_version": "1.0",
        "results": str(args.results),
        "nonpassing_count": len(rows),
        "status_counts": {
            status: sum(r["status"] == status for r in rows)
            for status in sorted(NONPASSING)
        },
        "missing_classification_count": sum(not r["classification"] for r in rows),
        "missing_artifact_count": sum(
            sum(not artifact["exists"] for artifact in row["artifacts"]) for row in rows
        ),
        "cases": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                key: payload[key]
                for key in (
                    "nonpassing_count",
                    "status_counts",
                    "missing_classification_count",
                    "missing_artifact_count",
                )
            },
            sort_keys=True,
        )
    )
    return 1 if payload["missing_artifact_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
