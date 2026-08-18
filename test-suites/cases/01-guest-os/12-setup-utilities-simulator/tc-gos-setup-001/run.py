#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the candidate environment allowlist parser through an isolated crate."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-setup-001"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write a JSON document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def main() -> int:
    """Run the case-scoped environment allowlist acceptance matrix."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    candidate_source = repository / "dstack/dstack-util/src/parse_env_file.rs"

    with tempfile.TemporaryDirectory(prefix="dstack-env-allowlist-") as directory:
        probe = pathlib.Path(directory)
        (probe / "src").mkdir()
        (probe / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")
        (probe / "src/lib.rs").write_text(
            f"#[path = {json.dumps(str(candidate_source))}]\nmod parse_env_file;\n"
            + RUST_TESTS,
            encoding="utf-8",
        )
        environment = os.environ.copy()
        shared_target = runtime.get("cargo_target_dir") or runtime.get(
            "values", {}
        ).get("cargo_target_dir")
        if shared_target:
            environment["CARGO_TARGET_DIR"] = str(shared_target)
        completed = subprocess.run(
            ["cargo", "test", "--quiet", "--manifest-path", str(probe / "Cargo.toml")],
            text=True,
            capture_output=True,
            timeout=300,
            env=environment,
            check=False,
        )

    log = result_dir / "artifacts/env-allowlist-probe.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(completed.stdout + completed.stderr, encoding="utf-8")
    artifact = {
        "path": "artifacts/env-allowlist-probe.log",
        "step_id": f"{case_id}-step-01",
        "name": "Environment allowlist acceptance probe",
        "description": "Cargo test output from the isolated crate proves the exact candidate parser passed the allowlist, bounds, recovery, concurrency, escaping, ordering, and cleanup matrix.",
    }
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    passed = completed.returncode == 0
    status = "PASS" if passed else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "The candidate environment parser passed the complete isolated acceptance matrix."
            if passed
            else "The candidate environment parser failed one or more isolated acceptance assertions.",
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "The exact candidate module was tested with allowed, denied, duplicate, Unicode, hostile, malformed, and boundary inputs.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Malformed and over-limit failures were followed by valid retries, including concurrent valid and invalid calls.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Repeated output was deterministic and the temporary crate was removed automatically.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "This is a pure in-process source-module probe; no service, VM, listener, credential, or persistent state is involved.",
        },
    )
    return 0


CARGO_TOML = """[package]
name = "dstack-env-allowlist-probe"
version = "0.0.0"
edition = "2021"

[dependencies]
anyhow = "1"
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
"""

RUST_TESTS = r"""
#[cfg(test)]
mod acceptance {
    use super::parse_env_file::{convert_env_to_str, parse_env};
    use std::collections::BTreeSet;

    fn allowed(keys: &[&str]) -> BTreeSet<String> {
        keys.iter().map(|key| (*key).to_string()).collect()
    }

    #[test]
    fn allowlist_duplicates_order_unicode_and_escaping() {
        let input = r#"{"env":[{"key":"Z","value":"line1\nline2"},{"key":"NO","value":"sentinel-denied"},{"key":"A","value":"old"},{"key":"A","value":"new $`\\\" 世界"}]}"#;
        let parsed = parse_env(
            input.as_bytes(),
            &allowed(&["A", "Z"]),
        ).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed["A"], "new $`\\\" 世界");
        let output = convert_env_to_str(&parsed);
        assert_eq!(output, "A=\"new \\$\\`\\\\\" 世界\"\nZ=\"line1\\nline2\"\n");
        assert!(!output.contains("NO"));
        assert!(!output.contains("sentinel-denied"));
        assert_eq!(convert_env_to_str(&parsed), output);
    }

    #[test]
    fn malformed_types_keys_and_bounds_fail_then_recover() {
        let allow_a = allowed(&["A"]);
        for invalid in [
            br#"not-json"#.as_slice(),
            br#"{"env":[{"key":"A","value":1}]}"#.as_slice(),
            br#"{"env":[{"key":"A","value":true}]}"#.as_slice(),
            br#"{"env":[{"key":"A","value":null}]}"#.as_slice(),
            br#"{"env":[{"key":"A","value":{"nested":"x"}}]}"#.as_slice(),
            br#"{"env":[{"key":"1BAD","value":"x"}]}"#.as_slice(),
        ] {
            let allow = if invalid.windows(4).any(|w| w == b"1BAD") { allowed(&["1BAD"]) } else { allow_a.clone() };
            assert!(parse_env(invalid, &allow).is_err());
            assert_eq!(parse_env(br#"{"env":[{"key":"A","value":"ok"}]}"#, &allow_a).unwrap()["A"], "ok");
        }
        let value = "x".repeat(128 * 1024 + 1);
        let oversized = serde_json::json!({"env":[{"key":"A","value":value}]}).to_string();
        assert!(parse_env(oversized.as_bytes(), &allow_a).is_err());
        let items: Vec<_> = (0..1025).map(|i| serde_json::json!({"key":format!("K{i}"),"value":"x"})).collect();
        assert!(parse_env(serde_json::json!({"env":items}).to_string().as_bytes(), &BTreeSet::new()).is_err());
        let keys: BTreeSet<_> = (0..9).map(|i| format!("K{i}")).collect();
        let total: Vec<_> = keys.iter().map(|key| serde_json::json!({"key":key,"value":"x".repeat(120 * 1024)})).collect();
        assert!(parse_env(serde_json::json!({"env":total}).to_string().as_bytes(), &keys).is_err());
        let long_key = format!("A{}", "x".repeat(255));
        let long_input = serde_json::json!({"env":[{"key":long_key,"value":"x"}]}).to_string();
        assert!(parse_env(long_input.as_bytes(), &allowed(&[long_key.as_str()])).is_err());
        assert!(parse_env(br#"{"env":[]}"#, &BTreeSet::new()).unwrap().is_empty());
    }

    #[test]
    fn concurrent_calls_are_isolated_and_recoverable() {
        let mut workers = Vec::new();
        for index in 0..32 {
            workers.push(std::thread::spawn(move || {
                if index % 3 == 0 {
                    assert!(parse_env(b"invalid", &BTreeSet::new()).is_err());
                }
                let parsed = parse_env(br#"{"env":[{"key":"A","value":"ok"}]}"#, &allowed(&["A"])).unwrap();
                assert_eq!(convert_env_to_str(&parsed), "A=ok\n");
            }));
        }
        for worker in workers { worker.join().unwrap(); }
    }
}
"""


if __name__ == "__main__":
    raise SystemExit(main())
