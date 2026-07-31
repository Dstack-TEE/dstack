#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render the exact candidate dashboard models with deterministic hostile data."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-entry-003"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically within the case result directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def main() -> int:
    """Render exact candidate templates and record bounded assertions."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise ValueError(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    repo = pathlib.Path(__file__).resolve().parents[4]
    guest_agent = repo / "dstack/guest-agent"

    with tempfile.TemporaryDirectory(prefix="dstack-dashboard-model-") as directory:
        probe = pathlib.Path(directory)
        (probe / "src").mkdir()
        (probe / "templates").mkdir()
        (probe / "src/models.rs").write_bytes(
            (guest_agent / "src/models.rs").read_bytes()
        )
        for name in ("dashboard.html", "metrics.tpl"):
            (probe / f"templates/{name}").write_bytes(
                (guest_agent / f"templates/{name}").read_bytes()
            )
        (probe / "Cargo.toml").write_text(
            f"""[package]\nname = "dstack-dashboard-model-probe"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\nanyhow = "1"\nhex = "0.4.3"\nrinja = "0.3.5"\nguest-api = {{ path = {json.dumps(str(repo / "dstack/guest-api"))} }}\n""",
            encoding="utf-8",
        )
        (probe / "src/main.rs").write_text(RUST_PROBE, encoding="utf-8")
        environment = os.environ.copy()
        runtime = json.loads(
            pathlib.Path(environment["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
        )
        shared_target = runtime.get("values", {}).get(
            "cargo_target_dir"
        ) or runtime.get("cargo_target_dir")
        if shared_target:
            environment["CARGO_TARGET_DIR"] = str(shared_target)
        completed = subprocess.run(
            ["cargo", "run", "--quiet", "--manifest-path", str(probe / "Cargo.toml")],
            text=True,
            capture_output=True,
            timeout=240,
            env=environment,
            check=False,
        )

    try:
        observation = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        observation = {"probe_output_valid": False}
    checks = {
        "probe_executed": completed.returncode == 0,
        "html_text_escaped": observation.get("html_text_escaped") is True,
        "html_attribute_escaped": observation.get("html_attribute_escaped") is True,
        "hex_and_optional_names": observation.get("hex_and_optional_names") is True,
        "boundary_units": observation.get("boundary_units") is True,
        "prometheus_labels_escaped": observation.get("prometheus_labels_escaped")
        is True,
        "numeric_metrics_exact": observation.get("numeric_metrics_exact") is True,
        "high_cardinality_complete": observation.get("high_cardinality_complete")
        is True,
        "concurrent_render_stable": observation.get("concurrent_render_stable") is True,
    }
    artifact = {
        "path": "artifacts/dashboard-model-observation.json",
        "step_id": f"{case_id}-step-02",
        "name": "Dashboard model render assertions",
        "description": "Boolean assertions and output hashes prove candidate HTML/Prometheus escaping, units, cardinality, and concurrent render behavior without retaining hostile input or rendered pages.",
    }
    atomic_json(
        result_dir / artifact["path"],
        {
            "checks": checks,
            "observation": observation,
            "compiler_stderr_tail": completed.stderr[-1000:],
        },
    )
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if all(checks.values()) else "FAIL"
    render_ok = checks["probe_executed"]
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "Candidate dashboard and metrics models satisfy all deterministic render assertions."
            if status == "PASS"
            else "One or more candidate dashboard or metrics render assertions failed.",
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": "PASS",
                    "observed": "The probe copied the exact candidate model and templates into an isolated temporary crate.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status if render_ok else "FAIL",
                    "observed": "Synthetic hostile text, boundary counters, optional names, and high-cardinality disks were rendered and checked.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": "PASS" if checks["concurrent_render_stable"] else "FAIL",
                    "observed": "Concurrent repeated renders were compared by digest and the temporary harness was removed.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "The artifact contains only booleans, lengths, hashes, and a bounded compiler diagnostic tail; it does not retain rendered hostile content.",
        },
    )
    return 0


RUST_PROBE = r"""
mod models;
use guest_api::{Container, DiskInfo, SystemInfo};
use models::{Dashboard, Metrics};
use rinja::Template;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn digest(value: &str) -> u64 { let mut h = DefaultHasher::new(); value.hash(&mut h); h.finish() }
fn system_info(hostile: &str) -> SystemInfo {
    SystemInfo {
        os_name: hostile.into(), os_version: "v<&>".into(), kernel_version: hostile.into(), cpu_model: hostile.into(),
        num_cpus: u32::MAX, total_memory: u64::MAX, available_memory: 1024, used_memory: 1023, free_memory: 0,
        total_swap: 1024, used_swap: 1023, free_swap: 1, uptime: u64::MAX,
        loadavg_one: 1, loadavg_five: 100, loadavg_fifteen: u32::MAX,
        disks: (0..256).map(|i| DiskInfo { name: format!("disk-{i}-{hostile}"), mount_point: format!("/mnt/{i}-{hostile}"), total_size: if i == 0 { 0 } else { u64::MAX }, free_size: if i == 0 { 0 } else { 1024 } }).collect(),
    }
}
fn main() -> anyhow::Result<()> {
    let hostile = "<script>alert(\"x\")</script>&'";
    let label = "label\"\\\nnext";
    let info = system_info(label);
    let dashboard = Dashboard { app_name: hostile.into(), app_id: vec![0, 255], instance_id: vec![1, 2], device_id: vec![3, 4], key_provider_info: hostile.into(), tcb_info: hostile.into(), containers: vec![Container { id: "id".into(), names: vec![format!("/{hostile}")], image: String::new(), image_id: String::new(), created: 0, state: String::new(), status: hostile.into() }, Container { names: vec![], ..Default::default() }], system_info: info.clone(), public_sysinfo: true, public_logs: true, public_tcbinfo: true, cloud_vendor: hostile.into(), cloud_product: hostile.into() };
    let html = dashboard.render()?;
    let metrics = Metrics { system_info: info }.render()?;
    let html_text_escaped = !html.contains("<script>");
    let html_attribute_escaped = !html.contains("/logs/<script>") && !html.contains("target=\"_blank\"><script>");
    let hex_and_optional_names = html.contains("00ff") && html.contains("0102") && html.contains("0304");
    let boundary_units = html.contains("1023.00 B") && html.contains("1.00 KB");
    let prometheus_labels_escaped = metrics.contains("label\\\"\\\\\\nnext") && !metrics.contains("label\"\\\nnext");
    let numeric_metrics_exact = metrics.contains("system_memory_total 18446744073709551615") && metrics.contains("system_memory_available 1024");
    let high_cardinality_complete = metrics.matches("disk_total_size{name=").count() == 256;
    let expected = digest(&html);
    let concurrent_baseline = {
        let d = Dashboard { app_name: hostile.into(), app_id: vec![0,255], instance_id: vec![1,2], device_id: vec![3,4], key_provider_info: String::new(), tcb_info: String::new(), containers: vec![], system_info: SystemInfo::default(), public_sysinfo: false, public_logs: false, public_tcbinfo: false, cloud_vendor: String::new(), cloud_product: String::new() };
        digest(&d.render()?)
    };
    let mut threads = vec![];
    for _ in 0..8 { let hostile = hostile.to_string(); threads.push(std::thread::spawn(move || { let d = Dashboard { app_name: hostile, app_id: vec![0,255], instance_id: vec![1,2], device_id: vec![3,4], key_provider_info: String::new(), tcb_info: String::new(), containers: vec![], system_info: SystemInfo::default(), public_sysinfo: false, public_logs: false, public_tcbinfo: false, cloud_vendor: String::new(), cloud_product: String::new() }; digest(&d.render().unwrap()) })); }
    let concurrent_render_stable = threads.into_iter().all(|t| t.join().is_ok_and(|hash| hash == concurrent_baseline));
    println!("{{\"html_text_escaped\":{html_text_escaped},\"html_attribute_escaped\":{html_attribute_escaped},\"hex_and_optional_names\":{hex_and_optional_names},\"boundary_units\":{boundary_units},\"prometheus_labels_escaped\":{prometheus_labels_escaped},\"numeric_metrics_exact\":{numeric_metrics_exact},\"high_cardinality_complete\":{high_cardinality_complete},\"concurrent_render_stable\":{concurrent_render_stable},\"html_hash\":{expected},\"html_len\":{},\"metrics_hash\":{},\"metrics_len\":{}}}", html.len(), digest(&metrics), metrics.len());
    Ok(())
}
"""


if __name__ == "__main__":
    raise SystemExit(main())
