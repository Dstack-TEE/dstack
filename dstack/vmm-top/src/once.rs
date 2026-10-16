// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! One snapshot to stdout, for pipes, scripts and `--once` / `--json`.

use crate::fmt;
use crate::snapshot::{NodeSnapshot, Report};
use crate::source::Source;
use anyhow::Result;
use std::fmt::Write as _;

pub async fn run(sources: Vec<Source>, json: bool) -> Result<()> {
    let now = fmt::now_ms();
    let polls = futures::future::join_all(sources.iter().map(|s| s.poll())).await;
    let mut nodes: Vec<NodeSnapshot> = Vec::new();
    for (src, result) in sources.iter().zip(polls) {
        match result {
            Ok(ns) => nodes.extend(ns.into_iter().map(|mut n| {
                if n.ok_at_ms.is_none() && n.error.is_none() {
                    n.ok_at_ms = Some(now);
                    n.polled_at_ms = now;
                }
                n
            })),
            Err(err) => nodes.push(NodeSnapshot {
                name: src.spec.name.clone(),
                endpoint: src.endpoint(),
                polled_at_ms: now,
                error: Some(format!("{err:#}")),
                ..Default::default()
            }),
        }
    }
    if json {
        let report = Report {
            hub: String::new(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            interval_ms: 0,
            nodes,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    print!("{}", render(&nodes));
    Ok(())
}

pub fn render(nodes: &[NodeSnapshot]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<20} {:<8} {:>7} {:>9} {:>11} {:>5} {:>6}  ENDPOINT",
        "NODE", "STATUS", "VMS", "VCPU", "MEM", "GPU", "RTT"
    );
    for n in nodes {
        let status = if n.error.is_some() { "down" } else { "online" };
        let res = n.resources.clone().unwrap_or_default();
        let known = n.ok_at_ms.is_some();
        let cell = |s: String| if known { s } else { "-".to_string() };
        let _ = writeln!(
            out,
            "{} {:<8} {:>7} {:>9} {:>11} {:>5} {:>6}  {}",
            fmt::pad(&n.name, 20),
            status,
            cell(format!("{}/{}", n.live_vms().count(), n.vms.len())),
            cell(format!("{}/{}", n.vcpu_used(), res.max_vcpu)),
            cell(format!(
                "{}/{}",
                fmt::mem_mb(n.memory_used_mb()),
                fmt::mem_mb(res.max_memory_mb as u64)
            )),
            if n.gpus.is_empty() {
                "-".to_string()
            } else {
                format!("{}/{}", n.gpus_used(), n.gpus.len())
            },
            n.latency_ms
                .map(|l| format!("{l}ms"))
                .unwrap_or_else(|| "-".into()),
            n.endpoint,
        );
        if let Some(e) = &n.error {
            let _ = writeln!(out, "  error: {e}");
        }
    }
    let vms: Vec<_> = nodes
        .iter()
        .flat_map(|n| n.vms.iter().map(move |v| (n, v)))
        .collect();
    if vms.is_empty() {
        return out;
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{:<28} {:<16} {:<14} {:>7} {:>5} {:>6} {:>6}  {:<8}  IMAGE",
        "VM", "NODE", "STATUS", "UPTIME", "VCPU", "MEM", "DISK", "ID"
    );
    let mut vms = vms;
    vms.sort_by(|(na, a), (nb, b)| {
        a.phase()
            .cmp(&b.phase())
            .then_with(|| na.name.cmp(&nb.name))
            .then_with(|| a.name.cmp(&b.name))
    });
    for (n, v) in vms {
        let _ = writeln!(
            out,
            "{} {} {} {:>7} {:>5} {:>6} {:>6}  {:<8}  {}",
            fmt::pad(&v.name, 28),
            fmt::pad(&n.name, 16),
            fmt::pad(v.phase().label(), 14),
            v.uptime_secs
                .map(fmt::duration)
                .unwrap_or_else(|| "-".into()),
            v.vcpu,
            fmt::mem_mb(v.memory_mb as u64),
            fmt::disk_gb(v.disk_gb as u64),
            v.short_id(),
            v.image,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Vm;

    #[test]
    fn plain_text_lists_nodes_then_vms() {
        let nodes = vec![NodeSnapshot {
            name: "tdx-01".into(),
            endpoint: "http://h:1".into(),
            ok_at_ms: Some(1),
            vms: vec![Vm {
                id: "abcdef0123".into(),
                name: "web".into(),
                status: "running".into(),
                vcpu: 2,
                memory_mb: 2048,
                ..Default::default()
            }],
            ..Default::default()
        }];
        let text = render(&nodes);
        assert!(text.lines().nth(1).unwrap().starts_with("tdx-01"));
        assert!(text.contains("web"));
        assert!(text.contains("abcdef01"));
        assert!(text.contains("2G"));
    }
}
