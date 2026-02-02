// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use anyhow::{bail, Result};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

mod tcp;
mod udp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForwardRule {
    pub protocol: Protocol,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub target_ip: IpAddr,
    pub target_port: u16,
}

impl ForwardRule {
    fn listen_sock(&self) -> SocketAddr {
        SocketAddr::new(self.listen_addr, self.listen_port)
    }

    fn target_sock(&self) -> SocketAddr {
        SocketAddr::new(self.target_ip, self.target_port)
    }
}

struct RunningRule {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

/// Manages a dynamic set of port forwarding rules.
///
/// Rules can be added and removed at runtime. Dropping the service cancels all
/// forwarding tasks.
pub struct ForwardService {
    cancel: CancellationToken,
    rules: HashMap<ForwardRule, RunningRule>,
}

impl ForwardService {
    pub fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
            rules: HashMap::new(),
        }
    }

    /// Add a forwarding rule. Returns error if the rule already exists.
    pub fn add_rule(&mut self, rule: ForwardRule) -> Result<()> {
        if self.rules.contains_key(&rule) {
            bail!("rule already exists: {:?}", rule);
        }

        let token = self.cancel.child_token();
        let listen = rule.listen_sock();
        let target = rule.target_sock();

        let task = match rule.protocol {
            Protocol::Tcp => tokio::spawn(tcp::run_tcp_forwarder(listen, target, token.clone())),
            Protocol::Udp => tokio::spawn(udp::run_udp_forwarder(listen, target, token.clone())),
        };

        tracing::info!("added forwarding rule: {listen} -> {target} ({:?})", rule.protocol);
        self.rules.insert(rule, RunningRule { cancel: token, task });
        Ok(())
    }

    /// Remove a forwarding rule and stop its task.
    pub async fn remove_rule(&mut self, rule: &ForwardRule) -> Result<()> {
        match self.rules.remove(rule) {
            Some(running) => {
                running.cancel.cancel();
                let _ = running.task.await;
                tracing::info!(
                    "removed forwarding rule: {} -> {} ({:?})",
                    rule.listen_sock(),
                    rule.target_sock(),
                    rule.protocol,
                );
                Ok(())
            }
            None => bail!("rule not found: {:?}", rule),
        }
    }

    /// Number of active rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Gracefully stop all forwarding and wait for tasks to finish.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        for (_, running) in std::mem::take(&mut self.rules) {
            let _ = running.task.await;
        }
    }
}

impl Default for ForwardService {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ForwardService {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
