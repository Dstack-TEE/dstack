// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, fmt::Debug, path::PathBuf, process::ExitStatus, time::Duration};

use anyhow::{Context, Result};
use bollard::{container::ListContainersOptions, Docker};
use dstack_guest_agent_rpc::v0::worker_server::WorkerRpc as _;
use dstack_types::shared_filenames::{HOST_SHARED_DIR, SYS_CONFIG};
use dstack_types::SysConfig;
use fs_err as fs;
use guest_api::{
    guest_api_server::{GuestApiRpc, GuestApiServer},
    Container, DiskInfo, Gateway, GuestInfo, Interface, IpAddress, ListContainersResponse,
    NetworkInformation, SystemInfo,
};
use host_api::Notification;
use ra_rpc::{CallContext, RpcCall};
use tokio::{process::Command, task::spawn_blocking, time::timeout};
use tracing::error;

use crate::{rpc_service::ExternalRpcHandler, AppState};

const GUEST_API_HANDLER_TIMEOUT: Duration = Duration::from_secs(20);
const DOCKER_API_TIMEOUT: Duration = Duration::from_secs(15);
const SHUTDOWN_NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);
const POWEROFF_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const WG_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

pub struct GuestApiHandler {
    state: AppState,
}

impl RpcCall<AppState> for GuestApiHandler {
    type PrpcService = GuestApiServer<Self>;

    fn construct(context: CallContext<'_, AppState>) -> Result<Self> {
        Ok(Self {
            state: context.state.clone(),
        })
    }
}

impl GuestApiRpc for GuestApiHandler {
    async fn info(self) -> Result<GuestInfo> {
        let ext_rpc = ExternalRpcHandler::new(self.state);
        let info = timeout(GUEST_API_HANDLER_TIMEOUT, ext_rpc.info())
            .await
            .context("Guest Info request timed out")??;
        Ok(GuestInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            app_id: info.app_id,
            instance_id: info.instance_id,
            device_id: info.device_id,
            app_cert: info.app_cert,
            tcb_info: info.tcb_info,
        })
    }

    async fn shutdown(self) -> Result<()> {
        tokio::spawn(async move {
            let _ = timeout(
                SHUTDOWN_NOTIFY_TIMEOUT,
                notify_host("shutdown.progress", "powering off"),
            )
            .await;
            let mut command = Command::new("systemctl");
            command.arg("poweroff").kill_on_drop(true);
            perr(
                timeout(POWEROFF_COMMAND_TIMEOUT, command.status())
                    .await
                    .context("systemctl poweroff timed out")
                    .and_then(|result| result.context("failed to run systemctl poweroff"))
                    .and_then(|status| ensure_command_success("systemctl poweroff", status)),
            );
        });
        Ok(())
    }

    async fn network_info(self) -> Result<NetworkInformation> {
        let mut info = timeout(
            GUEST_API_HANDLER_TIMEOUT,
            spawn_blocking(collect_network_info),
        )
        .await
        .context("NetworkInfo request timed out")?
        .context("NetworkInfo worker failed")??;
        info.wg_info = get_wg_info().await.unwrap_or_else(|e| e.to_string());
        Ok(info)
    }

    async fn sys_info(self) -> Result<SystemInfo> {
        let data_disks = self.state.config().data_disks.clone();
        timeout(
            GUEST_API_HANDLER_TIMEOUT,
            spawn_blocking(move || collect_sys_info(&data_disks)),
        )
        .await
        .context("SysInfo request timed out")?
        .context("SysInfo worker failed")
    }

    async fn list_containers(self) -> Result<ListContainersResponse> {
        timeout(GUEST_API_HANDLER_TIMEOUT, list_containers())
            .await
            .context("ListContainers request timed out")?
    }
}

fn collect_network_info() -> Result<NetworkInformation> {
    Ok(NetworkInformation {
        dns_servers: get_dns_servers(),
        gateways: get_gateways(),
        interfaces: get_interfaces(),
        wg_info: String::new(),
    })
}

fn collect_sys_info(data_disks: &HashSet<PathBuf>) -> SystemInfo {
    use sysinfo::{Disks, System};

    let system = System::new_all();
    let cpus = system.cpus();

    let disks = Disks::new_with_refreshed_list();
    let mut disks = disks
        .list()
        .iter()
        .filter(|d| data_disks.contains(d.mount_point()))
        .map(|d| DiskInfo {
            name: d.name().to_string_lossy().to_string(),
            mount_point: d.mount_point().to_string_lossy().to_string(),
            total_size: d.total_space(),
            free_size: d.available_space(),
        })
        .collect::<Vec<_>>();
    disks.sort_by(|d1, d2| d1.mount_point.cmp(&d2.mount_point));
    let avg = System::load_average();
    SystemInfo {
        os_name: System::name().unwrap_or_default(),
        os_version: System::os_version().unwrap_or_default(),
        kernel_version: System::kernel_version().unwrap_or_default(),
        cpu_model: cpus.first().map_or("".into(), |cpu| {
            format!("{} @{} MHz", cpu.name(), cpu.frequency())
        }),
        num_cpus: cpus.len() as _,
        total_memory: system.total_memory(),
        available_memory: system.available_memory(),
        used_memory: system.used_memory(),
        free_memory: system.free_memory(),
        total_swap: system.total_swap(),
        used_swap: system.used_swap(),
        free_swap: system.free_swap(),
        uptime: System::uptime(),
        loadavg_one: (avg.one * 100.0) as u32,
        loadavg_five: (avg.five * 100.0) as u32,
        loadavg_fifteen: (avg.fifteen * 100.0) as u32,
        disks,
    }
}

pub(crate) async fn list_containers() -> Result<ListContainersResponse> {
    let docker = Docker::connect_with_defaults().context("Failed to connect to Docker")?;
    let containers = timeout(
        DOCKER_API_TIMEOUT,
        docker.list_containers::<&str>(Some(ListContainersOptions {
            all: true,
            ..Default::default()
        })),
    )
    .await
    .context("Docker list-containers request timed out")?
    .context("Failed to list containers")?;
    Ok(ListContainersResponse {
        containers: containers
            .into_iter()
            .map(|c| Container {
                id: c.id.unwrap_or_default(),
                names: c.names.unwrap_or_default(),
                image: c.image.unwrap_or_default(),
                image_id: c.image_id.unwrap_or_default(),
                created: c.created.unwrap_or_default(),
                state: c.state.unwrap_or_default(),
                status: c.status.unwrap_or_default(),
            })
            .collect(),
    })
}

fn get_interfaces() -> Vec<Interface> {
    sysinfo::Networks::new_with_refreshed_list()
        .into_iter()
        .filter_map(|(interface_name, network)| {
            if !(interface_name.starts_with("dstack-wg")
                || interface_name.starts_with("enp")
                || interface_name.starts_with("eth"))
            {
                // We only get dstack gateway, enp and eth interfaces.
                // Docker bridge is not included due to privacy concerns.
                return None;
            }
            Some(Interface {
                name: interface_name.clone(),
                addresses: network
                    .ip_networks()
                    .iter()
                    .map(|ip| IpAddress {
                        address: ip.addr.to_string(),
                        prefix: ip.prefix as u32,
                    })
                    .collect(),
                rx_bytes: network.total_received(),
                tx_bytes: network.total_transmitted(),
                rx_errors: network.total_errors_on_received(),
                tx_errors: network.total_errors_on_transmitted(),
            })
        })
        .collect()
}

fn get_gateways() -> Vec<Gateway> {
    default_net::get_interfaces()
        .into_iter()
        .flat_map(|iface| {
            iface.gateway.map(|gw| Gateway {
                address: gw.ip_addr.to_string(),
            })
        })
        .collect()
}

fn get_dns_servers() -> Vec<String> {
    let mut dns_servers = Vec::new();
    // read /etc/resolv.conf
    let Ok(resolv_conf) = fs::read_to_string("/etc/resolv.conf") else {
        return dns_servers;
    };
    for line in resolv_conf.lines() {
        if line.starts_with("nameserver") {
            let Some(ip) = line.split_whitespace().nth(1) else {
                continue;
            };
            dns_servers.push(ip.to_string());
        }
    }
    dns_servers
}

async fn get_wg_info() -> Result<String> {
    let mut command = Command::new("wg");
    command.kill_on_drop(true);
    let output = timeout(WG_COMMAND_TIMEOUT, command.output())
        .await
        .context("wg command timed out")?
        .context("failed to run wg")?;
    ensure_command_success("wg", output.status)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn ensure_command_success(command: &str, status: ExitStatus) -> Result<()> {
    if !status.success() {
        anyhow::bail!("{command} exited with {status}");
    }
    Ok(())
}

pub async fn notify_host(event: &str, payload: &str) -> Result<()> {
    let local_config: SysConfig = serde_json::from_str(&fs::read_to_string(format!(
        "{HOST_SHARED_DIR}/{SYS_CONFIG}"
    ))?)?;
    let Some(host_api_url) = local_config.host_api_url else {
        anyhow::bail!("host_api_url not configured");
    };
    let nc = host_api::client::new_client(host_api_url);
    nc.notify(Notification {
        event: event.to_string(),
        payload: payload.to_string(),
    })
    .await?;
    Ok(())
}

fn perr<T, E: Debug>(result: Result<T, E>) {
    if let Err(e) = &result {
        error!("{e:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::ensure_command_success;
    use std::{os::unix::process::ExitStatusExt, process::ExitStatus};

    #[test]
    fn command_status_accepts_zero_exit_code() {
        assert!(ensure_command_success("test", ExitStatus::from_raw(0)).is_ok());
    }

    #[test]
    fn command_status_rejects_nonzero_exit_code() {
        let error = ensure_command_success("test", ExitStatus::from_raw(7 << 8))
            .expect_err("nonzero exit status must fail");
        assert!(error
            .to_string()
            .contains("test exited with exit status: 7"));
    }
}
