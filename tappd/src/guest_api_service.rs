use std::{path::Path, process::Command};

use anyhow::{Context, Result};
use bollard::{container::ListContainersOptions, Docker};
use fs_err as fs;
use guest_api::{
    guest_api_server::{GuestApiRpc, GuestApiServer},
    Container, DiskInfo, Gateway, GuestInfo, Interface, IpAddress, ListContainersResponse,
    NetworkInformation, SystemInfo,
};
use host_api::Notification;
use ra_rpc::{CallContext, RpcCall};
use serde::Deserialize;
use tappd_rpc::worker_server::WorkerRpc as _;

use crate::{rpc_service::ExternalRpcHandler, AppState};

#[derive(Deserialize)]
struct LocalConfig {
    host_api_url: String,
}

pub struct GuestApiHandler {
    state: AppState,
}

impl RpcCall<AppState> for GuestApiHandler {
    type PrpcService = GuestApiServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        GuestApiServer::new(self)
    }

    fn construct(context: CallContext<'_, AppState>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            state: context.state.clone(),
        })
    }
}

impl GuestApiRpc for GuestApiHandler {
    async fn info(self) -> Result<GuestInfo> {
        let ext_rpc = ExternalRpcHandler::new(self.state);
        let info = ext_rpc.info().await?;
        Ok(GuestInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            app_id: info.app_id,
            instance_id: info.instance_id,
            app_cert: info.app_cert,
            tcb_info: info.tcb_info,
        })
    }

    async fn shutdown(self) -> Result<()> {
        tokio::spawn(async move {
            notify_host("shutdown.progress", "stopping app").await.ok();
            run_command("systemctl stop app-compose").ok();
            notify_host("shutdown.progress", "powering off").await.ok();
            run_command("systemctl poweroff").ok();
        });
        Ok(())
    }

    async fn network_info(self) -> Result<NetworkInformation> {
        let networks = sysinfo::Networks::new_with_refreshed_list();
        for (interface_name, network) in &networks {
            println!("[{interface_name}]: {network:?}");
        }
        Ok(NetworkInformation {
            dns_servers: get_dns_servers(),
            gateways: get_gateways(),
            interfaces: get_interfaces(),
        })
    }

    async fn sys_info(self) -> Result<SystemInfo> {
        use sysinfo::System;

        let system = System::new_all();
        let cpus = system.cpus();

        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disks = disks
            .list()
            .iter()
            .filter(|d| d.mount_point() == Path::new("/"))
            .map(|d| DiskInfo {
                name: d.name().to_string_lossy().to_string(),
                mount_point: d.mount_point().to_string_lossy().to_string(),
                total_size: d.total_space(),
                free_size: d.available_space(),
            })
            .collect::<Vec<_>>();
        let avg = System::load_average();
        Ok(SystemInfo {
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
        })
    }

    async fn list_containers(self) -> Result<ListContainersResponse> {
        list_containers().await
    }
}

pub(crate) async fn list_containers() -> Result<ListContainersResponse> {
    let docker = Docker::connect_with_defaults().context("Failed to connect to Docker")?;
    let containers = docker
        .list_containers::<&str>(Some(ListContainersOptions {
            all: true,
            ..Default::default()
        }))
        .await
        .context("Failed to list containers")?;
    Ok(ListContainersResponse {
        containers: containers
            .into_iter()
            .map(|c| Container {
                id: c.id.unwrap_or_default(),
                names: c.names.unwrap_or_default(),
                image: c.image.unwrap_or_default(),
                image_id: c.image_id.unwrap_or_default(),
                command: c.command.unwrap_or_default(),
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
            if !(interface_name == "wg0" || interface_name.starts_with("enp")) {
                // We only get wg0 and enp interfaces.
                // Docker bridge is not included due to privacy concerns.
                return None;
            }
            Some(Interface {
                name: interface_name.clone(),
                addresses: network
                    .ip_networks()
                    .into_iter()
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

pub async fn notify_host(event: &str, payload: &str) -> Result<()> {
    let local_config: LocalConfig =
        serde_json::from_str(&fs::read_to_string("/tapp/config.json")?)?;
    let nc = host_api::client::new_client(local_config.host_api_url);
    nc.notify(Notification {
        event: event.to_string(),
        payload: payload.to_string(),
    })
    .await?;
    Ok(())
}

fn run_command(command: &str) -> Result<()> {
    let output = Command::new("sh").arg("-c").arg(command).output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!("Command failed: {}", output.status));
    }
    Ok(())
}