// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{path::Path, time::Duration};

use anyhow::{anyhow, Context, Result};
use app::App;
use clap::{Args as ClapArgs, Parser, Subcommand};
use config::{Config, NetdConfig};
use dstack_api_auth::{Authenticator, HttpAuthConfig, HttpAuthFairing};
use guest_api_service::GuestApiHandler;
use host_api_service::HostApiHandler;
use main_service::RpcHandler;
use path_absolutize::Absolutize;
use rocket::{
    fairing::AdHoc,
    figment::{providers::Serialized, Figment},
};
use rocket_vsock_listener::VsockListener;
use supervisor_client::SupervisorClient;
use tracing::{error, info, warn};

mod app;
mod config;
mod discovery;
mod gpu_reset;
mod guest_api_service;
mod host_api_service;
mod logrotate;
mod main_routes;
mod main_service;
mod netd;
mod one_shot;
mod openapi;
mod vm_launcher;

const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_REV: &str = dstack_build_info::git_revision!();

fn app_version() -> String {
    dstack_build_info::app_version!()
}

#[derive(Parser)]
#[command(author, version, about, long_version = app_version())]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
    /// Override the netd socket used by the VMM (useful without systemd).
    #[arg(long, global = true)]
    netd_socket: Option<String>,
    /// Subcommand to run
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Default, Subcommand)]
enum Command {
    /// Start the VMM server (default mode)
    #[default]
    Serve,
    /// Validate the effective server configuration without starting services.
    CheckConfig,
    /// One-shot VM execution mode for debugging
    Run(RunArgs),
    /// Run the privileged TAP and libvirt nwfilter broker.
    Netd(NetdArgs),
    /// Internal per-VM QEMU/swtpm launcher.
    #[command(hide = true)]
    VmLauncher(VmLauncherArgs),
}

#[derive(ClapArgs)]
struct NetdArgs {
    /// Override the Unix socket configured in [netd].
    #[arg(long)]
    socket: Option<String>,
    /// Inspect a running netd instead of starting one.
    #[command(subcommand)]
    command: Option<NetdCommand>,
}

#[derive(Subcommand)]
enum NetdCommand {
    /// List every host interface netd holds.
    ///
    /// Answers the question a leak is made of -- whose is this interface --
    /// which deriving a name from an identity cannot.
    List {
        /// Only this VMM instance's interfaces. Defaults to every one netd
        /// owns, including those it cannot attribute.
        #[arg(long)]
        instance: Option<String>,
    },
    /// Delete one interface by name.
    ///
    /// For what nothing else can name: an interface built before netd recorded
    /// ownership, or by another netd, whose VM is gone. `netd list` shows these
    /// with no instance and no VM, so nothing can derive the sweep that would
    /// take them; an operator who can tell what they are says so here.
    RemoveInterface {
        /// The interface name, as `netd list` prints it.
        name: String,
    },
    /// Delete every interface netd holds for one VM.
    ///
    /// For a VM whose VMM will never ask again -- one whose directory was
    /// deleted by hand, or whose instance is gone. A VMM sweeps its own VMs on
    /// every stop and every removal, and keeps a removal pending until the
    /// sweep lands; this is for when no VMM will ever run that sweep.
    RemoveVm {
        /// The `cvm.instance_id` of the VMM that created them. `netd list`
        /// shows it.
        #[arg(long)]
        instance: String,
        /// The VM's ID.
        #[arg(long)]
        vm: String,
    },
}

#[derive(ClapArgs)]
struct RunArgs {
    /// VM configuration file path
    vm_config: String,
    /// Working directory for one-shot mode (default: create in current directory)
    #[arg(long)]
    workdir: Option<String>,
    /// Dry run: only output QEMU command without executing
    #[arg(long)]
    dry_run: bool,
}

#[derive(ClapArgs)]
struct VmLauncherArgs {
    /// Path to the generated VM launch specification.
    #[arg(long)]
    spec: String,
}

async fn run_external_api(app: App, figment: Figment, api_auth: Authenticator) -> Result<()> {
    let version = app_version();
    let openapi_doc = openapi::build_openapi_doc(&version)?;

    let external_api = rocket::custom(figment)
        .mount("/", main_routes::routes())
        .mount("/guest", ra_rpc::prpc_routes!(App, GuestApiHandler))
        .mount(
            "/prpc",
            ra_rpc::prpc_routes!(App, RpcHandler, trim: "Teepod."),
        )
        .manage(app)
        .attach(HttpAuthFairing::new(
            api_auth,
            HttpAuthConfig {
                realm: "dstack-vmm API".into(),
                token_header: Some("X-Admin-Token".into()),
                allow_get_query_token: true,
            },
        ))
        .mount("/", dstack_api_auth::routes())
        .attach(AdHoc::on_response("Add app rev header", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-App-Version", app_version());
            })
        }))
        .attach(AdHoc::on_response("Disable buffering", |_req, res| {
            Box::pin(async move {
                res.set_raw_header("X-Accel-Buffering", "no");
            })
        }));
    let external_api =
        ra_rpc::rocket_helper::mount_openapi_docs(external_api, openapi_doc, "/api-docs");

    let _ = external_api
        .launch()
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

async fn run_host_api(app: App, figment: Figment) -> Result<()> {
    let figment = figment
        .clone()
        .merge(Serialized::defaults(figment.find_value("host_api")?));
    let rocket = rocket::custom(figment)
        .mount("/api", ra_rpc::prpc_routes!(App, HostApiHandler))
        .manage(app);
    let ignite = rocket
        .ignite()
        .await
        .map_err(|err| anyhow!("Failed to ignite rocket: {err}"))?;
    // Host API only supports vsock listener (validated at startup)
    let listener = VsockListener::bind_rocket(&ignite)
        .map_err(|err| anyhow!("Failed to bind host API: {err}"))?;
    ignite
        .launch_on(listener)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

async fn auto_restart_task(app: App) {
    if !app.config.cvm.auto_restart.enabled {
        info!("Auto restart CVMs is disabled");
        return;
    }
    let mut interval =
        tokio::time::interval(Duration::from_secs(app.config.cvm.auto_restart.interval));
    loop {
        interval.tick().await;
        info!("Checking for exited VMs");
        if let Err(err) = app.try_restart_exited_vms().await {
            error!("Failed to restart exited VMs: {err:?}");
        }
    }
}

async fn log_rotation_task(app: App) {
    if app.config.cvm.log.max_bytes == 0 {
        info!("Log rotation is disabled");
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(
        app.config.cvm.log.check_interval_secs.max(1),
    ));
    loop {
        interval.tick().await;
        if let Err(err) = app.rotate_oversized_logs().await {
            error!("Failed to rotate logs: {err:?}");
        }
    }
}

/// Client-side netd subcommands. Talks to the socket like the VMM does, so it
/// needs whatever the socket's permissions ask for and not root.
async fn run_netd_command(config: &NetdConfig, command: &NetdCommand) -> Result<()> {
    match command {
        NetdCommand::List { instance } => {
            let interfaces = netd::list(&config.socket, instance.as_deref().unwrap_or_default())
                .await
                .context("failed to list netd interfaces")?;
            println!(
                "{:<16} {:<8} {:<24} {:<38} {:>3}",
                "INTERFACE", "KIND", "INSTANCE", "VM", "NIC"
            );
            let mut unattributed = 0;
            for record in &interfaces {
                if record.instance_id.is_none() {
                    unattributed += 1;
                }
                println!(
                    "{:<16} {:<8} {:<24} {:<38} {:>3}",
                    record.tap,
                    record.kind,
                    record.instance_id.as_deref().unwrap_or("-"),
                    record.vm_id.as_deref().unwrap_or("-"),
                    record
                        .nic_index
                        .map_or_else(|| "-".to_string(), |index| index.to_string()),
                );
            }
            println!();
            println!("{} interface(s)", interfaces.len());
            if unattributed > 0 {
                // Not a fault to fix by hand: an interface built before netd
                // recorded ownership, or by another netd, carries no record and
                // gets one the next time its VM launches.
                println!(
                    "{unattributed} carry no ownership record; `netd remove-interface` takes \
                     one by name"
                );
            }
            Ok(())
        }
        NetdCommand::RemoveInterface { name } => {
            netd::remove_interface_named(&config.socket, name)
                .await
                .with_context(|| format!("failed to remove {name}"))?;
            println!("removed {name}");
            Ok(())
        }
        NetdCommand::RemoveVm { instance, vm } => {
            let removed = netd::remove_all(&config.socket, instance, vm)
                .await
                .context("failed to remove the VM's interfaces")?;
            println!("removed {removed} interface(s) for {vm}");
            Ok(())
        }
    }
}

#[rocket::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).with_ansi(false).init();
    }

    let args = Args::parse();

    // The per-VM launcher must stay minimal: do not load or validate the VMM
    // server configuration in this mode.
    if let Some(Command::VmLauncher(launcher_args)) = &args.command {
        return vm_launcher::run(Path::new(&launcher_args.spec)).await;
    }

    let figment = config::load_config_figment(args.config.as_deref());
    if let Some(Command::Netd(netd_args)) = &args.command {
        let mut netd_config: NetdConfig = figment
            .extract_inner("netd")
            .context("failed to load [netd] configuration")?;
        if let Some(socket) = args.netd_socket.as_deref() {
            netd_config.socket = socket.into();
        }
        if let Some(socket) = netd_args.socket.as_deref() {
            netd_config.socket = socket.into();
        }
        if netd_config.network_filter.is_none() {
            // netd and the VMM normally share one vmm.toml, so the node has
            // already stated whether its bridge traffic is filtered and with
            // what. Reading it here keeps the two from drifting apart, which is
            // what a second setting to keep in sync would invite.
            //
            // A malformed section is an error rather than a default: this is
            // the daemon's security policy, and `[cvm.network_filter] mode =
            // "Libvirt"` -- which the VMM itself refuses to start on -- must not
            // quietly resolve to "filter nothing" here.
            netd_config.network_filter = Some(
                figment
                    .extract_inner("cvm.network_filter")
                    .context("failed to load [cvm.network_filter] for netd")?,
            );
        }
        if let Some(command) = &netd_args.command {
            return run_netd_command(&netd_config, command).await;
        }
        return netd::serve(netd_config).await;
    }

    let mut config = Config::extract_or_default(&figment)?.abs_path()?;
    config.cvm.instance_id = netd::instance_id(&config.cvm.instance_id, config.run_path.as_path());
    if let Some(socket) = args.netd_socket.as_deref() {
        config.netd.socket = socket.into();
    }

    // Preserve the existing startup validation. The broader static checks are
    // opt-in through `check-config` until they have seen wider deployment use.
    netd::validate_instance_id(&config.cvm.instance_id)?;
    config
        .host_api
        .validate()
        .context("Invalid host_api configuration")?;
    config
        .cvm
        .auto_restart
        .validate()
        .context("Invalid cvm.auto_restart configuration")?;

    // Handle commands
    match args.command.unwrap_or_default() {
        Command::VmLauncher(_) => unreachable!("launcher mode handled before config loading"),
        Command::CheckConfig => {
            config.validate()?;
            let _: rocket::listener::Endpoint = figment
                .extract_inner("address")
                .context("Invalid management API address")?;
            let _: u16 = figment
                .extract_inner("port")
                .context("Invalid management API port")?;
            println!("configuration is valid");
            return Ok(());
        }
        Command::Netd(_) => unreachable!("netd mode handled before server startup"),
        Command::Run(run_args) => {
            // One-shot VM execution mode
            return one_shot::run_one_shot(
                &run_args.vm_config,
                config,
                run_args.workdir,
                run_args.dry_run,
            )
            .await;
        }
        Command::Serve => {
            // Default server mode - continue to main server logic
        }
    }

    // Register this VMM instance for local discovery
    discovery::cleanup_stale_registrations();
    // whether the management API binds a TCP address reachable beyond the local
    // host (i.e. not a Unix socket and not a loopback IP). Used to warn when the
    // surface is exposed without authentication.
    let mut listen_tcp_public = false;
    let listen_address = {
        // Use Rocket's Endpoint type to parse the address exactly as Rocket would,
        // then override the port with the figment's port value (matching Rocket's behavior).
        let endpoint: rocket::listener::Endpoint =
            figment.extract_inner("address").unwrap_or_default();
        match endpoint.tcp() {
            Some(addr) => {
                let port: u16 = figment.extract_inner("port").unwrap_or(addr.port());
                listen_tcp_public = !addr.ip().is_loopback();
                format!("{}:{port}", addr.ip())
            }
            None => endpoint.to_string(),
        }
    };
    let _discovery_reg = match discovery::DiscoveryRegistration::register(
        &listen_address,
        args.config.as_deref(),
        &config.image.path,
        &config.run_path,
        &config.node_name,
        &app_version(),
    ) {
        Ok(registration) => Some(registration),
        Err(err) => {
            warn!("failed to register VMM instance for discovery: {err:#}");
            None
        }
    };

    let mut api_auth = if config.auth.enabled {
        Authenticator::from_tokens(config.auth.tokens.clone())
    } else {
        Authenticator::disabled()
    };
    if config.auth.enabled && !config.auth.htpasswd_file.as_os_str().is_empty() {
        api_auth = api_auth.with_htpasswd_file(&config.auth.htpasswd_file)?;
    }
    if !config.auth.enabled && listen_tcp_public {
        warn!(
            "the management API is bound to a non-loopback address ({listen_address}) with \
             `[auth] enabled = false`: the entire VMM control surface (create/stop VM, UI, \
             pRPC) is exposed WITHOUT authentication. set `[auth] enabled = true` with a \
             token, or bind `address` to localhost / a Unix socket."
        );
    }
    let supervisor = {
        let cfg = &config.supervisor;
        let abs_exe = Path::new(&cfg.exe).absolutize()?;
        SupervisorClient::start_and_connect_uds(
            &abs_exe,
            &cfg.sock,
            &cfg.pid_file,
            &cfg.log_file,
            cfg.detached,
            cfg.auto_start,
        )
        .await
        .context("Failed to connect to supervisor")?
    };
    let state = app::App::new(config, supervisor);
    state.reload_vms().await.context("Failed to reload VMs")?;
    tokio::spawn(auto_restart_task(state.clone()));
    tokio::spawn(log_rotation_task(state.clone()));

    tokio::select! {
        result = run_external_api(state.clone(), figment.clone(), api_auth) => {
            result.context("Failed to run external API")?;
        }
        result = run_host_api(state, figment) => {
            result.context("Failed to run host API")?;
        }
    }
    Ok(())
}
