// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! command-line interface (clap definitions).

use clap::{Args, Parser, Subcommand};
use dstack_cli_core::config;

#[derive(Parser)]
#[command(name = "dstackup", version, about = "set up and manage a dstack host")]
pub(crate) struct Cli {
    /// VMM control socket / endpoint to talk to (for status and attach).
    #[arg(long, global = true)]
    pub(crate) host: Option<String>,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
// `Install` carries all the host-setup flags; the size gap to `Status`/`Destroy`
// is irrelevant for a CLI enum constructed once at startup.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Command {
    /// Bring up the host stack: SGX preflight, render configs, and start the
    /// VMM + auth webhook. (Gramine bring-up and KMS-in-CVM bootstrap follow.)
    Install(InstallOpts),
    /// Show the health of the host stack.
    Status,
    /// Download or list guest OS images.
    #[command(subcommand)]
    Image(ImageCmd),
    /// Tear down the deployment (keeps configs + KMS keys unless --purge).
    Destroy {
        /// install prefix to tear down.
        #[arg(long, default_value = "/var/lib/dstack")]
        prefix: String,
        /// also wipe the prefix (configs + KMS keys).
        #[arg(long)]
        purge: bool,
    },
}

/// `dstackup image` subcommands.
#[derive(Subcommand)]
pub(crate) enum ImageCmd {
    /// Download a guest OS image from meta-dstack releases.
    Pull {
        /// image version to fetch (default: the latest release).
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
        /// fetch the gpu (nvidia) image instead of the cpu one.
        #[arg(long)]
        gpu: bool,
        /// directory to unpack into (default: /var/lib/dstack/images).
        #[arg(long)]
        image_path: Option<String>,
        /// re-download even if the image is already present.
        #[arg(long)]
        force: bool,
    },
    /// List guest OS images already present locally.
    List {
        /// image directory to scan (default: /var/lib/dstack/images).
        #[arg(long)]
        image_path: Option<String>,
    },
    /// Remove one or more local guest OS images.
    #[command(visible_alias = "remove")]
    Rm {
        /// image name(s) to delete (as shown by `dstackup image list`).
        #[arg(value_name = "NAME", required = true)]
        names: Vec<String>,
        /// image directory to remove from (default: /var/lib/dstack/images).
        #[arg(long)]
        image_path: Option<String>,
    },
}

/// flags for `dstackup install`.
#[derive(Args)]
pub(crate) struct InstallOpts {
    /// expose the dashboard on this IP (default: bind localhost only —
    /// reach it via an SSH tunnel).
    #[arg(long, value_name = "IP")]
    pub(crate) expose: Option<String>,

    /// guest OS image version to deploy.
    #[arg(long, value_name = "VERSION")]
    pub(crate) image: Option<String>,

    /// confidential-computing platform: `auto` (detect) | `tdx` | `amd-sev-snp`.
    #[arg(long, default_value = "auto")]
    pub(crate) platform: String,

    /// install prefix for configs, certs, run state.
    #[arg(long, default_value = "/var/lib/dstack")]
    pub(crate) prefix: String,

    /// systemd instance suffix: units become `dstack-vmm-<instance>` etc.,
    /// so a fresh install coexists with an existing `dstack-vmm.service`.
    #[arg(long)]
    pub(crate) instance: Option<String>,

    /// guest image directory (default: <prefix>/images).
    #[arg(long)]
    pub(crate) image_path: Option<String>,

    /// dstack-vmm binary.
    #[arg(long, default_value = "dstack-vmm")]
    pub(crate) vmm_bin: String,

    /// dstack-auth binary.
    #[arg(long, default_value = "dstack-auth")]
    pub(crate) auth_bin: String,

    /// dstack-supervisor binary.
    #[arg(long, default_value = "dstack-supervisor")]
    pub(crate) supervisor_bin: String,

    /// qemu binary.
    #[arg(long, default_value = "/usr/bin/qemu-system-x86_64")]
    pub(crate) qemu: String,

    /// dashboard TCP port.
    #[arg(long, default_value_t = 9080)]
    pub(crate) dashboard_port: u16,

    /// auth webhook port.
    #[arg(long, default_value_t = 8001)]
    pub(crate) auth_port: u16,

    /// host-api vsock port (raise to coexist with an existing VMM on 10000).
    #[arg(long, default_value_t = 10000)]
    pub(crate) host_api_port: u32,

    /// CID pool start (default: auto — the first free block, so it coexists
    /// with any VMM already running on this host).
    #[arg(long)]
    pub(crate) cid_start: Option<u32>,

    /// use an existing key provider at ADDR:PORT instead of running our own.
    #[arg(long, value_name = "ADDR:PORT")]
    pub(crate) use_existing_key_provider: Option<String>,

    /// port for our own key provider (when not using an existing one).
    #[arg(long, default_value_t = 3443)]
    pub(crate) key_provider_port: u16,

    /// key-provider build/compose directory (to start our own).
    #[arg(long)]
    pub(crate) key_provider_src: Option<String>,

    /// KMS container image.
    #[arg(long, default_value = config::DEFAULT_KMS_IMAGE)]
    pub(crate) kms_image: String,

    /// host port for the KMS RPC (default: an auto-picked free port).
    #[arg(long)]
    pub(crate) kms_port: Option<u16>,

    /// skip the KMS-in-CVM deploy (bring up VMM + auth only).
    #[arg(long)]
    pub(crate) no_kms: bool,

    /// proceed even if the app OS image can't be pinned (no digest.txt) —
    /// apps will boot any unmeasured image and still get keys. NOT recommended.
    #[arg(long)]
    pub(crate) allow_unpinned_image: bool,

    /// render + write configs only; do not start any process.
    #[arg(long)]
    pub(crate) no_start: bool,
}
