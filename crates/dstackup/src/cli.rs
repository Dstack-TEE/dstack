// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! command-line interface (clap definitions).

use clap::{Args, Parser, Subcommand};
use dstack_cli_core::config;

pub(crate) const DEFAULT_VMM_BIN: &str = "dstack-vmm";
pub(crate) const DEFAULT_AUTH_BIN: &str = "dstack-auth";
pub(crate) const DEFAULT_SUPERVISOR_BIN: &str = "supervisor";
pub(crate) const DEFAULT_SOURCE_REPO: &str = "https://github.com/Dstack-TEE/dstack";
pub(crate) const DEFAULT_SOURCE_REF: &str = "master";

#[derive(Parser)]
#[command(name = "dstackup", version, about = "set up and manage a dstack host")]
pub(crate) struct Cli {
    /// VMM control socket / endpoint to talk to. Defaults to the local install state,
    /// then the local control socket.
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
    Status {
        /// installation root to inspect. Omit for the default system install.
        #[arg(long, value_name = "DIR")]
        prefix: Option<String>,
    },
    /// Download or list guest OS images.
    #[command(subcommand)]
    Image(ImageCmd),
    /// Tear down the deployment (keeps configs + KMS keys unless --purge).
    Destroy {
        /// installation root to tear down. Omit for the default system install.
        #[arg(long, value_name = "DIR")]
        prefix: Option<String>,
        /// also wipe generated config, state, cache, runtime files, and KMS keys.
        #[arg(long)]
        purge: bool,
    },
}

/// where guest images live, shared by every `image` subcommand and resolved the
/// same way `install` does: `--image-path` if given, else the layout image dir.
#[derive(Args)]
pub(crate) struct ImageLoc {
    /// image directory (overrides the layout image dir, e.g. an external store).
    #[arg(long)]
    pub(crate) image_path: Option<String>,
    /// installation root. Omit for the default system install.
    #[arg(long, value_name = "DIR")]
    pub(crate) prefix: Option<String>,
}

impl ImageLoc {
    /// the resolved image directory.
    pub(crate) fn dir(&self) -> String {
        crate::image::resolve_image_dir(self.image_path.as_deref(), self.prefix.as_deref())
    }
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
        #[command(flatten)]
        loc: ImageLoc,
        /// re-download even if the image is already present.
        #[arg(long)]
        force: bool,
        /// proceed even if the release publishes no sha256 to verify against.
        #[arg(long)]
        insecure: bool,
    },
    /// List guest OS images already present locally.
    List {
        #[command(flatten)]
        loc: ImageLoc,
    },
    /// Remove one or more local guest OS images.
    #[command(visible_alias = "remove")]
    Rm {
        /// image name(s) to delete (as shown by `dstackup image list`).
        #[arg(value_name = "NAME", required = true)]
        names: Vec<String>,
        #[command(flatten)]
        loc: ImageLoc,
    },
}

/// flags for `dstackup install`.
#[derive(Args)]
pub(crate) struct InstallOpts {
    /// expose the dashboard on this IP (default: bind localhost only —
    /// reach it via an SSH tunnel).
    #[arg(long, value_name = "IP")]
    pub(crate) expose: Option<String>,

    /// guest OS image name or release version to deploy.
    #[arg(long, value_name = "VERSION")]
    pub(crate) image: Option<String>,

    /// confidential-computing platform: `auto` (detect) | `tdx` | `amd-sev-snp`.
    #[arg(long, default_value = "auto")]
    pub(crate) platform: String,

    /// installation root. Omit for the default system install.
    #[arg(long, value_name = "DIR")]
    pub(crate) prefix: Option<String>,

    /// systemd instance suffix: units become `dstack-vmm-<instance>` etc.,
    /// so a fresh install coexists with an existing `dstack-vmm.service`.
    #[arg(long)]
    pub(crate) instance: Option<String>,

    /// guest image directory (default: the layout image directory).
    #[arg(long)]
    pub(crate) image_path: Option<String>,

    /// dstack source checkout used to build managed binaries.
    /// Defaults to the current checkout, or a source cache under the install layout.
    #[arg(long, value_name = "DIR")]
    pub(crate) source: Option<String>,

    /// Git repository used when dstackup needs to populate the source cache.
    #[arg(long, default_value = DEFAULT_SOURCE_REPO)]
    pub(crate) source_repo: String,

    /// Git ref used when dstackup needs to populate the source cache.
    #[arg(long, default_value = DEFAULT_SOURCE_REF)]
    pub(crate) source_ref: String,

    /// directory where dstackup installs user-facing dstack binaries.
    #[arg(long, value_name = "DIR")]
    pub(crate) bin_dir: Option<String>,

    /// directory where dstackup installs private host daemon binaries.
    #[arg(long, value_name = "DIR")]
    pub(crate) libexec_dir: Option<String>,

    /// directory where dstackup installs static assets and examples.
    #[arg(long, value_name = "DIR")]
    pub(crate) share_dir: Option<String>,

    /// use the configured binaries as-is; do not build or install managed binaries.
    #[arg(long)]
    pub(crate) skip_managed_binaries: bool,

    /// dstack-vmm binary.
    #[arg(long, default_value = DEFAULT_VMM_BIN)]
    pub(crate) vmm_bin: String,

    /// dstack-auth binary.
    #[arg(long, default_value = DEFAULT_AUTH_BIN)]
    pub(crate) auth_bin: String,

    /// supervisor binary.
    #[arg(long, default_value = DEFAULT_SUPERVISOR_BIN)]
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

    /// proceed even if the app OS image can't be pinned (missing platform
    /// digest) — apps will boot any unmeasured image and still get keys. not
    /// recommended.
    #[arg(long)]
    pub(crate) allow_unpinned_image: bool,

    /// render + write configs only; do not start any process.
    #[arg(long)]
    pub(crate) no_start: bool,
}
