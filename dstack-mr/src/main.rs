// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack-mr` CLI.
//!
//! Currently exposes the AMD SEV-SNP `os_image_hash` computation used by the
//! image build to emit `digest.sev.txt`.

use anyhow::{bail, Context, Result};
use std::path::Path;

const USAGE: &str = "usage: dstack-mr sev-os-image-hash <image_dir>";

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("sev-os-image-hash") => {
            let image_dir = args.next().context(USAGE)?;
            let hash = dstack_mr::sev::sev_os_image_hash_for_image_dir(Path::new(&image_dir))
                .context("failed to compute amd sev-snp os_image_hash")?;
            println!("{}", hex::encode(hash));
            Ok(())
        }
        Some("-h") | Some("--help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => bail!("unknown subcommand {other:?}\n{USAGE}"),
        None => bail!("{USAGE}"),
    }
}
