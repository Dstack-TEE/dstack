// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack-mr` CLI.
//!
//! Exposes build-time OS-image measurement material/hash computations.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::io::Write;
use std::path::Path;

const USAGE: &str = "\
usage:
  dstack-mr measure-os <image_dir>
  dstack-mr inspect-measurement [tdx|snp] <measurement.cbor>
  dstack-mr tdx-measurement-cbor <image_dir>
  dstack-mr snp-measurement-cbor <image_dir>
  dstack-mr tdx-measurement-hash <image_dir>
  dstack-mr snp-measurement-hash <image_dir>

features:
  split-cbor-measurement-v3";

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("measure-os") => {
            let image_dir = args.next().context(USAGE)?;
            let document = dstack_mr::measurement::os_image_measurement_document_for_image_dir(
                Path::new(&image_dir),
            )
            .context("failed to compute os image measurement document")?;
            println!(
                "{}",
                serde_json::to_string(&document)
                    .context("failed to serialize os image measurement document")?
            );
            Ok(())
        }
        Some("inspect-measurement") => {
            let first = args.next().context(USAGE)?;
            let second = args.next();
            let (kind, measurement_cbor) = match second {
                Some(path) => (first, path),
                None => (infer_measurement_kind(&first)?, first),
            };
            let document = inspect_measurement(&kind, Path::new(&measurement_cbor))
                .context("failed to inspect os image measurement document")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&document)
                    .context("failed to serialize decoded measurement document")?
            );
            Ok(())
        }
        Some("snp-measurement-cbor") => {
            let image_dir = args.next().context(USAGE)?;
            let cbor =
                dstack_mr::sev::sev_os_image_measurement_cbor_for_image_dir(Path::new(&image_dir))
                    .context("failed to compute amd sev-snp measurement CBOR")?;
            std::io::stdout()
                .write_all(&cbor)
                .context("failed to write amd sev-snp measurement CBOR")?;
            Ok(())
        }
        Some("tdx-measurement-cbor") => {
            let image_dir = args.next().context(USAGE)?;
            let cbor =
                dstack_mr::tdx::tdx_os_image_measurement_cbor_for_image_dir(Path::new(&image_dir))
                    .context("failed to compute tdx measurement CBOR")?;
            std::io::stdout()
                .write_all(&cbor)
                .context("failed to write tdx measurement CBOR")?;
            Ok(())
        }
        Some("snp-measurement-hash") | Some("sev-measurement-hash") => {
            let image_dir = args.next().context(USAGE)?;
            let hash = dstack_mr::sev::sev_measurement_hash_for_image_dir(Path::new(&image_dir))
                .context("failed to compute amd sev-snp measurement hash")?;
            println!("{}", hex::encode(hash));
            Ok(())
        }
        Some("tdx-measurement-hash") => {
            let image_dir = args.next().context(USAGE)?;
            let hash = dstack_mr::tdx::tdx_measurement_hash_for_image_dir(Path::new(&image_dir))
                .context("failed to compute tdx measurement hash")?;
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

fn inspect_measurement(kind: &str, path: &Path) -> Result<Value> {
    let cbor = fs_err::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    match kind {
        "tdx" => dstack_types::TdxOsImageMeasurement::cbor_json_value_from_slice(&cbor)
            .map_err(anyhow::Error::msg),
        "snp" | "sev" => dstack_types::SevOsImageMeasurement::cbor_json_value_from_slice(&cbor)
            .map_err(anyhow::Error::msg),
        other => bail!("unknown measurement kind {other:?}; expected tdx or snp"),
    }
}

fn infer_measurement_kind(path: &str) -> Result<String> {
    let filename = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);
    if filename.contains(".tdx.") || filename.contains("tdx") {
        Ok("tdx".to_string())
    } else if filename.contains(".snp.") || filename.contains("snp") || filename.contains("sev") {
        Ok("snp".to_string())
    } else {
        bail!("cannot infer measurement kind from {filename:?}; pass tdx or snp explicitly")
    }
}
